"""
Prompt Injection Radar and output checks (Phase 4 M4.1, docs/plans/phase4-m4-plan.md).

Looks at what a tool RETURNED, before the agent reads it, for two kinds of trouble:

  injection  text planted in data that tries to steer the agent (override, fake system markers, persona change, tool-call
             smuggling, exfiltration, concealment, prompt disclosure, authority and urgency tricks, hidden or encoded text)
  output     content that is dangerous to whatever renders or fetches it (script, dangerous URLs, image-based exfiltration,
             internal or metadata addresses, sensitive file paths)

Pure and bounded: no I/O, no logging of the text, at most 16 KiB, 1,000 values and depth 16 per scan (a larger value is read at both ends, so an appended attack is still seen), one level of decoding
(at most 8 blobs of 4 KiB). The text is untrusted and is NEVER copied into a finding: a finding carries a fixed rule id, family,
severity, confidence, a coarse place and a fixed reason, so a finding cannot itself carry an attack to whoever reads it.

These are deterministic rules. They catch known patterns, in English and Bahasa Malaysia, and a rephrased attack gets through.
The benchmark (`python -m agentwall.src.bench`) reports what they catch and what they falsely flag, per category and language;
that, not this docstring, is the claim. Block-eligibility is NOT decided here: it comes from the measured gate (plan 11.2).

Confidence is evidence-based and deterministic: it rises with corroborating cues in the same or a neighbouring sentence
(a destination, concealment, urgency, an authority claim, a request to reveal secrets), with evasion (hidden or encoded text,
lookalike letters), and when the text names a tool THIS agent holds (the caller passes the names from the agent's passport).
"""

from __future__ import annotations

import base64
import bisect
import binascii
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
import html
import ipaddress
import itertools
import re
from typing import Any, Literal, Protocol
from urllib.parse import unquote, urlsplit
import unicodedata

MAX_CHARS = 16 * 1024  # measured: about 0.8 ms per KiB (plan section 8), so the worst case stays well inside the 50 ms p99 budget
MAX_NODES = 1000
MAX_DEPTH = 16
MAX_BLOBS = 8
MAX_BLOB_CHARS = 4096
MAX_FINDINGS = 20
MIN_TEXT_CHARS = 6
MAX_SEGMENT_CHARS = 600
MAX_OUTPUT_MATCHES = 50  # URLs, images and path hits examined per value; the rest of a flood is not read

Kind = Literal["injection", "output"]
Level = Literal["low", "medium", "high"]
Where = Literal["text", "hidden", "decoded"]


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    family: str
    kind: Kind
    severity: Level
    confidence: Level
    where: Where
    evasion: tuple[str, ...]  # "invisible", "lookalike", "leet", "encoded", "hidden"
    reason: str  # fixed wording per rule, never taken from the text


@dataclass(frozen=True, slots=True)
class ScanReport:
    findings: tuple[Finding, ...]
    truncated: bool  # part of the result was past the scan budget and was not scanned
    skipped_binary: int  # large base64-looking values (images, files) that were deliberately not read as text


@dataclass(frozen=True, slots=True)
class ScanContext:
    """What the caller knows that makes a finding more or less likely. Tool names come from the agent's own passport."""

    tool_names: frozenset[str] = frozenset()


EMPTY_CONTEXT = ScanContext()

# rule id -> (family, kind, severity default, fixed reason)
RULES: dict[str, tuple[str, Kind, Level, str]] = {
    "RAD-INJ-001": ("override", "injection", "high", "The text tells the agent to ignore, drop or override its instructions."),
    "RAD-INJ-002": ("persona", "injection", "high", "The text tries to give the agent a new role, mode or identity."),
    "RAD-INJ-003": ("marker", "injection", "high", "The text contains fake system or role markers that imitate the conversation's own structure."),
    "RAD-INJ-004": ("exfiltration", "injection", "high", "The text asks the agent to send sensitive or bulk data to a destination."),
    "RAD-INJ-005": ("tool-call", "injection", "high", "The text tells the agent to call a tool or run a command, with signs it is not the user's request."),
    "RAD-INJ-006": ("concealment", "injection", "medium", "The text asks the agent to hide what it is doing from the user."),
    "RAD-INJ-007": ("disclosure", "injection", "high", "The text asks the agent to reveal its prompt, configuration or credentials."),
    "RAD-INJ-008": ("authority", "injection", "high", "The text claims authority over the agent to get a sensitive action done."),
    "RAD-INJ-009": ("hidden", "injection", "high", "The text hides instructions in characters a person cannot see."),
    "RAD-INJ-010": ("encoded", "injection", "high", "An encoded block in the text decodes to instructions for the agent."),
    "RAD-INJ-011": ("direction", "injection", "medium", "The text uses text-direction controls, which can make displayed text differ from what the agent reads."),
    "RAD-OUT-001": ("xss", "output", "high", "The content contains script or an event handler that runs when rendered."),
    "RAD-OUT-002": ("xss", "output", "high", "The content contains a link or source with a script-running URL scheme."),
    "RAD-OUT-003": ("xss", "output", "medium", "The content contains active markup (frame, object, redirect, external form or style import)."),
    "RAD-OUT-004": ("exfil-img", "output", "high", "The content embeds an image whose address carries data to an outside server."),
    "RAD-OUT-005": ("ssrf", "output", "high", "The content points at an internal, loopback, private or cloud-metadata address."),
    "RAD-OUT-006": ("ssrf", "output", "medium", "The content points at a risky URL scheme or a known data-collection service."),
    "RAD-OUT-007": ("path", "output", "high", "The content points at a sensitive file or escapes its directory."),
}

# Which benchmark category each rule informs; a rule family is credited only to its own category.
CATEGORY_OF_RULE: dict[str, str] = {
    **{r: "injection_indirect" for r in RULES if r.startswith("RAD-INJ")},
    "RAD-OUT-001": "output_xss", "RAD-OUT-002": "output_xss", "RAD-OUT-003": "output_xss", "RAD-OUT-004": "output_xss",
    "RAD-OUT-005": "output_ssrf", "RAD-OUT-006": "output_ssrf", "RAD-OUT-007": "output_path",
}

_LEVELS: tuple[Level, ...] = ("low", "medium", "high")


def _raise(level: Level, steps: int) -> Level:
    return _LEVELS[min(len(_LEVELS) - 1, _LEVELS.index(level) + steps)]


# --- preparing text: the normalisation layer (A1) ---------------------------------------------------------------------

# Zero-width, bidirectional-control, word-joiner and tag characters: invisible to a person, readable to a model.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_TAGS = re.compile("[\U000e0020-\U000e007e]")
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "ο": "o", "ε": "e", "α": "a", "ι": "i", "ν": "v", "τ": "t", "κ": "k", "ѵ": "v", "ӏ": "l", "ԛ": "q", "ԝ": "w",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})  # digits only: @ $ ! occur in emails, prices and prose
_SPACE = re.compile(r"\s+")
_LEET_WORD = re.compile(r"(?<![\w])(?=[a-z0-9]*[a-z])(?=[a-z0-9]*[013457])[a-z0-9]{3,24}(?![\w@.])")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
_BINARY_BLOB = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")


@dataclass(frozen=True, slots=True)
class Prepared:
    clean: str  # NFKC, invisible removed, lookalikes folded, case folded, whitespace collapsed
    leet: str | None  # clean with letter-like digits and symbols folded, only when that changed something
    hidden: str  # text carried by Unicode tag characters, decoded to ASCII (empty when none)
    decoded: tuple[str, ...]  # one level of base64 / hex blobs that decode to readable text
    markup: str  # for output rules: entities and percent-escapes decoded, case kept
    evasion: tuple[str, ...]
    has_bidi: bool


def _decode_blobs(text: str) -> list[str]:
    out: list[str] = []
    for pattern in (_BASE64, _HEX):
        for m in pattern.finditer(text):
            if len(out) >= MAX_BLOBS:
                return out
            blob = m.group(0)
            if len(blob) > MAX_BLOB_CHARS:
                continue
            try:
                raw = bytes.fromhex(blob) if pattern is _HEX else base64.b64decode(blob.replace("-", "+").replace("_", "/") + "=" * (-len(blob) % 4), validate=False)
                decoded = raw.decode("utf-8")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                continue
            printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
            if len(decoded) >= 8 and printable / len(decoded) >= 0.95 and any(c.isalpha() for c in decoded):
                out.append(decoded)
    return out


def _leet_fold(clean: str) -> str | None:
    folded = _LEET_WORD.sub(lambda m: m.group(0).translate(_LEET), clean)
    return folded if folded != clean else None


def prepare(text: str) -> Prepared:
    text = text[:MAX_CHARS]
    nfkc = unicodedata.normalize("NFKC", text)
    evasion: list[str] = []
    hidden = "".join(chr(ord(c) - 0xE0000) for c in _TAGS.findall(nfkc))
    stripped = _INVISIBLE.sub("", nfkc)
    if stripped != nfkc:
        evasion.append("invisible")
    folded = stripped.translate(_CONFUSABLES)
    if folded != stripped:
        evasion.append("lookalike")
    clean = _SPACE.sub(" ", folded.casefold()).strip()
    leet = _leet_fold(clean)
    if leet is not None:
        evasion.append("leet")
    decoded = tuple(_decode_blobs(stripped))
    markup = stripped
    for _ in range(2):  # a value that is escaped twice is still one value
        again = unquote(html.unescape(markup))
        if again == markup:
            break
        markup = again
    return Prepared(clean, leet, hidden, decoded, markup, tuple(evasion), bool(_BIDI.search(nfkc)))


# --- the injection analysis (features per sentence, rules over a small window) ---------------------------------------

_VERB_OVR = r"(?:ignore|disregard|forget|override|bypass|discard|abandon|neglect|set aside|put aside|overrule|supersede|drop)"
_PRIOR = r"(?:all|any|every|your|the|its|these|those|previous|prior|earlier|above|preceding|existing|old|original|initial|current|safety|security|system|my|our|other)"
_OBJ_STRONG = r"(?:instructions?|prompts?|directives?|guidance|programming|training|guidelines|orders|system (?:message|prompt))"
_OBJ_WEAK = r"(?:rules|polic(?:y|ies)|restrictions|safeguards|constraints|limits|guardrails|filters|protocols)"
_WEAK_NEEDS = r"(?=(?: \w+){0,3} (?:your|all|any|every|previous|prior|earlier|safety|security|above|existing|its)\b)"
_RECEIVED = r"(?:were told|were given|have been given|have been told|received|got|learned|know|were taught|were instructed|were programmed|said)"

_OVERRIDE_EN = (
    re.compile(rf"\b{_VERB_OVR}\b(?: {_PRIOR}){{1,4}} {_OBJ_STRONG}\b"),
    re.compile(rf"\b{_VERB_OVR}\b{_WEAK_NEEDS}(?: {_PRIOR}){{1,4}} {_OBJ_WEAK}\b"),
    re.compile(rf"\b{_VERB_OVR}\b (?:everything|anything|whatever|all)(?: \w+){{0,2}} (?:that )?(?:you|u)(?: have| had)?(?: been)? {_RECEIVED}\b"),
    re.compile(r"\b(?:new|updated|revised) (?:instructions?|directives?|orders)(?: from [\w ]{3,30})?:? (?:ignore|disregard|you (?:must|will|are to))"),
    re.compile(rf"\b(?:supersedes?|overrides?|replaces?|takes? precedence over)(?: {_PRIOR}){{0,3}} {_OBJ_STRONG}\b"),
    re.compile(rf"\b(?:supersedes?|overrides?|replaces?|takes? precedence over)(?: {_PRIOR}){{1,3}} {_OBJ_WEAK}\b"),
)
_OVERRIDE_MS = (
    re.compile(r"\b(?:abaikan|lupakan|ketepikan|abai|batalkan|langkau|tolak ke tepi)(?: semua| segala| setiap| apa yang)?(?: \w+){0,3} (?:arahan|peraturan|panduan|polisi|prompt|sekatan)\b"),
    re.compile(r"\b(?:abaikan|lupakan|ketepikan)(?: semua| segala)? (?:yang|apa yang) (?:anda|kamu) (?:telah )?(?:diberitahu|diberi|terima|pelajari)\b"),
)
_PERSONA = (
    re.compile(r"\byou are now\b(?: in)?(?: an?| the)?(?: \w+){0,2} (?:mode|dan|admin|administrator|unrestricted|unfiltered|uncensored|jailbroken|root|god|developer)\b"),
    re.compile(r"\b(?:developer|debug|god|jailbreak|admin|sudo|unrestricted|dan) mode\b"),
    re.compile(r"\bdo anything now\b"),
    re.compile(r"\b(?:act|behave|respond) as (?:an? |the )?(?:unrestricted|unfiltered|uncensored|jailbroken|root|admin|administrator|system)\b"),
    re.compile(r"\bpretend (?:that )?(?:you are|to be|you're)(?: an?| the)?(?: \w+){0,3} (?:owner|admin|administrator|system|root|manager|ceo|director)\b"),
    re.compile(r"\bfrom now on,? you (?:are|will be|must|work for|obey|only|shall)\b"),
    re.compile(r"\bwithout (?:any )?(?:restrictions|limits|filters|rules|guardrails)\b.{0,60}\b(?:you|do|export|print|reveal|delete)\b"),
    re.compile(r"\b(?:mulai sekarang|sekarang) (?:anda|kamu) (?:ialah|adalah|akan menjadi)\b"),
    re.compile(r"\b(?:tanpa|tiada) (?:sebarang )?sekatan\b"),
)
_MARKER = (
    re.compile(r"</?\s*(?:system|instructions?|admin|assistant|tool_result|function_results?|im_start|im_end|sys|sistem|arahan)\s*>"),
    re.compile(r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>"),
    re.compile(r"<<\s*/?sys\s*>>|\[/?inst\]"),
    re.compile(r"(?:^|[\s>\]#*])\[(?:system|admin|sistem|assistant)\]"),
    re.compile(r"#{2,}\s*(?:system|new instructions?|instructions?|admin)(?: \w+){0,2}\s*#{0,}"),
    re.compile(r"\bsystem (?:override|note for the (?:model|ai|assistant)|prompt:|message:)"),
    re.compile(r"\b(?:begin|end) (?:system|hidden|secret) (?:prompt|instructions?)\b"),
    re.compile(r"(?:^|[\s>])system: ?(?:you|call|run|ignore|send|forward|delete|execute|reveal|disregard)\b"),
    re.compile(r"<!--[^>]{0,400}\b(?:assistant|ai agent|ai assistant|llm|agent|model)\b[^>]{0,400}-->"),
    re.compile(r"\[//\]: ?# ?\([^)]{0,300}\b(?:ai|agent|assistant|model)s?\b"),
)
_SENSITIVE_OBJ = (
    r"(?:api[ _-]?keys?|access[ _-]?tokens?|session[ _-]?(?:tokens?|ids?|cookies?)|credentials?|passwords?|secrets?|private keys?|"
    r"system prompt|hidden (?:instructions?|prompt|configuration)|initial instructions|chat history|conversation(?: history| summary)?|"
    r"address book|contacts?|customer (?:list|data|records|emails)|database|ledger|kata laluan|kunci api|sejarah perbualan|senarai pelanggan|pangkalan data)"
)
_BULK_OBJ = r"(?:(?:all|every|each|full|entire|complete|whole)(?: \w+){0,2} (?:files?|folders?|documents?|records|messages?|emails?|data|contracts?|history|text|users?|customers?)|semua (?:fail|mesej|rekod|data|dokumen))"
_EXFIL_VERB = r"(?:send|forward|email|e-mail|mail|post|upload|copy|append|paste|leak|export|exfiltrate|transmit|submit|fetch|hantar|e-melkan|salin|muat naik|eksport|kirim)"
_DESTINATION = re.compile(
    r"(?:https?://[^\s'\"<>]+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|\b(?:third[- ]party|external|remote|shared) (?:server|service|folder|drive|address)\b|"
    r"\bthe (?:address|link|url) (?:below|in the footer|at the bottom)\b|\b(?:alamat|pautan) (?:di|pada) (?:bahagian )?(?:bawah|footer|hujung)\b|\bshared (?:folder|drive)\b|\bbcc:)"
)
_CALL_ID = re.compile(r"\b(?:call|invoke|run|execute|trigger|use|panggil|jalankan|gunakan)\b(?: the| alat| fungsi)?(?: [a-z']{1,12}){0,2}? (?P<id>[a-z][a-z0-9]*_[a-z0-9_]+)\b")
_CALL_NAMED = re.compile(r"\b(?:call|invoke|run|execute|panggil)\b(?: the)? (?P<id>[a-z][a-z0-9_]{3,40}) (?:tool|function|alat)\b")
_CALL_SHELL = re.compile(r"\b(?:run|execute|jalankan)\b[^.]{0,40}\b(?:curl|wget|bash|sh|nc|netcat|powershell|rm -rf|chmod|cat ~|cat /)\b|\b(?:curl|wget) \S+ ?\| ?(?:sh|bash)\b|\| ?nc \S+ \d+")
_CONCEAL = re.compile(
    r"\b(?:do not|don't|dont|never|jangan)\s+(?:\w+ ){0,3}?(?:tell|mention|reveal|show|inform|notify|alert|disclose|log|record|dedahkan|beritahu|sebut|maklumkan|rekodkan|tunjuk)\b(?: \w+){0,4}"
    r"|\b(?:without|before) (?:telling|informing|notifying|alerting|asking) (?:the )?(?:user|human|operator|owner)\b"
    r"|\bleave out (?:any )?mention\b|\bkeep (?:this|it|that) (?:a )?secret\b|\b(?:act|behave|respond) normally\b"
    r"|\b(?:silently|secretly|covertly|quietly|senyap-senyap|secara senyap|diam-diam)\b|\bhidden instruction\b|\barahan tersembunyi\b"
)
_URGENCY = re.compile(r"\b(?:urgent|immediately|right now|asap|no time|within \d+ (?:minutes?|seconds?|hours?)|in \d+ minutes|segera|sekarang juga|serta-merta)\b")
_AUTHORITY = re.compile(
    r"\b(?:message from|note from|this is|from) (?:the )?(?:it |security |system |platform |site )?(?:admin(?:istrator)?|security team|management|support team|owner|developer|ceo|administrators?|your (?:developer|administrator|boss))\b"
    r"|\b(?:mesej|nota|arahan) (?:daripada|dari) (?:pentadbir|pengurusan|pemilik|pembangun)\b|\bauthori[sz]ed by\b|\bthe user has authori[sz]ed\b"
)
_REVEAL = re.compile(
    r"\b(?:reveal|print|show|output|repeat|display|leak|disclose|paste|dump|share|give me|tell me|reply with|respond with|send me|dedahkan|tunjukkan|bocorkan|tampal)\b"
    r"[^.]{0,40}\b(?:your|the|its|anda|kamu)\b(?: \w+){0,2} (?:system prompt|hidden (?:instructions?|prompt|configuration)|initial instructions|instructions|api key|password|credentials|secret|token|configuration|prompt sistem|arahan sistem|kata laluan|kunci api)"
)
_RISKY_ACTION = re.compile(
    r"\b(?:delete|wipe|erase|drop|destroy|remove)[ _](?:all|every|backups?|records?|database|users?|data)\b|\b(?:transfer|wire|send)[ _](?:funds|money|payment)\b"
    r"|\bapprove (?:every|all|the pending|any)\b|\braise the [\w ]{0,20}limit\b|\b(?:disable|turn off) (?:logging|safety|the safeguards|checks|monitoring)\b|\bgrant (?:me |full )?(?:admin|access)\b"
)
_HAS_SENSITIVE = re.compile(_SENSITIVE_OBJ)
_HAS_BULK = re.compile(_BULK_OBJ)
_HAS_EXFIL_VERB = re.compile(rf"\b{_EXFIL_VERB}\b")
_ADDRESSES_AGENT = re.compile(
    r"\b(?:assistant|ai agent|ai assistant|ai model|llm|language model|ejen ai|pembantu ai)\b|(?:^|[\s>:])(?:ai|agent|ejen)[:,]|\byou (?:must|should|will|need to|are to|have to)\b|\bpastikan anda\b|\banda (?:mesti|perlu|hendaklah)\b|\bagents? reading this\b"
)
_QUOTE_BEFORE = re.compile(
    r"(?:\b(?:says?|said|saying|reads?|phrases?|such as|for example|e\.g\.?|examples? (?:include|are)|like|quoted?|titled|called|wording|string|typical|tells? \w+(?: \w+){0,2} to|told \w+ to)\b\W*(?:\w+\W+){0,3}|[\"'“‘«]\s?)$"
)
_NEGATION = re.compile(r"(?:do not|don't|dont|never|must not|should not|mustn't|jangan|tidak boleh|not to|avoid|without)(?: [\w']+){0,3} $")
_SEGMENT_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+|(?=<!--)")


# Per-sentence cues as bits, so combining neighbouring sentences is three integer ORs.
OVERRIDE, OVERRIDE_STRONG, QUOTED, PERSONA, MARKER, CALL, CALL_HELD, EXFIL, DEST, CONCEAL, URGENCY, AUTH, REVEAL, RISKY, AGENT, MENTION_HELD = (
    1 << i for i in range(16)
)
_CUES = DEST | CONCEAL | URGENCY | AUTH | REVEAL | AGENT | RISKY | CALL


def _bit(condition: object, flag: int) -> int:
    return flag if condition else 0


def _inside_quotes(before: str) -> bool:
    """True when the text just before a match has an opening quote (at a word start) that has not been closed."""
    window = before[-90:]
    opener = -1
    for i, ch in enumerate(window):
        if ch in "'\"“‘«" and (i == 0 or window[i - 1] in " :([,"):
            opener = i
    if opener == -1:
        return False
    return not any(c in "'\"”’»" for c in window[opener + 1:])


def _guarded(text: str, start: int, *, quote: bool = True) -> tuple[bool, bool]:
    """(negated, quoted) for a match starting at `start`: a warning about the attack, or a report of it."""
    before = text[max(0, start - 90): start]
    return bool(_NEGATION.search(before[-45:])), bool(quote and (_QUOTE_BEFORE.search(before[-70:]) or _inside_quotes(before)))


def _first_unguarded(patterns: Iterable[re.Pattern[str]], text: str) -> tuple[bool, bool]:
    """(found, only_quoted): a match that is neither negated nor quoted wins; otherwise a quoted one is remembered."""
    quoted_only = False
    for pattern in patterns:
        for m in pattern.finditer(text):
            negated, quoted = _guarded(text, m.start())
            if negated:
                continue
            if quoted:
                quoted_only = True
                continue
            return True, False
    return False, quoted_only


def _unnegated(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    """The first match that is not a warning ("do not share your password", "never run ...")."""
    for m in pattern.finditer(text):
        if not _NEGATION.search(text[max(0, m.start() - 45): m.start()]):
            return m
    return None


def _features(seg: str, ctx: ScanContext) -> int:
    f = 0
    found, quoted_only = _first_unguarded((*_OVERRIDE_EN, *_OVERRIDE_MS), seg)
    f |= _bit(found or quoted_only, OVERRIDE) | _bit(quoted_only and not found, QUOTED) | _bit(found, OVERRIDE_STRONG)
    f |= _bit(_first_unguarded(_PERSONA, seg)[0], PERSONA)
    f |= _bit(any(p.search(seg) for p in _MARKER), MARKER)
    calls = [m for p in (_CALL_ID, _CALL_NAMED) for m in p.finditer(seg) if not _NEGATION.search(seg[max(0, m.start() - 45): m.start()])]
    f |= _bit(calls or _unnegated(_CALL_SHELL, seg), CALL)
    # "send_email(to, subject, body)" is documentation of a tool, not a request to call it: it does not count as naming a held tool.
    f |= _bit(any(m.group("id") in ctx.tool_names and not seg.startswith("(", m.end()) for m in calls), CALL_HELD)
    f |= _bit(any(t in seg for t in ctx.tool_names if len(t) >= 4 and "_" in t), MENTION_HELD)
    f |= _bit(_DESTINATION.search(seg), DEST)
    f |= _bit(_unnegated(_HAS_EXFIL_VERB, seg) and (_HAS_SENSITIVE.search(seg) or _HAS_BULK.search(seg)), EXFIL)
    for m in _CONCEAL.finditer(seg):
        if not _NEGATION.search(seg[max(0, m.start() - 45): m.start()]) or m.group(0).startswith(("silently", "secretly", "quietly", "covertly")):
            f |= CONCEAL
            break
    f |= _bit(_URGENCY.search(seg), URGENCY) | _bit(_AUTHORITY.search(seg), AUTH)
    f |= _bit(_unnegated(_REVEAL, seg), REVEAL) | _bit(_RISKY_ACTION.search(seg), RISKY) | _bit(_ADDRESSES_AGENT.search(seg), AGENT)
    return f


def _union(flags: Sequence[int], i: int) -> int:
    out = flags[i]
    if i > 0:
        out |= flags[i - 1]
    if i + 1 < len(flags):
        out |= flags[i + 1]
    return out


# A sentence that contains none of these stems cannot satisfy any injection rule, so it is skipped without running them.
# Every rule above must have at least one of its required words here; a test replays the whole corpus with and without the
# prefilter to prove the two agree.
_TRIGGER = re.compile(
    r"ignor|disregard|forget|overrid|bypass|discard|abandon|neglect|set aside|put aside|overrul|supersed|drop|replace|precedence|"
    r"new (?:instruction|directive|order)|updated (?:instruction|directive)|revised (?:instruction|directive)|"
    r"abai|lupakan|ketepikan|batalkan|langkau|tolak ke|you are now|mode\b|do anything|act as|behave|respond|pretend|from now on|"
    r"without|mulai sekarang|sekarang|sekatan|<|\[|#|system|sistem|call|invoke|run\b|execute|trigger|use\b|panggil|jalankan|gunakan|"
    r"curl|wget|\| ?nc|send|forward|mail|post\b|upload|copy|append|paste|leak|export|transmit|submit|fetch|hantar|salin|muat naik|"
    r"eksport|kirim|http|@|third|external|remote|shared|alamat|pautan|bcc|not\b|n't|dont|never|jangan|before|leave out|keep|normal|"
    r"silent|secret|covert|quiet|senyap|diam|hidden|tersembunyi|urgent|immediate|right now|asap|no time|within|segera|serta-merta|"
    r"message from|note from|this is|from the|mesej|nota|authori|reveal|print|show|output|repeat|display|disclose|dump|share|give me|"
    r"tell me|reply|dedahkan|tunjukkan|bocorkan|tampal|delete|wipe|erase|destroy|remove|transfer|wire|approve|raise|disable|turn off|"
    r"grant|assistant|\bai\b|llm|language model|ejen|pembantu|you |pastikan|anda |agent"
)

def _segments(clean: str) -> list[str]:
    segs: list[str] = []
    for part in _SEGMENT_SPLIT.split(clean):
        part = part.strip()
        while len(part) > MAX_SEGMENT_CHARS:  # a very long unbroken run is examined in pieces, never skipped
            segs.append(part[:MAX_SEGMENT_CHARS])
            part = part[MAX_SEGMENT_CHARS:]
        if part:
            segs.append(part)
    return segs


def _finding(rule_id: str, where: Where, confidence: Level, evasion: tuple[str, ...], severity: Level | None = None) -> Finding:
    family, kind, default, reason = RULES[rule_id]
    return Finding(rule_id, family, kind, severity or default, confidence, where, evasion, reason)


def _confidence(base: Level, *, cues: int, evasion: tuple[str, ...], held: bool, quoted: bool) -> Level:
    steps = (1 if cues >= 2 else 0) + (1 if evasion else 0) + (1 if held else 0)
    level = _raise(base, steps)
    return "low" if quoted and level == "medium" else level


def _analyse_injection(text: str, ctx: ScanContext, where: Where, evasion: tuple[str, ...]) -> dict[str, Finding]:
    found: dict[str, Finding] = {}
    segs = _segments(text)
    flags = [_features(seg, ctx) if _TRIGGER.search(seg) else 0 for seg in segs]

    def add(rule_id: str, base: Level, cues: int, held: bool, quoted: bool = False, severity: Level | None = None) -> None:
        if rule_id not in found:
            found[rule_id] = _finding(rule_id, where, _confidence(base, cues=cues, evasion=evasion, held=held, quoted=quoted), evasion, severity)

    for i, f in enumerate(flags):
        if f == 0 and (i == 0 or flags[i - 1] == 0) and (i + 1 >= len(flags) or flags[i + 1] == 0):
            continue  # no cue here or next to here: nothing a rule could combine
        w = _union(flags, i)
        cues = (w & _CUES).bit_count()
        held = bool(w & (CALL_HELD | MENTION_HELD))
        if f & OVERRIDE and (f & OVERRIDE_STRONG or cues):
            add("RAD-INJ-001", "medium", cues, held, quoted=bool(f & QUOTED) and not cues)
        if f & PERSONA:
            add("RAD-INJ-002", "medium", cues, False)
        if f & MARKER:
            add("RAD-INJ-003", "medium", cues, held)
        if f & EXFIL and w & (DEST | AGENT | CONCEAL | OVERRIDE_STRONG | URGENCY | AUTH):
            add("RAD-INJ-004", "medium", cues, held)
        if f & CALL and (w & (DEST | CONCEAL | URGENCY | AUTH | AGENT | OVERRIDE_STRONG | RISKY) or f & CALL_HELD):
            add("RAD-INJ-005", "medium", cues, bool(f & CALL_HELD))
        if f & CONCEAL and w & (AGENT | CALL | EXFIL | DEST | OVERRIDE_STRONG | REVEAL | RISKY):
            add("RAD-INJ-006", "medium", cues, held, severity="medium")
        if f & REVEAL:
            add("RAD-INJ-007", "medium", cues, False)
        if f & AUTH and w & (CALL | EXFIL | REVEAL | RISKY | OVERRIDE_STRONG):
            add("RAD-INJ-008", "medium", cues, held)
        if f & URGENCY and f & RISKY and w & (CALL | CONCEAL | AUTH | AGENT):
            add("RAD-INJ-008", "medium", cues, held)
    return found


class Detector(Protocol):
    """A detector turns prepared text into findings. Rules are one kind; a measured classifier could be another (plan A9)."""

    name: str

    def scan(self, prepared: Prepared, ctx: ScanContext) -> list[Finding]: ...


class InjectionDetector:
    name = "injection_rules"

    def scan(self, prepared: Prepared, ctx: ScanContext) -> list[Finding]:
        findings = _analyse_injection(prepared.clean, ctx, "text", prepared.evasion)
        if prepared.leet is not None:
            for rule_id, finding in _analyse_injection(prepared.leet, ctx, "text", prepared.evasion).items():
                findings.setdefault(rule_id, finding)
        out = list(findings.values())
        if prepared.hidden:
            hidden = _analyse_injection(_SPACE.sub(" ", prepared.hidden.casefold()).strip(), ctx, "hidden", ("hidden",))
            out.append(_finding("RAD-INJ-009", "hidden", "high", ("hidden",)))
            out.extend(f for r, f in hidden.items() if r not in findings)
        for blob in prepared.decoded:
            decoded = _analyse_injection(_SPACE.sub(" ", unicodedata.normalize("NFKC", blob).casefold()).strip(), ctx, "decoded", ("encoded",))
            if decoded:
                out.append(_finding("RAD-INJ-010", "decoded", "high", ("encoded",)))
                break
        if prepared.has_bidi:
            out.append(_finding("RAD-INJ-011", "text", "medium", prepared.evasion))
        return out


# --- the output analysis ---------------------------------------------------------------------------------------------

_SCRIPT = re.compile(r"<\s*script\b|<\s*/\s*script\s*>")
_HANDLER = re.compile(r"<[a-z][a-z0-9]*(?:\s[^<>]{0,300}?)?[\s/\"']on[a-z]{3,20}\s*=", re.I)
_JS_URL = re.compile(
    r"(?:href|src|action|formaction|data|xlink:href|poster|background|content)\s*=\s*[\"']?\s*(?:javascript|vbscript|livescript)\s*:"
    r"|\]\(\s*<?\s*(?:javascript|vbscript)\s*:|url\(\s*[\"']?\s*javascript\s*:|(?:href|src|action)\s*=\s*[\"']?\s*data\s*:\s*text/html",
    re.I,
)
_ACTIVE = re.compile(
    r"<\s*(?:iframe|object|embed|applet|frame|frameset)\b|<\s*meta\b[^>]{0,200}http-equiv\s*=\s*[\"']?refresh|<\s*base\b[^>]{0,100}href\s*="
    r"|<\s*form\b[^>]{0,200}action\s*=\s*[\"']?https?://|@import\s+(?:url\()?\s*[\"']?https?://|\bsrcdoc\s*=|expression\s*\(",
    re.I,
)
_IMG = re.compile(r"!\[[^\]]{0,100}\]\(\s*<?(https?://[^)\s>]+)|<\s*img\b[^>]{0,300}?\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I)
_PLACEHOLDER_VALUE = re.compile(r"^(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,}|\{\{?[^}]{1,40}\}\}?|<[^>]{1,40}>|\$\{[^}]{1,40}\})$")
_SENSITIVE_PARAM = re.compile(r"^(?:d|data|q|c|cookie|token|session|sess|sid|email|user|name|conv|conversation|history|msg|message|secret|key|password|pass|auth|payload|text|content|info|log)$", re.I)
_COLLECTORS_ALWAYS = (
    "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "hookbin.com", "interact.sh", "oast.pro", "oast.live", "oast.site",
    "oast.fun", "oast.me", "oast.online", "burpcollaborator.net", "canarytokens.com", "beeceptor.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
)
_COLLECTORS_WITH_VERB = ("file.io", "transfer.sh", "pastebin.com", "paste.ee", "anonfiles.com", "0x0.st", "temp.sh", "dpaste.org", "hastebin.com", "gofile.io")
_URL = re.compile(r"\b([a-z][a-z0-9+.-]{1,12}):/{2}(\[[0-9a-f:.]+\]|[^\s\"'<>)/?#\]\\]+)", re.I)
_FETCH_VERB = re.compile(r"\b(?:fetch|open|call|read|visit|browse|download|get|send|post|query|pull|use|check|run|connect|request|load|paste|show|list|export|test|hit|curl|wget|navigate|go to|access|ping|sambung|ambil|buka|baca|hantar|periksa|semak)\b", re.I)
_TARGET_NOUN = re.compile(r"\b(?:target|endpoint|console|server|wiki|admin|dashboard|api|webhook|service|internal|portal|panel|jenkins|database|queue|metadata|config)\b", re.I)
_DOC_CONTEXT = re.compile(r"\b(?:example|e\.g\.?|for instance|returns|docs?|documentation|should be blocked|blocked|must not|do not|don't|never|avoid|such as)\b", re.I)
_UPLOAD_VERB = re.compile(r"\b(?:send|post|upload|paste|forward|submit|copy|push|reply|share|hantar|muat naik)\b", re.I)
_INTERNAL_SUFFIXES = (".internal", ".local", ".localdomain", ".corp", ".lan", ".home", ".intranet", ".svc", ".consul", ".localhost", ".cluster.local")
_METADATA_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}
_METADATA_NAMES = {"metadata", "metadata.google.internal", "instance-data", "metadata.azure.internal", "metadata.tencentyun.com"}
_TEST_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_RISKY_SCHEMES = {"gopher", "dict", "ldap", "ldaps", "tftp", "sftp", "jar", "netdoc"}
_SENSITIVE_PATH = re.compile(
    r"/etc/(?:passwd|shadow|gshadow|sudoers|master\.passwd|ssl/private|ssh/)|/proc/(?:self|\d+)/(?:environ|cmdline|maps|mem|fd)|/root/|"
    r"(?:~|/home/[\w.-]+|/users/[\w. -]+|/mnt/c/users/[\w. -]+)/\.(?:ssh|aws|kube|docker|gnupg|config/gcloud|bash_history|zsh_history|netrc|npmrc|git-credentials)\b|"
    r"\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/(?:credentials|config)|\.kube/config|\.docker/config\.json|\.config/gcloud|\.git/config|\.git-credentials|"
    r"\b(?:credentials\.db|\.bash_history|\.zsh_history|\.pgpass|\.netrc)\b|/var/log/(?:auth|secure)|/var/lib/(?:mysql|docker|postgresql)|"
    r"\\windows\\(?:system32\\config|repair)\\|\bboot\.ini\b|appdata\\roaming\\microsoft\\credentials|\\users\\[^\\]+\\(?:\.ssh|\.aws|appdata\\roaming\\microsoft)|"
    r"(?:^|[\s/\\])(?:secrets?[/\\]|prod(?:uction)?\.env|\.env(?:\.[a-z0-9]+)?(?=$|[\s\"'.,;)]))|/server\.key\b|\.pem\b|\.key\b",
    re.I,
)
_TRAVERSAL = re.compile(r"(?:\.\.[/\\]){2,}|\.{2,}//+|\.\.;/|\.\.%c0%af|%c0%ae", re.I)
_TRAVERSAL_ONE = re.compile(r"\.\.[/\\]", re.I)
_READ_VERB = re.compile(r"\b(?:read|open|show|cat|print|dump|attach|include|display|paste|send|fetch|load|add|baca|buka|tunjuk|tampal|sertakan)\b", re.I)
_PATH_DOC = re.compile(r"\b(?:never|do not|don't|avoid|rejects?|blocks?|blocked|should not|must not|attack|lists? accounts|ignored by git|do not commit|never commit|copy \.env\.example)\b", re.I)
_SENTENCE_END = re.compile(r"[.;!?](?=\s)|\n")
_FILE_SCHEME = re.compile(r"\bfile:/{2,3}[^\s\"'<>]{3,}", re.I)


def _loose_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """IPv4 in the forms a browser or libc accepts: decimal, hex, octal, and short dotted forms like 127.1."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(not p for p in parts):
        return None
    nums: list[int] = []
    for p in parts:
        try:
            nums.append(int(p, 16) if p.lower().startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") and p.isdigit() else int(p, 10))
        except ValueError:
            return None
    value = 0
    for n in nums[:-1]:
        if n > 255:
            return None
        value = (value << 8) | n
    last_bits = 8 * (5 - len(nums))
    if nums[-1] >= (1 << last_bits):
        return None
    value = (value << last_bits) | nums[-1]
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def _internal_host(host: str) -> str | None:
    """"metadata", "internal" or None for a host that is public or unknown."""
    host = host.lower().rstrip(".")
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    if ":" in host:
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError:
            return None
        ip = ip6.ipv4_mapped or ip6
    else:
        ip = _loose_ipv4(host)
    if ip is not None:
        if any(net.version == ip.version and ip in net for net in _TEST_NETS):
            return None
        if str(ip) in _METADATA_IPS or ip.is_link_local:
            return "metadata"
        return None if ip.is_global else "internal"
    if host in _METADATA_NAMES:
        return "metadata"
    if host == "localhost" or host.endswith(_INTERNAL_SUFFIXES) or "." not in host:
        return "internal"
    return None


def _query_looks_like_data(query: str) -> bool:
    for pair in query.split("&")[:20]:
        key, _, value = pair.partition("=")
        value = unquote(value)
        if _PLACEHOLDER_VALUE.match(value) or "%7b" in pair.lower():
            return True
        if _SENSITIVE_PARAM.match(key) and len(value) >= 12:
            return True
        if len(value) >= 40 and re.fullmatch(r"[A-Za-z0-9+/_=-]{40,}", value):
            return True
    return False


def _domain_matches(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


class OutputDetector:
    name = "output_rules"

    def scan(self, prepared: Prepared, ctx: ScanContext) -> list[Finding]:
        text = prepared.markup
        low = text.lower()
        out: dict[str, Finding] = {}

        def add(rule_id: str, confidence: Level = "medium") -> None:
            out.setdefault(rule_id, _finding(rule_id, "text", confidence, prepared.evasion))

        if "<" in text and (_SCRIPT.search(low) or _HANDLER.search(text)):
            add("RAD-OUT-001", "high")
        if _JS_URL.search(text):
            add("RAD-OUT-002", "high")
        if "<" in text or "@import" in low or "srcdoc" in low or "expression(" in low:
            if _ACTIVE.search(text):
                add("RAD-OUT-003")
        for m in itertools.islice(_IMG.finditer(text), MAX_OUTPUT_MATCHES):
            url = m.group(1) or m.group(2)
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if _domain_matches(host, _COLLECTORS_ALWAYS) or (parts.query and _query_looks_like_data(parts.query)):
                add("RAD-OUT-004", "high")
                break
        self._urls(text, add)
        self._paths(text, add)
        return list(out.values())

    @staticmethod
    def _urls(text: str, add: Callable[..., None]) -> None:
        breaks = [m.end() for m in _SENTENCE_END.finditer(text)]  # sentence starts, found once (not once per URL)
        for m in itertools.islice(_URL.finditer(text), MAX_OUTPUT_MATCHES):
            scheme, authority = m.group(1).lower(), m.group(2)
            if scheme in _RISKY_SCHEMES:
                add("RAD-OUT-006")
                continue
            if scheme not in ("http", "https", "ftp"):
                continue
            hostpart = authority.rsplit("@", 1)[-1]
            host = hostpart[1:hostpart.index("]")] if hostpart.startswith("[") and "]" in hostpart else hostpart.split(":")[0]
            if not host:
                continue
            k = bisect.bisect_right(breaks, m.start())
            start = breaks[k - 1] if k else 0
            end = breaks[bisect.bisect_left(breaks, m.end())] if bisect.bisect_left(breaks, m.end()) < len(breaks) else len(text)
            sentence = text[start: min(end, start + 600)]
            doc = bool(_DOC_CONTEXT.search(sentence))
            kind = _internal_host(host)
            if kind == "metadata" and not doc:
                add("RAD-OUT-005", "high")
            elif kind == "internal" and not doc and (_FETCH_VERB.search(sentence) or _TARGET_NOUN.search(sentence)):
                add("RAD-OUT-005", "high")
            elif _domain_matches(host.lower(), _COLLECTORS_ALWAYS):
                add("RAD-OUT-006")
            elif _domain_matches(host.lower(), _COLLECTORS_WITH_VERB) and _UPLOAD_VERB.search(sentence):
                add("RAD-OUT-006")

    @staticmethod
    def _paths(text: str, add: Callable[..., None]) -> None:
        for m in _FILE_SCHEME.finditer(text):
            add("RAD-OUT-007", "high")
            return
        traversal = _TRAVERSAL.search(text)
        for m in itertools.islice(_SENSITIVE_PATH.finditer(text), MAX_OUTPUT_MATCHES):
            window = text[max(0, m.start() - 160): m.end() + 40]
            if _PATH_DOC.search(window):
                continue
            near_traversal = _TRAVERSAL_ONE.search(text[max(0, m.start() - 60): m.start() + 2])
            is_env = ".env" in m.group(0).lower() or "prod.env" in m.group(0).lower()
            if is_env and not (near_traversal or _READ_VERB.search(text[max(0, m.start() - 40): m.start()])):
                continue
            weak_suffix = m.group(0).lower().endswith((".pem", ".key")) and not (near_traversal or _READ_VERB.search(text[max(0, m.start() - 40): m.start()]))
            if weak_suffix:
                continue
            add("RAD-OUT-007", "high")
            return
        if traversal and not _PATH_DOC.search(text):
            depth = len(_TRAVERSAL_ONE.findall(text))
            if depth >= 3 or "....//" in text or "..;/" in text:
                add("RAD-OUT-007")


DEFAULT_DETECTORS: tuple[Detector, ...] = (InjectionDetector(), OutputDetector())


# --- walking a tool result -------------------------------------------------------------------------------------------

@dataclass(slots=True)
class _Budget:
    chars: int = MAX_CHARS
    nodes: int = MAX_NODES
    truncated: bool = False
    skipped_binary: int = 0
    texts: list[str] = field(default_factory=list)


def _collect(value: Any, budget: _Budget, depth: int) -> None:
    if budget.nodes <= 0 or depth > MAX_DEPTH:
        budget.truncated = True
        return
    budget.nodes -= 1
    if isinstance(value, str):
        if len(value) < MIN_TEXT_CHARS:
            return
        if len(value) >= 2048 and _BINARY_BLOB.fullmatch(value):
            budget.skipped_binary += 1
            return
        if budget.chars <= 0:
            budget.truncated = True
            return
        if len(value) > budget.chars:
            budget.truncated = True  # read both ends: attacks are usually at the start or appended at the end
            half = budget.chars // 2
            value = value[:half] + " " + value[-half:]
        budget.chars -= len(value)
        budget.texts.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _collect(item, budget, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect(item, budget, depth + 1)


def scan_result(
    value: Any,
    ctx: ScanContext = EMPTY_CONTEXT,
    kinds: frozenset[Kind] = frozenset({"injection", "output"}),
    detectors: tuple[Detector, ...] = DEFAULT_DETECTORS,
) -> ScanReport:
    """Findings for a tool result (any JSON-like value). Never raises on odd input; the caller decides what a scanner error means."""
    budget = _Budget()
    _collect(value, budget, 0)
    seen: dict[tuple[str, str], Finding] = {}
    for text in budget.texts:
        prepared = prepare(text)
        for detector in detectors:
            for finding in detector.scan(prepared, ctx):
                if finding.kind in kinds:
                    key = (finding.rule_id, finding.where)
                    previous = seen.get(key)
                    if previous is None or _LEVELS.index(finding.confidence) > _LEVELS.index(previous.confidence):
                        seen[key] = finding
        if len(seen) >= MAX_FINDINGS:
            break
    return ScanReport(tuple(list(seen.values())[:MAX_FINDINGS]), budget.truncated, budget.skipped_binary)


def category_of(finding: Finding) -> str:
    """The benchmark category a finding informs."""
    return CATEGORY_OF_RULE[finding.rule_id]
