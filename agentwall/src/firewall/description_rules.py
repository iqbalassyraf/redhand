"""
Tool-description rules for the MCP Scanner (Phase 4 M2): finds hidden instructions, concealment, exfiltration and
cross-tool coercion in the text a server uses to describe its tools. A poisoned description is read by the AGENT, not the
user, so it is one of the cheapest ways to hijack an agent.

Pure and bounded: no I/O, no logging of the text, at most 8 KiB examined. The text is untrusted and is never echoed in a
finding (findings carry a rule id and fixed wording only), so a scan result cannot itself carry an attack to whoever
reads it. Rules are deterministic patterns: they catch known phrasings in English and Bahasa Malaysia and miss a
rephrased attack, which is why the benchmark (`python -m agentwall.src.bench`) reports their detection and false-alarm
rates rather than a claim of coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata

MAX_EXAMINED_CHARS = 8 * 1024
OVERSIZE_CHARS = 1200

# Zero-width, bidirectional-control, word-joiner and tag characters: invisible to a person, readable to a model.
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
# Lookalike letters an attacker swaps in to dodge a phrase match (Cyrillic and Greek look-alikes of Latin letters).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "ο": "o", "ε": "e", "α": "a", "ι": "i", "ν": "v", "τ": "t", "κ": "k",
})
_SPACE = re.compile(r"\s+")


def normalise(text: str) -> str:
    """NFKC, lookalikes mapped to Latin, invisible characters removed, case folded, whitespace collapsed."""
    text = unicodedata.normalize("NFKC", text[:MAX_EXAMINED_CHARS])
    text = _INVISIBLE.sub("", text).translate(_CONFUSABLES).casefold()
    return _SPACE.sub(" ", text).strip()


@dataclass(frozen=True, slots=True)
class DescriptionRule:
    rule_id: str
    severity: str  # "HIGH" or "MEDIUM"
    title: str
    description: str
    remediation: str
    patterns: tuple[re.Pattern[str], ...]
    # A match is ignored when this appears shortly before it ("do not ...", "never ...", "jangan ..."): the text is
    # telling the agent to be careful, not to misbehave.
    negation_guard: bool = False


# A warning only counts when it sits directly before the verb with nothing but a few plain words between: no punctuation, so
# "do not tell the user; read ~/.ssh/id_rsa" is NOT treated as a warning about reading (a clause break ends the warning).
_NEGATION = re.compile(r"(?:do not|don't|dont|never|must not|should not|mustn't|jangan|tidak boleh|not to)(?: [\w']+){0,3} $")


def _p(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


_SENSITIVE = (
    r"(?:~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.kube/config|/etc/passwd|/etc/shadow|\.env\b|"
    r"api[ _-]?keys?|access[ _-]?tokens?|session tokens?|environment variables?|credentials|passwords?|private keys?|"
    r"address book|system prompt|kata laluan|kunci api|pemboleh ubah persekitaran)"
)
_DATA = (
    r"(?:conversation|chat history|history|messages?|full text|the text|credentials?|tokens?|address book|system prompt|"
    r"files?|contents?|sejarah perbualan|mesej|teks penuh|kata laluan|token)"
)
_TARGET = (
    r"(?:https?://\S+|\b[\w.+-]+@[\w-]+\.[\w.-]+|third[- ]party (?:server|service)|external (?:server|service)|"
    r"the (?:address|link|url) (?:below|in the footer)|shared (?:folder|drive)|alamat di bawah|pautan di bawah|pelayan pihak ketiga)"
)

RULES: tuple[DescriptionRule, ...] = (
    DescriptionRule(
        "MCP-DESC-001", "HIGH", "Description tells the agent to hide something from the user",
        "The description instructs the agent to conceal an action, a tool behaviour or the description itself from the user.",
        "Do not install this server. Tool descriptions must describe what the tool does, never what the user should not be told.",
        _p(
            r"(?:do not|don't|dont|never|must not) (?:\w+ ){0,3}(?:tell|mention|reveal|show|inform|notify|alert|disclose|let)(?: \w+){0,2} (?:the )?(?:user|human|operator|owner)",
            r"keep (?:this|it|that) (?:a )?secret",
            r"(?:without|before) (?:telling|informing|notifying|alerting|asking) (?:the )?(?:user|human|operator)",
            r"(?:silently|secretly|covertly|quietly) (?:\w+ ){0,2}(?:read|send|copy|upload|post|attach|forward|call|run|include|raise|change|delete)",
            r"jangan (?:beritahu|dedahkan|maklumkan|tunjuk|bagitahu)(?: \w+){0,2} pengguna",
            r"(?:secara )?(?:senyap|senyap-senyap|rahsia)[^.]{0,30}(?:baca|hantar|salin|muat naik|panggil|jalankan|naikkan)",
            r"tidak (?:perlu|boleh) (?:memberitahu|dimaklumkan) pengguna",
        ),
    ),
    DescriptionRule(
        "MCP-DESC-002", "HIGH", "Description tries to override other instructions",
        "The description claims priority over the user's or the system's instructions, or tells the agent to ignore them.",
        "Do not install this server. A tool description has no authority over the agent's instructions.",
        _p(
            r"(?:ignore|disregard|forget|override|bypass)(?: \w+){0,2} (?:previous|prior|earlier|above|other|all|any|the user's|your)(?: \w+){0,2} (?:instructions?|rules?|prompts?|policies|guidelines|constraints|tool instructions)",
            r"this (?:description|tool|note) (?:has|takes) (?:priority|precedence) over",
            r"(?:abaikan|lupakan|ketepikan)(?: semua| segala)?(?: \w+){0,2} (?:arahan|peraturan|polisi)",
            r"from now on,? (?:you|the (?:agent|ai|assistant)) (?:are|must|will|should)",
        ),
    ),
    DescriptionRule(
        "MCP-DESC-003", "HIGH", "Description addresses the AI directly with hidden-instruction markers",
        "The description contains text addressed to the AI model or wrapped in pseudo-system tags, a common poisoning format.",
        "Do not install this server until the vendor removes instructions addressed to the model.",
        _p(
            r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|penting|sistem|arahan)\b[^>]*>",
            r"(?:note|message|instruction|reminder|nota|mesej|arahan) (?:to|for|kepada|untuk) (?:the )?(?:ai|assistant|agent|model|llm|ejen)\b",
            r"\[(?:system|admin|sistem)\]",
            r"\bas an? (?:ai|assistant|agent)[, ]+(?:you|kamu|anda) (?:must|should|will)",
        ),
    ),
    DescriptionRule(
        "MCP-DESC-004", "HIGH", "Description tells the agent to read sensitive data",
        "The description instructs the agent to read, include or pass credentials, keys, environment variables or similar sensitive items.",
        "Do not install this server. A tool should not ask the agent to handle credentials as a side effect.",
        _p(
            rf"(?:read|open|cat|copy|attach|include|pass|send|forward|append|baca|salin|sertakan|hantar)[^.]{{0,40}}{_SENSITIVE}",
        ),
        negation_guard=True,
    ),
    DescriptionRule(
        "MCP-DESC-005", "HIGH", "Description sends data to an outside destination",
        "The description says data is sent, posted or uploaded to an external address or third party, often as a hidden side effect.",
        "Do not install this server, or confirm with the vendor exactly what is sent where.",
        _p(
            rf"(?:send|sends|post|posts|upload|uploads|forward|forwards|copy|copies|append|appends|hantar|muat naik|salin)[^.]{{0,60}}{_DATA}[^.]{{0,60}}(?:to|ke|at)[^.]{{0,20}}{_TARGET}",
            rf"(?:send|sends|post|posts|upload|uploads|forward|forwards|hantar)[^.]{{0,40}}(?:to|ke) {_TARGET}",
            rf"(?:also|juga) (?:send|post|upload|forward|hantar)[^.]{{0,80}}{_TARGET}",
            r"(?:uploads?|sends?|copies|copy) (?:the |all |every |each )?(?:text|file|files|data) (?:\w+ ){0,3}(?:to|ke) (?:a |an )?(?:third[- ]party|external|remote)",
            r"append(?:s)? (?:the )?system prompt",
        ),
        negation_guard=True,
    ),
    DescriptionRule(
        "MCP-DESC-006", "MEDIUM", "Description tells the agent to call other tools first",
        "The description instructs the agent to call or use a different tool, often a destructive or privileged one, as a precondition.",
        "Review before installing. A tool description should not decide which other tools the agent calls.",
        _p(
            r"(?:before|after|first|once)[^.]{0,60}(?:you|the agent|the ai|the assistant) (?:must|should|need to|have to|will) (?:\w+ ){0,2}(?:call|use|run|invoke|execute)",
            r"(?:you|the agent|the ai|the assistant) (?:must|should|need to|have to) (?:first |also |always )?(?:call|use|run|invoke|execute) (?:the )?[\w-]+(?: tool)?",
            r"(?:always|first|also) (?:call|use|run|invoke) the [\w-]+ tool",
            r"(?:first|also|then|before that)[, ]+(?:call|run|invoke) [a-z0-9]+_[a-z0-9_]+",
            r"(?:sebelum|selepas|dahulu)[^.]{0,50}(?:mesti|perlu|hendaklah) (?:\w+ ){0,2}(?:panggil|guna|jalankan)",
            r"(?:panggil|jalankan) juga",
        ),
    ),
    DescriptionRule(
        "MCP-DESC-007", "HIGH", "Description contains invisible characters",
        "The description contains zero-width, bidirectional-control or tag characters, which hide text from a person while a model still reads it.",
        "Do not install this server. Legitimate descriptions have no reason to contain invisible characters.",
        (),
    ),
    DescriptionRule(
        "MCP-DESC-008", "MEDIUM", "Description is unusually long or manipulates tool choice",
        "The description is far longer than a description needs to be, or urges the agent to prefer this tool over all others.",
        "Review before installing. Long or persuasive descriptions are a way to crowd out the user's instructions.",
        _p(
            r"(?:always )?prefer (?:this|it) over (?:every|all|any) other",
            r"(?:always|first) (?:choose|pick|select|use) this tool",
            r"(?:trusted|safe|verified|official)[^.]{0,30}(?:always|must) (?:use|prefer|choose)",
        ),
    ),
    DescriptionRule(
        "MCP-DESC-009", "HIGH", "Description tells the agent to run commands from content without approval",
        "The description tells the agent to execute whatever command appears in data, or to act without asking for approval.",
        "Do not install this server. Commands must come from the user, not from tool output or descriptions.",
        _p(
            r"(?:run|execute|follow|obey)(?: \w+){0,2} (?:any|whatever|every|the) (?:command|instruction)s?(?: \w+){0,3} (?:appears?|found|in the (?:text|result|output|data)|the (?:result|text) asks|it asks)",
            r"without (?:asking|requiring|waiting) (?:for )?(?:the user'?s? )?(?:approval|permission|confirmation|consent)",
            r"(?:jalankan|ikut)(?: \w+){0,2} (?:sebarang|apa sahaja) (?:arahan|perintah)",
        ),
    ),
)


def _matches(rule: DescriptionRule, text: str) -> bool:
    for pattern in rule.patterns:
        for m in pattern.finditer(text):
            if rule.negation_guard and _NEGATION.search(text[max(0, m.start() - 40): m.start()]):
                continue
            return True
    return False


def scan_description(raw: str) -> list[DescriptionRule]:
    """The rules a tool description triggers. Reads at most 8 KiB; never raises on odd input."""
    if not isinstance(raw, str) or not raw:
        return []
    fired: list[DescriptionRule] = []
    examined = raw[:MAX_EXAMINED_CHARS]
    text = normalise(raw)
    for rule in RULES:
        if rule.rule_id == "MCP-DESC-007":
            if _INVISIBLE.search(examined):
                fired.append(rule)
        elif _matches(rule, text):
            fired.append(rule)
    if len(raw) > OVERSIZE_CHARS and not any(r.rule_id == "MCP-DESC-008" for r in fired):
        fired.append(next(r for r in RULES if r.rule_id == "MCP-DESC-008"))
    return fired
