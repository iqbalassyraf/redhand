"""
Black Box payload capture (Phase 3 M2b): turns a tool call's arguments or result into a redacted,
size-capped excerpt that the recorder may store, for organizations that turned capture on.

The rules this module keeps (docs/plans/phase3-plan.md, ADR 0011 addendum):
- REDACT FIRST, TRUNCATE SECOND. Cutting first could slice a secret in half so no pattern matched and half
  of it was stored; here the whole value is scanned, then the redacted text is cut.
- NEVER STORE TEXT THAT WAS NOT SCANNED. The scan budget is bounded (16 KiB of text, 1,000 values, depth 16);
  anything past it is replaced by a marker, not copied. Only JSON types are copied; anything else is a marker.
  The budget is small on purpose: only 2 KB is ever stored, and capture runs on the request path, so its cost
  is bounded by the budget (measured in docs/plans/phase3-plan.md), not by the size of the payload.
- Pure and bounded: no I/O, no logging of values, no network. Cost is linear in the (bounded) input.

Redaction is best effort and pattern based. It finds secrets (API keys, tokens, private keys), email
addresses, Malaysian NRIC (MyKad) numbers, card numbers (Luhn-checked) and phone numbers, and it blanks the
value of any field whose NAME looks sensitive (password, token, secret, ...). It does NOT find names,
addresses, free-text descriptions or a number split across several fields. Capture therefore still stores
customer data; the dashboard and docs say so, and make no compliance claim.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable

MAX_EXCERPT_BYTES = 2048
MAX_SCAN_CHARS = 16 * 1024
# A number with fewer digits than this cannot be a phone, card or NRIC number, so it is not scanned.
MIN_SCANNED_DIGITS = 8
# The shortest thing any rule can match is an email address such as a@b.co, so shorter text is never scanned.
MIN_MATCH_CHARS = 6
MAX_NODES = 1000
MAX_DEPTH = 16

TOO_LARGE = "[NOT_CAPTURED:TOO_LARGE]"
TOO_MANY = "[NOT_CAPTURED:TOO_MANY_ITEMS]"
TOO_DEEP = "[NOT_CAPTURED:TOO_DEEP]"
UNSUPPORTED = "[NOT_CAPTURED:UNSUPPORTED_TYPE]"
SENSITIVE_KEY = "[REDACTED:SENSITIVE_FIELD]"


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _card_ok(match: str) -> bool:
    digits = re.sub(r"[ -]", "", match)
    return 13 <= len(digits) <= 19 and _luhn_valid(digits)


def _mykad_ok(match: str) -> bool:
    """YYMMDD-PB-###G: a real month and day, and a non-zero place-of-birth code. Cuts false positives such
    as timestamps and order numbers that merely have twelve digits."""
    d = re.sub(r"-", "", match)
    return 1 <= int(d[2:4]) <= 12 and 1 <= int(d[4:6]) <= 31 and int(d[6:8]) != 0


def _intl_phone_ok(match: str) -> bool:
    return 8 <= len(re.sub(r"\D", "", match)) <= 15


# (kind, pattern, validator, hints). A rule is skipped when none of its hints occur in the text: most text has
# no "@", no "eyJ", no digits, so most rules never run. DIGIT stands for "the text contains a digit". The hints
# only decide whether to RUN a rule; they never decide that something is safe. Order matters: secrets, then
# email, then cards (long digit runs) before the shorter phone and NRIC shapes, so a card number is never
# half-redacted as a phone number.
DIGIT = "\x00digit"
_Rule = tuple[str, "re.Pattern[str]", Callable[[str], bool] | None, tuple[str, ...]]
_RULES: tuple[_Rule, ...] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), None, ("PRIVATE KEY",)),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), None, ("eyJ",)),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), None, ("Bearer", "bearer", "BEARER")),
    ("API_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), None, ("sk-",)),
    ("STRIPE_KEY", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), None, ("_live_", "_test_")),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None, ("AKIA", "ASIA")),
    ("GCP_TOKEN", re.compile(r"\bya29\.[0-9A-Za-z_.-]{16,}"), None, ("ya29.",)),
    ("GCP_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), None, ("AIza",)),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), None, ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), None, ("xox",)),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None, ("@",)),
    ("CARD_NUMBER", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _card_ok, (DIGIT,)),
    ("NRIC", re.compile(r"(?<!\d)\d{6}-?\d{2}-?\d{4}(?!\d)"), _mykad_ok, (DIGIT,)),
    ("PHONE", re.compile(r"(?<![\d+])(?:\+?60|0)1\d[ -]?\d{3,4}[ -]?\d{4}(?!\d)"), None, (DIGIT,)),
    ("PHONE", re.compile(r"(?<![\d+])(?:\+?60|0)[3-9][ -]?\d{3,4}[ -]?\d{4}(?!\d)"), None, (DIGIT,)),
    ("PHONE", re.compile(r"(?<![\w+])\+[1-9]\d{0,2}(?:[ -]?\(?\d{1,5}\)?){2,5}(?!\d)"), _intl_phone_ok, ("+",)),
)
_HAS_DIGIT = re.compile(r"\d").search

_SENSITIVE_NAME = re.compile(
    r"(?i)(?:^|[^a-z])(?:pass(?:word|wd|code)?|secret|token|api[-_ ]?key|authorization|cookie|credential|"
    r"private[-_ ]?key|nric|mykad|ssn)(?:$|[^a-z])"
)


def redact_text(text: str) -> tuple[str, int]:
    """Returns the text with every match replaced by [REDACTED:KIND], and how many matches there were."""
    if len(text) < MIN_MATCH_CHARS:
        return text, 0
    count = 0
    has_digit = _HAS_DIGIT(text) is not None
    for kind, pattern, valid, hints in _RULES:
        if not any((has_digit if hint == DIGIT else hint in text) for hint in hints):
            continue

        def _sub(m: re.Match[str], kind: str = kind, valid: Callable[[str], bool] | None = valid) -> str:
            nonlocal count
            if valid is not None and not valid(m.group(0)):
                return m.group(0)
            count += 1
            return f"[REDACTED:{kind}]"

        text = pattern.sub(_sub, text)
    return text, count


@dataclass(frozen=True, slots=True)
class Excerpt:
    """What the recorder sends: compact JSON text of the redacted value, cut to at most 2 KB."""

    text: str
    truncated: bool
    original_bytes: int
    redactions: int

    def as_dict(self) -> dict[str, Any]:
        return {"text": self.text, "truncated": self.truncated, "original_bytes": self.original_bytes}


class _Walker:
    def __init__(self) -> None:
        self.chars_left = MAX_SCAN_CHARS
        self.nodes_left = MAX_NODES
        self.redactions = 0

    def text(self, value: str) -> str:
        if len(value) > self.chars_left:
            self.chars_left = 0
            return TOO_LARGE
        self.chars_left -= len(value)
        clean, n = redact_text(value)
        self.redactions += n
        return clean

    def walk(self, value: Any, depth: int) -> Any:
        if self.nodes_left <= 0:
            return TOO_MANY
        self.nodes_left -= 1
        if depth > MAX_DEPTH:
            return TOO_DEEP
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, (int, float)):
            # A number can be a phone, card or NRIC number: scan its digits, and keep it only if clean. Short
            # numbers cannot be any of those, so they are kept without a scan.
            as_text = str(value)
            if len(as_text) < MIN_SCANNED_DIGITS:
                return value
            clean, n = redact_text(as_text)
            if n:
                self.redactions += n
                return clean
            return value
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                name = self.text(key) if isinstance(key, str) else UNSUPPORTED
                unique = name
                suffix = 1
                while unique in out:  # two keys can redact to the same text; never lose a value
                    suffix += 1
                    unique = f"{name}#{suffix}"
                if isinstance(key, str) and _SENSITIVE_NAME.search(key):
                    self.redactions += 1
                    out[unique] = SENSITIVE_KEY
                else:
                    out[unique] = self.walk(item, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self.walk(item, depth + 1) for item in value]
        return UNSUPPORTED


def redact_value(value: Any) -> tuple[Any, int]:
    """Redacts a JSON-like value within the scan budget. Returns the redacted copy and the number of
    redactions. Nothing in the copy is unscanned text."""
    walker = _Walker()
    redacted = walker.walk(value, 0)
    return redacted, walker.redactions


def build_excerpt(value: Any) -> Excerpt:
    """Redacts `value` (JSON-like), serialises it compactly, and cuts the redacted text to 2 KB."""
    redacted, redactions = redact_value(value)
    raw = json.dumps(redacted, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) <= MAX_EXCERPT_BYTES:
        return Excerpt(raw.decode("utf-8"), False, len(raw), redactions)
    return Excerpt(raw[:MAX_EXCERPT_BYTES].decode("utf-8", errors="ignore"), True, len(raw), redactions)
