"""
Honeytoken scanner (Phase 3 M3): finds a planted fake credential in a tool call's arguments or in a tool result.

The gateway never holds a honeytoken VALUE, only SHA-256 digests (from core's context). The scanner pulls out
text that looks like the issued formats, hashes each candidate, and checks it against the digests: pure lookups,
no I/O, no logging of values. Bounded work: at most 64 KiB of text, 1,000 values and depth 16 per scan; whatever
lies past the budget is NOT scanned (stated in the threat model), and the caller counts that in a metric.

Candidates follow the formats core generates (docs/adr/0012-honeytokens.md): `sk_live_` + 32 base62, `AKIA` + 16
uppercase alphanumerics, and a maximal run of exactly 24 alphanumerics (the password format). A honeytoken that
an agent re-encodes (base64, URL-encoding, split across fields) is not found: a stated limit.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any
from uuid import UUID

MAX_SCAN_CHARS = 64 * 1024
MAX_NODES = 1000
MAX_DEPTH = 16
REDACTED = "[REDACTED:HONEYTOKEN]"

_API_KEY = re.compile(r"(?<![A-Za-z0-9_])sk_live_[A-Za-z0-9]{32}(?![A-Za-z0-9])")
_AWS_KEY = re.compile(r"(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])")
_PASSWORD = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{24}(?![A-Za-z0-9])")
MIN_CANDIDATE_CHARS = 20  # the shortest issued format (AKIA + 16)


@dataclass(frozen=True, slots=True)
class HoneytokenRef:
    id: UUID
    digest: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    matched: tuple[UUID, ...]  # honeytokens found, first seen first, no duplicates
    value: Any  # the scanned value with every match replaced by REDACTED (only meaningful when matched)
    truncated: bool  # part of the value was past the scan budget and was not scanned


class _Scan:
    def __init__(self, index: dict[str, UUID]) -> None:
        self.index = index
        self.chars_left = MAX_SCAN_CHARS
        self.nodes_left = MAX_NODES
        self.matched: list[UUID] = []
        self.truncated = False

    def _candidate(self, m: re.Match[str]) -> str:
        found = self.index.get(hashlib.sha256(m.group(0).encode("utf-8")).hexdigest())
        if found is None:
            return m.group(0)
        if found not in self.matched:
            self.matched.append(found)
        return REDACTED

    def text(self, value: str) -> str:
        if len(value) < MIN_CANDIDATE_CHARS:
            return value
        if len(value) > self.chars_left:
            # Scan what the budget allows (a bait inside that window is still found) and pass the rest through
            # unscanned. Skipping the whole string would let a single oversized value hide the bait.
            self.truncated = True
            window, self.chars_left = self.chars_left, 0
            return self._scan_text(value[:window]) + value[window:] if window >= MIN_CANDIDATE_CHARS else value
        self.chars_left -= len(value)
        return self._scan_text(value)

    def _scan_text(self, value: str) -> str:
        if "sk_live_" in value:
            value = _API_KEY.sub(self._candidate, value)
        if "AKIA" in value:
            value = _AWS_KEY.sub(self._candidate, value)
        return _PASSWORD.sub(self._candidate, value)

    def walk(self, value: Any, depth: int) -> Any:
        if self.nodes_left <= 0 or depth > MAX_DEPTH:
            self.truncated = True
            return value
        self.nodes_left -= 1
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            for key, item in value.items():
                name = self.text(key) if isinstance(key, str) else key
                unique, n = name, 1
                while unique in out:  # two keys can redact to the same text; never lose a value
                    n += 1
                    unique = f"{name}#{n}"
                out[unique] = self.walk(item, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self.walk(item, depth + 1) for item in value]
        return value


def scan(value: Any, honeytokens: tuple[HoneytokenRef, ...]) -> ScanResult:
    """Looks for any of the organization's honeytokens in `value` (JSON-like). Free when there are none."""
    if not honeytokens:
        return ScanResult((), value, False)
    scanner = _Scan({h.digest: h.id for h in honeytokens})
    redacted = scanner.walk(value, 0)
    return ScanResult(tuple(scanner.matched), redacted if scanner.matched else value, scanner.truncated)
