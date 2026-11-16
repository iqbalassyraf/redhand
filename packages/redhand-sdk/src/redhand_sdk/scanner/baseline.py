"""
A reviewed baseline for `redhand scan` (docs/runbooks/scan-secrets-in-files.md).

A repository can hold deliberate fake keys (test fixtures, demos) that the scan rightly flags. Rather than an inline "ignore" marker (which would let
a real secret be hidden by anyone who can edit the line), the accepted findings live in one reviewed file. Each entry is a file, a rule, the SHA-256
of the offending line (trimmed) and a reason: never the secret text. Rules of the gate:

  - a finding that matches no entry is NEW and fails the gate;
  - an entry that matches nothing (or fewer findings than its count) is STALE and also fails, so the list can only shrink;
  - a missing, oversized, malformed or placeholder-reason baseline is refused (the CLI exits 2): fail closed, never "no baseline, so allow".

The line number is deliberately not part of an entry, so moving code does not break the baseline; changing a line does. Run the scan from the
repository root with path "." so that file paths match.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from redhand_sdk.scanner.ast_checker import ScanFinding

BASELINE_VERSION = 1
MAX_ENTRIES = 500
MAX_BASELINE_BYTES = 1024 * 1024
MAX_COUNT = 50
MIN_REASON = 10
MAX_REASON = 300
PLACEHOLDER_REASON = "TODO: say why this is safe"
_RULE = re.compile(r"^RH-SEC-[0-9]{3}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ENTRY_KEYS = frozenset({"file", "rule", "line_sha256", "count", "reason"})


class BaselineError(Exception):
    """The baseline file is missing, too big, malformed or has an entry that is not acceptable. The message names the problem, never file contents."""


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    file: str
    rule: str
    line_sha256: str
    count: int
    reason: str


@dataclass(frozen=True, slots=True)
class Baseline:
    entries: tuple[BaselineEntry, ...]


@dataclass(frozen=True, slots=True)
class StaleEntry:
    file: str
    rule: str
    unmatched: int


@dataclass(slots=True)
class BaselineResult:
    new: list[ScanFinding] = field(default_factory=list)
    accepted: int = 0
    stale: list[StaleEntry] = field(default_factory=list)


def line_fingerprint(line: str) -> str:
    """SHA-256 of the trimmed line. Indentation and trailing spaces do not matter; any other change does."""
    return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()


def normalize_path(path: str) -> str:
    """Forward slashes, no leading "./"."""
    posix = path.replace("\\", "/")
    while posix.startswith("./"):
        posix = posix[2:]
    return posix


def _valid_file(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or value.startswith("/"):
        return False
    return ".." not in value.split("/") and "\x00" not in value


def _parse_entry(raw: Any, index: int) -> BaselineEntry:
    where = f"entry {index + 1}"
    if not isinstance(raw, dict) or set(raw) - _ENTRY_KEYS or not {"file", "rule", "line_sha256", "reason"} <= set(raw):
        raise BaselineError(f"{where} must be an object with file, rule, line_sha256, reason and optionally count")
    file, rule, digest, reason = raw["file"], raw["rule"], raw["line_sha256"], raw["reason"]
    count = raw.get("count", 1)
    if not _valid_file(file):
        raise BaselineError(f"{where}: file must be a relative path with forward slashes")
    if not isinstance(rule, str) or not _RULE.match(rule):
        raise BaselineError(f"{where}: rule must look like RH-SEC-004")
    if not isinstance(digest, str) or not _SHA.match(digest):
        raise BaselineError(f"{where}: line_sha256 must be 64 lower-case hex digits")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_COUNT:
        raise BaselineError(f"{where}: count must be a whole number from 1 to {MAX_COUNT}")
    if not isinstance(reason, str) or not MIN_REASON <= len(reason.strip()) <= MAX_REASON or reason.strip().upper().startswith("TODO"):
        raise BaselineError(f"{where}: a real reason of {MIN_REASON} to {MAX_REASON} characters is required (not a TODO)")
    return BaselineEntry(file=file, rule=rule, line_sha256=digest, count=count, reason=reason.strip())


def load_baseline(path: Path) -> Baseline:
    """Reads and validates the baseline. Anything unexpected raises BaselineError."""
    try:
        if path.stat().st_size > MAX_BASELINE_BYTES:
            raise BaselineError("the baseline file is larger than 1 MiB")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError("the baseline file could not be read") from exc
    except UnicodeDecodeError as exc:
        raise BaselineError("the baseline file is not UTF-8 text") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise BaselineError("the baseline file is not valid JSON") from exc
    if not isinstance(data, dict) or set(data) != {"version", "entries"}:
        raise BaselineError("the baseline must be an object with exactly version and entries")
    if isinstance(data["version"], bool) or data["version"] != BASELINE_VERSION:
        raise BaselineError(f"the baseline version must be {BASELINE_VERSION}")
    raw_entries = data["entries"]
    if not isinstance(raw_entries, list):
        raise BaselineError("entries must be a list")
    if len(raw_entries) > MAX_ENTRIES:
        raise BaselineError(f"at most {MAX_ENTRIES} entries are allowed")
    entries = tuple(_parse_entry(raw, i) for i, raw in enumerate(raw_entries))
    keys = [(e.file, e.rule, e.line_sha256) for e in entries]
    if len(keys) != len(set(keys)):
        raise BaselineError("two entries name the same file, rule and line: merge them with a count")
    return Baseline(entries=entries)


def apply_baseline(
    findings: Sequence[ScanFinding], line_of: Callable[[ScanFinding], str | None], baseline: Baseline
) -> BaselineResult:
    """Splits findings into accepted (matched, up to each entry's count) and new, and lists the entries that matched fewer findings than they promise.
    A finding whose line cannot be read is never accepted."""
    remaining: dict[tuple[str, str, str], int] = {(e.file, e.rule, e.line_sha256): e.count for e in baseline.entries}
    result = BaselineResult()
    for finding in findings:
        line = line_of(finding)
        key = (normalize_path(finding.file_path), finding.rule_id, line_fingerprint(line)) if line is not None else None
        if key is not None and remaining.get(key, 0) > 0:
            remaining[key] -= 1
            result.accepted += 1
        else:
            result.new.append(finding)
    for entry in baseline.entries:
        left = remaining[(entry.file, entry.rule, entry.line_sha256)]
        if left > 0:
            result.stale.append(StaleEntry(file=entry.file, rule=entry.rule, unmatched=left))
    return result


def entries_for(findings: Sequence[ScanFinding], line_of: Callable[[ScanFinding], str | None]) -> list[dict[str, object]]:
    """Baseline entries (with a placeholder reason the loader refuses) for the findings whose line can be read. Never contains the line itself."""
    counts: Counter[tuple[str, str, str]] = Counter()
    for finding in findings:
        line = line_of(finding)
        if line is not None:
            counts[(normalize_path(finding.file_path), finding.rule_id, line_fingerprint(line))] += 1
    return [
        {"file": file, "rule": rule, "line_sha256": digest, "count": min(count, MAX_COUNT), "reason": PLACEHOLDER_REASON}
        for (file, rule, digest), count in sorted(counts.items())
    ]
