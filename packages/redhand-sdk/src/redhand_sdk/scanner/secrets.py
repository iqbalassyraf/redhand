"""
RedHand SDK - secrets in prompt and config files (RH-SEC-004).
File: packages/redhand-sdk/src/redhand_sdk/scanner/secrets.py

Finds credentials pasted into prompt and config files and says WHICH FILE, WHICH LINE and WHAT KIND. It never holds, prints or exports
the value: a finding has no field for it, and every message comes from a fixed table. Plan: docs/plans/phase4-m5b-secrets-in-files.md.

What it does not do (the CLI help and the runbook say the same): it finds only the key formats below, not passwords, database URLs or
custom tokens; it reads only the listed file types; and a clean result does not prove a repository holds no secret. It makes no
network call. Every read is bounded (file size, number of files, findings per file), and symlinks are never followed.

The patterns are copied from the gateway's EgressTaintGuardrail (agentwall/src/firewall/ast_guardrails.py) because this package must
install on its own and cannot import `agentwall`; agentwall/tests/test_sdk_secret_patterns_in_sync.py keeps them in step. They differ in
one deliberate way: they only match at a word boundary (so "risk-assessment-and-mitigation" is not an "sk-" key), and the AWS pattern
needs a whole 20-character key id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat

from redhand_sdk.scanner.ast_checker import ScanFinding

RULE_ID = "RH-SEC-004"
RULE_NAME = "Secret in a Prompt or Config File"

MAX_FILE_BYTES = 1024 * 1024  # a larger file is skipped and counted, never partly read
MAX_FILES = 5_000  # candidate files per run
MAX_FINDINGS_PER_FILE = 50
BINARY_CHECK_BYTES = 8192
MAX_SKIPPED_EXAMPLES = 10

SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "__pycache__"})
SCANNED_SUFFIXES = frozenset({".yaml", ".yml", ".json", ".toml", ".md", ".txt", ".py"})  # plus .env and .env.*

# Well-known documentation examples that are not secrets. Only this one; there is no inline "ignore" marker, because one would let a
# real secret be hidden.
DOCUMENTED_EXAMPLES = frozenset({"AKIAIOSFODNN7EXAMPLE"})

_WORD_START = r"(?<![A-Za-z0-9_-])"
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Most specific first: an Anthropic key also matches the OpenAI pattern, and is reported once, as the more specific kind.
    ("ANTHROPIC_KEY", re.compile(_WORD_START + r"sk-ant-[a-zA-Z0-9_-]{20,}")),
    ("OPENAI_KEY", re.compile(_WORD_START + r"sk-[a-zA-Z0-9_-]{20,}")),
    ("AWS_KEY", re.compile(r"(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("GCP_BEARER", re.compile(_WORD_START + r"ya29\.[0-9a-zA-Z_.-]{16,}")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----")),
)

# What the developer is told. Fixed text per kind: nothing from the file is ever put in a message.
SECRET_MESSAGES: dict[str, str] = {
    "ANTHROPIC_KEY": "An Anthropic API key appears on this line. Rotate it: deleting the line does not remove it from git history.",
    "OPENAI_KEY": "An API key that looks like an OpenAI key appears on this line. Rotate it: deleting the line does not remove it from git history.",
    "AWS_KEY": "An AWS access key id appears on this line. Rotate it: deleting the line does not remove it from git history.",
    "GCP_BEARER": "A Google Cloud access token appears on this line. Revoke it: deleting the line does not remove it from git history.",
    "PRIVATE_KEY": "A private key appears in this file. Replace it: deleting it does not remove it from git history.",
}


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """A secret was found at this place. There is deliberately NO field for the matched text, so it cannot leak by accident."""

    file_path: str
    line_number: int
    secret_type: str

    def to_scan_finding(self) -> ScanFinding:
        return ScanFinding(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            severity="error",
            file_path=self.file_path,
            line_number=self.line_number,
            tool_name="",
            message=SECRET_MESSAGES[self.secret_type],
        )


@dataclass(slots=True)
class SecretScanResult:
    findings: list[SecretFinding] = field(default_factory=list)
    files_read: int = 0
    skipped: dict[str, int] = field(default_factory=dict)  # reason -> how many files
    skipped_examples: list[tuple[str, str]] = field(default_factory=list)  # (path, reason), the first few
    stopped_at_file_limit: bool = False
    files_with_capped_findings: int = 0

    def skip(self, path: str, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        if len(self.skipped_examples) < MAX_SKIPPED_EXAMPLES:
            self.skipped_examples.append((path, reason))


def scan_text(text: str, file_path: str, limit: int | None = None) -> list[SecretFinding]:
    """Finds secrets in one text, line by line: at most one finding per line and kind. Pure; stops after `limit` findings if given."""
    findings: list[SecretFinding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        accepted: list[tuple[int, int]] = []
        seen: set[str] = set()
        for name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                start, end = match.span()
                if match.group(0) in DOCUMENTED_EXAMPLES:
                    continue
                if any(a <= start and end <= b for a, b in accepted):
                    continue  # already reported as a more specific kind
                accepted.append((start, end))
                if name not in seen:
                    seen.add(name)
                    findings.append(SecretFinding(file_path, number, name))
                    if limit is not None and len(findings) >= limit:
                        return findings
    return findings


def _is_candidate(name: str) -> bool:
    lower = name.lower()
    return lower == ".env" or lower.startswith(".env.") or os.path.splitext(lower)[1] in SCANNED_SUFFIXES


def _read(path: str) -> tuple[str | None, str | None]:
    """The text of a file, or (None, the reason it was not read). Never follows a symlink, never reads more than the size cap."""
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            return None, "symlink"
        if not stat.S_ISREG(info.st_mode):
            return None, "not a regular file"
        if info.st_size > MAX_FILE_BYTES:
            return None, "too large"
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)  # a file that grew since lstat is still capped
    except OSError:
        return None, "unreadable"
    if len(data) > MAX_FILE_BYTES:
        return None, "too large"
    if b"\x00" in data[:BINARY_CHECK_BYTES]:
        return None, "binary"
    return data.decode("utf-8", errors="replace"), None


def _scan_file(path: str, result: SecretScanResult) -> None:
    text, reason = _read(path)
    if text is None:
        result.skip(path, reason or "unreadable")
        return
    result.files_read += 1
    found = scan_text(text, path, limit=MAX_FINDINGS_PER_FILE + 1)
    if len(found) > MAX_FINDINGS_PER_FILE:
        found = found[:MAX_FINDINGS_PER_FILE]
        result.files_with_capped_findings += 1
    result.findings.extend(found)


def scan_secrets(target: str | Path) -> SecretScanResult:
    """Scans a folder (the listed file types, bounded) or one file (whatever its type). Never raises for a bad file: it is counted as skipped."""
    root = os.fspath(target)
    result = SecretScanResult()
    if os.path.isdir(root):
        considered = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if not _is_candidate(name):
                    continue
                if considered >= MAX_FILES:
                    result.stopped_at_file_limit = True
                    return result
                considered += 1
                _scan_file(os.path.join(dirpath, name), result)
    elif os.path.lexists(root):
        _scan_file(root, result)
    return result


def summary_lines(result: SecretScanResult) -> list[str]:
    """What the run covered, in plain words, for the console. Never contains anything read from a file except paths."""
    files = "file" if result.files_read == 1 else "files"
    lines = [f"Secrets pass: read {result.files_read} {files} (prompt and config file types, up to 1 MiB each)."]
    if result.skipped:
        total = sum(result.skipped.values())
        reasons = ", ".join(f"{reason}: {count}" for reason, count in sorted(result.skipped.items()))
        lines.append(f"  {total} {'file' if total == 1 else 'files'} skipped ({reasons}).")
        lines.extend(f"    skipped {path}: {reason}" for path, reason in result.skipped_examples)
    if result.stopped_at_file_limit:
        lines.append(f"  Stopped at the limit of {MAX_FILES} files: the rest of the folder was NOT scanned.")
    if result.files_with_capped_findings:
        lines.append(f"  {result.files_with_capped_findings} file(s) hit the limit of {MAX_FINDINGS_PER_FILE} findings: more may exist.")
    return lines
