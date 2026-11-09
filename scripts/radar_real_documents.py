#!/usr/bin/env python3
"""
Runs the Radar's checks over REAL, LONG documents that nobody wrote for the benchmark: this repository's own docs, code and built web pages (and any folder you
add), as if a tool had returned each one. It answers the question our short test samples cannot: how often does a check flag an ordinary long document?

  PYTHONPATH=. uv run python scripts/radar_real_documents.py                       # the repository
  PYTHONPATH=. uv run python scripts/radar_real_documents.py --root apps/redhand-ui/.next/server/app --root ../redhand-helpdesk-demo/docs
  PYTHONPATH=. uv run python scripts/radar_real_documents.py --format markdown --out docs/security/real-document-replay.md

What it prints: counts per kind of document and per check, the 95% upper bound of the strong-finding rate, the rules that fired, and the PATHS of flagged files
(so a person can open them and judge). Never document text. Read the limits before quoting a number:
  * This repository's own docs and code were written by the same team as the rules (and a security product's text is full of attack vocabulary), so those groups are NOT
    typical. The third-party READMEs of installed packages are strangers' real documentation and are the fairest group. None of it is blind evidence for the block gate.
  * "Security write-ups" (threat model, plans, test records) quote attacks on purpose, so flags there are expected; they are reported separately.
  * Every flagged document is assumed harmless here, so a flag counts as a false alarm. A document that really contains an attack would be counted against the check.
  * The Radar reads at most 16 KiB from each end of a document, as in the gateway.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentwall.src.bench.metrics import wilson  # noqa: E402
from agentwall.src.firewall import radar  # noqa: E402
from agentwall.src.firewall.radar_fingerprint import rules_fingerprint  # noqa: E402

LONG_BYTES = 2048
MIN_BYTES = 256
MAX_BYTES = 2 * 1024 * 1024
DEFAULT_ROOTS = ("docs", "README.md", "CHANGELOG.md", "services", "agentwall", "apps/redhand-ui/src", "apps/redhand-ui/public", "packages", "scripts", "deploy")
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".next", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build", "target"}
# Test material that IS attack text on purpose (the benchmark corpus, raw sample exports): not a real document, so never part of this measurement.
SKIP_PARTS = ("agentwall/bench", "docs/testing/exports", "docs/review")
KINDS: dict[str, str] = {
    ".md": "documentation", ".txt": "documentation", ".html": "web page", ".json": "data", ".yaml": "data", ".yml": "data", ".toml": "data",
    ".py": "code", ".ts": "code", ".tsx": "code", ".js": "code", ".mjs": "code", ".sql": "code", ".sh": "code", ".css": "code",
}
WRITEUP_PARTS = ("docs/security", "docs/plans", "docs/adr", "docs/testing", "docs/runbooks", "docs/briefing", "docs/handoff", "CHANGELOG")
THIRD_PARTY = "third-party README"
GROUPS = ("web page", THIRD_PARTY, "documentation", "code", "data", "security write-up")


def classify(relative: str) -> str | None:
    """The group a file belongs to, or None when it is not a document we measure."""
    if any(part in relative for part in SKIP_PARTS):
        return None
    kind = KINDS.get(Path(relative).suffix.lower())
    if kind is None:
        return None
    if kind in ("documentation", "data", "code") and any(part in relative for part in WRITEUP_PARTS):
        return "security write-up"
    return kind


def third_party_documents(base: Path = ROOT) -> Iterable[tuple[str, Path, str]]:
    """Real documentation written by strangers for their own projects: the README of every installed npm package and the long description of every installed
    Python package. Nobody chose them for a benchmark and the rule author did not write them, which makes them the best independent sample on this machine."""
    patterns = (
        "apps/redhand-ui/node_modules/*/README*", "apps/redhand-ui/node_modules/@*/*/README*",
        ".venv/lib/python*/site-packages/*.dist-info/METADATA",
    )
    for pattern in patterns:
        for path in sorted(base.glob(pattern)):
            if path.is_file():
                yield str(path.relative_to(base)), path, THIRD_PARTY


def iter_documents(roots: Iterable[Path], base: Path = ROOT) -> Iterable[tuple[str, Path, str]]:
    seen: set[Path] = set()
    for root in roots:
        candidates = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for path in candidates:
            if path in seen or any(part in SKIP_DIRS for part in path.relative_to(root if root.is_dir() else root.parent).parts[:-1]):
                continue
            seen.add(path)
            try:
                shown = str(path.resolve().relative_to(base))
            except ValueError:
                shown = str(path)  # a root outside the repository (for example the helpdesk demo): show the path as given
            group = classify(shown)
            if group is not None:
                yield shown, path, group


@dataclass(slots=True)
class FileResult:
    path: str
    group: str
    size: int
    flagged: dict[str, bool] = field(default_factory=dict)   # kind -> any finding
    strong: dict[str, bool] = field(default_factory=dict)    # kind -> any strong finding
    rules: tuple[str, ...] = ()


def scan_text(path: str, group: str, text: str) -> FileResult:
    report = radar.scan_result(text, radar.ScanContext(tool_names=frozenset()), frozenset({"injection", "output"}), radar.DEFAULT_DETECTORS)
    flagged = {k: any(f.kind == k for f in report.findings) for k in ("injection", "output")}
    strong = {k: any(f.kind == k and f.actionable for f in report.findings) for k in ("injection", "output")}
    strong_rules = tuple(sorted({f.rule_id for f in report.findings if f.actionable}))
    return FileResult(path, group, len(text.encode("utf-8")), flagged, strong, strong_rules)


def scan_documents(documents: Iterable[tuple[str, Path, str]]) -> list[FileResult]:
    results: list[FileResult] = []
    for shown, path, group in documents:
        try:
            size = path.stat().st_size
            if not MIN_BYTES <= size <= MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # a binary or unreadable file is not a document
        results.append(scan_text(shown, group, text))
    return results


def summarise(results: list[FileResult]) -> dict[str, Any]:
    def block(rows: list[FileResult]) -> dict[str, Any]:
        out: dict[str, Any] = {"documents": len(rows), "long": sum(1 for r in rows if r.size >= LONG_BYTES), "bytes": sum(r.size for r in rows)}
        for kind in ("injection", "output"):
            strong = sum(1 for r in rows if r.strong[kind])
            low, high = wilson(strong, len(rows)) if rows else (0.0, 1.0)
            out[kind] = {"flagged": sum(1 for r in rows if r.flagged[kind]), "strong": strong, "strong_rate": strong / len(rows) if rows else 0.0, "upper": high, "lower": low}
        out["rules"] = dict(Counter(rule for r in rows for rule in r.rules).most_common())
        return out

    by_group = {g: block([r for r in results if r.group == g]) for g in GROUPS if any(r.group == g for r in results)}
    return {
        "rules_fingerprint": rules_fingerprint(), "all": block(results), "without_security_writeups": block([r for r in results if r.group != "security write-up"]),
        "third_party_only": block([r for r in results if r.group == THIRD_PARTY]),
        "by_group": by_group,
        "flagged_paths": {g: sorted(r.path for r in results if r.group == g and any(r.strong.values())) for g in by_group},
    }


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Real-document replay (generated)", "",
        "The Radar's checks run over real, long documents that were not written for the benchmark, as if a tool had returned each one. "
        f"Rules version `{summary['rules_fingerprint']}`. Read the limits at the end before quoting a number.", "",
        "| Group | Documents | Long (2 KiB or more) | Hidden instructions: strong | upper bound | Risky output: strong | upper bound |", "|---|---|---|---|---|---|---|",
    ]
    rows = {**summary["by_group"], "**all of the above**": summary["all"], "**without security write-ups**": summary["without_security_writeups"]}
    rows = {name: b for name, b in rows.items() if b["documents"]}
    for name, b in rows.items():
        lines.append(
            f"| {name} | {b['documents']} | {b['long']} | {b['injection']['strong']} ({_pct(b['injection']['strong_rate'])}) | {_pct(b['injection']['upper'])} | "
            f"{b['output']['strong']} ({_pct(b['output']['strong_rate'])}) | {_pct(b['output']['upper'])} |"
        )
    lines += ["", "## Rules that fired strongly (document counts)", ""]
    for name, b in rows.items():
        if b["rules"]:
            lines.append(f"- {name}: " + ", ".join(f"{rule} x{n}" for rule, n in b["rules"].items()))
    lines += ["", "## Flagged documents (paths only, so a person can open them and judge)", ""]
    for group, paths in summary["flagged_paths"].items():
        lines.append(f"### {group} ({len(paths)})")
        lines += [f"- `{p}`" for p in paths[:60]] + ([f"- ... and {len(paths) - 60} more"] if len(paths) > 60 else [])
        lines.append("")
    lines += [
        "## Limits", "",
        "- This repository's own documents and code were written by the team that wrote the rules, and a security product's text is full of attack vocabulary, so those rows are NOT typical. "
        "The third-party READMEs are strangers' real documentation and are the fairest row. None of this is blind evidence and none of it counts for the block gate.",
        "- Security write-ups quote attacks on purpose, so flags there are expected. They are reported separately.",
        "- Every flagged document is treated as harmless here, so a flag counts as a false alarm.",
        "- The Radar reads at most 16 KiB from each end of a document, as the gateway does.",
        "- The 95% upper bound is the same interval the block gate uses; with few documents in a group it is wide.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", action="append", default=[], help="a folder or file to scan (repeatable); default: this repository's docs, code and data")
    parser.add_argument("--no-third-party", action="store_true", help="skip the READMEs of installed npm and Python packages")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--out", help="write the report here instead of printing it")
    args = parser.parse_args()
    roots = [Path(r).resolve() for r in args.root] if args.root else [ROOT / r for r in DEFAULT_ROOTS if (ROOT / r).exists()]
    if args.root and not all(r.exists() for r in roots):
        raise SystemExit("a --root does not exist")
    documents = list(iter_documents(roots))
    if not args.no_third_party:
        documents += list(third_party_documents())
    summary = summarise(scan_documents(documents))
    output = json.dumps(summary, indent=2, sort_keys=True) + "\n" if args.format == "json" else render_markdown(summary)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    raise SystemExit(main())
