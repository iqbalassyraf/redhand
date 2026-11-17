"""
No invisible or bidirectional-control characters in product source ("Trojan Source", CVE-2021-42574; found by a one-off Bandit run, 2026-11-17).

The repository is public and takes pull requests. A right-to-left override or a zero-width character written literally into code or a script can make a
reviewer see something other than what runs, and a diff hides it. Radar and the MCP scanner have to NAME these characters in their detection patterns:
they do it with `\\uXXXX` escapes, which are visible in review. Tests and benchmark corpora may contain the real characters (they are the inputs the
detectors are tested on) and are not scanned here.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HIDDEN = re.compile("[­؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
SOURCE_DIRS = ("agentwall/src", "agentwall/config", "services/redhand-core/src", "packages/redhand-sdk/src", "packages/redhand-sidecar", "apps/redhand-ui/src",
               "supabase/migrations", "supabase/rollbacks", "deploy", "scripts", ".github")
SUFFIXES = {".py", ".ts", ".tsx", ".js", ".mjs", ".sh", ".sql", ".yml", ".yaml", ".json", ".toml", ".css"}
SKIP_PARTS = {"node_modules", ".next", ".venv", "__pycache__", "dist"}


def source_files() -> list[Path]:
    found: list[Path] = []
    for directory in SOURCE_DIRS:
        base = ROOT / directory
        if base.exists():
            found.extend(p for p in base.rglob("*") if p.is_file() and p.suffix in SUFFIXES and not SKIP_PARTS & set(p.parts))
    return found


def test_product_source_has_no_literal_invisible_or_bidi_characters() -> None:
    files = source_files()
    assert len(files) > 100, "the scan found too few files; its directory list is stale"
    offenders = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if HIDDEN.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, f"literal invisible characters (write them as \\uXXXX escapes): {offenders}"


def test_the_detection_patterns_still_name_the_characters_they_detect() -> None:
    """Escaping must not have emptied the patterns: they still match a real override and a real zero-width space."""
    from agentwall.src.firewall import description_rules, radar

    for pattern in (description_rules._INVISIBLE, radar._INVISIBLE):  # noqa: SLF001
        assert pattern.search("a‮b") and pattern.search("a​b") and pattern.search("a\U000e0041b")
        assert not pattern.search("plain text, 123")
    assert radar._BIDI.search("x⁦y") and not radar._BIDI.search("xy")  # noqa: SLF001
