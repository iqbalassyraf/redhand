"""
The M4.7b split (docs/security/m4-7b-split.md): deterministic, 60 and 60, no overlap, and the committed lists are exactly what the rule computes,
so they cannot be edited by hand to favour a result.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("radar_real_documents_split", ROOT / "scripts" / "radar_real_documents_split.py")
assert SPEC is not None and SPEC.loader is not None
split_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(split_module)
DOC = (ROOT / "docs" / "security" / "m4-7b-split.md").read_text(encoding="utf-8")


def _section(title: str) -> list[str]:
    body = DOC.split(f"## {title}", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^- `([^`]+)`$", body, flags=re.MULTILINE)


def test_the_sets_are_sixty_and_sixty_and_do_not_overlap() -> None:
    tuning, frozen = split_module.split()
    assert len(tuning) == 60 and len(frozen) == 60 and not set(tuning) & set(frozen) and len(set(tuning + frozen)) == 120


def test_the_committed_lists_are_exactly_what_the_rule_computes() -> None:
    tuning, frozen = split_module.split()
    assert _section("Tuning set (60)") == tuning and _section("Frozen set (60)") == frozen


def test_the_split_is_by_hash_of_the_name_not_by_position() -> None:
    tuning, frozen = split_module.split()
    key = lambda n: hashlib.sha256(n.encode("utf-8")).hexdigest()  # noqa: E731
    assert max(map(key, tuning)) < min(map(key, frozen))
    assert tuning != split_module.repo_names()[:60]  # the order of the proof script's list plays no part


def test_the_hundred_and_twenty_are_the_first_hundred_and_twenty_of_the_proof_script() -> None:
    names = split_module.repo_names()
    assert len(names) == 120 and names[0] == "facebook/react"
