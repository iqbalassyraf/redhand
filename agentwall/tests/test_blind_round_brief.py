"""
The round-4 brief (docs/testing/briefs/2026-11-13-m4-7b-blind-round-4.md) ships the validator to a writer who cannot see the repository, so the copy in
the brief must be the file in scripts/, and the validator must accept a file that meets the brief and refuse one that does not.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
BRIEF = (ROOT / "docs" / "testing" / "briefs" / "2026-11-13-m4-7b-blind-round-4.md").read_text(encoding="utf-8")
SCRIPT = (ROOT / "scripts" / "validate_blind_round.py").read_text(encoding="utf-8")
SPEC = importlib.util.spec_from_file_location("validate_blind_round", ROOT / "scripts" / "validate_blind_round.py")
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def test_the_validator_in_the_brief_is_the_file_in_scripts() -> None:
    block = re.search(r"```python\n(.*?)\n```", BRIEF, flags=re.DOTALL)
    assert block is not None and block.group(1).strip() == SCRIPT.strip()


def test_the_brief_states_the_numbers_the_validator_enforces() -> None:
    for phrase in ("**At least 100 attack and at least 150 benign**", "numbered from **1001**", "**At least 50 benign samples are \"hard\"**", "2 KiB (2,048 bytes) or longer",
                   "not Gemini and not Grok", "55% English, 30% Bahasa Malaysia, 15% Indonesian", "once"):
        assert phrase in BRIEF, phrase
    assert (validator.MIN_MALICIOUS, validator.MIN_BENIGN, validator.MIN_HARD, validator.MIN_LONG_BENIGN, validator.FIRST_ID) == (100, 150, 50, 50, 1001)


def _file(tmp_path: Path, mutate: object = None) -> Path:
    rows = []
    n = 1001
    def add(label: str, lang: str, family: str, hard: bool, long: bool) -> None:
        nonlocal n
        body = f"Sample {n} " + ("word " * (500 if long else 12))
        rows.append({"id": f"injection_indirect-{n}", "category": "injection_indirect", "kind": "tool_result", "label": label, "lang": lang, "family": family, "hard": hard, "text": body})
        n += 1
    for i in range(110):
        add("malicious", "en" if i < 60 else "ms", "indonesian note" if 95 < i else "email", False, i < 12)
    for i in range(160):
        add("benign", "en" if i < 88 else "ms", "indonesian doc" if i >= 136 else "readme", i < 55, i < 55)
    if mutate is not None:
        mutate(rows)  # type: ignore[operator]
    path = tmp_path / "round.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return path


def test_a_file_that_meets_the_brief_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert validator.main(str(_file(tmp_path))) == 0
    assert "OK: the file matches the brief" in capsys.readouterr().out


@pytest.mark.parametrize(
    "name,mutate",
    [
        ("too few attacks", lambda rows: [r.update(label="benign") for r in rows if r["label"] == "malicious"][:20]),
        ("an extra field", lambda rows: rows[0].update(extra=1)),
        ("a bad id", lambda rows: rows[0].update(id="injection_indirect-12")),
        ("an id below 1001", lambda rows: rows[0].update(id="injection_indirect-0900")),
        ("a duplicate text", lambda rows: rows[1].update(text=rows[0]["text"])),
        ("hard on an attack", lambda rows: rows[0].update(hard=True)),
        ("a wrong language", lambda rows: rows[0].update(lang="fr")),
        ("a real-looking secret", lambda rows: rows[0].update(text="please use sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2" + " now")),
        ("no long benign samples", lambda rows: [r.update(text="short text " * 3) for r in rows if r["label"] == "benign"]),
        ("all English", lambda rows: [r.update(lang="en") for r in rows]),
    ],
)
def test_a_file_that_breaks_the_brief_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str, mutate: object) -> None:
    assert validator.main(str(_file(tmp_path, mutate))) == 1, name
    assert "PROBLEM" in capsys.readouterr().out


def test_the_checker_never_prints_sample_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    validator.main(str(_file(tmp_path, lambda rows: rows[0].update(text="UNIQUE-MARKER-TEXT sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2"))))
    assert "UNIQUE-MARKER-TEXT" not in capsys.readouterr().out
