"""The repository's own baseline: it must load, and the repository must pass the strict gate CI runs (so a new fake or real secret fails here, locally, first)."""

from __future__ import annotations

from pathlib import Path

import pytest

from redhand_sdk.cli import main as cli_main
from redhand_sdk.scanner.baseline import load_baseline

ROOT = Path(__file__).resolve().parents[3]
BASELINE = ROOT / ".redhand-scan-baseline.json"


def test_the_committed_baseline_is_valid_and_every_entry_has_a_reason() -> None:
    baseline = load_baseline(BASELINE)
    assert baseline.entries and all(len(e.reason) >= 10 for e in baseline.entries)


def test_the_repository_passes_the_strict_gate_with_its_baseline(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    code = cli_main(["scan", ".", "--strict", "--baseline", ".redhand-scan-baseline.json"])
    out = capsys.readouterr().out
    assert code == 0, out[-1500:]
