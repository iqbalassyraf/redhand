"""
`redhand bench` (Phase 4 M1): the corpus is valid and big enough to mean something, the rate maths and status rules are
right, the regression gate really fails on a worse result, and the committed baseline and coverage table are exactly what
a fresh run produces (so a detector change cannot slip through without the numbers being updated on purpose).
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import pytest

from agentwall.src.bench import __main__ as bench_cli
from agentwall.src.bench.corpus import DEFAULT_CORPUS_DIR, MACROS, Sample, corpus_digest, load_corpus
from agentwall.src.bench.detectors import DETECTORS, Detector, flagged_by
from agentwall.src.bench.metrics import (
    MIN_SAMPLES_PER_SIDE, CategoryResult, evaluate, wilson,
)
from agentwall.src.bench.report import (
    baseline_is_current, compare_with_baseline, render_markdown, to_json,
)

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "agentwall" / "bench" / "baseline.json"
MATRIX = ROOT / "docs" / "security" / "coverage-matrix.md"


def _sample(i: int, label: str = "malicious", category: str = "injection_indirect", **over: Any) -> Sample:
    base: dict[str, Any] = dict(
        id=f"{category}-{i:03d}", category=category, kind="tool_result", label=label, lang="en", family=f"f{i}", text="hello",
    )
    base.update(over)
    return Sample.model_validate(base)


# --- the corpus -----------------------------------------------------------------------------------------------

def test_the_committed_corpus_loads_and_every_category_has_enough_samples_on_both_sides() -> None:
    samples = [s for s in load_corpus() if s.split == "dev"]
    by_category: dict[str, dict[str, int]] = {}
    for s in samples:
        by_category.setdefault(s.category, {"malicious": 0, "benign": 0})[s.label] += 1
    assert len(by_category) >= 7
    for category, counts in by_category.items():
        assert counts["malicious"] >= MIN_SAMPLES_PER_SIDE and counts["benign"] >= MIN_SAMPLES_PER_SIDE, category


def test_the_corpus_has_hard_benign_cases_and_malay_samples_in_every_category() -> None:
    samples = load_corpus()
    benign = [s for s in samples if s.label == "benign"]
    assert sum(s.hard for s in benign) / len(benign) >= 0.30  # benign samples built to look like attacks
    for category in {s.category for s in samples}:
        assert any(s.lang == "ms" and s.label == "malicious" for s in samples if s.category == category), category
        assert any(s.hard for s in samples if s.category == category and s.label == "benign"), category


def test_no_secret_shaped_string_sits_in_the_corpus_files() -> None:
    """Fake credentials are expanded from pieces at load time so scanners and push protection never see them."""
    patterns = [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"sk_live_[A-Za-z0-9]{20,}", r"xox[abprs]-[A-Za-z0-9-]{10,}",
                r"BEGIN (?:RSA )?PRIVATE KEY", r"AIza[0-9A-Za-z_-]{30,}", r"sk-[A-Za-z0-9_-]{30,}", r"ya29\.[0-9A-Za-z_.-]{20,}"]
    for path in DEFAULT_CORPUS_DIR.glob("*.jsonl"):
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            assert not re.search(pattern, text), f"{path.name} contains text matching {pattern}"


def test_placeholders_expand_into_the_values_the_detectors_see() -> None:
    samples = {s.id: s for s in load_corpus()}
    leaked = [s for s in samples.values() if s.category == "secret_leak" and s.label == "malicious" and s.text]
    assert any(MACROS["AWS_KEY"] in (s.text or "") for s in leaked)
    assert not any(re.search(r"\{\{[A-Z0-9_]+\}\}", s.text or "") for s in samples.values())  # none left unexpanded


def _write(tmp_path: Path, name: str, rows: list[dict[str, Any]]) -> Path:
    (tmp_path / f"{name}.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return tmp_path


def _row(**over: Any) -> dict[str, Any]:
    row: dict[str, Any] = dict(id="secret_leak-001", category="secret_leak", kind="tool_result", label="malicious", lang="en", family="a", text="x")
    row.update(over)
    return row


@pytest.mark.parametrize(("name", "rows", "why"), [
    ("secret_leak", [_row(), _row()], "duplicate id"),
    ("secret_leak", [_row(category="made_up")], "unknown category"),
    ("secret_leak", [_row(text=None)], "text and manifest"),
    ("secret_leak", [_row(manifest={"name": "x"})], "text and manifest"),
    ("secret_leak", [_row(kind="manifest", text="x")], "text and manifest"),
    ("secret_leak", [_row(hard=True)], "hard"),
    ("secret_leak", [_row(text="{{NOT_A_MACRO}}")], "unknown placeholder"),
    ("secret_leak", [_row(unexpected="field")], "extra"),
    ("secret_leak", [_row(id="injection_indirect-001")], "category"),
    ("injection_indirect", [_row()], "does not match the file name"),
])
def test_an_invalid_corpus_is_refused_not_measured(tmp_path: Path, name: str, rows: list[dict[str, Any]], why: str) -> None:
    with pytest.raises(ValueError):
        load_corpus(_write(tmp_path, name, rows))


def test_an_empty_corpus_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no corpus files"):
        load_corpus(tmp_path)


def test_the_digest_changes_when_the_corpus_does(tmp_path: Path) -> None:
    _write(tmp_path, "secret_leak", [_row()])
    first = corpus_digest(tmp_path)
    _write(tmp_path, "secret_leak", [_row(text="changed")])
    assert corpus_digest(tmp_path) != first


# --- the maths ----------------------------------------------------------------------------------------------

def test_wilson_interval_is_wide_for_small_samples_and_bounded() -> None:
    lo, hi = wilson(0, 20)
    assert lo == 0.0 and 0.15 < hi < 0.17
    lo, hi = wilson(20, 20)
    assert 0.83 < lo < 0.85 and hi == 1.0
    assert wilson(0, 0) == (0.0, 1.0)
    lo, hi = wilson(5, 10)
    assert 0.23 < lo < 0.26 and 0.74 < hi < 0.78  # about 50% +/- 26 points at n=10


def _result(mal: int, ben: int, detected: int, false_alarms: int) -> CategoryResult:
    return CategoryResult("injection_indirect", "LLM01", n_malicious=mal, n_benign=ben, detected=detected, false_alarms=false_alarms)


@pytest.mark.parametrize(("mal", "ben", "detected", "false_alarms", "status"), [
    (20, 20, 20, 0, "covered"), (20, 100, 18, 1, "covered"), (20, 100, 18, 2, "partial"),
    (20, 20, 10, 1, "partial"), (20, 20, 10, 2, "weak"), (20, 20, 9, 0, "weak"), (20, 20, 1, 0, "weak"),
    (20, 20, 0, 0, "not covered"), (19, 20, 19, 0, "insufficient data"), (20, 19, 20, 0, "insufficient data"),
])
def test_status_rules(mal: int, ben: int, detected: int, false_alarms: int, status: str) -> None:
    assert _result(mal, ben, detected, false_alarms).status == status


def _detector(name: str, rule: Any) -> Detector:
    return Detector(name, frozenset({"tool_result"}), rule)


def test_evaluate_counts_detections_false_alarms_families_and_languages() -> None:
    samples = [
        _sample(1, family="a"), _sample(2, family="a"), _sample(3, family="b", lang="ms"),
        _sample(4, "benign"), _sample(5, "benign", hard=True), _sample(6, "benign", hard=True),
    ]
    flags_even = _detector("evens", lambda s: int(s.id[-3:]) % 2 == 0)
    ev = evaluate(samples, (flags_even,))
    cat = ev.categories["injection_indirect"]
    assert (cat.n_malicious, cat.n_benign, cat.families) == (3, 3, 2)
    assert cat.detected == 1 and cat.missed == ["injection_indirect-001", "injection_indirect-003"]
    assert cat.false_alarms == 2 and cat.hard_false_alarms == 1  # samples 4 and 6 are flagged, 6 is hard
    assert cat.by_lang == {"en": (2, 1), "ms": (1, 0)}


def test_a_detector_only_counts_for_the_kinds_it_applies_to() -> None:
    manifest_only = Detector("m", frozenset({"manifest"}), lambda s: True)
    ev = evaluate([_sample(1)], (manifest_only,))
    assert ev.categories["injection_indirect"].detected == 0


# --- reports and the regression gate -------------------------------------------------------------------------

def _current() -> tuple[Any, str]:
    return evaluate(load_corpus()), corpus_digest()


def test_the_committed_baseline_is_exactly_a_fresh_run() -> None:
    """If a detector or the corpus changed, this fails until the baseline is regenerated on purpose."""
    ev, digest = _current()
    assert baseline_is_current(ev, digest, json.loads(BASELINE.read_text(encoding="utf-8")))


def test_the_committed_coverage_table_is_exactly_what_the_benchmark_generates() -> None:
    ev, digest = _current()
    assert MATRIX.read_text(encoding="utf-8") == render_markdown(ev, digest)


def test_the_gate_fails_when_detection_drops_or_false_alarms_rise() -> None:
    ev, digest = _current()
    baseline = to_json(ev, digest)
    assert compare_with_baseline(ev, digest, baseline) == []
    worse_detection = json.loads(json.dumps(baseline))
    worse_detection["categories"]["secret_leak"]["detected"] += 1  # baseline claimed one more catch than we make
    assert any("detection fell" in p for p in compare_with_baseline(ev, digest, worse_detection))
    worse_false_alarms = json.loads(json.dumps(baseline))
    worse_false_alarms["categories"]["manifest_risk"]["false_alarms"] -= 1
    assert any("false alarms rose" in p for p in compare_with_baseline(ev, digest, worse_false_alarms))


def test_an_improvement_passes_the_gate_but_asks_for_the_baseline_to_be_updated() -> None:
    ev, digest = _current()
    baseline = to_json(ev, digest)
    baseline["categories"]["secret_leak"]["detected"] -= 1  # we now catch one more than the baseline says
    assert compare_with_baseline(ev, digest, baseline) == []
    assert baseline_is_current(ev, digest, baseline) is False


def test_a_changed_corpus_needs_a_new_baseline_on_purpose() -> None:
    ev, digest = _current()
    baseline = to_json(ev, "deadbeefdeadbeef")
    assert any("corpus changed" in p for p in compare_with_baseline(ev, digest, baseline))


def test_a_category_missing_from_either_side_is_a_problem() -> None:
    ev, digest = _current()
    baseline = to_json(ev, digest)
    baseline["categories"]["brand_new"] = {"detected": 0, "false_alarms": 0}
    assert any("missing from the corpus" in p for p in compare_with_baseline(ev, digest, baseline))
    del baseline["categories"]["brand_new"]
    del baseline["categories"]["output_xss"]
    assert any("not in the baseline" in p for p in compare_with_baseline(ev, digest, baseline))


def test_reports_are_honest_about_what_is_not_covered_and_never_claim_perfection() -> None:
    ev, digest = _current()
    markdown = render_markdown(ev, digest)
    assert "flatter" in markdown and "not covered" in markdown and "RedHand only checks what flows through its gateway" in markdown
    for name in ("LLM04", "LLM08", "LLM09"):
        assert re.search(rf"\| {name} \|.*not (measured|covered)|\| {name} \|.*Not covered", markdown, re.IGNORECASE)
    # A flat "100%" may appear in the DEV table (the rules are written against those samples) but never in what is
    # meant to be quoted: the held-out results and the OWASP table.
    quotable = markdown.split("## Held-out results")[1]
    assert "= 100%" not in quotable


def test_the_report_is_deterministic() -> None:
    ev, digest = _current()
    assert render_markdown(ev, digest) == render_markdown(evaluate(load_corpus()), corpus_digest())


# --- the shipped detectors, on known cases -------------------------------------------------------------------

def test_the_shipped_detectors_catch_what_they_claim_and_the_gaps_are_real() -> None:
    samples = {s.id: s for s in load_corpus()}
    aws = next(s for s in samples.values() if s.category == "secret_leak" and s.family == "aws")
    assert "egress_guardrail" in flagged_by(aws)
    injection = next(s for s in samples.values() if s.category == "injection_indirect" and s.label == "malicious")
    assert flagged_by(injection) == []  # no gateway detector for injection yet: Radar (M4) is what changes this
    shell = next(s for s in samples.values() if s.category == "manifest_risk" and s.family == "shell-cmd")
    assert "manifest_auditor" in flagged_by(shell)
    assert {d.name for d in DETECTORS} == {"egress_guardrail", "manifest_auditor", "description_auditor"}


# --- the command line ----------------------------------------------------------------------------------------

def test_cli_check_passes_on_the_committed_baseline_and_fails_on_a_doctored_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert bench_cli.main(["--check", str(BASELINE), "--format", "json", "--out", str(tmp_path / "out.json")]) == 0
    doctored = json.loads(BASELINE.read_text(encoding="utf-8"))
    doctored["categories"]["secret_leak"]["detected"] += 1
    path = tmp_path / "doctored.json"
    path.write_text(json.dumps(doctored), encoding="utf-8")
    assert bench_cli.main(["--check", str(path), "--out", str(tmp_path / "o.txt")]) == 1
    assert "REGRESSION" in capsys.readouterr().err


def test_cli_refuses_an_invalid_corpus_with_a_distinct_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path, "secret_leak", [_row(), _row()])
    assert bench_cli.main(["--corpus", str(tmp_path)]) == 2
    assert "corpus is invalid" in capsys.readouterr().err


def test_cli_update_baseline_writes_a_file_that_passes_its_own_check(tmp_path: Path) -> None:
    out = tmp_path / "baseline.json"
    assert bench_cli.main(["--update-baseline", str(out), "--out", str(tmp_path / "r.txt")]) == 0
    assert bench_cli.main(["--check", str(out), "--out", str(tmp_path / "r2.txt")]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == json.loads(BASELINE.read_text(encoding="utf-8"))


# --- held-out samples ---------------------------------------------------------------------------------------

def test_holdout_samples_are_marked_by_file_name_and_never_share_ids_with_dev() -> None:
    samples = load_corpus()
    holdout = [s for s in samples if s.split == "holdout"]
    assert holdout and all(s.id.split("-")[1] >= "100" for s in holdout)
    assert len({s.id for s in samples}) == len(samples)
    for category in {s.category for s in holdout}:
        mal = sum(1 for s in holdout if s.category == category and s.label == "malicious")
        ben = sum(1 for s in holdout if s.category == category and s.label == "benign")
        assert mal >= MIN_SAMPLES_PER_SIDE and ben >= MIN_SAMPLES_PER_SIDE, category


def test_a_holdout_file_with_an_unknown_suffix_is_refused(tmp_path: Path) -> None:
    (tmp_path / "secret_leak.extra.jsonl").write_text(json.dumps(_row()) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown corpus file kind"):
        load_corpus(tmp_path)


def test_evaluate_keeps_dev_and_holdout_apart_and_quotes_holdout_when_it_has_enough_samples() -> None:
    dev = [_sample(i) for i in range(1, 21)] + [_sample(i, "benign") for i in range(21, 41)]
    held = [_sample(100 + i, split="holdout") for i in range(20)] + [_sample(200 + i, "benign", split="holdout") for i in range(20)]
    always = _detector("always", lambda s: True)
    never = _detector("never", lambda s: False)
    ev = evaluate(dev + held, (always,))
    assert ev.categories["injection_indirect"].detected == 20 and ev.holdout["injection_indirect"].false_alarms == 20
    headline, label = ev.headline("injection_indirect")
    assert label == "held-out" and headline is ev.holdout["injection_indirect"]
    small = evaluate(dev + held[:5], (never,))
    assert small.headline("injection_indirect")[1] == "dev only"  # too few held-out samples to quote


def test_the_gate_also_watches_the_held_out_results() -> None:
    ev, digest = _current()
    baseline = to_json(ev, digest)
    baseline["holdout"]["tool_poisoning"]["detected"] += 1
    assert any("(held-out)" in p and "detection fell" in p for p in compare_with_baseline(ev, digest, baseline))


def test_the_report_labels_dev_results_as_flattering_and_keeps_held_out_misses_unlisted() -> None:
    ev, digest = _current()
    markdown = render_markdown(ev, digest)
    assert "flatter them" in markdown and "Held-out results" in markdown
    held = ev.holdout["tool_poisoning"]
    assert held.missed  # there are held-out misses...
    assert not any(missed_id in markdown for missed_id in held.missed)  # ...and they are deliberately not listed
