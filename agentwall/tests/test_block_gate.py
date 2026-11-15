"""
The block gate (Phase 4 M4.6a): which checks, if any, have measured evidence good enough to ever offer block mode. Every rule is tested on both
sides of its limit and alone, so one weak spot cannot hide behind four strong ones. Block mode itself does not exist; the refusals are pinned by
tests/test_gateway_radar.py::test_an_unknown_mode_from_core_denies_the_call, services/redhand-core/tests/test_radar_findings.py::
test_block_mode_is_not_available_yet_whatever_the_request and supabase/tests/radar_findings_test.sql.
"""

from __future__ import annotations

import ast
from dataclasses import replace
import inspect
import json
from pathlib import Path

import pytest

from agentwall.src.bench import gate
from agentwall.src.bench.gate import (
    BLOCK_ELIGIBLE, CHECKS, DETECTION_LOWER_LIMIT, FALSE_ALARM_UPPER_LIMIT, MIN_HARD_BENIGN, MIN_LONG_BENIGN, eligible_checks, evaluate_check,
    evaluate_gate, gate_json, min_samples_without_false_alarms, render_gate_text,
)
from agentwall.src.bench.metrics import evaluate, wilson
from agentwall.src.bench.corpus import corpus_digest, load_corpus
from agentwall.src.bench.report import BLIND_ROUNDS, BlindRound, BlindRow, render_markdown, render_ui_json, to_ui_json
from agentwall.src.firewall import radar, radar_fingerprint
from agentwall.src.firewall.radar_fingerprint import MODEL_SUFFIX, UNKNOWN, fingerprint_of, rules_fingerprint

ROOT = Path(__file__).resolve().parents[2]
FP = "0123456789abcdef"
CAT = "output_xss"


def passing_row(**changes: int) -> BlindRow:
    base = dict(category=CAT, detected=90, malicious=100, false_alarms=0, benign=150, hard_false_alarms=0, hard_benign=MIN_HARD_BENIGN, long_benign=MIN_LONG_BENIGN)
    base.update(changes)
    return BlindRow(**base)  # type: ignore[arg-type]  # keys match the dataclass; the dict is built from its own defaults


def make_round(row: BlindRow | None = None, *, key: str = "r", independent: bool = True, scored_on: str | None = FP) -> BlindRound:
    return BlindRound(key, f"Round {key}", "Someone else", "docs/x.md", "note", (row or passing_row(),), independent=independent, scored_on=scored_on)


def judged(row: BlindRow | None = None, fingerprint: str = FP, **round_changes: object):
    return evaluate_check(CAT, [make_round(row, **round_changes)], fingerprint)  # type: ignore[arg-type]


def failed_rules(check) -> set[str]:
    return {r.id for r in check.results if not r.passed}


# --- a clean round passes, and each rule can fail alone ---------------------------------------------------------

def test_a_round_that_meets_every_rule_is_eligible() -> None:
    check = judged()
    assert check.eligible and check.missing == () and failed_rules(check) == set()


@pytest.mark.parametrize(
    ("rule", "row_changes", "round_changes"),
    [
        ("G1", {}, {"independent": False}),
        ("G2", {}, {"scored_on": "ffffffffffffffff"}),
        ("G2", {}, {"scored_on": None}),
        ("G3", {"false_alarms": 4}, {}),
        ("G3", {"hard_benign": MIN_HARD_BENIGN - 1}, {}),
        ("G4", {"detected": 40}, {}),
        ("G5", {"long_benign": MIN_LONG_BENIGN - 1}, {}),
    ],
)
def test_each_rule_fails_on_its_own_and_blocks_eligibility(rule: str, row_changes: dict[str, int], round_changes: dict[str, object]) -> None:
    check = judged(passing_row(**row_changes), **round_changes)
    assert failed_rules(check) == {rule} and not check.eligible
    assert len(check.missing) == 1


# --- limits, on both sides --------------------------------------------------------------------------------------

def test_the_smallest_harmless_sample_that_can_reach_the_limit_is_125_not_100() -> None:
    assert min_samples_without_false_alarms() == 125
    assert wilson(0, 124)[1] > FALSE_ALARM_UPPER_LIMIT >= wilson(0, 125)[1]
    assert wilson(0, 100)[1] > FALSE_ALARM_UPPER_LIMIT  # the error in the plan that was first approved: 100 samples with no false alarm is NOT enough
    assert wilson(1, 100)[1] > FALSE_ALARM_UPPER_LIMIT


@pytest.mark.parametrize(("false_alarms", "benign", "passes"), [(0, 124, False), (0, 125, True), (1, 184, False), (1, 185, True), (2, 238, False), (2, 239, True)])
def test_false_alarm_limit_boundaries(false_alarms: int, benign: int, passes: bool) -> None:
    check = judged(passing_row(false_alarms=false_alarms, benign=benign, hard_false_alarms=0))
    assert ("G3" not in failed_rules(check)) is passes


def test_detection_limit_uses_the_lower_end_of_the_range_not_the_point_estimate() -> None:
    first = next(d for d in range(101) if wilson(d, 100)[0] >= DETECTION_LOWER_LIMIT)
    assert first > 50  # 50 of 100 has a point estimate of exactly 50% and is still not enough
    assert "G4" not in failed_rules(judged(passing_row(detected=first)))
    assert "G4" in failed_rules(judged(passing_row(detected=first - 1)))
    assert "G4" in failed_rules(judged(passing_row(detected=50)))


@pytest.mark.parametrize(("hard", "passes"), [(MIN_HARD_BENIGN - 1, False), (MIN_HARD_BENIGN, True)])
def test_hard_benign_boundary(hard: int, passes: bool) -> None:
    assert ("G3" not in failed_rules(judged(passing_row(hard_benign=hard)))) is passes


@pytest.mark.parametrize(("long_count", "passes"), [(MIN_LONG_BENIGN - 1, False), (MIN_LONG_BENIGN, True)])
def test_long_sample_boundary(long_count: int, passes: bool) -> None:
    assert ("G5" not in failed_rules(judged(passing_row(long_benign=long_count)))) is passes


def test_empty_rows_never_pass() -> None:
    check = judged(passing_row(malicious=0, detected=0, benign=0, false_alarms=0))
    assert {"G3", "G4"} <= failed_rules(check)


# --- the rules fingerprint (G2) ---------------------------------------------------------------------------------

def test_a_changed_fingerprint_makes_old_evidence_stale() -> None:
    assert judged(fingerprint=FP).eligible
    stale = judged(fingerprint="ffffffffffffffff")
    assert failed_rules(stale) == {"G2"} and "rules changed" in stale.missing[0]


@pytest.mark.parametrize("current", [FP + MODEL_SUFFIX, UNKNOWN])
def test_helper_model_on_or_unknown_rules_never_count(current: str) -> None:
    assert "G2" in failed_rules(judged(fingerprint=current))
    assert "G2" in failed_rules(judged(passing_row(), fingerprint=current, scored_on=current))  # even if someone recorded the same odd value


def test_the_fingerprint_changes_on_any_edit_and_ignores_line_endings() -> None:
    source = b"RULES = 1\n# a comment\n"
    assert fingerprint_of(source) == fingerprint_of(source.replace(b"\n", b"\r\n"))
    assert fingerprint_of(source) != fingerprint_of(source + b"# edited\n")  # blunt on purpose: even a comment makes evidence stale
    assert len(fingerprint_of(source)) == 16


def test_the_fingerprint_reads_the_real_rules_file_and_is_unknown_when_it_cannot(monkeypatch: pytest.MonkeyPatch) -> None:
    assert rules_fingerprint() == fingerprint_of(Path(radar.__file__).read_bytes())
    assert rules_fingerprint(model_enabled=True) == rules_fingerprint() + MODEL_SUFFIX
    monkeypatch.setattr(radar_fingerprint.radar, "__file__", str(ROOT / "does-not-exist.py"))
    assert rules_fingerprint() == UNKNOWN
    monkeypatch.setattr(radar_fingerprint.radar, "__file__", None)
    assert rules_fingerprint() == UNKNOWN


# --- which round counts -----------------------------------------------------------------------------------------

def test_the_newest_round_for_a_check_is_the_one_judged() -> None:
    old = make_round(passing_row(), key="old")
    new = make_round(passing_row(false_alarms=9), key="new")
    assert evaluate_check(CAT, [old, new], FP).evidence_round == "new" and not evaluate_check(CAT, [old, new], FP).eligible
    assert evaluate_check(CAT, [new, old], FP).evidence_round == "old" and evaluate_check(CAT, [new, old], FP).eligible


def test_a_check_no_round_measured_fails_every_rule_with_a_reason() -> None:
    check = evaluate_check("output_ssrf", [make_round()], FP)
    assert failed_rules(check) == {"G1", "G2", "G3", "G4", "G5"} and check.evidence_round is None
    assert all("No frozen blind round" in text for text in check.missing)


def test_evidence_never_comes_from_our_own_held_out_or_development_samples() -> None:
    imported = {n.module for n in ast.walk(ast.parse(inspect.getsource(gate))) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"__future__", "dataclasses", "typing", "metrics", "report"}  # no corpus, no detectors, no evaluation
    ev = evaluate(load_corpus())
    assert ev.holdout  # there IS a held-out result with clean-looking numbers...
    assert to_ui_json(ev, corpus_digest())["block_gate"] == gate_json(BLIND_ROUNDS, rules_fingerprint())  # ...and it has no say


# --- what is true today -----------------------------------------------------------------------------------------

def test_no_check_is_eligible_today_and_the_constant_says_so() -> None:
    assert BLOCK_ELIGIBLE == frozenset()
    assert eligible_checks(BLIND_ROUNDS, rules_fingerprint()) == BLOCK_ELIGIBLE  # a check passing makes this fail until a person edits the constant


def test_the_recorded_rounds_are_the_ones_the_plan_measured() -> None:
    by_key = {r.key: r for r in BLIND_ROUNDS}
    assert by_key["round1"].independent is False and by_key["round1"].scored_on is None  # its samples became development data
    assert by_key["round2"].independent and by_key["round3"].independent
    assert by_key["round2"].scored_on == by_key["round3"].scored_on
    gates = {g.category: g for g in evaluate_gate(BLIND_ROUNDS, rules_fingerprint())}
    assert set(gates) == set(CHECKS)
    assert gates["injection_indirect"].evidence_round == "round3" and gates["output_xss"].evidence_round == "round2"
    for g in gates.values():
        assert not g.eligible and "G3" in failed_rules(g) and "G5" in failed_rules(g)
    # M4.7b edited the rules file, so the fingerprint the rounds were scored on no longer matches it: G2 fails for every check until a new round
    # is scored on the new rules (blind round 4). Before M4.7b this line asserted the opposite.
    for g in gates.values():
        assert "G2" in failed_rules(g)


def test_script_checks_fail_on_a_hair_and_say_how_many_samples_are_missing() -> None:
    xss = next(g for g in evaluate_gate(BLIND_ROUNDS, rules_fingerprint()) if g.category == "output_xss")
    assert (xss.false_alarms, xss.benign) == (0, 120) and wilson(0, 120)[1] > FALSE_ALARM_UPPER_LIMIT
    assert any("at least 125" in line for line in xss.missing)  # the "rules changed" line (G2) now comes first, so look through them all


# --- what the page and the matrix are given ---------------------------------------------------------------------

def test_the_gate_json_says_block_is_not_available_and_carries_no_sample_text() -> None:
    data = gate_json(BLIND_ROUNDS, rules_fingerprint())
    assert data["block_available"] is False and data["eligible"] == [] and data["min_harmless_without_false_alarms"] == 125
    assert [c["category"] for c in data["checks"]] == list(CHECKS) and [r["id"] for r in data["rules"]] == ["G1", "G2", "G3", "G4", "G5"]
    blob = json.dumps(data)
    assert all(s.text not in blob for s in load_corpus() if s.text and len(s.text) > 40)


def test_the_text_and_markdown_reports_state_the_verdict_per_check() -> None:
    text = render_gate_text(BLIND_ROUNDS, rules_fingerprint())
    assert text.count("not eligible") == 4 and "ELIGIBLE\n" not in text and "does not exist" in text
    ev = evaluate(load_corpus())
    markdown = render_markdown(ev, corpus_digest())
    assert "## Ready to block? (the block gate)" in markdown and rules_fingerprint() in markdown
    assert json.loads(render_ui_json(ev, corpus_digest()))["block_gate"]["eligible"] == []


def test_a_gate_that_passes_would_say_so_everywhere() -> None:
    rounds = [make_round(passing_row(category=c), key="ok") for c in CHECKS]
    assert eligible_checks(rounds, FP) == frozenset(CHECKS)
    assert "ELIGIBLE\n" in render_gate_text(rounds, FP) and gate_json(rounds, FP)["eligible"] == sorted(CHECKS)
    assert eligible_checks([replace(rounds[0], independent=False)], FP) == frozenset()


def test_the_limits_are_the_ones_the_plan_fixed_and_cannot_drift_without_a_failing_test() -> None:
    """Written as plain numbers on purpose: loosening a limit must break this test and so needs a plan change (docs/plans/phase4-m4-6-block-gate.md)."""
    assert (FALSE_ALARM_UPPER_LIMIT, DETECTION_LOWER_LIMIT) == (0.03, 0.50)
    assert (MIN_HARD_BENIGN, MIN_LONG_BENIGN, gate.LONG_SAMPLE_CHARS) == (40, 40, 2048)
