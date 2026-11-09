"""
The block gate (Phase 4 M4.6, docs/adr/0016-block-gate.md, docs/plans/phase4-m4-6-block-gate.md).

Decides, per check, whether the measured evidence would be enough to ever offer block mode. It reads only the frozen blind rounds and the
fingerprint of the current rules, so the answer cannot be changed by editing a label or a held-out file we wrote ourselves. It grants
nothing: block mode still does not exist (refused by SQL, core and the gateway context); this is the written-down, tested reason why.

A check is eligible only if ALL of these hold:
  G1  the evidence is a frozen blind round written by someone other than the rule author, scored once;
  G2  that round was scored on exactly the rules that run now (same fingerprint, helper model off);
  G3  false alarms: the 95% upper bound is at most 3% and at least 40 of the harmless samples were built to look like attacks;
  G4  detection: the 95% LOWER bound is at least 50%;
  G5  at least 40 harmless samples are long (2 KiB or more), because real tool answers are pages and documents, not one-liners.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from .metrics import wilson

if TYPE_CHECKING:
    from .report import BlindRound

FALSE_ALARM_UPPER_LIMIT = 0.03
DETECTION_LOWER_LIMIT = 0.50
MIN_HARD_BENIGN = 40
MIN_LONG_BENIGN = 40
LONG_SAMPLE_CHARS = 2048

# Checks that have earned block eligibility. Empty today. A test compares this with the computed result, so a check becoming eligible
# fails the build until a person edits this line on purpose (with the evidence in the commit).
BLOCK_ELIGIBLE: frozenset[str] = frozenset()

CHECKS: dict[str, str] = {
    "injection_indirect": "Hidden instructions in tool answers",
    "output_xss": "Script and active markup",
    "output_ssrf": "Internal and cloud-metadata addresses",
    "output_path": "Sensitive file paths",
}

RULES: tuple[tuple[str, str, str], ...] = (
    ("G1", "Independent evidence", "A frozen test round written by someone other than the rule author, scored once."),
    ("G2", "Measured on these rules", "That round was scored on exactly the rules that run now (same fingerprint, helper model off)."),
    ("G3", "False alarms low enough",
     f"The 95% upper bound of false alarms is at most {FALSE_ALARM_UPPER_LIMIT:.0%}, with at least {MIN_HARD_BENIGN} harmless samples built to look like attacks."),
    ("G4", "Catches enough", f"The 95% lower bound of attacks found is at least {DETECTION_LOWER_LIMIT:.0%}."),
    ("G5", "Tested on long, realistic text",
     f"At least {MIN_LONG_BENIGN} harmless samples are {LONG_SAMPLE_CHARS // 1024} KiB or longer (pages, emails, documents)."),
)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def min_samples_without_false_alarms(limit: float = FALSE_ALARM_UPPER_LIMIT) -> int:
    """The fewest harmless samples that can reach the false alarm limit even if none is flagged (125 at 3%)."""
    n = 1
    while wilson(0, n)[1] > limit:
        n += 1
    return n


@dataclass(frozen=True, slots=True)
class RuleResult:
    id: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class CheckGate:
    category: str
    label: str
    evidence_round: str | None
    evidence_title: str | None
    detected: int
    malicious: int
    detection_low: float
    false_alarms: int
    benign: int
    false_alarm_high: float
    hard_benign: int
    long_benign: int
    results: tuple[RuleResult, ...]

    @property
    def eligible(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def missing(self) -> tuple[str, ...]:
        return tuple(r.detail for r in self.results if not r.passed)


def _latest_round(rounds: Sequence[BlindRound], category: str) -> tuple[BlindRound, Any] | None:
    for rnd in reversed(rounds):
        for row in rnd.rows:
            if row.category == category:
                return rnd, row
    return None


def evaluate_check(category: str, rounds: Sequence[BlindRound], current_fingerprint: str) -> CheckGate:
    """Judges one check on its most recent frozen round. A missing round fails every rule with a plain reason."""
    label = CHECKS.get(category, category)
    found = _latest_round(rounds, category)
    if found is None:
        reason = "No frozen blind round measured this check."
        return CheckGate(category, label, None, None, 0, 0, 0.0, 0, 0, 1.0, 0, 0, tuple(RuleResult(r[0], False, reason) for r in RULES))
    rnd, row = found
    det_low = wilson(row.detected, row.malicious)[0] if row.malicious else 0.0
    fa_high = wilson(row.false_alarms, row.benign)[1] if row.benign else 1.0
    needed = min_samples_without_false_alarms()

    g1 = rnd.independent
    g2 = rnd.scored_on is not None and rnd.scored_on == current_fingerprint and not current_fingerprint.endswith("+model") \
        and current_fingerprint != "unknown"
    g3 = bool(row.benign) and fa_high <= FALSE_ALARM_UPPER_LIMIT and row.hard_benign >= MIN_HARD_BENIGN
    g4 = bool(row.malicious) and det_low >= DETECTION_LOWER_LIMIT
    g5 = row.long_benign >= MIN_LONG_BENIGN

    if g1:
        g1_text = f"Evidence: {rnd.title}."
    else:
        g1_text = f"The newest round for this check ({rnd.key}) does not count as independent evidence: its samples were used to improve the rules."
    if g2:
        g2_text = "The round was scored on the rules that run now."
    elif current_fingerprint == "unknown" or rnd.scored_on is None:
        g2_text = "Cannot tell which rules the round was scored on, so it does not count."
    elif current_fingerprint.endswith("+model"):
        g2_text = "The helper model is on, and it was trained on earlier test rounds, so the measurement of the rules alone does not cover it."
    else:
        g2_text = "The rules changed after this round was scored. It needs a new round."
    g3_text = (
        f"False alarms: {row.false_alarms} of {row.benign} harmless samples, 95% upper bound {_pct(fa_high)} (limit {_pct(FALSE_ALARM_UPPER_LIMIT)}); "
        f"{row.hard_benign} built to look like attacks (need {MIN_HARD_BENIGN}). Even with no false alarm, at least {needed} harmless samples are needed."
    )
    g4_text = (
        f"Attacks found: {row.detected} of {row.malicious}, 95% lower bound {_pct(det_low)} (need at least {_pct(DETECTION_LOWER_LIMIT)})."
    )
    g5_text = (
        f"Long harmless samples (2 KiB or more): {row.long_benign} (need {MIN_LONG_BENIGN}). "
        "Real tool answers are pages and documents; the samples we have are short."
    )
    results = (
        RuleResult("G1", g1, g1_text), RuleResult("G2", g2, g2_text), RuleResult("G3", g3, g3_text),
        RuleResult("G4", g4, g4_text), RuleResult("G5", g5, g5_text),
    )
    return CheckGate(
        category, label, rnd.key, rnd.title, row.detected, row.malicious, det_low, row.false_alarms, row.benign, fa_high,
        row.hard_benign, row.long_benign, results,
    )


def evaluate_gate(rounds: Sequence[BlindRound], current_fingerprint: str) -> tuple[CheckGate, ...]:
    return tuple(evaluate_check(category, rounds, current_fingerprint) for category in CHECKS)


def eligible_checks(rounds: Sequence[BlindRound], current_fingerprint: str) -> frozenset[str]:
    return frozenset(g.category for g in evaluate_gate(rounds, current_fingerprint) if g.eligible)


def gate_json(rounds: Sequence[BlindRound], current_fingerprint: str) -> dict[str, Any]:
    """Counts, limits and plain sentences only. This is what the Coverage page reads."""
    return {
        "rules_fingerprint": current_fingerprint,
        "block_available": False,
        "eligible": sorted(eligible_checks(rounds, current_fingerprint)),
        "rules": [{"id": rid, "name": name, "description": description} for rid, name, description in RULES],
        "min_harmless_without_false_alarms": min_samples_without_false_alarms(),
        "checks": [
            {
                "category": g.category, "label": g.label, "eligible": g.eligible,
                "evidence_round": g.evidence_round, "evidence_title": g.evidence_title,
                "numbers": {
                    "detected": g.detected, "malicious": g.malicious, "detection_low": _pct(g.detection_low),
                    "false_alarms": g.false_alarms, "benign": g.benign, "false_alarm_high": _pct(g.false_alarm_high),
                    "hard_benign": g.hard_benign, "long_benign": g.long_benign,
                },
                "results": [{"id": r.id, "passed": r.passed, "detail": r.detail} for r in g.results],
            }
            for g in evaluate_gate(rounds, current_fingerprint)
        ],
    }


def render_gate_text(rounds: Sequence[BlindRound], current_fingerprint: str) -> str:
    lines = [f"Block gate (rules fingerprint {current_fingerprint}). Block mode does not exist; this says whether the evidence would allow it.", ""]
    for g in evaluate_gate(rounds, current_fingerprint):
        lines.append(f"{g.label}: {'ELIGIBLE' if g.eligible else 'not eligible'}")
        for r in g.results:
            lines.append(f"  {r.id} {'pass' if r.passed else 'FAIL'}  {r.detail}")
    return "\n".join(lines) + "\n"
