"""
Is this organization's own traffic good evidence for block mode? (Phase 4 M4.6b, docs/plans/phase4-m4-6-block-gate.md, ADR 0016.)

Pure judgement over the inputs the database hands over, so every rule is testable on both sides of its limit. It is DISPLAY ONLY: block
mode does not exist (SQL, core and the gateway all refuse it), and a check that is "ready" is a candidate for a human decision, nothing more.
Missing or odd data reads as "not ready" (fail closed).

All of these must hold for a check, over the last 7 UTC days (today included):
  R1 it stayed on Watch the whole window;                       R5 the counts are complete (little loss, no daily-cap pressure, no gap
  R2 at least 200 results were scanned;                            between what was counted and what was stored);
  R3 every strong finding was reviewed;                         R6 the same rules ran the whole window (not unknown, helper model off);
  R4 no silence was live at any time in the window;             R7 false alarms, counted the hard way, have a 95% upper bound of at most 3%.
"Counted the hard way": if even one strong finding of a rule was marked a false alarm, EVERY result that rule flagged strongly in the window counts as a
false alarm. A real attack caught by the same rule is counted against it too, which makes the figure pessimistic on purpose.
"""

from __future__ import annotations

import math

from redhand_core.radar.models import KindInputs, RadarKind, ReadinessCheck, ReadinessCondition, ReadinessInputs, ReadinessResponse

WINDOW_DAYS = 7
MIN_SCANNED = 200
MAX_FALSE_ALARM_UPPER = 0.03
MAX_LOSS_RATE = 0.01
MAX_FINDINGS_PER_AGENT_DAY = 1000  # the database caps new findings at 2,000 per agent per 24 hours; half of that is already a sign something is badly wrong
Z = 1.96

LABELS = {
    "injection": "Hidden instructions in tool answers",
    "output": "Risky output (script, odd links, internal addresses, file paths)",
}
NOTE = (
    "This only says whether your own traffic has produced enough clean evidence to consider blocking. Blocking is not available and cannot be switched on. "
    "The Coverage page shows the separate test our rules must pass on independent samples first."
)


def wilson_upper(successes: int, total: int) -> float:
    """Upper end of the 95% Wilson interval (the same formula as agentwall/src/bench/metrics.py; a test compares them)."""
    if total == 0:
        return 1.0
    p = successes / total
    denom = 1 + Z * Z / total
    centre = (p + Z * Z / (2 * total)) / denom
    margin = Z * math.sqrt(p * (1 - p) / total + Z * Z / (4 * total * total)) / denom
    return min(1.0, centre + margin)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def false_alarms_worst_case(inputs: KindInputs) -> int:
    """
    Results counted as false alarms: every strong flag of each rule that had a strong finding marked a false alarm.

    A result is one false alarm however many rules flagged it, but each rule's own count includes every result it flagged, so a document hit by
    two reviewed rules is in both counts and the sum overstates. The figure is therefore capped at the results with a strong finding: it cannot
    be higher than the number of results that were flagged strongly at all. (The M4.6 staging run summed to 81 where at most 36 results qualified.)
    """
    total = 0
    for rule in set(inputs.false_alarm_rules):
        counts = inputs.rules.get(rule)
        total += counts.strong if counts is not None else inputs.strong  # no per-rule count: assume the worst, all of this check's strong flags
    return min(total, inputs.strong, inputs.scanned)


def _condition(cid: str, name: str, passed: bool, detail: str) -> ReadinessCondition:
    return ReadinessCondition(id=cid, name=name, passed=passed, detail=detail)


def _counts_complete(inputs: KindInputs) -> tuple[bool, str]:
    attempts = inputs.scanned + inputs.dropped + inputs.errors
    loss = (inputs.dropped + inputs.errors) / attempts if attempts else 0.0
    if loss >= MAX_LOSS_RATE:
        return False, f"{inputs.dropped + inputs.errors} of {attempts} results were not scanned ({_pct(loss)}; at most {_pct(MAX_LOSS_RATE)} allowed)."
    if inputs.max_findings_per_agent_day >= MAX_FINDINGS_PER_AGENT_DAY:
        return False, "One agent produced a very large number of findings in a day, so some may have been dropped by the daily limit."
    gaps = sorted(
        rule for rule, stored in inputs.stored_occurrences.items()
        if stored > (inputs.rules[rule].flagged if rule in inputs.rules else 0)
    )
    if gaps:
        return False, f"More findings are stored than the gateway counted for {', '.join(gaps[:3])}: some counts were lost on the way."
    return True, "Almost every result was scanned and the counts agree with the stored findings."


def judge_kind(kind: RadarKind, inputs: KindInputs, mode_unchanged_in_window: bool) -> ReadinessCheck:
    fa = false_alarms_worst_case(inputs)
    upper = wilson_upper(fa, inputs.scanned) if inputs.scanned else None
    fingerprints = inputs.fingerprints
    same_rules = len(fingerprints) == 1 and fingerprints[0] != "unknown" and not fingerprints[0].endswith("+model")
    complete, complete_detail = _counts_complete(inputs)

    if inputs.mode != "observe":
        watch_detail = f"This check is {inputs.mode}. It must be on Watch for the whole window."
    elif not mode_unchanged_in_window:
        watch_detail = "This check was changed during the window. It needs 7 days on Watch without a change."
    else:
        watch_detail = "On Watch for the whole window."
    if not fingerprints:
        rules_detail = "No counts from the gateway yet, so the rules version is not known."
    elif len(fingerprints) > 1:
        rules_detail = "The Radar rules changed during the window. Evidence starts again on the new rules."
    elif fingerprints[0] == "unknown":
        rules_detail = "The gateway could not tell which rules it runs, so the evidence does not count."
    elif fingerprints[0].endswith("+model"):
        rules_detail = "The helper model was on. It was trained on earlier test rounds, so its results do not count."
    else:
        rules_detail = "The same rules ran the whole window."

    conditions = [
        _condition("R1", "Watching the whole time", inputs.mode == "observe" and mode_unchanged_in_window, watch_detail),
        _condition("R2", "Enough traffic", inputs.scanned >= MIN_SCANNED, f"{inputs.scanned} results scanned (need at least {MIN_SCANNED})."),
        _condition("R3", "Every strong finding reviewed", inputs.strong_open == 0,
                   "Every strong finding was marked real or a false alarm." if inputs.strong_open == 0
                   else f"{inputs.strong_open} strong finding(s) are still not reviewed."),
        _condition("R4", "No silence", inputs.silences_in_window == 0,
                   "No rule was silenced during the window." if inputs.silences_in_window == 0
                   else "A rule was silenced during the window. A silence hides findings, so the evidence does not count."),
        _condition("R5", "Counts are complete", complete, complete_detail),
        _condition("R6", "Same rules the whole time", same_rules, rules_detail),
        _condition(
            "R7", "False alarms low enough", upper is not None and upper <= MAX_FALSE_ALARM_UPPER,
            "Nothing was scanned, so there is nothing to measure." if upper is None else
            f"{fa} false alarms counted the hard way in {inputs.scanned} results; 95% upper bound {_pct(upper)} (limit {_pct(MAX_FALSE_ALARM_UPPER)}).",
        ),
    ]
    return ReadinessCheck(
        kind=kind, label=LABELS[kind], ready=all(c.passed for c in conditions), scanned=inputs.scanned, strong=inputs.strong,
        strong_rate=(inputs.strong / inputs.scanned) if inputs.scanned else None, false_alarms_worst_case=fa,
        false_alarm_upper=upper, conditions=conditions,
    )


KINDS: tuple[RadarKind, ...] = ("injection", "output")


def judge(inputs: ReadinessInputs) -> ReadinessResponse:
    """Raises KeyError when a check is missing from the inputs: the caller turns that into an error, never into a verdict."""
    checks = [judge_kind(kind, inputs.kinds[kind], inputs.kinds[kind].mode_changed_at <= inputs.window_start) for kind in KINDS]
    return ReadinessResponse(window_start=inputs.window_start, window_days=WINDOW_DAYS, checks=checks, note=NOTE)
