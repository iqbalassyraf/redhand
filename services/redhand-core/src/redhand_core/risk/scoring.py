"""
The Risk Engine's score (Phase 4.5 B1, ADR 0019): a deterministic, explainable number per agent, built only from signals RedHand
already records. Pure: counts in, a score, a level and the contribution of each signal out. No I/O, no clock, no model.

The weights are judgement, not measurement (plan section 9), so they live here as constants with a version that the dashboard shows.
They are deliberately low for open Radar findings, whose false-alarm rate on documentation is still high (M4.7b: 15.8% of unseen
documents had a strong finding), and high for honeytoken trips, which have almost no false alarms.

Two scores are computed from the same weights:
- the **shown** score counts every signal of the last 7 days;
- the **action** score counts only signals after the agent's last human release (an unfreeze or Safe Mode turned off), so an agent a
  person has just released cannot be frozen again by the signals that person already looked at. Automatic actions use only this one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

RISK_MODEL: Final = "2026-11-14"
MAX_SCORE: Final = 100
OLDER_FACTOR: Final = 0.5  # a signal from day 2 to day 7 counts half; the last 24 hours count in full


class Signal(str, Enum):
    """The signals the score reads. The values are the keys the SQL function returns and the API shows."""

    TRIP = "trip"  # a honeytoken, canary or honey-tool trip
    CONFIRMED_FINDING = "confirmed_finding"  # a Radar, loop or destination finding a person marked as real
    DESTINATION_OPEN = "destination_open"  # an address outside the agent's allowed list, not reviewed yet
    RADAR_OPEN = "radar_open"  # a hidden-instruction or risky-output finding, medium or high confidence, not reviewed yet
    LOOP_OPEN = "loop_open"  # repeated identical calls, not reviewed yet
    REFUSAL = "refusal"  # the gateway refused a call outside the passport (scope, unapproved tool)
    BUDGET_LIMIT = "budget_limit"  # the daily call limit was reached today


@dataclass(frozen=True, slots=True)
class Weight:
    points: int
    cap: int


WEIGHTS: Final[dict[Signal, Weight]] = {
    Signal.TRIP: Weight(points=40, cap=80),
    Signal.CONFIRMED_FINDING: Weight(points=25, cap=50),
    Signal.DESTINATION_OPEN: Weight(points=10, cap=30),
    Signal.RADAR_OPEN: Weight(points=4, cap=16),
    Signal.LOOP_OPEN: Weight(points=3, cap=9),
    Signal.REFUSAL: Weight(points=2, cap=20),
    Signal.BUDGET_LIMIT: Weight(points=10, cap=10),
}

# Plain words for each signal: shown on the dashboard and used in alerts and audit reasons. Never taken from the data.
LABELS: Final[dict[Signal, str]] = {
    Signal.TRIP: "honeytoken or canary trip",
    Signal.CONFIRMED_FINDING: "finding marked real",
    Signal.DESTINATION_OPEN: "address outside the allowed list",
    Signal.RADAR_OPEN: "Radar finding (not reviewed)",
    Signal.LOOP_OPEN: "repeated identical calls",
    Signal.REFUSAL: "call refused (outside the passport)",
    Signal.BUDGET_LIMIT: "daily call limit reached",
}


class Level(str, Enum):
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


LEVEL_FLOORS: Final[tuple[tuple[int, Level], ...]] = ((80, Level.CRITICAL), (50, Level.HIGH), (20, Level.ELEVATED), (0, Level.LOW))


@dataclass(frozen=True, slots=True)
class Counts:
    """How often one signal happened: in the last 24 hours, and from day 2 to day 7. Never negative."""

    recent: int = 0
    older: int = 0

    def __post_init__(self) -> None:
        if self.recent < 0 or self.older < 0:
            raise ValueError("signal counts cannot be negative")


@dataclass(frozen=True, slots=True)
class Contribution:
    signal: Signal
    label: str
    recent: int
    older: int
    points: int
    capped: bool


@dataclass(frozen=True, slots=True)
class Assessment:
    score: int
    level: Level
    contributions: tuple[Contribution, ...]  # only signals that added points, largest first
    model: str = RISK_MODEL

    def reason(self, limit: int = 3) -> str:
        """A short, fixed-wording reason for alerts and audit rows: "honeytoken or canary trip (2), finding marked real (1)"."""
        parts = [f"{c.label} ({c.recent + c.older})" for c in self.contributions[:limit]]
        return ", ".join(parts) if parts else "no signals"


def level_for(score: int) -> Level:
    for floor, level in LEVEL_FLOORS:
        if score >= floor:
            return level
    return Level.LOW


def _round(value: float) -> int:
    # Round half up, not to even: 1.5 points is 2, so a half-weighted signal is never silently dropped.
    return int(value + 0.5)


def assess(counts: dict[Signal, Counts]) -> Assessment:
    """The score for one agent. Signals missing from `counts` count zero; a signal that is not in WEIGHTS cannot be passed."""
    contributions: list[Contribution] = []
    total = 0
    for signal, weight in WEIGHTS.items():
        c = counts.get(signal, Counts())
        raw = c.recent * weight.points + c.older * weight.points * OLDER_FACTOR
        points = min(weight.cap, _round(raw))
        if points > 0:
            # capped: this signal already adds the most it can, so more of it would not raise the score
            contributions.append(Contribution(signal, LABELS[signal], c.recent, c.older, points, capped=points >= weight.cap))
            total += points
    score = min(MAX_SCORE, total)
    contributions.sort(key=lambda item: (-item.points, item.signal.value))
    return Assessment(score=score, level=level_for(score), contributions=tuple(contributions))


@dataclass(frozen=True, slots=True)
class Ladder:
    """An organization's response ladder. None means the rung is off. When set: 1 to 100, alert <= Safe Mode <= freeze."""

    alert_at: int | None = 50
    safe_mode_at: int | None = None
    freeze_at: int | None = None

    def __post_init__(self) -> None:
        set_values = [v for v in (self.alert_at, self.safe_mode_at, self.freeze_at) if v is not None]
        if any(not 1 <= v <= MAX_SCORE for v in set_values):
            raise ValueError("a threshold must be between 1 and 100")
        if set_values != sorted(set_values):
            raise ValueError("thresholds must rise: alert, then Safe Mode, then freeze")


class Action(str, Enum):
    ALERT = "alert"
    SAFE_MODE = "safe_mode"
    FREEZE = "freeze"


def actions_for(action_score: int, ladder: Ladder) -> tuple[Action, ...]:
    """The rungs an action score reaches, lowest first. Off rungs never fire. Pure: whether an action is still needed (already
    frozen, alert cooldown) is decided by the caller from the agent's state."""
    reached: list[Action] = []
    for action, threshold in ((Action.ALERT, ladder.alert_at), (Action.SAFE_MODE, ladder.safe_mode_at), (Action.FREEZE, ladder.freeze_at)):
        if threshold is not None and action_score >= threshold:
            reached.append(action)
    return tuple(reached)
