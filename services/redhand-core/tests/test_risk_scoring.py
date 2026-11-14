"""
The Risk Engine's score (Phase 4.5 B1, ADR 0019): the weights, caps and half-weight for older signals, the levels, the fixed-wording
reason, the ladder's validation and which rungs a score reaches. Pure functions, so these tests need no database.
"""

from __future__ import annotations

import random

import pytest

from redhand_core.risk.scoring import (
    MAX_SCORE,
    RISK_MODEL,
    WEIGHTS,
    Action,
    Counts,
    Ladder,
    Level,
    Signal,
    actions_for,
    assess,
    level_for,
)


def test_no_signals_is_a_zero_score_with_no_reasons() -> None:
    result = assess({})
    assert (result.score, result.level, result.contributions) == (0, Level.LOW, ())
    assert result.reason() == "no signals" and result.model == RISK_MODEL


@pytest.mark.parametrize(
    ("counts", "score", "level"),
    [
        ({Signal.TRIP: Counts(recent=1)}, 40, Level.ELEVATED),
        ({Signal.TRIP: Counts(recent=2)}, 80, Level.CRITICAL),
        ({Signal.TRIP: Counts(recent=5)}, 80, Level.CRITICAL),  # capped at 80
        ({Signal.TRIP: Counts(older=1)}, 20, Level.ELEVATED),  # older counts half
        ({Signal.CONFIRMED_FINDING: Counts(recent=2)}, 50, Level.HIGH),
        ({Signal.RADAR_OPEN: Counts(recent=10)}, 16, Level.LOW),  # open Radar findings alone never reach "elevated"
        ({Signal.LOOP_OPEN: Counts(older=1)}, 2, Level.LOW),  # 1.5 rounds half up to 2, not to even
        ({Signal.LOOP_OPEN: Counts(older=3)}, 5, Level.LOW),  # 4.5 rounds half up to 5 (round-half-even would give 4)
        ({Signal.REFUSAL: Counts(recent=3, older=4)}, 10, Level.LOW),
        ({Signal.BUDGET_LIMIT: Counts(recent=1)}, 10, Level.LOW),
        ({Signal.TRIP: Counts(recent=2), Signal.CONFIRMED_FINDING: Counts(recent=2)}, 100, Level.CRITICAL),  # total capped at 100
        ({Signal.DESTINATION_OPEN: Counts(recent=2), Signal.RADAR_OPEN: Counts(recent=1)}, 24, Level.ELEVATED),
    ],
)
def test_the_score_follows_the_published_weights(counts: dict[Signal, Counts], score: int, level: Level) -> None:
    result = assess(counts)
    assert (result.score, result.level) == (score, level)


def test_the_contributions_explain_the_score_largest_first() -> None:
    result = assess({Signal.RADAR_OPEN: Counts(recent=1), Signal.TRIP: Counts(recent=3), Signal.REFUSAL: Counts(older=2)})
    assert [c.signal for c in result.contributions] == [Signal.TRIP, Signal.RADAR_OPEN, Signal.REFUSAL]
    trip = result.contributions[0]
    assert (trip.points, trip.capped, trip.recent, trip.older) == (80, True, 3, 0)
    assert sum(c.points for c in result.contributions) == result.score
    assert result.reason() == "honeytoken or canary trip (3), Radar finding (not reviewed) (1), call refused (outside the passport) (2)"
    assert result.reason(limit=1) == "honeytoken or canary trip (3)"


def test_capped_means_the_signal_already_adds_its_maximum() -> None:
    assert assess({Signal.TRIP: Counts(recent=2)}).contributions[0].capped is True  # exactly 80: one more trip adds nothing
    assert assess({Signal.TRIP: Counts(recent=1)}).contributions[0].capped is False


def test_a_signal_that_adds_nothing_is_not_listed() -> None:
    assert assess({Signal.TRIP: Counts(), Signal.LOOP_OPEN: Counts(recent=1)}).contributions[0].signal is Signal.LOOP_OPEN
    assert len(assess({Signal.TRIP: Counts()}).contributions) == 0


def test_negative_counts_are_refused() -> None:
    with pytest.raises(ValueError):
        Counts(recent=-1)


@pytest.mark.parametrize(("score", "level"), [(0, Level.LOW), (19, Level.LOW), (20, Level.ELEVATED), (49, Level.ELEVATED),
                                              (50, Level.HIGH), (79, Level.HIGH), (80, Level.CRITICAL), (100, Level.CRITICAL)])
def test_level_boundaries(score: int, level: Level) -> None:
    assert level_for(score) is level


def test_every_signal_has_a_weight_and_a_label() -> None:
    assert set(WEIGHTS) == set(Signal)
    assert all(w.points > 0 and w.cap >= w.points for w in WEIGHTS.values())


def test_the_score_never_falls_when_a_signal_grows_and_stays_in_range() -> None:
    """Property, seeded: adding one more occurrence of any signal never lowers the score, and the score stays within 0..100."""
    rng = random.Random(20261114)
    signals = list(Signal)
    for _ in range(2000):
        counts = {s: Counts(rng.randint(0, 6), rng.randint(0, 6)) for s in signals if rng.random() < 0.6}
        before = assess(counts).score
        assert 0 <= before <= MAX_SCORE
        grown = rng.choice(signals)
        old = counts.get(grown, Counts())
        bumped = {**counts, grown: Counts(old.recent + 1, old.older) if rng.random() < 0.5 else Counts(old.recent, old.older + 1)}
        assert assess(bumped).score >= before


# --- the ladder -----------------------------------------------------------------------------------------------------------

def test_the_default_ladder_only_alerts() -> None:
    ladder = Ladder()
    assert (ladder.alert_at, ladder.safe_mode_at, ladder.freeze_at) == (50, None, None)
    assert actions_for(100, ladder) == (Action.ALERT,)
    assert actions_for(49, ladder) == ()


def test_each_rung_fires_at_its_threshold_lowest_first() -> None:
    ladder = Ladder(alert_at=50, safe_mode_at=70, freeze_at=90)
    assert actions_for(69, ladder) == (Action.ALERT,)
    assert actions_for(70, ladder) == (Action.ALERT, Action.SAFE_MODE)
    assert actions_for(90, ladder) == (Action.ALERT, Action.SAFE_MODE, Action.FREEZE)


def test_an_off_rung_never_fires_even_when_higher_ones_do() -> None:
    assert actions_for(95, Ladder(alert_at=None, safe_mode_at=None, freeze_at=90)) == (Action.FREEZE,)
    assert actions_for(100, Ladder(alert_at=None)) == ()


@pytest.mark.parametrize(
    "values",
    [(0, None, None), (101, None, None), (50, 40, None), (None, 80, 70), (60, None, 50)],
)
def test_a_ladder_out_of_range_or_out_of_order_is_refused(values: tuple[int | None, int | None, int | None]) -> None:
    with pytest.raises(ValueError):
        Ladder(*values)


def test_equal_thresholds_are_allowed() -> None:
    assert actions_for(80, Ladder(alert_at=80, safe_mode_at=80, freeze_at=80)) == (Action.ALERT, Action.SAFE_MODE, Action.FREEZE)


def test_contributions_are_ordered_by_points_not_by_the_table() -> None:
    # In the weights table "Radar finding" comes before "call refused"; here the refusals add more points, so they come first.
    result = assess({Signal.RADAR_OPEN: Counts(recent=1), Signal.REFUSAL: Counts(recent=5)})
    assert [c.signal for c in result.contributions] == [Signal.REFUSAL, Signal.RADAR_OPEN]
