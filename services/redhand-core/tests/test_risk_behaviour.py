"""
Behaviour baseline rules (Phase 4.5 B2, ADR 0020): warm-up, spike, new tool, and the back-test, including that the back-test never sees the
future. Pure functions with an explicit "now", so no clock and no database.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random

import pytest

from redhand_core.risk.behaviour import (
    BACKTEST_HOURS,
    MAX_NEW_TOOLS,
    SPIKE_FLOOR,
    HourCount,
    assess_behaviour,
    hour_index,
    read_since,
)

NOW = datetime(2026, 11, 20, 12, 30, tzinfo=timezone.utc)  # half past the hour: the current hour started at 12:00


def at(hours_ago: int) -> datetime:
    return NOW.replace(minute=0) - timedelta(hours=hours_ago)


def steady(days: int, per_hour: int = 2, tool: str = "read_ticket", skip_last: int = 1) -> list[HourCount]:
    """`per_hour` calls every hour for `days` days, ending `skip_last` hours before now."""
    return [HourCount(at(h), tool, per_hour) for h in range(skip_last, days * 24 + skip_last)]


# --- warm-up -------------------------------------------------------------------------------------------------------------------

def test_no_history_is_not_warm_and_has_no_warning() -> None:
    result = assess_behaviour([], NOW)
    assert not result.verdict.warm and not result.warning and result.backtest.hours == 0


def test_an_agent_younger_than_seven_days_is_warming_up_and_never_flagged() -> None:
    rows = steady(6) + [HourCount(at(0), "read_ticket", 500), HourCount(at(0), "delete_all", 1)]
    result = assess_behaviour(rows, NOW)
    assert not result.verdict.warm and result.verdict.history_days == 6
    assert not result.warning  # a burst and a new tool, but no baseline yet


def test_warm_up_starts_exactly_at_seven_days() -> None:
    assert not assess_behaviour([HourCount(at(7 * 24 - 1), "t", 1)], NOW).verdict.warm
    assert assess_behaviour([HourCount(at(7 * 24), "t", 1)], NOW).verdict.warm


# --- spike ---------------------------------------------------------------------------------------------------------------------

def test_a_surge_far_above_the_usual_hour_is_a_spike() -> None:
    rows = steady(14, per_hour=4) + [HourCount(at(0), "read_ticket", 30)]
    v = assess_behaviour(rows, NOW).verdict
    assert v.warm and v.usual_hourly == 4.0 and v.spike_threshold == 30 and v.spike  # max(30, 5 x 4 = 20)


def test_the_spike_threshold_is_five_times_the_usual_hour_above_the_floor() -> None:
    rows = steady(14, per_hour=10)
    assert assess_behaviour(rows + [HourCount(at(0), "read_ticket", 49)], NOW).verdict.spike is False
    v = assess_behaviour(rows + [HourCount(at(0), "read_ticket", 50)], NOW).verdict
    assert v.spike_threshold == 50 and v.spike is True  # exactly 5x is a spike


def test_below_the_floor_is_never_a_spike_even_for_a_quiet_agent() -> None:
    rows = steady(14, per_hour=0) + [HourCount(at(200), "read_ticket", 1)]  # warm, almost silent
    assert assess_behaviour(rows + [HourCount(at(0), "read_ticket", SPIKE_FLOOR - 1)], NOW).verdict.spike is False
    assert assess_behaviour(rows + [HourCount(at(0), "read_ticket", SPIKE_FLOOR)], NOW).verdict.spike is True


def test_empty_hours_count_as_zero_in_the_usual_hour() -> None:
    rows = [HourCount(at(h), "t", 168) for h in (24 * 10,)] + [HourCount(at(1), "t", 168)]  # one busy hour inside the baseline
    v = assess_behaviour(rows, NOW).verdict
    assert v.usual_hourly == 1.0  # 168 calls spread over 168 hours, not over the 1 hour that had calls


def test_calls_of_every_tool_add_up_for_the_spike() -> None:
    rows = steady(14, per_hour=1, tool="a") + [HourCount(at(0), "a", 15), HourCount(at(0), "b", 15)]
    assert assess_behaviour(rows, NOW).verdict.spike is True


# --- new tool ------------------------------------------------------------------------------------------------------------------

def test_a_tool_never_used_in_fourteen_days_is_new_when_warm() -> None:
    rows = steady(14) + [HourCount(at(3), "export_customers", 1)]
    assert assess_behaviour(rows, NOW).verdict.new_tools == ("export_customers",)


def test_a_tool_first_used_exactly_24_hours_ago_is_no_longer_new() -> None:
    assert assess_behaviour(steady(14) + [HourCount(at(23), "x", 1)], NOW).verdict.new_tools == ("x",)
    assert assess_behaviour(steady(14) + [HourCount(at(24), "x", 1)], NOW).verdict.new_tools == ()


def test_a_tool_last_used_more_than_fourteen_days_before_counts_as_new_again() -> None:
    rows = steady(16) + [HourCount(at(15 * 24), "old_tool", 1), HourCount(at(2), "old_tool", 1)]
    assert assess_behaviour(rows, NOW).verdict.new_tools == ("old_tool",)
    recent = steady(16) + [HourCount(at(13 * 24), "old_tool", 1), HourCount(at(2), "old_tool", 1)]
    assert assess_behaviour(recent, NOW).verdict.new_tools == ()


def test_at_most_ten_new_tools_are_listed_in_the_order_they_appeared() -> None:
    rows = steady(14) + [HourCount(at(20 - i), f"tool_{i:02d}", 1) for i in range(15)]
    tools = assess_behaviour(rows, NOW).verdict.new_tools
    assert len(tools) == MAX_NEW_TOOLS and tools[0] == "tool_00" and tools[-1] == "tool_09"


def test_a_very_long_tool_name_is_cut_to_the_stored_length() -> None:
    rows = steady(14) + [HourCount(at(1), "x" * 500, 1)]
    assert assess_behaviour(rows, NOW).verdict.new_tools == ("x" * 128,)


# --- back-test -----------------------------------------------------------------------------------------------------------------

def test_steady_traffic_back_tests_quiet() -> None:
    result = assess_behaviour(steady(21), NOW)
    assert result.backtest.hours == BACKTEST_HOURS and result.backtest.flagged_hours == 0


def test_the_back_test_counts_past_spikes_and_new_tools() -> None:
    rows = steady(21, per_hour=2) + [HourCount(at(50), "read_ticket", 40), HourCount(at(30), "new_tool", 1)]
    bt = assess_behaviour(rows, NOW).backtest
    assert (bt.spike_hours, bt.new_tool_starts, bt.flagged_hours) == (1, 1, 2)


def test_the_back_test_never_sees_the_future() -> None:
    # A spike in the current hour must not be counted in any replayed (past) hour, and rows after "now" are ignored entirely.
    rows = steady(21, per_hour=2) + [HourCount(at(0), "read_ticket", 500), HourCount(at(-5), "future_tool", 1)]
    result = assess_behaviour(rows, NOW)
    assert result.verdict.spike is True and result.backtest.spike_hours == 0 and result.backtest.new_tool_starts == 0
    assert "future_tool" not in result.verdict.new_tools


def test_a_young_agent_is_replayed_only_from_its_first_hour() -> None:
    bt = assess_behaviour([HourCount(at(10), "t", 1)], NOW).backtest
    assert bt.hours == 10 and bt.flagged_hours == 0  # replayed hours 10..1 before now; not warm, so nothing flagged


def test_the_back_test_agrees_with_judging_each_past_hour_directly() -> None:
    """Property, seeded: replaying hour h from the full series gives the same answer as judging h with only the rows up to h."""
    rng = random.Random(20261114)
    for _ in range(25):
        rows = [HourCount(at(h), rng.choice(["a", "b", "c", "d"]), rng.choice([0, 1, 1, 2, 3, 40])) for h in range(1, 21 * 24) if rng.random() < 0.5]
        result = assess_behaviour(rows, NOW)
        flagged = 0
        for back in range(1, BACKTEST_HOURS + 1):
            then = NOW.replace(minute=0) - timedelta(hours=back)
            known = [r for r in rows if hour_index(r.hour) <= hour_index(then)]
            v = assess_behaviour(known, then).verdict
            started = [t for t in v.new_tools if any(hour_index(r.hour) == hour_index(then) and r.tool == t for r in known)]
            flagged += int(v.spike or bool(started))
        assert result.backtest.flagged_hours == flagged


def test_reading_21_days_back_covers_the_oldest_replayed_hour() -> None:
    assert NOW - read_since(NOW) >= timedelta(days=21)


@pytest.mark.parametrize("calls", [0, -3])
def test_rows_with_no_calls_are_ignored(calls: int) -> None:
    assert assess_behaviour([HourCount(at(200), "t", calls)], NOW).verdict.warm is False
