"""
Behaviour baseline (Phase 4.5 B2, ADR 0020): does an agent behave unlike itself? Pure: hourly call counts in, a verdict and a back-test out.
No I/O, no clock (the caller passes "now"), no model.

Watch-only in this version: the result is shown on the Risk panel but adds no points, sends no alert and triggers no action. The approved
plan asks that its false-alarm rate is measured before it is offered as more than a warning, so every verdict comes with a back-test: the
same rules replayed for each of the last 168 hours. Every rule looks only at hours at or before the hour it judges, so replaying past hours
from the full series cannot see the future (a test seeds a later spike and checks it is not counted earlier).

Rules (judgement, versioned in BEHAVIOUR_MODEL, shown on the page):
- warm-up: an agent is judged only once its first call (in the read window) is at least WARMUP_DAYS old;
- spike: calls in the hour >= max(SPIKE_FLOOR, SPIKE_FACTOR x the average hourly calls of the BASELINE_HOURS before it, empty hours zero);
- new tool: a tool with no call in the WINDOW_DAYS before its first call of the last NEW_TOOL_HOURS (only when warm).
Limit stated in the runbook: a baseline only catches sudden change; an agent that changes slowly teaches the baseline as it goes.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Final

BEHAVIOUR_MODEL: Final = "2026-11-14"
WARMUP_DAYS: Final = 7
WINDOW_DAYS: Final = 14
BASELINE_HOURS: Final = 168
SPIKE_FACTOR: Final = 5
SPIKE_FLOOR: Final = 30
NEW_TOOL_HOURS: Final = 24
MAX_NEW_TOOLS: Final = 10
BACKTEST_HOURS: Final = 168
READ_DAYS: Final = WINDOW_DAYS + BACKTEST_HOURS // 24  # 21: the oldest replayed hour still sees a full 14-day window
MAX_TOOL_NAME: Final = 128

_HOUR_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class HourCount:
    """Calls one agent made to one tool in one clock hour (UTC; `hour` is any moment within it)."""

    hour: datetime
    tool: str
    calls: int


@dataclass(frozen=True, slots=True)
class Verdict:
    warm: bool
    history_days: int  # whole days since the first call in the read window
    hour_calls: int  # calls in the current clock hour so far
    usual_hourly: float  # average hourly calls over the BASELINE_HOURS before the current hour
    spike_threshold: int
    spike: bool
    new_tools: tuple[str, ...]  # at most MAX_NEW_TOOLS, in the order they appeared


@dataclass(frozen=True, slots=True)
class Backtest:
    hours: int  # past hours replayed (BACKTEST_HOURS, fewer while the agent's history is shorter)
    flagged_hours: int  # hours that would have shown a warning: a spike, or a tool appearing
    spike_hours: int
    new_tool_starts: int  # tools that would have been reported as new


@dataclass(frozen=True, slots=True)
class Behaviour:
    verdict: Verdict
    backtest: Backtest
    model: str = BEHAVIOUR_MODEL

    @property
    def warning(self) -> bool:
        return self.verdict.spike or bool(self.verdict.new_tools)


def hour_index(moment: datetime) -> int:
    """The clock hour as an integer (whole hours since the epoch, UTC). A naive datetime is read as UTC."""
    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return math.floor(aware.timestamp() / _HOUR_SECONDS)


def hour_start(index: int) -> datetime:
    return datetime.fromtimestamp(index * _HOUR_SECONDS, tz=timezone.utc)


def read_since(now: datetime) -> datetime:
    """The oldest hour a caller must read so that every replayed hour sees a full window."""
    return hour_start(hour_index(now) - READ_DAYS * 24)


class _Series:
    """Hourly totals with prefix sums, and each tool's sorted hours. Built once per agent; every question below is O(log n)."""

    def __init__(self, rows: list[HourCount], last_hour: int) -> None:
        totals: dict[int, int] = {}
        by_tool: dict[str, set[int]] = {}
        for row in rows:
            h = hour_index(row.hour)
            if row.calls <= 0 or h > last_hour:
                continue  # nothing after "now" is ever read
            totals[h] = totals.get(h, 0) + row.calls
            by_tool.setdefault(row.tool[:MAX_TOOL_NAME], set()).add(h)
        self.hours = sorted(totals)
        self.prefix = [0]
        for h in self.hours:
            self.prefix.append(self.prefix[-1] + totals[h])
        self.totals = totals
        self.tool_hours = {tool: sorted(hs) for tool, hs in by_tool.items()}
        self.first_hour = self.hours[0] if self.hours else None

    def calls_between(self, start: int, end: int) -> int:
        """Calls in hours [start, end)."""
        return self.prefix[bisect_left(self.hours, end)] - self.prefix[bisect_left(self.hours, start)]

    def tool_used_between(self, tool: str, start: int, end: int) -> bool:
        """Whether the tool was called in any hour of [start, end)."""
        hours = self.tool_hours.get(tool, [])
        i = bisect_left(hours, start)
        return i < len(hours) and hours[i] < end

    def tool_used_at(self, tool: str, hour: int) -> bool:
        hours = self.tool_hours.get(tool, [])
        i = bisect_left(hours, hour)
        return i < len(hours) and hours[i] == hour

    def tool_first_between(self, tool: str, start: int, end: int) -> int | None:
        """The tool's first hour within [start, end], or None."""
        hours = self.tool_hours.get(tool, [])
        i = bisect_left(hours, start)
        return hours[i] if i < len(hours) and hours[i] <= end else None


def _warm(series: _Series, hour: int) -> bool:
    return series.first_hour is not None and hour - series.first_hour >= WARMUP_DAYS * 24


def _spike(series: _Series, hour: int) -> tuple[bool, float, int, int]:
    usual = series.calls_between(hour - BASELINE_HOURS, hour) / BASELINE_HOURS
    threshold = max(SPIKE_FLOOR, math.ceil(SPIKE_FACTOR * usual))
    calls = series.totals.get(hour, 0)
    return calls >= threshold, usual, threshold, calls


def _is_new_at(series: _Series, tool: str, first: int) -> bool:
    """A tool is new at hour `first` when it was not called in the WINDOW_DAYS before it."""
    return not series.tool_used_between(tool, first - WINDOW_DAYS * 24, first)


def _verdict(series: _Series, hour: int) -> Verdict:
    if series.first_hour is None or series.first_hour > hour:
        return Verdict(False, 0, 0, 0.0, SPIKE_FLOOR, False, ())
    warm = _warm(series, hour)
    spike, usual, threshold, calls = _spike(series, hour)
    fresh: list[tuple[int, str]] = []
    if warm:
        for tool in series.tool_hours:
            first = series.tool_first_between(tool, hour - NEW_TOOL_HOURS + 1, hour)
            if first is not None and _is_new_at(series, tool, first):
                fresh.append((first, tool))
    fresh.sort()
    return Verdict(
        warm=warm, history_days=(hour - series.first_hour) // 24, hour_calls=calls, usual_hourly=round(usual, 2),
        spike_threshold=threshold, spike=warm and spike, new_tools=tuple(t for _, t in fresh[:MAX_NEW_TOOLS]),
    )


def assess_behaviour(rows: list[HourCount], now: datetime) -> Behaviour:
    """The verdict for the current clock hour, and the back-test over the BACKTEST_HOURS before it. Rows after `now` are ignored."""
    current = hour_index(now)
    series = _Series(rows, current)
    verdict = _verdict(series, current)

    replayed = flagged = spike_hours = new_starts = 0
    for hour in range(current - BACKTEST_HOURS, current):
        if series.first_hour is None or series.first_hour > hour:
            continue  # the agent did not exist yet: nothing to replay
        replayed += 1
        if not _warm(series, hour):
            continue
        spike, _, _, _ = _spike(series, hour)
        starts = [t for t in series.tool_hours if series.tool_used_at(t, hour) and _is_new_at(series, t, hour)]
        spike_hours += int(spike)
        new_starts += len(starts)
        flagged += int(spike or bool(starts))
    return Behaviour(verdict, Backtest(replayed, flagged, spike_hours, new_starts))

