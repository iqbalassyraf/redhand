"""
Loop meter (Phase 4 M6, docs/plans/phase4-m6-loop-detection.md section 3.1): the counting rules, the throttle recovery rule, the
bounds that stop a flood of distinct calls from growing memory, and what happens with arguments that cannot be hashed.
All time is a fake clock.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentwall.src.gateway.loops import MAX_HASHED_BYTES, LoopMeter

LIMIT = 5
WINDOW = 60.0
A = uuid4()
B = uuid4()


class Clock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make(clock: Clock | None = None, **kwargs: Any) -> tuple[LoopMeter, Clock]:
    clock = clock or Clock()
    return LoopMeter(clock=clock, **kwargs), clock


def call(meter: LoopMeter, agent: UUID = A, tool: str = "get_status", args: dict[str, Any] | None = None, *, throttle: bool = False,
         limit: int = LIMIT) -> Any:
    return meter.check(agent, tool, {} if args is None else args, limit=limit, window_seconds=WINDOW, throttle=throttle)


# ---------------------------------------------------------------------------
# The counting rule: N-1 pass, N flags
# ---------------------------------------------------------------------------


def test_calls_before_the_limit_pass_and_the_limit_call_flags() -> None:
    meter, _ = make()
    results = [call(meter) for _ in range(LIMIT)]
    assert [r.flagged for r in results] == [False] * (LIMIT - 1) + [True]
    assert results[-1].count == LIMIT
    assert all(r.outcome == "ok" for r in results[:-1]) and results[-1].outcome == "flagged"


def test_the_limit_is_exact_inside_one_window() -> None:
    meter, clock = make()
    for _ in range(LIMIT - 1):
        clock.now += 1
        assert not call(meter).flagged
    clock.now += 1
    assert call(meter).flagged


def test_a_different_argument_tool_or_agent_is_counted_apart() -> None:
    meter, _ = make()
    for _ in range(LIMIT - 1):
        call(meter, args={"id": 1})
    assert not call(meter, args={"id": 2}).flagged
    assert not call(meter, tool="other_tool", args={"id": 1}).flagged
    assert not call(meter, agent=B, args={"id": 1}).flagged
    assert call(meter, args={"id": 1}).flagged


def test_the_order_of_keys_does_not_matter_and_types_do() -> None:
    meter, _ = make()
    for i in range(LIMIT - 1):
        call(meter, args={"a": 1, "b": {"x": 1, "y": 2}} if i % 2 else {"b": {"y": 2, "x": 1}, "a": 1})
    assert call(meter, args={"b": {"x": 1, "y": 2}, "a": 1}).flagged
    other, _ = make()
    for _ in range(LIMIT - 1):
        call(other, args={"id": 1})
    assert not call(other, args={"id": "1"}).flagged  # the number 1 and the text "1" are different calls


def test_calls_with_no_arguments_are_counted() -> None:
    meter, _ = make()
    assert [call(meter, args={}).flagged for _ in range(LIMIT)][-1] is True


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def test_the_window_expires() -> None:
    meter, clock = make()
    for _ in range(LIMIT - 1):
        call(meter)
    clock.now += 2 * WINDOW + 1  # two whole windows later nothing is remembered
    assert [call(meter).flagged for _ in range(LIMIT - 1)] == [False] * (LIMIT - 1)
    assert call(meter).flagged


def test_the_estimate_across_a_window_edge_is_within_one_call_of_the_exact_count() -> None:
    meter, clock = make(Clock(1000.0))
    limit = 10
    assert not call(meter, limit=limit).flagged  # the window starts here, at t=1000
    clock.now = 1059.0  # the last second of that window
    for _ in range(limit - 2):
        assert not call(meter, limit=limit).flagged  # 9 calls in all so far
    clock.now = 1061.0  # the next window, but all 9 calls are still inside the last 60 seconds
    first, second = call(meter, limit=limit), call(meter, limit=limit)
    assert not first.flagged  # the exact count would flag here; the estimate (9.85) is one call late
    assert second.flagged  # and no later than one call after


def test_observe_counts_every_call_so_a_continuing_loop_stays_flagged() -> None:
    meter, clock = make()
    for _ in range(10):
        call(meter, throttle=False)
    clock.now += WINDOW + 1
    assert call(meter, throttle=False).flagged


# ---------------------------------------------------------------------------
# Throttle: a refused call is not counted, so the agent recovers
# ---------------------------------------------------------------------------


def test_throttle_does_not_count_a_refused_call_and_the_agent_recovers() -> None:
    meter, clock = make()
    for _ in range(LIMIT - 1):
        assert not call(meter, throttle=True).flagged
    for _ in range(50):  # refused repeats must not push the count up
        assert call(meter, throttle=True).flagged
    clock.now += WINDOW + 1
    assert not call(meter, throttle=True).flagged  # the window moved on: this call may go through


def test_throttle_lets_about_limit_minus_one_identical_calls_through_per_window() -> None:
    meter, clock = make()
    passed = 0
    for _ in range(300):
        clock.now += 1.0
        if not call(meter, throttle=True).flagged:
            passed += 1
    # 300 seconds, window 60 s, limit 5: roughly (limit - 1) per window; never anywhere near one per second
    assert 15 <= passed <= 30


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_the_per_agent_cap_drops_the_oldest_key_and_never_touches_another_agent() -> None:
    meter, _ = make(max_keys_per_agent=2)
    for _ in range(LIMIT - 1):
        call(meter, agent=B, args={"id": "b"})
    for _ in range(LIMIT - 1):
        call(meter, agent=A, args={"id": 1})
    call(meter, agent=A, args={"id": 2})
    call(meter, agent=A, args={"id": 3})  # agent A now holds 2 keys: id 1 was dropped
    assert meter.evictions == 1
    assert not call(meter, agent=A, args={"id": 1}).flagged  # forgotten: counts as a first call again
    assert call(meter, agent=B, args={"id": "b"}).flagged  # agent B's count is intact


def test_the_global_cap_bounds_the_table_and_drops_the_least_recently_used_agent_first() -> None:
    meter, _ = make(max_keys=3)
    agents = [uuid4() for _ in range(4)]
    for agent in agents:
        call(meter, agent=agent, args={"id": 1})
    assert meter.size == 3
    assert meter.evictions == 1
    assert agents[0] not in meter.agents()  # the first agent seen, not used since, lost its entry


def test_a_flood_of_distinct_calls_stays_inside_the_default_caps() -> None:
    meter, _ = make()
    for _ in range(300):
        call(meter, args={"nonce": uuid4().hex})
    assert meter.size <= 16  # per-agent cap
    started = time.perf_counter()
    for i in range(20_000):
        call(meter, agent=UUID(int=i), args={"n": i})
    assert meter.size <= 100_000
    assert time.perf_counter() - started < 5.0


def test_a_one_mebibyte_argument_is_handled_inside_a_time_limit() -> None:
    meter, _ = make()
    started = time.perf_counter()
    decision = call(meter, args={"blob": "x" * (1024 * 1024)})
    assert time.perf_counter() - started < 1.0
    assert decision.outcome == "ok"


def test_arguments_longer_than_the_hash_limit_are_hashed_on_their_start_and_length() -> None:
    """The stated limit: a change past the first 64 KiB of an identical-length call is not seen, which errs toward calling it a repeat."""
    meter, _ = make()
    head = "h" * MAX_HASHED_BYTES
    assert not call(meter, args={"blob": head + "A" * 100}, limit=2).flagged
    assert call(meter, args={"blob": head + "B" * 100}, limit=2).flagged
    other, _ = make()
    assert not call(other, args={"blob": head + "A" * 100}, limit=2).flagged
    assert not call(other, args={"blob": head + "B" * 101}, limit=2).flagged  # a different length is a different call


# ---------------------------------------------------------------------------
# Arguments that cannot be hashed, privacy, salt, bad settings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", [{"x": {1, 2}}, {"x": object()}, {"x": float("nan")}, {"x": b"bytes"}, {1: "a", "b": 2}],
    ids=["set", "object", "nan", "bytes", "keys that cannot be sorted"],
)
def test_arguments_that_cannot_be_hashed_are_untracked_and_store_nothing(bad: dict[Any, Any]) -> None:
    meter, _ = make()
    decision = call(meter, args=bad)
    assert decision.outcome == "untracked" and decision.flagged is False
    assert meter.size == 0


def test_arguments_nested_too_deeply_are_untracked_not_a_crash() -> None:
    meter, _ = make()
    nested: Any = "leaf"
    for _ in range(100_000):  # parsed JSON cannot be this deep (json.loads fails first); the meter must still not crash
        nested = {"a": nested}
    assert call(meter, args={"deep": nested}).outcome == "untracked"


def test_the_table_holds_no_argument_text() -> None:
    meter, _ = make()
    call(meter, args={"password": "SECRET-VALUE-123", "SECRET-KEY-NAME": 1})
    assert "SECRET" not in repr(meter.agents()) and "SECRET" not in repr(meter.__dict__)
    for slots in meter.keys_for(A):
        assert len(slots) == 16 and b"SECRET" not in slots


def test_the_digest_is_salted_per_meter_and_stable_inside_one() -> None:
    one, _ = make()
    two, _ = make()
    assert one.digest("t", {"a": 1}) == one.digest("t", {"a": 1})
    assert one.digest("t", {"a": 1}) != two.digest("t", {"a": 1})
    assert one.digest("t", {"a": 1}) != one.digest("t2", {"a": 1})
    assert one.digest("ab", {"c": 1}) != one.digest("a", {"bc": 1})  # the tool name and the arguments cannot run together


@pytest.mark.parametrize("limit,window", [(0, 60.0), (-1, 60.0), (5, 0.0), (5, -1.0)])
def test_nonsense_settings_raise_so_the_gateway_can_treat_them_as_an_error(limit: int, window: float) -> None:
    meter, _ = make()
    with pytest.raises(ValueError):
        meter.check(A, "t", {}, limit=limit, window_seconds=window, throttle=False)
