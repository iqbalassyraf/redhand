"""
Budget Guard in the gateway (Phase 2, M3b): the meter's rules, what does and does not consume budget,
fail-closed parsing of core's budget, reporting to core, and a two-instance simulation of the overshoot
bound documented in docs/plans/phase2-m3-budget-guard.md.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
import pytest

from agentwall.src.gateway.budget import BudgetMeter, BudgetState
from agentwall.src.gateway.service import JSONRPC_GATEWAY_UNAVAILABLE, JSONRPC_POLICY_VIOLATION

from test_gateway import INVOICES_READ, MIXED_SCOPES, FakeReporter, Harness, tool

DAY = "2026-11-04"
RESETS = datetime(2026, 11, 4, 16, 0, tzinfo=timezone.utc)
READ_ANY = [{"server": "xero", "tool": "*", "access": "read"}]


def state(limit: int | None, others: int = 0, day: str = DAY) -> BudgetState:
    return BudgetState(daily_call_limit=limit, used_by_other_instances=others, day_key=day, resets_at=RESETS)


def meter(**kwargs: Any) -> tuple[BudgetMeter, FakeReporter]:
    reporter = kwargs.pop("reporter", None) or FakeReporter()
    return BudgetMeter(instance_id="test-instance-0001", reporter=reporter, jitter=lambda: 0.5, **kwargs), reporter


def forwarded(h: Harness) -> list[str]:
    return [m["params"]["name"] for m in h.upstream.received if m["method"] == "tools/call"]


# ---------------------------------------------------------------------------
# The meter's rules
# ---------------------------------------------------------------------------


def test_the_limit_is_exact() -> None:
    m, _ = meter()
    agent = uuid4()
    results = [m.try_consume(agent, state(3)) for _ in range(5)]
    assert [r.allowed for r in results] == [True, True, True, False, False]
    assert [r.used for r in results] == [1, 2, 3, 3, 3]
    assert results[3].reason == "limit"


def test_usage_by_other_instances_counts_toward_the_limit() -> None:
    m, _ = meter()
    agent = uuid4()
    assert [m.try_consume(agent, state(10, others=7)).allowed for _ in range(5)] == [True, True, True, False, False]


def test_a_limit_lowered_below_usage_refuses_at_once_and_raising_it_allows_again() -> None:
    m, _ = meter()
    agent = uuid4()
    for _ in range(5):
        assert m.try_consume(agent, state(None)).allowed
    assert not m.try_consume(agent, state(5)).allowed  # lowered to exactly what is used
    assert not m.try_consume(agent, state(3)).allowed
    assert m.try_consume(agent, state(6)).allowed  # raised again


def test_a_new_day_starts_a_fresh_counter() -> None:
    m, _ = meter()
    agent = uuid4()
    assert m.try_consume(agent, state(1)).allowed and not m.try_consume(agent, state(1)).allowed
    assert m.try_consume(agent, state(1, day="2026-11-05")).allowed


def test_agents_without_a_limit_are_counted_and_never_refused() -> None:
    m, _ = meter()
    agent = uuid4()
    assert all(m.try_consume(agent, state(None)).allowed for _ in range(500))
    assert m.unreported_keys == 1
    assert not m.try_consume(agent, state(500)).allowed  # the 500 were really counted


def test_agents_are_counted_separately() -> None:
    m, _ = meter()
    first, second = uuid4(), uuid4()
    assert m.try_consume(first, state(1)).allowed and not m.try_consume(first, state(1)).allowed
    assert m.try_consume(second, state(1)).allowed


def test_a_full_table_refuses_limited_agents_and_ignores_unlimited_ones() -> None:
    m, _ = meter(max_keys=2)
    a, b, c, d = uuid4(), uuid4(), uuid4(), uuid4()
    assert m.try_consume(a, state(5)).allowed and m.try_consume(b, state(5)).allowed
    refused = m.try_consume(c, state(5))
    assert not refused.allowed and refused.reason == "meter_full"  # cannot track it: fail closed
    assert m.try_consume(d, state(None)).allowed  # nothing to enforce, so nothing to track
    assert m.try_consume(a, state(5)).allowed  # agents already tracked keep working


def test_crossing_80_and_100_percent_asks_for_an_immediate_report_once_each() -> None:
    m, _ = meter()
    agent = uuid4()
    urgent = [m.try_consume(agent, state(10)).urgent for _ in range(12)]
    assert urgent == [False] * 7 + [True, False, True, False, False]  # 8th call (80%) and 10th (100%)


def test_a_restart_forgets_unreported_calls_which_is_a_bounded_undercount() -> None:
    """Documented trade-off: calls not yet reported to core are lost when the process dies."""
    first, _ = meter()
    agent = uuid4()
    for _ in range(4):
        assert first.try_consume(agent, state(5)).allowed  # 4 calls, none reported yet
    restarted, _ = meter()  # a new process; core knows nothing of those 4 calls
    allowed = sum(restarted.try_consume(agent, state(5, others=0)).allowed for _ in range(10))
    assert allowed == 5  # the new process starts from zero: 4 + 5 calls got through in total (the undercount)
    # whereas calls that WERE reported come back through "usage by others" and count in full
    again, _ = meter()
    assert sum(again.try_consume(agent, state(5, others=4)).allowed for _ in range(10)) == 1


# ---------------------------------------------------------------------------
# Through the gateway
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_sixth_call_is_refused_with_a_clear_message_and_logged() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=5)
    token = h.token(agent)
    for _ in range(5):
        assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    refused = await h.call(token, params=tool("list_invoices"))
    assert refused.status_code == 200 and refused.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert "daily limit of 5 tool calls" in refused.body["error"]["message"]
    assert refused.body["error"]["data"] == {
        "tool_name": "list_invoices", "daily_call_limit": 5, "used": 5, "resets_at": RESETS.isoformat(),
    }
    assert len(forwarded(h)) == 5  # the refused call never reached the upstream server
    record = h.decisions(1)[-1]
    assert record["decision"] == "BLOCK" and "Daily limit of 5 tool calls reached" in record["reasons"][0]
    assert 'reason="budget_exceeded"' in h.gateway.metrics.render()


@pytest.mark.asyncio
async def test_concurrent_calls_cannot_overshoot_the_limit() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=100)
    token = h.token(agent)
    responses = await asyncio.gather(*(h.call(token, params=tool("list_invoices")) for _ in range(400)))
    assert sum("result" in r.body for r in responses) == 100
    assert sum("error" in r.body for r in responses) == 300
    assert len(forwarded(h)) == 100


@pytest.mark.asyncio
async def test_refused_calls_do_not_consume_budget() -> None:
    h = Harness()
    agent = h.add_agent(MIXED_SCOPES, limit=2)
    token = h.token(agent)
    for _ in range(6):  # out of scope, against a guardrail rule, and refused by a limit-free path
        await h.call(token, params=tool("execute_sql", query="select 1"))
        await h.call(token, params=tool("delete_invoice_nope"))
    assert h.budget.unreported_keys == 0  # nothing was consumed
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    assert "error" in (await h.call(token, params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_safe_mode_and_guardrail_refusals_do_not_consume_budget() -> None:
    h = Harness()
    agent = h.add_agent(MIXED_SCOPES + [{"server": "xero", "tool": "execute_sql", "access": "read"}], safe_mode=True, limit=1)
    token = h.token(agent)
    for _ in range(4):
        await h.call(token, params=tool("delete_invoice", id="1"))  # write: refused by Safe Mode
        await h.call(token, params=tool("execute_sql", query="DROP TABLE invoices;"))  # refused by a guardrail
    assert h.budget.unreported_keys == 0
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["frozen", "revoked"])
async def test_calls_refused_because_the_passport_is_inactive_do_not_consume(status: str) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, status=status, limit=1)
    for _ in range(3):
        assert (await h.call(h.token(agent), params=tool("list_invoices"))).status_code == 403
    assert h.budget.unreported_keys == 0


@pytest.mark.asyncio
async def test_only_tool_calls_count() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=1)
    token = h.token(agent)
    for method in ("initialize", "ping", "tools/list", "tools/list", "ping"):
        await h.call(token, method=method)
    assert h.budget.unreported_keys == 0
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    assert "error" in (await h.call(token, params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_calls_that_fail_upstream_still_count() -> None:
    h = Harness()
    h.upstream.mode = "error"
    agent = h.add_agent(INVOICES_READ, limit=2)
    token = h.token(agent)
    first = await h.call(token, params=tool("list_invoices"))
    second = await h.call(token, params=tool("list_invoices"))
    assert first.status_code == second.status_code == 502  # the work may have been done, so it counts
    third = await h.call(token, params=tool("list_invoices"))
    assert third.status_code == 200 and "daily limit" in third.body["error"]["message"]


@pytest.mark.asyncio
async def test_usage_by_other_instances_from_core_counts() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=5, used_by_others=4)
    token = h.token(agent)
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    assert "error" in (await h.call(token, params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_a_raised_or_lowered_limit_reaches_the_gateway_within_the_cache_window() -> None:
    h = Harness(ttl=2.0)
    agent = h.add_agent(INVOICES_READ, limit=1)
    token = h.token(agent)
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    assert "error" in (await h.call(token, params=tool("list_invoices"))).body

    h.core.agents[str(agent)]["budget"]["daily_call_limit"] = 3  # raised in core
    h.clock.now += 2.01
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body

    h.core.agents[str(agent)]["budget"]["daily_call_limit"] = 2  # lowered below usage
    h.clock.now += 2.01
    assert "error" in (await h.call(token, params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_the_gateway_tells_core_which_instance_is_asking() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    seen: list[dict[str, str]] = []

    def spy(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return h.core.handler(request)

    h.gateway.contexts._http = httpx.AsyncClient(transport=httpx.MockTransport(spy))
    await h.call(h.token(agent), params=tool("list_invoices"))
    assert seen[0]["instance_id"] == "test-gateway-0001"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "broken",
    [
        "missing", None, "5", 1.5, True, -1,
    ],
)
async def test_a_missing_or_malformed_limit_denies_everything(broken: Any) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    if broken == "missing":
        del h.core.agents[str(agent)]["budget"]
    elif broken is None:
        h.core.agents[str(agent)]["budget"] = None
    else:
        h.core.agents[str(agent)]["budget"]["daily_call_limit"] = broken
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 503 and resp.body["error"]["code"] == JSONRPC_GATEWAY_UNAVAILABLE
    assert h.upstream.received == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [("used_by_other_instances", -1), ("used_by_other_instances", "3"), ("used_by_other_instances", 2.5),
     ("day_key", "tomorrow"), ("day_key", "2026-13-45x"), ("resets_at", "soon"), ("action", "explode")],
)
async def test_malformed_budget_details_deny_everything(field: str, value: Any) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=10)
    h.core.agents[str(agent)]["budget"][field] = value
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 503
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_a_limit_of_zero_from_core_refuses_every_call() -> None:
    """Core sends 0 for a malformed stored limit: the restrictive reading."""
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=0)
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert "daily limit of 0 tool calls" in resp.body["error"]["message"]
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_an_untrackable_agent_gets_its_own_message() -> None:
    h = Harness()
    h.budget._max_keys = 0
    agent = h.add_agent(INVOICES_READ, limit=5)
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert "cannot track" in resp.body["error"]["message"]
    assert 'reason="budget_untracked"' in h.gateway.metrics.render()
    assert h.upstream.received == []


# ---------------------------------------------------------------------------
# Reporting to core
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reports_are_cumulative_totals_not_deltas() -> None:
    m, reporter = meter()
    agent = uuid4()
    for _ in range(3):
        m.try_consume(agent, state(None))
    assert await m.flush() is True
    assert reporter.reports == [[{"agent_id": str(agent), "day_key": DAY, "calls": 3}]]
    for _ in range(2):
        m.try_consume(agent, state(None))
    await m.flush()
    assert reporter.reports[-1] == [{"agent_id": str(agent), "day_key": DAY, "calls": 5}]  # 5 in total, not 2
    assert m.unreported_keys == 0
    await m.flush()
    assert len(reporter.reports) == 2  # nothing changed: nothing sent


@pytest.mark.asyncio
async def test_a_failed_report_loses_nothing_and_retries_with_backoff() -> None:
    clock = [100.0]
    m, reporter = meter(clock=lambda: clock[0], flush_interval=5.0)
    agent = uuid4()
    m.try_consume(agent, state(None))
    reporter.accept = False
    assert await m.flush() is False
    assert m.unreported_keys == 1
    m.try_consume(agent, state(None))  # more calls while core is unreachable

    m.schedule_flush_if_due()
    await asyncio.sleep(0)
    assert len(reporter.reports) == 1  # backing off: no new attempt yet
    clock[0] += 60.0
    reporter.accept = True
    m.schedule_flush_if_due()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert reporter.reports[-1] == [{"agent_id": str(agent), "day_key": DAY, "calls": 2}]
    assert m.unreported_keys == 0


@pytest.mark.asyncio
async def test_a_reporter_that_crashes_never_reaches_the_caller() -> None:
    m, reporter = meter()
    agent = uuid4()
    m.try_consume(agent, state(None))
    reporter.crash = True
    assert await m.flush() is False
    await m.flush_now(timeout=0.5)  # must not raise either
    assert m.unreported_keys == 1


@pytest.mark.asyncio
async def test_calls_made_while_a_report_is_in_flight_stay_unreported() -> None:
    agent = uuid4()

    class Busy(FakeReporter):
        async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
            m.try_consume(agent, state(None))  # a call arrives while the report is on the wire
            return await super().send(instance_id, items)

    m, reporter = meter(reporter=Busy())
    m.try_consume(agent, state(None))
    await m.flush()
    assert m.unreported_keys == 1  # the extra call is still owed to core
    await m.flush()
    assert reporter.reports[-1][0]["calls"] == 2


@pytest.mark.asyncio
async def test_reports_are_split_into_chunks_core_accepts() -> None:
    m, reporter = meter()
    for _ in range(2500):
        m.try_consume(uuid4(), state(None))
    assert await m.flush() is True
    assert [len(r) for r in reporter.reports] == [1000, 1000, 500]
    assert m.unreported_keys == 0


@pytest.mark.asyncio
async def test_old_days_are_dropped_once_reported() -> None:
    m, _ = meter()
    agent = uuid4()
    m.try_consume(agent, state(None, day="2026-11-01"))
    m.try_consume(agent, state(None, day="2026-11-05"))
    await m.flush()
    assert (agent, "2026-11-01") not in m._counts and (agent, "2026-11-05") in m._counts


@pytest.mark.asyncio
async def test_crossing_80_percent_is_reported_before_the_call_returns() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=10)
    token = h.token(agent)
    for _ in range(7):
        await h.call(token, params=tool("list_invoices"))
    reports_before = len(h.reporter.reports)
    await h.call(token, params=tool("list_invoices"))  # the 8th call crosses 80%
    assert len(h.reporter.reports) > reports_before
    assert h.reporter.reports[-1][0]["calls"] == 8


@pytest.mark.asyncio
async def test_an_urgent_report_completes_even_when_a_background_report_was_just_scheduled() -> None:
    """
    Regression: the gateway schedules a due report and then waits for an urgent one in the same call. They
    must be one report, not two racing tasks where the waited-for one is an instant no-op (the 100% report
    used to go out only seconds later). The reporter here takes real time, which an instant fake hid.
    """
    class Yielding(FakeReporter):
        async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
            await asyncio.sleep(0.05)
            return await super().send(instance_id, items)

    h = Harness()
    h.budget._reporter = Yielding()
    reporter: Yielding = h.budget._reporter  # type: ignore[assignment]
    agent = h.add_agent(INVOICES_READ, limit=5)
    token = h.token(agent)
    for _ in range(3):
        await h.call(token, params=tool("list_invoices"))
    await h.call(token, params=tool("list_invoices"))  # the 4th call: 80%
    assert reporter.reports and reporter.reports[-1][0]["calls"] == 4  # already with core when the call returned
    await h.call(token, params=tool("list_invoices"))  # the 5th call: 100%
    assert reporter.reports[-1][0]["calls"] == 5
    assert h.budget.unreported_keys == 0


@pytest.mark.asyncio
async def test_calls_that_arrive_during_an_urgent_report_get_a_follow_up_report() -> None:
    agent = uuid4()

    class Busy(FakeReporter):
        injected = False

        async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
            if not self.injected:
                self.injected = True
                m.try_consume(agent, state(None))  # a concurrent call lands while this report is on the wire
            await asyncio.sleep(0.01)
            return await super().send(instance_id, items)

    m, reporter = meter(reporter=Busy())
    m.try_consume(agent, state(None))
    await m.flush_now(timeout=1.0)
    assert [r[0]["calls"] for r in reporter.reports] == [1, 2]  # the follow-up carried the extra call
    assert m.unreported_keys == 0


@pytest.mark.asyncio
async def test_a_slow_core_delays_only_the_call_that_crosses_a_threshold_and_only_briefly() -> None:
    class Slow(FakeReporter):
        async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
            await asyncio.sleep(0.4)
            return await super().send(instance_id, items)

    h = Harness()
    h.budget._reporter = Slow()
    agent = h.add_agent(INVOICES_READ, limit=10)
    token = h.token(agent)
    loop = asyncio.get_running_loop()
    for _ in range(7):
        await h.call(token, params=tool("list_invoices"))
    started = loop.time()
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body
    assert loop.time() - started < 1.5  # waited at most about a second for the report, then carried on


@pytest.mark.asyncio
async def test_the_periodic_loop_and_shutdown_report_what_is_left() -> None:
    reporter = FakeReporter()
    m = BudgetMeter(instance_id="test-instance-0001", reporter=reporter, flush_interval=0.05)
    agent = uuid4()
    m.start()
    m.try_consume(agent, state(None))
    await asyncio.sleep(0.3)
    assert reporter.reports and reporter.reports[-1][0]["calls"] == 1
    m.try_consume(agent, state(None))
    await m.stop()  # the final report on shutdown
    assert reporter.reports[-1][0]["calls"] == 2 and m.unreported_keys == 0


# ---------------------------------------------------------------------------
# Several instances: the documented overshoot bound
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("instances", [1, 2, 3])
def test_several_instances_overshoot_by_at_most_the_documented_bound(instances: int) -> None:
    """
    Each tick every instance makes one call. Every instance reports its running total every FLUSH ticks
    (immediately visible to core) and refreshes "usage by others" every CACHE ticks. The plan documents
    that the cap can be exceeded by at most (instances - 1) x calls per tick x (CACHE + FLUSH) ticks. The
    assertion below is exactly that documented bound (the simulation measures 0, 0 and 8 against 0, 7 and 14).
    """
    limit, flush_ticks, cache_ticks = 100, 5, 2
    agent = uuid4()
    meters = [meter()[0] for _ in range(instances)]
    reported = [0] * instances  # what core has from each instance
    seen_others = [0] * instances  # each gateway's cached view of the others
    allowed_total = 0
    for tick in range(1, 400):
        for i, m in enumerate(meters):
            if m.try_consume(agent, state(limit, others=seen_others[i])).allowed:
                allowed_total += 1
        if tick % flush_ticks == 0:
            for i, m in enumerate(meters):
                reported[i] = m._counts.get((agent, DAY), 0)
        if tick % cache_ticks == 0:
            for i in range(instances):
                seen_others[i] = sum(reported) - reported[i]
    bound = (instances - 1) * 1 * (cache_ticks + flush_ticks)
    assert allowed_total >= limit  # the cap does bite
    assert allowed_total <= limit + bound  # the documented overshoot bound, not a looser one


def test_a_single_instance_never_overshoots() -> None:
    m, _ = meter()
    agent = uuid4()
    assert sum(m.try_consume(agent, state(100)).allowed for _ in range(1000)) == 100


@pytest.mark.asyncio
async def test_the_backoff_survives_thousands_of_consecutive_failures() -> None:
    """Regression: 2**failures overflowed a float after ~1,000 failures and switched the backoff off."""
    clock = [0.0]
    m, reporter = meter(clock=lambda: clock[0], flush_interval=5.0)
    agent = uuid4()
    m.try_consume(agent, state(None))
    reporter.accept = False
    for _ in range(1500):
        clock[0] += 3600.0
        assert await m.flush() is False  # must not raise OverflowError
    assert 30.0 <= m._next_flush_at - clock[0] <= 60.0  # still a bounded, jittered backoff
    assert m.unreported_keys == 1


@pytest.mark.asyncio
async def test_repeated_refusals_over_the_limit_are_audited_once_a_minute_but_always_counted() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, limit=1)
    token = h.token(agent)
    await h.call(token, params=tool("list_invoices"))
    for _ in range(50):  # a runaway agent retrying in a loop
        assert "error" in (await h.call(token, params=tool("list_invoices"))).body
    blocks = [r for r in h.full_rows(100) if r["decision"] == "BLOCK"]
    assert len(blocks) == 1  # one record, not fifty
    assert 'redhand_gateway_decisions_total{method="tools/call",outcome="deny",reason="budget_exceeded"} 50' in h.gateway.metrics.render()
    h.gateway._budget_refusal_logged[next(iter(h.gateway._budget_refusal_logged))] -= 61.0  # a minute passes
    await h.call(token, params=tool("list_invoices"))
    assert len([r for r in h.full_rows(100) if r["decision"] == "BLOCK"]) == 2


@pytest.mark.asyncio
async def test_an_unexpected_error_in_the_urgent_report_path_is_logged_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    import structlog

    m, _ = meter()
    agent = uuid4()
    m.try_consume(agent, state(None))

    def boom() -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(m, "_start_report", boom)
    with structlog.testing.capture_logs() as logs:
        await m.flush_now(timeout=0.5)  # does not raise to the caller...
    assert any(entry.get("event") == "Urgent usage report failed" and entry.get("error_type") == "RuntimeError" for entry in logs)  # ...but leaves a trace
