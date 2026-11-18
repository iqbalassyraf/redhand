"""
Loop detection in the gateway (Phase 4 M6, docs/plans/phase4-m6-loop-detection.md): observe flags a repeated identical call and never
refuses; throttle refuses the repeat before it can use budget and recovers as the window moves on; an exempt agent, a switched-off
organization and the kill switch skip the meter; a meter error denies in throttle and changes nothing in observe; and the settings from
core are required, so an older core makes the call fail closed.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentwall.src.gateway.loops import LoopMeter
from agentwall.src.gateway.service import JSONRPC_POLICY_VIOLATION

from test_gateway import INVOICES_READ, MIXED_SCOPES, ORG, Harness, tool

LIMIT = 5
SECRET_MARKER = "zq-marker-4417"


def wired(mode: str = "throttle", *, limit: int = LIMIT, window: int = 60, exempt: bool = False, daily: int | None = None) -> tuple[Harness, str]:
    h = Harness()
    h.gateway.loops = LoopMeter(clock=h.clock)  # the same fake clock as the passport cache
    agent = h.add_agent(INVOICES_READ, loop_mode=mode, loop_limit=limit, loop_window_seconds=window, loop_exempt=exempt, limit=daily)
    return h, h.token(agent)


def forwarded(h: Harness) -> int:
    return sum(1 for m in h.upstream.received if m["method"] == "tools/call")


async def send(h: Harness, token: str, **args: Any) -> Any:
    return await h.call(token, params=tool("list_invoices", **args))


def refused(response: Any) -> bool:
    return "error" in (response.body or {})


def spy(h: Harness) -> list[int]:
    """Records every call to the meter. (Raising instead would be swallowed: the gateway treats a meter error as an error.)"""
    ran: list[int] = []
    real = h.gateway.loops.check

    def recording(*args: Any, **kwargs: Any) -> Any:
        ran.append(1)
        return real(*args, **kwargs)

    h.gateway.loops.check = recording  # type: ignore[method-assign]
    return ran


def loop_reports(h: Harness) -> list[dict[str, Any]]:
    return [i for r in h.findings_reporter.reports for i in r.items if i["rule_id"] == "RAD-LOOP-001"]


# --- observe ----------------------------------------------------------------------------------------------------------

async def test_observe_flags_the_limit_call_and_never_refuses() -> None:
    h, token = wired("observe")
    for _ in range(LIMIT - 1):
        assert not refused(await send(h, token, id=1))
    await h.radar.wait_idle()
    assert loop_reports(h) == []  # N-1 identical calls: nothing yet
    assert not refused(await send(h, token, id=1))  # the limit-th call is flagged, still forwarded
    for _ in range(10):
        assert not refused(await send(h, token, id=1))
    await h.radar.wait_idle()
    assert forwarded(h) == LIMIT + 10  # observe changed no decision
    reports = loop_reports(h)
    assert len(reports) == 1  # one report, however many flagged calls (the same repeat limit as the Radar's findings)
    assert reports[0] == {
        "rule_id": "RAD-LOOP-001", "kind": "loop", "family": "loop", "severity": "medium", "confidence": "high", "place": "call",
        "evasion": [], "tool_name": "list_invoices", "server": "xero", "would_block": False, "occurrences": 1,
    }
    text = h.gateway.metrics.render()
    assert 'redhand_gateway_loops_total{outcome="flagged"} 11' in text and 'outcome="report_throttled"' in text


async def test_a_loop_report_carries_no_call_details() -> None:
    h, token = wired("observe")
    for _ in range(LIMIT):
        await send(h, token, note=SECRET_MARKER)
    await h.radar.wait_idle()
    assert loop_reports(h)
    assert SECRET_MARKER not in json.dumps([r.items for r in h.findings_reporter.reports])
    assert SECRET_MARKER not in h.gateway.metrics.render()


async def test_different_arguments_are_not_a_loop() -> None:
    h, token = wired("throttle")
    for i in range(50):
        assert not refused(await send(h, token, id=i))
    assert loop_reports(h) == []


async def test_other_methods_are_not_counted() -> None:
    h, token = wired("throttle")
    for _ in range(30):
        assert not refused(await h.call(token, method="tools/list"))
        assert not refused(await h.call(token, method="ping"))


async def test_two_agents_and_two_organizations_are_counted_apart() -> None:
    h, token_a = wired("throttle")
    agent_b = h.add_agent(INVOICES_READ, loop_mode="throttle", loop_limit=LIMIT)
    other_org = uuid4()
    agent_c = h.add_agent(INVOICES_READ, org=other_org, loop_mode="throttle", loop_limit=LIMIT)
    for _ in range(LIMIT - 1):
        await send(h, token_a, id=1)
    assert refused(await send(h, token_a, id=1))
    assert not refused(await send(h, h.token(agent_b), id=1))
    assert not refused(await send(h, h.token(agent_c, org=other_org), id=1))


# --- throttle ---------------------------------------------------------------------------------------------------------

async def test_throttle_refuses_the_limit_call_and_it_never_reaches_the_tool() -> None:
    h, token = wired("throttle")
    for _ in range(LIMIT - 1):
        assert not refused(await send(h, token, id=1))
    response = await send(h, token, id=1)
    assert response.status_code == 200 and response.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert "paused" in response.body["error"]["message"] and "list_invoices" not in response.body["error"]["message"]
    assert response.body["error"]["data"] == {"tool_name": "list_invoices", "loop_limit": LIMIT, "loop_window_seconds": 60}
    assert forwarded(h) == LIMIT - 1  # the refused call was not forwarded
    text = h.gateway.metrics.render()
    assert 'reason="loop_throttled"' in text and 'redhand_gateway_loops_total{outcome="throttled"} 1' in text


async def test_the_refusal_message_echoes_no_argument() -> None:
    h, token = wired("throttle")
    for _ in range(LIMIT):
        response = await send(h, token, note=SECRET_MARKER)
    assert refused(response) and SECRET_MARKER not in json.dumps(response.body)


async def test_throttle_recovers_when_the_window_moves_on() -> None:
    h, token = wired("throttle")
    for _ in range(LIMIT - 1):
        await send(h, token, id=1)
    assert refused(await send(h, token, id=1))
    for _ in range(20):  # retrying while refused must not keep the loop alive
        assert refused(await send(h, token, id=1))
    h.clock.now += 61.0
    assert not refused(await send(h, token, id=1))


async def test_a_refused_repeat_does_not_use_budget() -> None:
    h, token = wired("throttle", daily=6)
    for _ in range(LIMIT - 1):
        assert not refused(await send(h, token, id=1))  # 4 units used
    for _ in range(30):
        assert refused(await send(h, token, id=1))  # loop-throttled: no budget used
    assert not refused(await send(h, token, id=2))  # unit 5
    assert not refused(await send(h, token, id=3))  # unit 6
    over = await send(h, token, id=4)
    assert refused(over) and "daily limit" in over.body["error"]["message"]  # unit 7 is the budget's refusal, so only 6 were used


async def test_calls_refused_earlier_are_not_counted() -> None:
    h = Harness()
    h.gateway.loops = LoopMeter(clock=h.clock)
    agent = h.add_agent(INVOICES_READ, loop_mode="throttle", loop_limit=LIMIT)
    token = h.token(agent)
    for _ in range(40):  # out of scope: refused before the loop check
        assert "out of scope" in (await h.call(token, params=tool("delete_invoice", id=1))).body["error"]["message"]
    for _ in range(LIMIT - 1):
        assert not refused(await send(h, token, id=1))
    assert refused(await send(h, token, id=1))
    assert h.gateway.loops.size == 1  # only the in-scope call was ever counted


async def test_refusals_reach_the_ledger_once_a_minute_and_are_always_counted() -> None:
    h, token = wired("throttle")
    for _ in range(LIMIT - 1):
        await send(h, token, id=1)
    for _ in range(40):
        assert refused(await send(h, token, id=1))
    blocks = [r for r in h.full_rows(200) if r["decision"] == "BLOCK"]
    assert len(blocks) == 1  # one ledger record for forty refusals
    assert 'reason="loop_throttled"} 40' in h.gateway.metrics.render()
    h.gateway._loop_refusal_logged[next(iter(h.gateway._loop_refusal_logged))] -= 61.0
    await send(h, token, id=1)
    assert len([r for r in h.full_rows(200) if r["decision"] == "BLOCK"]) == 2


async def test_a_loop_refusal_has_its_own_ledger_record_and_does_not_silence_a_budget_refusal() -> None:
    h, token = wired("throttle", daily=1)
    await send(h, token, id=1)  # uses the one allowed call
    assert refused(await send(h, token, id=2))  # budget refusal: its own ledger record
    assert len([r for r in h.full_rows(200) if r["decision"] == "BLOCK"]) == 1
    for _ in range(LIMIT - 1):  # the loop check runs before Budget Guard, so these budget-refused calls are counted as repeats too
        assert refused(await send(h, token, id=2))
    blocks = [r for r in h.full_rows(200) if r["decision"] == "BLOCK"]
    assert len(blocks) == 2  # the budget's one record, and the loop's own (the loop's ledger limit is separate from the budget's)
    assert 'reason="loop_throttled"} 1' in h.gateway.metrics.render() and 'reason="budget_exceeded"} 4' in h.gateway.metrics.render()


# --- who skips the meter ----------------------------------------------------------------------------------------------

async def test_an_exempt_agent_is_never_flagged_or_throttled() -> None:
    h, token = wired("throttle", exempt=True)
    ran = spy(h)
    for _ in range(40):
        assert not refused(await send(h, token, id=1))
    await h.radar.wait_idle()
    assert loop_reports(h) == [] and ran == []


async def test_an_organization_with_detection_off_skips_the_meter() -> None:
    h, token = wired("off")
    ran = spy(h)
    for _ in range(40):
        assert not refused(await send(h, token, id=1))
    assert ran == []


async def test_the_kill_switch_skips_the_meter_whatever_core_says() -> None:
    h, token = wired("throttle")
    h.gateway.loop_detection_enabled = False
    ran = spy(h)
    for _ in range(40):
        assert not refused(await send(h, token, id=1))
    assert ran == []


# --- failure ----------------------------------------------------------------------------------------------------------

def _broken(*_: Any, **__: Any) -> Any:
    raise RuntimeError("meter failure")


async def test_a_meter_error_denies_in_throttle_and_the_call_is_not_forwarded() -> None:
    h, token = wired("throttle")
    h.gateway.loops.check = _broken  # type: ignore[method-assign,assignment]
    response = await send(h, token, id=1)
    assert response.body["error"]["code"] == JSONRPC_POLICY_VIOLATION and "could not be checked" in response.body["error"]["message"]
    assert forwarded(h) == 0
    assert 'redhand_gateway_loops_total{outcome="error"} 1' in h.gateway.metrics.render()
    assert 'reason="loop_check_error"' in h.gateway.metrics.render()


async def test_a_meter_error_changes_nothing_in_observe() -> None:
    h, token = wired("observe")
    h.gateway.loops.check = _broken  # type: ignore[method-assign,assignment]
    for _ in range(3):
        assert not refused(await send(h, token, id=1))
    assert forwarded(h) == 3
    assert 'redhand_gateway_loops_total{outcome="error"} 3' in h.gateway.metrics.render()


async def test_a_failure_to_queue_a_loop_report_never_affects_the_call(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired("throttle")
    monkeypatch.setattr(h.radar._dispatcher, "submit", _broken)
    for _ in range(LIMIT - 1):
        await send(h, token, id=1)
    assert refused(await send(h, token, id=1))  # still refused by the throttle, no exception reaches the caller


async def test_unhashable_arguments_are_not_counted_and_never_raise_from_the_loop_check() -> None:
    """NaN is valid for Python's JSON parser, so it can reach the gateway. (A separate, older problem: the upstream forwarder cannot
    send it, which is reported in the handoff; the loop check itself must simply step aside.)"""
    h, token = wired("throttle")
    agent = next(iter(h.core.agents))
    context = await h.gateway.contexts.get(UUID(agent), ORG, "xero")
    identity = await h.gateway.verifier.verify(token)
    decision = h.gateway._loop_check(identity, context, "list_invoices", {"x": float("nan")}, throttle=True)
    assert decision is not None and decision.outcome == "untracked" and decision.flagged is False
    assert h.gateway.loops.size == 0
    assert 'redhand_gateway_loops_total{outcome="untracked"} 1' in h.gateway.metrics.render()


async def test_the_evictions_of_a_full_table_are_counted() -> None:
    h, token = wired("observe")
    h.gateway.loops = LoopMeter(clock=h.clock, max_keys_per_agent=1)
    await send(h, token, id=1)
    await send(h, token, id=2)
    assert 'redhand_gateway_loops_total{outcome="evicted"} 1' in h.gateway.metrics.render()


async def test_the_loop_check_stage_is_timed() -> None:
    h, token = wired("observe")
    await send(h, token, id=1)
    assert 'stage="loop_check"' in h.gateway.metrics.render()


# --- the settings from core are required ------------------------------------------------------------------------------

@pytest.mark.parametrize("missing", ["loop_mode", "loop_limit", "loop_window_seconds", "loop_exempt"])
async def test_a_context_without_the_loop_settings_denies(missing: str) -> None:
    h, token = wired("observe")
    del h.core.agents[next(iter(h.core.agents))][missing]  # an older core
    response = await send(h, token, id=1)
    assert response.status_code == 503 and "unavailable" in response.body["error"]["message"].lower()
    assert forwarded(h) == 0


@pytest.mark.parametrize(
    "bad",
    [{"loop_mode": "block"}, {"loop_mode": None}, {"loop_mode": True}, {"loop_limit": 2}, {"loop_limit": 1001}, {"loop_limit": "20"},
     {"loop_limit": True}, {"loop_window_seconds": 9}, {"loop_window_seconds": 601}, {"loop_exempt": "yes"}, {"loop_exempt": 1}],
    ids=["block", "null mode", "bool mode", "limit 2", "limit 1001", "string limit", "bool limit", "window 9", "window 601", "string exempt", "int exempt"],
)
async def test_a_malformed_loop_setting_denies(bad: dict[str, Any]) -> None:
    h, token = wired("observe")
    h.core.agents[next(iter(h.core.agents))].update(bad)
    response = await send(h, token, id=1)
    assert response.status_code == 503 and forwarded(h) == 0


async def test_the_settings_are_per_agent_context_and_follow_core_within_the_cache_lifetime() -> None:
    h, token = wired("observe")
    for _ in range(LIMIT + 3):
        assert not refused(await send(h, token, id=1))
    agent = next(iter(h.core.agents))
    h.core.agents[agent]["loop_mode"] = "throttle"  # an admin turns throttling on
    h.clock.now += 3.0  # the cached passport expires (2 s)
    assert refused(await send(h, token, id=1))  # the observe-mode calls were counted, so the loop is already established


async def test_scopes_and_the_loop_check_share_one_order_so_a_write_tool_is_refused_by_scope_first() -> None:
    h = Harness()
    h.gateway.loops = LoopMeter(clock=h.clock)
    agent = h.add_agent(MIXED_SCOPES, safe_mode=True, loop_mode="throttle", loop_limit=3)
    token = h.token(agent)
    for _ in range(10):
        response = await h.call(token, params=tool("delete_invoice", id=1))
        assert "Safe Mode" in response.body["error"]["message"]
    assert ORG and h.gateway.loops.size == 0
