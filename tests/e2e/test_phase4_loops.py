"""
Phase 4 M6 (done test 9), end to end through the real gateway and the real core: an organization sets its loop limit, a loop is flagged
in observe and refused in throttle, the owner sees a finding without any call details, an exempt agent and a switched-off organization
are left alone, and only an admin with a confirmation can turn throttling on.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from test_phase1_done import Stack

from agentwall.src.gateway.loops import LoopMeter
from agentwall.src.gateway.upstream import UpstreamForwarder

ALL_TOOLS = [{"server": "xero", "tool": "*", "access": "read"}]
LIMIT = 3
SECRET_MARKER = "zq-marker-9082"


class Clock:
    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


def _upstream() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        result: Any = {"content": [{"type": "text", "text": "ok"}], "isError": False} if message["method"] == "tools/call" else {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _setup(monkeypatch: pytest.MonkeyPatch) -> tuple[Stack, str, Clock]:
    stack = Stack(monkeypatch, context_ttl=0.0)  # no context cache: a setting change applies on the next call
    clock = Clock()
    stack.gateway.loops = LoopMeter(clock=clock)
    stack.gateway.forwarder = UpstreamForwarder(allow_insecure=True, max_response_bytes=1_000_000, connect_timeout=2, total_timeout=5, http_client=_upstream())
    await stack.register_server()
    created = await stack.register_agent("Loop bot", ALL_TOOLS)
    return stack, await stack.agent_token(created["agent_key"]), clock


async def _set(stack: Stack, mode: str, user: str = "admin", **extra: Any) -> httpx.Response:
    body = {"loop_mode": mode, "loop_limit": LIMIT, "loop_window_seconds": 60, **extra}
    return await stack.core.put("/v1/radar/loop-settings", json=body, headers=stack.operator(user))


async def _call(stack: Stack, token: str, **args: Any) -> httpx.Response:
    response = await stack.call_tool(token, "list_invoices", **args)
    await stack.gateway.radar.wait_idle()  # the report runs in the background
    return response


def _refused(response: httpx.Response) -> bool:
    return "error" in response.json()


async def _loop_findings(stack: Stack) -> list[dict[str, Any]]:
    resp = await stack.core.get("/v1/findings", params={"kind": "loop"}, headers=stack.operator("operator"))
    assert resp.status_code == 200, resp.text
    return list(resp.json()["findings"])


@pytest.mark.asyncio
async def test_done_9_observe_flags_a_loop_without_refusing_and_the_owner_sees_a_finding_without_details(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, _ = await _setup(monkeypatch)
    assert (await _set(stack, "observe")).status_code == 200
    for _ in range(LIMIT + 4):
        response = await _call(stack, token, note=SECRET_MARKER)
        assert response.status_code == 200 and not _refused(response)  # observe never refuses
    findings = await _loop_findings(stack)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "RAD-LOOP-001" and finding["kind"] == "loop" and finding["place"] == "call"
    assert finding["agent_name"] == "Loop bot" and finding["tool_name"] == "list_invoices" and finding["server_slug"] == "xero"
    assert SECRET_MARKER not in json.dumps(findings)
    # a loop is not a false alarm of the Radar's own checks
    radar = await stack.core.get("/v1/radar/settings", headers=stack.operator("operator"))
    assert radar.json()["last_7_days"].get("findings", 0) == 0
    summary = await stack.core.get("/v1/radar/loop-settings", headers=stack.operator("operator"))
    assert summary.json()["last_7_days"]["findings"] == 1


@pytest.mark.asyncio
async def test_done_9_throttle_refuses_the_repeat_and_the_agent_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, clock = await _setup(monkeypatch)
    assert (await _set(stack, "throttle", confirm=True)).status_code == 200
    for _ in range(LIMIT - 1):
        assert not _refused(await _call(stack, token, id=1))
    refused = await _call(stack, token, id=1)
    assert _refused(refused) and refused.json()["error"]["code"] == -32000 and "repeated too often" in refused.json()["error"]["message"]
    assert not _refused(await _call(stack, token, id=2))  # a different call is not a loop
    clock.now += 61.0
    assert not _refused(await _call(stack, token, id=1))  # the window moved on
    assert len(await _loop_findings(stack)) == 1


@pytest.mark.asyncio
async def test_a_refused_repeat_is_not_forwarded_and_does_not_count_against_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, _ = await _setup(monkeypatch)
    agent = (await stack.core.get("/v1/passports", headers=stack.operator("viewer"))).json()[0]["id"]
    limited = await stack.core.put(
        f"/v1/passports/{agent}/budget", json={"daily_call_limit": LIMIT + 1, "action": "deny", "confirm": True}, headers=stack.operator("admin")
    )
    assert limited.status_code == 200, limited.text
    assert (await _set(stack, "throttle", confirm=True)).status_code == 200
    for _ in range(LIMIT - 1):
        assert not _refused(await _call(stack, token, id=1))  # LIMIT - 1 units
    for _ in range(25):
        assert _refused(await _call(stack, token, id=1))  # loop-throttled: no units
    assert not _refused(await _call(stack, token, id=2))  # unit LIMIT
    assert not _refused(await _call(stack, token, id=3))  # unit LIMIT + 1 (the last one)
    assert _refused(await _call(stack, token, id=4))  # now the daily limit


@pytest.mark.asyncio
async def test_an_exempt_agent_is_not_throttled_and_losing_the_exemption_ends_it(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, _ = await _setup(monkeypatch)
    await _set(stack, "throttle", confirm=True)
    agent = (await stack.core.get("/v1/passports", headers=stack.operator("viewer"))).json()[0]["id"]
    made = await stack.core.post(
        "/v1/radar/suppressions", json={"agent_id": agent, "rule_id": "RAD-LOOP-001", "reason": "a polling agent", "confirm": True},
        headers=stack.operator("admin"),
    )
    assert made.status_code in (200, 201), made.text
    for _ in range(20):
        assert not _refused(await _call(stack, token, id=1))
    assert await _loop_findings(stack) == []
    revoked = await stack.core.delete(f"/v1/radar/suppressions/{made.json()['id']}", headers=stack.operator("admin"))
    assert revoked.status_code == 200
    results = [_refused(await _call(stack, token, id=1)) for _ in range(LIMIT)]
    assert results[-1] is True


@pytest.mark.asyncio
async def test_turning_detection_off_stops_counting_and_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, _ = await _setup(monkeypatch)
    assert (await _set(stack, "off")).status_code == 400  # off needs a confirmation
    assert (await _set(stack, "off", confirm=True)).status_code == 200
    for _ in range(LIMIT * 3):
        assert not _refused(await _call(stack, token, id=1))
    assert await _loop_findings(stack) == []
    assert stack.gateway.loops.size == 0


@pytest.mark.asyncio
async def test_only_an_admin_with_a_confirmation_can_turn_throttling_on(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, _ = await _setup(monkeypatch)
    assert (await _set(stack, "throttle", user="viewer", confirm=True)).status_code == 403
    assert (await _set(stack, "throttle", user="operator", confirm=True)).status_code == 403
    assert (await _set(stack, "throttle")).status_code == 400  # an admin without the confirmation
    for _ in range(LIMIT * 2):
        assert not _refused(await _call(stack, token, id=1))  # still observe: nothing was refused
    audit = await stack.core.get("/v1/audit/control", headers=stack.operator("viewer"))
    assert audit.status_code == 200 and not any(r.get("action") == "organization.loop_settings_changed" for r in audit.json())


@pytest.mark.asyncio
async def test_the_kill_switch_overrides_a_throttling_organization(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, _ = await _setup(monkeypatch)
    await _set(stack, "throttle", confirm=True)
    stack.gateway.loop_detection_enabled = False
    for _ in range(LIMIT * 3):
        assert not _refused(await _call(stack, token, id=1))
