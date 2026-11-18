"""
Phase 2 "done" test 3 (Budget Guard), end to end over the real core and gateway.

  3. An agent over its daily limit is refused and the owner is alerted.

Real components wired in-process: operator -> core, agent -> gateway -> core and the demo MCP server. The
gateway reports its call counts to core over the real /internal/v1/usage endpoint, and core's alerts reach a
fake Telegram. (Done test 1 is in services/redhand-core/tests/test_telegram.py, done test 2 in
tests/e2e/test_phase2_done.py.)
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from examples import demo_mcp_server
from redhand_core.routers import telegram as telegram_router
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS
from test_phase1_done import Stack

READ_ONE = [{"server": "xero", "tool": "list_invoices", "access": "read"}]
OWNER_CHAT = 4242


class FakeTelegram:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str) -> bool:
        self.sent.append((chat_id, text))
        return True


def _stack_with_telegram(monkeypatch: pytest.MonkeyPatch) -> tuple[Stack, FakeTelegram]:
    stack = Stack(monkeypatch)
    fake = FakeTelegram()
    stack.core_app.dependency_overrides[telegram_router.get_optional_telegram_client] = lambda: fake
    stack.store.tables.setdefault("telegram_links", []).append(
        {"id": "link-1", "organization_id": DEFAULT_ORG_ID, "user_id": DEV_OPERATORS["owner"]["id"],
         "chat_id": OWNER_CHAT, "created_at": "2026-11-04T00:00:00+00:00", "revoked_at": None}
    )
    return stack, fake


async def _set_limit(stack: Stack, agent_id: str, limit: int, action: str = "deny") -> None:
    resp = await stack.core.put(
        f"/v1/passports/{agent_id}/budget", json={"daily_call_limit": limit, "action": action}, headers=stack.operator("operator")
    )
    assert resp.status_code == 200, resp.text


def _executed() -> list[str]:
    return [c["params"]["name"] for c in demo_mcp_server.calls if c["method"] == "tools/call"]


def _alerts(fake: FakeTelegram) -> list[str]:
    return [text for chat, text in fake.sent if chat == OWNER_CHAT and text.startswith("Budget Guard:")]


@pytest.mark.asyncio
async def test_done_3_an_agent_over_its_daily_limit_is_refused_and_the_owner_is_alerted(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, fake = _stack_with_telegram(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", READ_ONE)
    token = await stack.agent_token(created["agent_key"])
    agent_id = created["passport"]["id"]
    await _set_limit(stack, agent_id, 5)

    results: list[Any] = []
    for _ in range(5):
        results.append(await stack.call_tool(token, "list_invoices", month="2026-10"))
    assert all("result" in r.json() for r in results)

    sixth = await stack.call_tool(token, "list_invoices", month="2026-10")
    error = sixth.json()["error"]
    assert "daily limit of 5 tool calls" in error["message"]
    assert error["data"]["daily_call_limit"] == 5 and error["data"]["used"] == 5
    assert _executed() == ["list_invoices"] * 5  # the sixth call never reached the MCP server

    blocked = [e for e in await stack.blackbox_events() if e["decision"] == "BLOCK"]
    assert blocked and "Daily limit of 5 tool calls reached" in blocked[-1]["reasons"][0]

    # The owner was alerted at 80% (the 4th call) and at the limit (the 5th), once each, in plain "calls".
    alerts = _alerts(fake)
    assert alerts[0] == "Budget Guard: Invoice bot has used 4 of its 5 daily tool calls (80%)."
    assert "reached its daily limit of 5 tool calls" in alerts[1] and len(alerts) == 2

    usage = (await stack.core.get("/v1/usage", headers=stack.operator("viewer"))).json()
    mine = next(a for a in usage["agents"] if a["agent_id"] == agent_id)
    assert mine["calls"] == 5 and mine["daily_call_limit"] == 5 and mine["percent"] == 100
    await stack.close()


@pytest.mark.asyncio
async def test_done_3_with_auto_freeze_the_agent_ends_up_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, fake = _stack_with_telegram(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Runaway bot", READ_ONE)
    token = await stack.agent_token(created["agent_key"])
    agent_id = created["passport"]["id"]
    await _set_limit(stack, agent_id, 3, "freeze")

    for _ in range(3):
        assert "result" in (await stack.call_tool(token, "list_invoices")).json()
    assert "daily limit of 3" in (await stack.call_tool(token, "list_invoices")).json()["error"]["message"]

    listed = (await stack.core.get("/v1/passports", headers=stack.operator("viewer"))).json()
    assert next(p for p in listed if p["id"] == agent_id)["status"] == "frozen"
    audit = (await stack.core.get("/v1/audit/control", headers=stack.operator("viewer"))).json()
    freeze = next(e for e in audit if e["action"] == "passport.frozen" and e["target_id"] == agent_id)
    assert freeze["actor_user_id"] == "00000000-0000-0000-0000-000000000000"  # the Budget Guard system actor
    assert "It has also been frozen" in _alerts(fake)[-1]

    await asyncio.sleep(2.1)  # the gateway's cache window: now the passport itself refuses the agent
    after = await stack.call_tool(token, "list_invoices")
    assert after.status_code == 403
    assert _executed() == ["list_invoices"] * 3
    await stack.close()


@pytest.mark.asyncio
async def test_an_agent_without_a_limit_is_counted_but_never_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, fake = _stack_with_telegram(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Free bot", READ_ONE)
    token = await stack.agent_token(created["agent_key"])
    for _ in range(12):
        assert "result" in (await stack.call_tool(token, "list_invoices")).json()
    await stack.gateway.budget.flush()
    usage = (await stack.core.get("/v1/usage", headers=stack.operator("viewer"))).json()
    mine = next(a for a in usage["agents"] if a["agent_id"] == created["passport"]["id"])
    assert mine["calls"] == 12 and mine["percent"] is None
    assert _alerts(fake) == []
    await stack.close()


@pytest.mark.asyncio
async def test_raising_the_limit_lets_the_agent_work_again_within_the_cache_window(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, _ = _stack_with_telegram(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", READ_ONE)
    token = await stack.agent_token(created["agent_key"])
    agent_id = created["passport"]["id"]
    await _set_limit(stack, agent_id, 2)
    for _ in range(2):
        await stack.call_tool(token, "list_invoices")
    assert "daily limit" in (await stack.call_tool(token, "list_invoices")).json()["error"]["message"]

    raised = await stack.core.put(
        f"/v1/passports/{agent_id}/budget", json={"daily_call_limit": 4, "confirm": True}, headers=stack.operator("admin")
    )
    assert raised.status_code == 200
    await asyncio.sleep(2.1)
    assert "result" in (await stack.call_tool(token, "list_invoices")).json()
    await stack.close()
