"""
Phase 2 "done" test 2 (Safe Mode), end to end over the real core and gateway.

  2. With Safe Mode on, a read call succeeds and a write call is refused. The operator turns it
     on in core; the gateway follows within its cache window (<= 2 s, so inside the 5 s SLO).

(Done test 1, the Telegram panic command, is covered in services/redhand-core/tests/test_telegram.py;
 done test 3, Budget Guard, arrives with M3.)
"""

from __future__ import annotations

import asyncio
import time

import pytest

from examples import demo_mcp_server
from test_phase1_done import REVOCATION_SLO_SECONDS, Stack

MIXED = [
    {"server": "xero", "tool": "list_invoices", "access": "read"},
    {"server": "xero", "tool": "delete_invoice", "access": "write"},
]


def _executed() -> list[str]:
    return [c["params"]["name"] for c in demo_mcp_server.calls if c["method"] == "tools/call"]


async def _wait_until_write_refused(stack: Stack, token: str) -> float:
    start = time.monotonic()
    while True:
        resp = await stack.call_tool(token, "delete_invoice", invoice_id="INV-1")
        if "error" in resp.json():
            return time.monotonic() - start
        if time.monotonic() - start > REVOCATION_SLO_SECONDS:
            pytest.fail("Safe Mode did not take effect within the SLO")
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_done_2_agent_safe_mode_allows_reads_and_refuses_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = Stack(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", MIXED)
    token = await stack.agent_token(created["agent_key"])
    agent_id = created["passport"]["id"]

    assert "result" in (await stack.call_tool(token, "delete_invoice", invoice_id="INV-0")).json()  # works today

    on = await stack.core.post(
        f"/v1/passports/{agent_id}/safe-mode", json={"enabled": True, "reason": "incident"}, headers=stack.operator("operator")
    )
    assert on.status_code == 200 and on.json()["changed"] is True
    elapsed = await _wait_until_write_refused(stack, token)
    assert elapsed <= REVOCATION_SLO_SECONDS

    writes_before = _executed().count("delete_invoice")  # includes the calls made while waiting
    read = await stack.call_tool(token, "list_invoices", month="2026-10")
    assert read.json()["result"]["content"][0]["text"] == "demo: list_invoices executed"
    refused = await stack.call_tool(token, "delete_invoice", invoice_id="INV-2")
    assert "Safe Mode is on" in refused.json()["error"]["message"]
    assert _executed().count("delete_invoice") == writes_before  # no write reached the server after the flip
    assert _executed().count("list_invoices") == 1

    blocked = [e for e in await stack.blackbox_events() if e["decision"] == "BLOCK"]
    assert blocked and "not declared read-only" in blocked[-1]["reasons"][0]
    actions = [e["action"] for e in (await stack.core.get("/v1/audit/control", headers=stack.operator("viewer"))).json()]
    assert "passport.safe_mode_enabled" in actions

    # Turning it off needs an admin and an explicit confirmation; writes work again.
    url = f"/v1/passports/{agent_id}/safe-mode"
    assert (await stack.core.post(url, json={"enabled": False, "confirm": True}, headers=stack.operator("operator"))).status_code == 403
    off = await stack.core.post(url, json={"enabled": False, "confirm": True}, headers=stack.operator("admin"))
    assert off.status_code == 200
    await asyncio.sleep(2.1)  # the gateway's cache window
    assert "result" in (await stack.call_tool(token, "delete_invoice", invoice_id="INV-3")).json()
    await stack.close()


@pytest.mark.asyncio
async def test_done_2_organization_safe_mode_covers_every_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = Stack(monkeypatch)
    await stack.register_server()
    first = await stack.register_agent("Bot one", MIXED)
    second = await stack.register_agent("Bot two", MIXED)
    tokens = [await stack.agent_token(a["agent_key"]) for a in (first, second)]

    on = await stack.core.post("/v1/organization/safe-mode", json={"enabled": True}, headers=stack.operator("operator"))
    assert on.status_code == 200
    for token in tokens:
        assert await _wait_until_write_refused(stack, token) <= REVOCATION_SLO_SECONDS
        assert "result" in (await stack.call_tool(token, "list_invoices")).json()
    await stack.close()
