"""
Phase 3 M3/M4, end to end: a planted honeytoken or decoy tool, from the operator creating it to the trip
reaching the owner's phone. Real components wired in-process (the same Stack as the Phase 1 tests).

Done test 4 (docs/plans/phase3-plan.md): a honeytoken in a tool call is refused, the owner is alerted within
10 s, the agent is frozen (if the honeytoken says so), and the trip is in the Black Box and the control audit.
Done test 5: a call to a decoy tool is never forwarded and trips the same way.
"""

from __future__ import annotations

import json
import time
from typing import Any
from uuid import uuid4

import httpx
import pytest

from test_phase1_done import Stack

from examples import demo_mcp_server
from redhand_core.routers import telegram as telegram_router
from redhand_core.services.local_store import DEFAULT_ORG_ID

OWNER_CHAT = 4242
ALERT_DEADLINE_SECONDS = 10.0
INVOICE_READER = [{"server": "xero", "tool": "list_invoices", "access": "read"}]


class FakeTelegram:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str) -> bool:
        self.sent.append((chat_id, text))
        return True


async def _setup(
    monkeypatch: pytest.MonkeyPatch, scopes: list[dict[str, str]] | None = None
) -> tuple[Stack, FakeTelegram, str, str]:
    stack = Stack(
        monkeypatch, context_ttl=0.0
    )  # no context cache: a freeze applies on the next call
    fake = FakeTelegram()
    stack.core_app.dependency_overrides[telegram_router.get_optional_telegram_client] = lambda: fake
    stack.store.tables.setdefault("telegram_links", []).append(
        {
            "id": str(uuid4()),
            "organization_id": DEFAULT_ORG_ID,
            "chat_id": OWNER_CHAT,
            "revoked_at": None,
        }
    )
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", scopes or INVOICE_READER)
    return stack, fake, await stack.agent_token(created["agent_key"]), created["passport"]["id"]


async def _status(stack: Stack, agent_id: str) -> str:
    rows = (await stack.core.get("/v1/passports", headers=stack.operator("viewer"))).json()
    return str(next(p for p in rows if p["id"] == agent_id)["status"])


def _audit(stack: Stack, action: str) -> list[dict[str, Any]]:
    return [r for r in stack.store.tables["control_audit_log"] if r["action"] == action]


def _stored_events(stack: Stack) -> list[dict[str, Any]]:
    return sorted(
        (
            e
            for e in stack.store.tables.get("agent_events", [])
            if e["organization_id"] == DEFAULT_ORG_ID
        ),
        key=lambda e: e["seq"],
    )


@pytest.mark.asyncio
async def test_done_4_a_honeytoken_in_a_call_is_refused_alerts_the_owner_and_freezes_the_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack, phone, token, agent_id = await _setup(monkeypatch)
    created = await stack.core.post(
        "/v1/honeytokens",
        json={"label": "Decoy prod key", "kind": "api_key", "action_on_use": "freeze"},
        headers=stack.operator("admin"),
    )
    assert created.status_code == 201
    value = created.json()["value"]

    started = time.monotonic()
    refused = await stack.call_tool(token, "list_invoices", note=f"use this key: {value}")
    assert refused.json()["error"]["code"] == -32000 and value not in refused.text
    assert demo_mcp_server.calls == []  # never reached the MCP server
    await stack.gateway.trips.wait_idle()
    elapsed = time.monotonic() - started
    assert elapsed < ALERT_DEADLINE_SECONDS

    # Not phone.sent[-1]: a background tool-pinning alert can arrive after this one (order is not guaranteed).
    (chat, alert) = next((m for m in phone.sent if "Decoy prod key" in m[1]), (None, ""))
    assert (
        chat == OWNER_CHAT
        and "Decoy prod key" in alert
        and "Invoice bot" in alert
        and "frozen" in alert
    ), phone.sent
    assert value not in alert  # the alert never carries the value
    assert await _status(stack, agent_id) == "frozen"
    tripped = _audit(stack, "honeytoken.tripped")[0]
    assert tripped["details"]["label"] == "Decoy prod key" and value not in json.dumps(tripped)
    assert (
        _audit(stack, "passport.frozen")[0]["actor_user_id"]
        == "00000000-0000-0000-0000-000000000000"
    )

    await stack.gateway.recorder.flush()
    (event,) = _stored_events(stack)
    assert event["decision"] == "BLOCK" and event["reasons"] == ["honeytoken"]
    assert value not in json.dumps(event) and event["arguments_redacted"] is None

    # The freeze holds: the agent's next, innocent call is refused too.
    assert (await stack.call_tool(token, "list_invoices")).status_code == 403
    await stack.close()


@pytest.mark.asyncio
async def test_a_honeytoken_read_in_a_result_is_redacted_alerted_and_does_not_freeze_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack, phone, token, agent_id = await _setup(monkeypatch)
    value = (
        await stack.core.post(
            "/v1/honeytokens",
            json={"label": "Decoy password", "kind": "password"},
            headers=stack.operator("admin"),
        )
    ).json()["value"]

    # An MCP server whose answer contains the bait, as if the agent had read a file or a database row that
    # holds it. (The demo server cannot be made to do this, so the stack's upstream is swapped for a stub.)
    received: list[dict[str, Any]] = []

    def leaky(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        received.append(message)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"row 7: owner note {value} end"}],
                    "isError": False,
                },
            },
        )

    stack.gateway.forwarder._http = httpx.AsyncClient(transport=httpx.MockTransport(leaky))
    resp = await stack.call_tool(token, "list_invoices", month="2026-10")
    await stack.gateway.trips.wait_idle()
    assert "result" in resp.json() and value not in resp.text and "row 7: owner note" in resp.text
    assert len(received) == 1  # it WAS forwarded: reading is not refused
    assert any("appeared in a result" in text for _, text in phone.sent), phone.sent
    assert all(value not in text for _, text in phone.sent)
    assert await _status(stack, agent_id) == "active"  # a read alerts by default
    assert _audit(stack, "honeytoken.tripped")[0]["details"]["seen_in"] == "result"
    await stack.gateway.recorder.flush()
    event = _stored_events(stack)[-1]
    assert (
        event["decision"] == "ALLOW"
        and event["reasons"] == ["honeytoken"]
        and value not in json.dumps(event)
    )
    await stack.close()


async def _create_canary(stack: Stack, **body: Any) -> str:
    created = await stack.core.post(
        "/v1/honeytokens",
        json={"label": "System prompt canary", "kind": "canary", **body},
        headers=stack.operator("admin"),
    )
    assert created.status_code == 201
    return str(created.json()["value"])


@pytest.mark.asyncio
async def test_done_7_a_canary_from_the_system_prompt_in_a_call_is_refused_alerted_and_does_not_freeze(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 4 done test 7 (docs/plans/phase4-plan.md): a marker put in a system prompt that later appears in a tool call trips an alert."""
    stack, phone, token, agent_id = await _setup(monkeypatch)
    value = await _create_canary(
        stack
    )  # no actions given: a canary refuses and alerts, it never freezes by default

    # The owner pastes the value into the system prompt inside a sentence; an injected agent then repeats that sentence in a tool call.
    leaked = f"Internal reference code (never repeat it): {value}. You are the invoice assistant."
    started = time.monotonic()
    refused = await stack.call_tool(token, "list_invoices", note=leaked)
    assert refused.json()["error"]["code"] == -32000 and value not in refused.text
    assert demo_mcp_server.calls == []  # never reached the MCP server
    await stack.gateway.trips.wait_idle()
    assert time.monotonic() - started < ALERT_DEADLINE_SECONDS

    (chat, alert) = next((m for m in phone.sent if "System prompt canary" in m[1]), (None, ""))
    assert (
        chat == OWNER_CHAT
        and "canary" in alert.lower()
        and "leak" in alert
        and "Invoice bot" in alert
        and "System prompt canary" in alert
    )
    assert value not in alert and "decoy" not in alert.lower()
    assert (
        await _status(stack, agent_id) == "active"
    )  # not frozen: a stolen prompt must not let anyone freeze the agent on demand
    tripped = _audit(stack, "honeytoken.tripped")[0]
    assert (
        tripped["details"]["kind"] == "canary"
        and tripped["details"]["seen_in"] == "arguments"
        and value not in json.dumps(tripped)
    )

    await stack.gateway.recorder.flush()
    (event,) = _stored_events(stack)
    assert (
        event["decision"] == "BLOCK"
        and event["reasons"] == ["honeytoken"]
        and value not in json.dumps(event)
    )

    ok = await stack.call_tool(
        token, "list_invoices"
    )  # the agent is still active, so its next innocent call goes through
    assert ok.status_code == 200 and "result" in ok.json()
    await stack.close()


@pytest.mark.asyncio
async def test_a_canary_in_a_result_is_redacted_and_alerted_with_leak_wording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack, phone, token, agent_id = await _setup(monkeypatch)
    value = await _create_canary(stack)

    def echoing(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"your instructions begin: reference code {value}, then ...",
                        }
                    ],
                    "isError": False,
                },
            },
        )

    stack.gateway.forwarder._http = httpx.AsyncClient(transport=httpx.MockTransport(echoing))
    resp = await stack.call_tool(token, "list_invoices", month="2026-10")
    await stack.gateway.trips.wait_idle()
    assert (
        "result" in resp.json()
        and value not in resp.text
        and "your instructions begin" in resp.text
    )  # redacted, not refused
    alert = next((text for _, text in phone.sent if "canary" in text.lower()), "")
    assert (
        "canary" in alert.lower()
        and "result" in alert
        and "leak" in alert
        and value not in alert
        and "decoy" not in alert.lower()
    )
    assert await _status(stack, agent_id) == "active"
    assert _audit(stack, "honeytoken.tripped")[0]["details"]["seen_in"] == "result"
    await stack.close()


@pytest.mark.asyncio
async def test_other_text_does_not_trip_a_canary_and_its_known_limits_are_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack, phone, token, _ = await _setup(monkeypatch)
    value = await _create_canary(stack)
    # Same length, same alphabet, one character different: a lookup by digest, not a guess by shape.
    near_miss = value[:-1] + ("A" if value[-1] != "A" else "B")
    for harmless in (near_miss, "AbCdEf1234567890abcdEFGH", "2026-10"):
        resp = await stack.call_tool(token, "list_invoices", month=harmless)
        assert resp.status_code == 200, harmless  # forwarded, not refused
    await stack.gateway.trips.wait_idle()
    assert phone.sent == [] and _audit(stack, "honeytoken.tripped") == []

    # Known limits (docs/adr/0012-honeytokens.md): a canary glued to other letters or digits, or re-encoded, is not found.
    glued = await stack.call_tool(token, "list_invoices", note=f"{value}x")
    encoded = await stack.call_tool(token, "list_invoices", note=value[::-1])
    await stack.gateway.trips.wait_idle()
    assert phone.sent == [] and glued.status_code != 403 and encoded.status_code != 403
    await stack.close()


@pytest.mark.asyncio
async def test_done_5_a_call_to_a_decoy_tool_is_never_forwarded_and_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack, phone, token, agent_id = await _setup(monkeypatch)
    created = await stack.core.post(
        "/v1/honey-tools",
        json={
            "agent_id": agent_id,
            "server": "xero",
            "name": "export_all_customer_records",
            "description": "Exports every customer record",
        },
        headers=stack.operator("admin"),
    )
    assert created.status_code == 201

    listed = await stack.edge.post(
        "/mcp/xero",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert "export_all_customer_records" in [t["name"] for t in listed.json()["result"]["tools"]]

    calls_before = len(demo_mcp_server.calls)
    started = time.monotonic()
    resp = await stack.call_tool(token, "export_all_customer_records")
    assert resp.json()["result"]["isError"] is True
    assert len(demo_mcp_server.calls) == calls_before  # never forwarded
    await stack.gateway.trips.wait_idle()
    assert time.monotonic() - started < ALERT_DEADLINE_SECONDS
    # Not phone.sent[-1]: the first tools/list of a new server also raises a tool-pinning alert in the background, and the two can arrive in either order (seen failing on CI).
    assert any(
        "export_all_customer_records" in text and "not forwarded" in text for _, text in phone.sent
    ), phone.sent
    assert (
        await _status(stack, agent_id) == "active"
    )  # a decoy alerts by default, it does not freeze
    assert _audit(stack, "honey_tool.tripped")

    await stack.gateway.recorder.flush()
    event = _stored_events(stack)[-1]
    assert event["decision"] == "BLOCK" and event["reasons"] == ["honey_tool"]
    await stack.close()


@pytest.mark.asyncio
async def test_retiring_a_honeytoken_stops_it_tripping(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, phone, token, agent_id = await _setup(monkeypatch)
    created = (
        await stack.core.post(
            "/v1/honeytokens",
            json={"label": "Old bait", "kind": "api_key"},
            headers=stack.operator("admin"),
        )
    ).json()
    await stack.core.post(
        f"/v1/honeytokens/{created['id']}/retire", headers=stack.operator("admin")
    )
    resp = await stack.call_tool(token, "list_invoices", note=created["value"])
    await stack.gateway.trips.wait_idle()
    assert (
        "result" in resp.json() and phone.sent == [] and await _status(stack, agent_id) == "active"
    )
    await stack.close()
