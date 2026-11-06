"""
Phase 3 M2b, end to end: payload capture from an operator's switch to a stored, redacted excerpt.

Real components wired in-process (the same Stack as the Phase 1 tests):
  operator --> core: turn capture on / off, read the timeline and verify the chain
  agent    --> gateway --> demo MCP server; the gateway's recorder --> core's ingest --> the store

Done test 3 (docs/plans/phase3-plan.md): with capture off no argument values or results are stored; with
capture on they are stored redacted and size-capped; the chain still verifies.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from test_phase1_done import Stack

from redhand_core.services.local_store import DEFAULT_ORG_ID

INVOICE_READER = [{"server": "xero", "tool": "list_invoices", "access": "read"}]
EMAIL = "ali.bin.abu@example.com.my"
NRIC = "900101-14-5678"


def _stored(stack: Stack) -> list[dict[str, Any]]:
    return sorted(
        (e for e in stack.store.tables.get("agent_events", []) if e["organization_id"] == DEFAULT_ORG_ID),
        key=lambda e: e["seq"],
    )


async def _set_capture(stack: Stack, user: str, **body: Any) -> Any:
    return await stack.core.put("/v1/blackbox/payload-capture", json=body, headers=stack.operator(user))


async def _setup(monkeypatch: pytest.MonkeyPatch) -> tuple[Stack, str]:
    stack = Stack(monkeypatch, context_ttl=0.0)  # no context cache: a setting change applies on the next call
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", INVOICE_READER)
    return stack, await stack.agent_token(created["agent_key"])


@pytest.mark.asyncio
async def test_done_3_capture_off_stores_no_payload_then_on_stores_redacted_excerpts(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, token = await _setup(monkeypatch)

    # Off by default: the call is recorded, its values are not.
    await stack.call_tool(token, "list_invoices", contact=EMAIL, ic=NRIC)
    await stack.gateway.recorder.flush()
    (first,) = _stored(stack)
    assert first["decision"] == "ALLOW" and first["argument_keys"] == ["contact", "ic"]
    assert first["arguments_redacted"] is None and first["result_excerpt"] is None

    # An admin turns it on (confirmation required).
    assert (await _set_capture(stack, "admin", enabled=True)).status_code == 400
    resp = await _set_capture(stack, "admin", enabled=True, confirm=True, reason="debugging")
    assert resp.status_code == 200 and resp.json()["payload_capture_enabled"] is True

    await stack.call_tool(token, "list_invoices", month="2026-10", contact=EMAIL, ic=NRIC)
    await stack.call_tool(token, "delete_invoice", invoice_id="INV-9", contact=EMAIL)  # out of scope: refused
    await stack.gateway.recorder.flush()
    allowed, refused = _stored(stack)[1:]

    assert allowed["decision"] == "ALLOW" and refused["decision"] == "BLOCK"
    args = json.loads(allowed["arguments_redacted"]["text"])
    assert args["month"] == "2026-10"  # ordinary values are kept
    assert args["contact"] == "[REDACTED:EMAIL]" and args["ic"] == "[REDACTED:NRIC]"  # personal data is not
    assert "demo: list_invoices executed" in allowed["result_excerpt"]["text"]
    assert refused["arguments_redacted"] is not None and refused["result_excerpt"] is None
    for event in (allowed, refused):
        assert EMAIL not in json.dumps(event) and NRIC not in json.dumps(event)
        for excerpt in (event["arguments_redacted"], event["result_excerpt"]):
            if excerpt is not None:
                assert len(excerpt["text"]) <= 2048 and excerpt["truncated"] is False

    # The operator timeline never carries payloads, and the chain verifies with and without them.
    timeline = await stack.core.get("/v1/blackbox/events", headers=stack.operator("viewer"))
    assert "arguments_redacted" not in timeline.text and "[REDACTED" not in timeline.text
    verify = await stack.core.get("/v1/blackbox/verify", params={"from_seq": 1, "to_seq": 3}, headers=stack.operator("viewer"))
    assert verify.json() == {"ok": True, "checked": 3, "broken_seq": None, "reason": None}

    # A security operator can turn it off at once, without confirmation, and capture stops.
    assert (await _set_capture(stack, "operator", enabled=False)).status_code == 200
    await stack.call_tool(token, "list_invoices", contact=EMAIL)
    await stack.gateway.recorder.flush()
    last = _stored(stack)[-1]
    assert last["arguments_redacted"] is None and last["result_excerpt"] is None
    await stack.close()


@pytest.mark.asyncio
async def test_capture_changes_are_audited_with_the_acting_user(monkeypatch: pytest.MonkeyPatch) -> None:
    stack, _ = await _setup(monkeypatch)
    await _set_capture(stack, "admin", enabled=True, confirm=True)
    await _set_capture(stack, "operator", enabled=False)
    audit = [
        r for r in stack.store.tables["control_audit_log"] if r["action"] == "organization.payload_capture_changed"
    ]
    assert [r["details"]["new_enabled"] for r in audit] == [False, True]
    assert {r["actor_user_id"] for r in audit} == {
        "00000000-0000-0000-0000-0000000000a2",  # admin
        "00000000-0000-0000-0000-0000000000a3",  # security operator
    }
    await stack.close()


@pytest.mark.asyncio
async def test_a_captured_payload_is_read_and_exported_only_by_the_right_roles_and_each_access_is_audited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack, token = await _setup(monkeypatch)
    await _set_capture(stack, "admin", enabled=True, confirm=True)
    await stack.call_tool(token, "list_invoices", month="2026-10", contact=EMAIL)
    await stack.gateway.recorder.flush()

    def audits(action: str) -> list[dict[str, Any]]:
        return [r for r in stack.store.tables["control_audit_log"] if r["action"] == action]

    assert (await stack.core.get("/v1/blackbox/events/1/payload", headers=stack.operator("viewer"))).status_code == 403
    assert (await stack.core.get("/v1/blackbox/events/1/payload", headers=stack.operator("operator"))).status_code == 403
    assert audits("organization.blackbox_payload_viewed") == []

    viewed = await stack.core.get("/v1/blackbox/events/1/payload", headers=stack.operator("admin"))
    assert viewed.status_code == 200 and viewed.headers["cache-control"] == "no-store"
    args = json.loads(viewed.json()["arguments_redacted"]["text"])
    assert args["contact"] == "[REDACTED:EMAIL]" and EMAIL not in viewed.text
    assert len(audits("organization.blackbox_payload_viewed")) == 1

    export = await stack.core.get(
        "/v1/blackbox/export", params={"include_payloads": "true"}, headers=stack.operator("admin")
    )
    lines = [json.loads(line) for line in export.text.splitlines()]
    assert lines[0]["seq"] == 1 and "[REDACTED:EMAIL]" in lines[0]["arguments_redacted"]["text"]
    assert lines[-1] == {"export_complete": True, "rows": 1, "capped_at": None}
    assert EMAIL not in export.text
    assert audits("organization.blackbox_exported")[0]["details"]["include_payloads"] is True
    await stack.close()
