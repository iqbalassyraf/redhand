"""
Errors from the customer's MCP server (H4.3). The gateway redacted secrets and checked for honeytokens in a tool RESULT only, and passed a JSON-RPC
`error` through untouched. A server (or a failing backend behind it) that puts a credential, a stack trace with a connection string, or a planted
bait value in an error message or its data therefore reached the agent, and a bait read through an error was never reported. An error is now
treated like a result: secrets are redacted, bait is redacted and reported as a trip, and nothing the server says is added or kept.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from test_gateway import Harness, INVOICES_READ, tool
from test_gateway_honeytokens import AWS_KEY, PASSWORD, _ref, _wired

LEAK = "AKIAIOSFODNN7EXAMPLE"


def serve(h: Harness, error: Any, methods: tuple[str, ...] = ("tools/call",)) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if message.get("method") in methods:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "error": error})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {}})

    h.gateway.forwarder._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_a_secret_in_an_error_message_is_redacted_and_the_error_keeps_its_code() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, {"code": -32010, "message": f"backend failed: key {LEAK} rejected"})
    resp = await h.call(token, params=tool("list_invoices"))
    assert LEAK not in json.dumps(resp.body)
    assert resp.body["error"]["code"] == -32010 and "backend failed" in resp.body["error"]["message"]
    assert resp.body["id"] == 7


@pytest.mark.asyncio
async def test_a_secret_deep_in_the_error_data_is_redacted() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, {"code": -32000, "message": "failed", "data": {"trace": [{"frame": f"connect(key={LEAK})"}], "other": 1}})
    resp = await h.call(token, params=tool("list_invoices"))
    assert LEAK not in json.dumps(resp.body) and resp.body["error"]["data"]["other"] == 1


@pytest.mark.asyncio
async def test_the_redaction_is_counted_in_the_black_box_record() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, {"code": -32000, "message": f"key {LEAK}"})
    await h.call(token, params=tool("list_invoices"))
    await h.recorder.flush()
    (event,) = h.event_reporter.events
    assert event["redaction_count"] >= 1 and LEAK not in json.dumps(event)


@pytest.mark.asyncio
async def test_a_clean_error_passes_through_unchanged() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    error = {"code": -32602, "message": "Invalid params: invoice_id is required", "data": {"field": "invoice_id"}}
    serve(h, error)
    resp = await h.call(token, params=tool("list_invoices"))
    assert resp.body["error"] == error


@pytest.mark.asyncio
async def test_bait_read_through_an_error_is_redacted_and_reported_as_a_trip() -> None:
    ref = _ref(PASSWORD)
    h, _, token = _wired([ref], payload_capture=True)
    serve(h, {"code": -32000, "message": f"db error near password {PASSWORD} end"})
    resp = await h.call(token, params=tool("list_invoices"))
    assert PASSWORD not in json.dumps(resp.body) and "db error near password" in resp.body["error"]["message"]
    await h.trips.wait_idle()
    (trip,) = h.trip_reporter.trips
    assert (trip.kind, trip.seen_in, trip.ref_id) == ("honeytoken", "result", ref.id)
    await h.recorder.flush()
    (event,) = h.event_reporter.events
    assert event["reasons"] == ["honeytoken"] and PASSWORD not in json.dumps(event)


@pytest.mark.asyncio
async def test_a_string_error_object_is_handled_and_still_an_error() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, f"plain text failure with {AWS_KEY} and {LEAK}")
    resp = await h.call(token, params=tool("list_invoices"))
    assert "error" in resp.body and LEAK not in json.dumps(resp.body)


@pytest.mark.asyncio
async def test_errors_to_other_methods_are_redacted_too() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, {"code": -32000, "message": f"list failed {LEAK}"}, methods=("tools/list",))
    resp = await h.call(token, method="tools/list")
    assert LEAK not in json.dumps(resp.body) and "error" in resp.body


@pytest.mark.asyncio
async def test_a_scanner_failure_on_an_error_denies_instead_of_leaking(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentwall.src.gateway import service

    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, {"code": -32000, "message": f"x {LEAK}"})

    real = service.scan_honeytokens
    calls: list[int] = []

    def boom_on_the_error(value: Any, tokens: Any) -> Any:
        calls.append(1)
        if len(calls) == 1:  # the first scan is of the request's arguments: let it run
            return real(value, tokens)
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(service, "scan_honeytokens", boom_on_the_error)
    resp = await h.call(token, params=tool("list_invoices"))
    assert resp.body["error"]["code"] == -32000 and LEAK not in json.dumps(resp.body)
    assert resp.body["error"]["message"] == "PolicyViolation: result could not be checked."


@pytest.mark.asyncio
async def test_the_kill_switch_restores_the_pass_through() -> None:
    h = Harness()
    h.gateway.redact_upstream_errors_enabled = False
    token = h.token(h.add_agent(INVOICES_READ))
    serve(h, {"code": -32000, "message": f"key {LEAK}"})
    assert LEAK in json.dumps((await h.call(token, params=tool("list_invoices"))).body)
