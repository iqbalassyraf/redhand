"""
The gateway's catch-all (CLAUDE.md 6.2: on the enforcement path any unexpected error is a deny): whatever fails inside `handle()`, the
caller gets a generic JSON-RPC error and never an unhandled exception (an HTTP 500), and the answer says nothing about the cause.
"""

from __future__ import annotations

import json

import pytest

from agentwall.src.gateway.service import JSONRPC_GATEWAY_UNAVAILABLE

from test_gateway import INVOICES_READ, Harness, tool


@pytest.mark.asyncio
async def test_any_other_unexpected_error_inside_the_gateway_is_a_generic_json_rpc_error_not_an_exception() -> None:
    """A 5,000-digit integer makes the audit logger raise (a different module from the forwarder): handle() still answers, and says nothing about why."""
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    response = await h.call(token, params=tool("list_invoices", x=10**5000))
    assert response.status_code == 503 and response.body["error"]["code"] == JSONRPC_GATEWAY_UNAVAILABLE
    assert response.body["error"]["message"] == "The gateway could not process this request."
    assert "Exceeds" not in json.dumps(response.body) and "ValueError" not in json.dumps(response.body)
    assert 'reason="internal_error"' in h.gateway.metrics.render()


@pytest.mark.asyncio
async def test_the_catch_all_keeps_the_request_id_and_an_unauthenticated_caller_still_gets_401() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    ok = await h.call(token, message={"jsonrpc": "2.0", "id": "req-77", "method": "tools/call", "params": tool("list_invoices", x=10**5000)})
    assert ok.body["id"] == "req-77"
    assert (await h.call(None, params=tool("list_invoices"))).status_code == 401
