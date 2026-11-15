"""
Numbers and nesting that Python's JSON parser accepts but JSON does not (or that cannot be sent on): NaN, Infinity, 1e999, a
5,000-digit integer, and a body nested 100,000 levels. None of them may reach the tool or end in an unhandled error (HTTP 500).
At the edge they are an invalid request (after authentication, as for any unparsable body); inside the gateway, a message that
cannot be encoded for the upstream is a JSON-RPC error and never an exception.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from httpx import ASGITransport, AsyncClient
import pytest

from agentwall.src import main as gateway_main
from agentwall.src.gateway.service import JSONRPC_INVALID_REQUEST, JSONRPC_UPSTREAM_UNAVAILABLE

from test_gateway import INVOICES_READ, Harness, tool

CALL = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"x":%s}}}'
BAD_BODIES = {
    "NaN": CALL % "NaN",
    "Infinity": CALL % "Infinity",
    "-Infinity": CALL % "-Infinity",
    "nested NaN": CALL % "[1,[2,{\"y\":NaN}]]",
    "1e999": CALL % "1e999",
    "-1e999": CALL % "-1e999",
    "5000 digit integer": CALL % ("9" * 5000),
    "top level NaN": "NaN",
}


def _edge(monkeypatch: pytest.MonkeyPatch, h: Harness) -> AsyncClient:
    monkeypatch.setattr(gateway_main, "gateway", h.gateway)
    return AsyncClient(transport=ASGITransport(app=gateway_main.app), base_url="http://gateway")


async def _post(client: AsyncClient, body: bytes | str, token: str | None) -> httpx.Response:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return await client.post("/mcp/xero", content=body.encode() if isinstance(body, str) else body, headers=headers)


def _forwarded(h: Harness) -> int:
    return len(h.upstream.received)


@pytest.mark.parametrize("name", list(BAD_BODIES))
@pytest.mark.asyncio
async def test_a_body_json_does_not_allow_is_an_invalid_request_not_an_error(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    response = await _post(_edge(monkeypatch, h), BAD_BODIES[name], token)
    assert response.status_code == 400, name
    assert response.json()["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert _forwarded(h) == 0


@pytest.mark.parametrize("name", list(BAD_BODIES))
@pytest.mark.asyncio
async def test_without_a_token_such_a_body_is_still_a_401(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    h = Harness()
    h.add_agent(INVOICES_READ)
    response = await _post(_edge(monkeypatch, h), BAD_BODIES[name], None)
    assert response.status_code == 401
    assert _forwarded(h) == 0


@pytest.mark.asyncio
async def test_a_body_nested_a_hundred_thousand_levels_is_an_invalid_request(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    body = b"[" * 100_000 + b"]" * 100_000
    response = await _post(_edge(monkeypatch, h), body, token)
    assert response.status_code == 400 and response.json()["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert _forwarded(h) == 0


@pytest.mark.parametrize("literal", ["1", "0.1", "-2.5e10", "1e300", "123456789012345678901234567890", '"NaN"', "null", "true"])
@pytest.mark.asyncio
async def test_ordinary_values_still_pass(monkeypatch: pytest.MonkeyPatch, literal: str) -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    response = await _post(_edge(monkeypatch, h), CALL % literal, token)
    assert response.status_code == 200 and "result" in response.json(), literal
    assert _forwarded(h) == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")], ids=["nan", "inf", "-inf"])
@pytest.mark.asyncio
async def test_a_message_that_cannot_be_encoded_for_the_upstream_is_a_json_rpc_error_never_an_exception(value: Any) -> None:
    """Defence in depth: a caller of handle() that did not go through the edge parser (a test, a future transport) still gets an answer."""
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    response = await h.call(token, params=tool("list_invoices", x=value))
    assert response.status_code == 502 and response.body["error"]["code"] == JSONRPC_UPSTREAM_UNAVAILABLE
    assert "could not be encoded" in response.body["error"]["message"]
    assert _forwarded(h) == 0
    assert 'reason="upstream_error"' in h.gateway.metrics.render()


@pytest.mark.asyncio
async def test_a_message_that_can_be_encoded_still_reaches_the_upstream_byte_for_byte() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    response = await h.call(token, params=tool("list_invoices", note="Kedai Kita – invoice", n=[1, 2.5, None, True]))
    assert response.status_code == 200
    assert h.upstream.received[0]["params"]["arguments"] == {"note": "Kedai Kita – invoice", "n": [1, 2.5, None, True]}
    assert json.dumps(h.upstream.received[0])  # round-trips
