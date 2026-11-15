"""
The gateway starts a passport refresh when a call ends upstream (docs/plans/phase4-context-refresh-after-call.md), so a slow upstream
tool does not leave the agent's next call waiting for core. Freshness rules are unchanged (see test_context_refresh.py).
"""

from __future__ import annotations

import httpx
import pytest

from agentwall.src.gateway.context import REFRESH_AHEAD_FRACTION

from test_context_refresh import settle, stage_count
from test_gateway import INVOICES_READ, Harness, tool

SLOW_UPSTREAM_SECONDS = 2.5


def make_upstream_slow(h: Harness, seconds: float = SLOW_UPSTREAM_SECONDS) -> None:
    real = h.upstream.handler

    def slow(request: httpx.Request) -> httpx.Response:
        h.clock.now += seconds  # the upstream tool is slow: the fake clock moves while the call is open
        return real(request)

    h.gateway.forwarder._http = httpx.AsyncClient(transport=httpx.MockTransport(slow))


async def test_the_call_after_a_slow_upstream_call_does_not_wait_for_core() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    make_upstream_slow(h)
    first = await h.call(token, params=tool("list_invoices"))
    assert first.status_code == 200
    await settle(h)
    h.clock.now += 0.2
    second = await h.call(token, params=tool("list_invoices"))
    assert second.status_code == 200
    assert stage_count(h, "context_miss") == 1, "only the very first call should have looked up for itself"
    assert stage_count(h, "context_hit") == 1


async def test_a_refresh_is_requested_after_a_successful_forward() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    make_upstream_slow(h, seconds=1.0)  # the entry is old enough to refresh when the call ends
    await h.call(token, params=tool("list_invoices"))
    await settle(h)
    assert h.core.calls == 2


@pytest.mark.parametrize("mode", ["down", "error", "redirect", "huge"])
async def test_a_refresh_is_requested_after_a_failed_forward(mode: str) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    h.upstream.mode = mode
    make_upstream_slow(h, seconds=1.0)
    await h.call(token, params=tool("list_invoices"))
    await settle(h)
    assert h.core.calls == 2


async def test_a_refresh_is_requested_when_the_forward_raises_something_unexpected() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)

    def boom(request: httpx.Request) -> httpx.Response:
        h.clock.now += 1.0
        raise RuntimeError("unexpected")

    h.gateway.forwarder._http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    response = await h.call(token, params=tool("list_invoices"))
    # Changed with the gateway's catch-all: the unexpected error used to escape handle() as an exception (an HTTP 500); it is now a generic
    # deny (CLAUDE.md 6.2). What this test is about is unchanged: the refresh is still requested.
    assert response.status_code == 503
    await settle(h)
    assert h.core.calls == 2


async def test_a_quick_call_starts_no_extra_refresh() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    await h.call(token, params=tool("list_invoices"))  # the fake upstream advances no time
    await settle(h)
    assert h.core.calls == 1


@pytest.mark.parametrize("bad", ["no_token", "bad_token", "invalid_message"])
async def test_calls_denied_before_the_passport_lookup_start_no_refresh(bad: str) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    make_upstream_slow(h)
    if bad == "no_token":
        resp = await h.call(None, params=tool("list_invoices"))
    elif bad == "bad_token":
        resp = await h.call("not-a-token", params=tool("list_invoices"))
    else:
        resp = await h.call(h.token(agent), message={"jsonrpc": "1.0", "id": 1})
    assert resp.status_code in (400, 401)
    assert h.gateway.contexts._refreshing == {} and h.core.calls == 0


async def test_a_denied_out_of_scope_call_never_goes_upstream_and_starts_no_refresh_of_its_own() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    make_upstream_slow(h)
    await h.call(token, params=tool("delete_invoice"))  # out of scope: refused before the forward
    await settle(h)
    assert h.upstream.received == [] and h.core.calls == 1


async def test_a_frozen_agent_is_still_refused_after_a_slow_call_and_the_refresh_never_serves_a_stale_passport() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    make_upstream_slow(h)
    assert (await h.call(token, params=tool("list_invoices"))).status_code == 200
    h.core.agents[str(agent)]["status"] = "frozen"  # frozen in core while the first call was still open
    await settle(h)
    h.clock.now += 0.2
    resp = await h.call(token, params=tool("list_invoices"))
    assert resp.status_code == 403 and REFRESH_AHEAD_FRACTION == 0.25
