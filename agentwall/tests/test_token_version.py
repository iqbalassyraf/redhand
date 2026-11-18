"""
Stale agent tokens (H4.1). A token carries the passport version it was issued at; the version rises with every change of status, scopes or
expiry. The gateway used to parse `ver` and never compare it, so a token issued before a freeze worked again after the unfreeze, and one issued
before a scope reduction kept the old authority only through the passport (which is current), but never proved it was issued for this state.
Now a token older than the passport is refused ("token_stale") and the agent exchanges its key again.
"""

from __future__ import annotations

import pytest

from test_gateway import INVOICES_READ, Harness, tool


def bump(h: Harness, agent: object, version: int, status: str = "active") -> None:
    row = h.core.agents[str(agent)]
    row["version"], row["status"] = version, status


@pytest.mark.asyncio
async def test_a_token_older_than_the_passport_is_refused_as_stale_and_nothing_is_forwarded() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    old = h.token(agent, ver=1)
    assert (await h.call(old, params=tool("list_invoices"))).status_code == 200
    bump(h, agent, 2)  # a scope or expiry change
    forwarded = len(h.upstream.received)
    resp = await h.call(old, params=tool("list_invoices"))
    assert resp.status_code == 401
    assert resp.body["error"]["message"] == "Agent access token is out of date. Request a new one."
    assert resp.headers.get("WWW-Authenticate") == 'Bearer realm="redhand-gateway"'
    assert len(h.upstream.received) == forwarded


@pytest.mark.asyncio
async def test_a_fresh_token_for_the_current_version_works() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    bump(h, agent, 3)
    assert (await h.call(h.token(agent, ver=3), params=tool("list_invoices"))).status_code == 200


@pytest.mark.asyncio
async def test_unfreezing_does_not_revive_a_token_issued_before_the_freeze() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    before_freeze = h.token(agent, ver=1)
    bump(h, agent, 2, status="frozen")
    frozen = await h.call(before_freeze, params=tool("list_invoices"))
    assert frozen.status_code == 403 and frozen.body["error"]["data"] == {"passport_status": "frozen"}, "frozen is reported as frozen, not stale"
    bump(h, agent, 3, status="active")  # a person unfreezes it
    revived = await h.call(before_freeze, params=tool("list_invoices"))
    assert revived.status_code == 401 and "out of date" in revived.body["error"]["message"]
    assert (await h.call(h.token(agent, ver=3), params=tool("list_invoices"))).status_code == 200


@pytest.mark.asyncio
async def test_a_token_newer_than_the_gateways_context_is_accepted() -> None:
    """The agent exchanged its key after a change the gateway's cache has not caught up with yet: not stale, and no worse than today."""
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    assert (await h.call(h.token(agent, ver=2), params=tool("list_invoices"))).status_code == 200


@pytest.mark.asyncio
async def test_the_refusal_is_recorded_and_counted_with_its_own_reason() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    bump(h, agent, 2)
    await h.call(h.token(agent, ver=1), params=tool("list_invoices"))
    assert h.decisions(1)[0]["reasons"] == ["token_stale"]
    assert 'reason="token_stale"' in h.metrics.render()
    await h.recorder.flush()
    assert [e["reasons"] for e in h.event_reporter.events] == [["token_stale"]]


@pytest.mark.asyncio
async def test_the_kill_switch_restores_the_old_behaviour() -> None:
    h = Harness(ttl=0.0)
    h.gateway.token_version_check_enabled = False
    agent = h.add_agent(INVOICES_READ)
    bump(h, agent, 5)
    assert (await h.call(h.token(agent, ver=1), params=tool("list_invoices"))).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["frozen", "revoked"])
async def test_a_stale_token_for_an_inactive_passport_is_still_reported_by_status(status: str) -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ, status=status)
    bump(h, agent, 9, status=status)
    resp = await h.call(h.token(agent, ver=1), params=tool("list_invoices"))
    assert resp.status_code == 403 and resp.body["error"]["data"] == {"passport_status": status}


@pytest.mark.asyncio
async def test_a_token_with_a_non_numeric_version_is_invalid_not_stale() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    resp = await h.call(h.token(agent, ver="abc"), params=tool("list_invoices"))
    assert resp.status_code == 401 and "Invalid or expired" in resp.body["error"]["message"]
