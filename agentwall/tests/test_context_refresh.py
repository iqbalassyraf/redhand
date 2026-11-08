"""
Refresh-ahead for the gateway's passport cache: a busy agent's calls stop waiting for core, and the revocation SLO still holds
(no served entry is ever older than the TTL, a failed refresh never extends an entry, a refresh never overwrites newer data).
"""

from __future__ import annotations

import asyncio
from uuid import UUID

import httpx
import pytest

from agentwall.src.gateway.context import MAX_BACKGROUND_REFRESHES, REFRESH_AHEAD_FRACTION, AgentUnknownError, ContextUnavailableError, GatewayContext

from test_gateway import INVOICES_READ, ORG, Harness

TTL = 2.0


def setup() -> tuple[Harness, UUID]:
    h = Harness(ttl=TTL)
    return h, h.add_agent(INVOICES_READ)


async def get(h: Harness, agent: UUID) -> GatewayContext:
    return await h.gateway.contexts.get(agent, ORG, "xero")


async def settle(h: Harness) -> None:
    tasks = list(h.gateway.contexts._refreshing.values())
    if tasks:
        await asyncio.gather(*tasks)


async def test_in_the_first_half_of_the_lifetime_nothing_is_refreshed() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += TTL * REFRESH_AHEAD_FRACTION - 0.01
    await get(h, agent)
    await settle(h)
    assert h.core.calls == 1


async def test_after_half_the_lifetime_a_call_is_served_from_cache_and_refreshes_in_the_background() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.1
    served = await get(h, agent)
    assert served.status == "active" and h.core.calls == 1  # the call did not wait for core
    await settle(h)
    assert h.core.calls == 2
    h.clock.now += 1.0  # 2.1 s after the first fetch: the original entry would have expired, the refreshed one has not
    await get(h, agent)
    assert h.core.calls == 2


async def test_many_calls_in_the_refresh_window_start_one_refresh() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    for _ in range(20):
        await get(h, agent)
    await settle(h)
    assert h.core.calls == 2


async def test_a_freeze_is_seen_within_the_ttl_and_no_entry_older_than_the_ttl_is_ever_served() -> None:
    h, agent = setup()
    fetched_at = h.clock.now
    assert (await get(h, agent)).status == "active"
    h.core.agents[str(agent)]["status"] = "frozen"  # frozen in core right after the first fetch
    seen_frozen_at = None
    for step in range(1, 40):
        h.clock.now = fetched_at + step * 0.1
        context = await get(h, agent)
        await settle(h)
        if context.status == "frozen" and seen_frozen_at is None:
            seen_frozen_at = h.clock.now - fetched_at
        if h.clock.now - fetched_at >= TTL:
            assert context.status == "frozen", "an entry older than the TTL was served"
    assert seen_frozen_at is not None and seen_frozen_at < TTL


@pytest.mark.parametrize("mode", ["down", "error", "malformed"])
async def test_a_failed_refresh_never_extends_the_old_entry(mode: str) -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    h.core.mode = mode
    assert (await get(h, agent)).status == "active"  # still inside the lifetime
    await settle(h)
    h.clock.now += 1.0  # now past the original lifetime
    with pytest.raises(ContextUnavailableError):
        await get(h, agent)  # no stale answer: the caller denies


async def test_an_agent_removed_in_core_is_unknown_once_the_old_entry_expires() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    del h.core.agents[str(agent)]
    await get(h, agent)
    await settle(h)
    h.clock.now += 1.0
    with pytest.raises(AgentUnknownError):
        await get(h, agent)


async def test_invalidate_discards_a_refresh_that_was_already_running() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    await get(h, agent)  # starts the refresh, which has not run yet
    h.gateway.contexts.invalidate()
    await settle(h)
    assert h.gateway.contexts._cache == {}


async def test_a_refresh_does_not_overwrite_a_newer_entry() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    await get(h, agent)  # refresh started at t=1.2 but not yet run
    h.clock.now += 1.0  # the entry expires; the next call fetches directly (newer than the refresh's start)
    h.gateway.contexts._cache.clear()
    h.core.agents[str(agent)]["status"] = "frozen"
    await get(h, agent)
    key = (str(agent), str(ORG), "xero")
    newer = h.gateway.contexts._cache[key][0]
    await settle(h)
    assert h.gateway.contexts._cache[key][0] == newer and h.gateway.contexts._cache[key][1].status == "frozen"


async def test_the_number_of_background_refreshes_is_bounded() -> None:
    h, _ = setup()
    agents = [h.add_agent(INVOICES_READ) for _ in range(MAX_BACKGROUND_REFRESHES + 20)]
    for a in agents:
        await get(h, a)
    h.clock.now += 1.2
    for a in agents:
        await get(h, a)
    assert len(h.gateway.contexts._refreshing) <= MAX_BACKGROUND_REFRESHES
    await settle(h)


async def test_with_no_cache_lifetime_there_is_never_a_refresh() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    for _ in range(3):
        await get(h, agent)
    assert h.core.calls == 3 and h.gateway.contexts._refreshing == {}


async def test_a_slow_refresh_is_stamped_with_when_it_was_requested_not_when_it_finished() -> None:
    h, agent = setup()
    await get(h, agent)
    requested_at = h.clock.now + 1.2
    h.clock.now = requested_at
    real = h.core.handler

    def slow(request: httpx.Request) -> httpx.Response:
        h.clock.now += 0.8  # core takes 0.8 s to answer
        return real(request)

    h.gateway.contexts._http = httpx.AsyncClient(transport=httpx.MockTransport(slow))
    await get(h, agent)
    await settle(h)
    key = (str(agent), str(ORG), "xero")
    assert h.gateway.contexts._cache[key][0] == requested_at
