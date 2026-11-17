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


async def test_a_refresh_starts_a_quarter_of_the_way_through_the_lifetime() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += TTL * REFRESH_AHEAD_FRACTION + 0.01
    await get(h, agent)
    await settle(h)
    assert REFRESH_AHEAD_FRACTION == 0.25 and h.core.calls == 2


async def test_a_call_after_expiry_waits_for_the_refresh_already_running_instead_of_looking_up_again() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.5
    await get(h, agent)  # starts a refresh at t=1.5 that has not run yet
    h.clock.now += 0.6  # t=2.1: the first entry has expired; the refresh (stamped 1.5) is still inside its lifetime
    served = await get(h, agent)
    assert served.status == "active" and h.core.calls == 2  # one lookup at the start, one refresh, no third
    assert 'stage="context_wait_refresh"' in h.metrics.render()


async def test_if_the_refresh_failed_the_call_looks_up_for_itself_and_is_denied_when_core_is_down() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.5
    await get(h, agent)
    h.core.mode = "down"
    h.clock.now += 0.6
    with pytest.raises(ContextUnavailableError):
        await get(h, agent)  # never served from the expired entry


async def test_a_refresh_older_than_the_lifetime_is_not_used_when_a_call_waits_for_it() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.0
    await get(h, agent)  # refresh requested at t=1.0
    h.clock.now += 2.5  # t=3.5: even the refresh's entry (stamped 1.0) is past the lifetime
    h.core.agents[str(agent)]["status"] = "frozen"
    assert (await get(h, agent)).status == "frozen"  # a fresh lookup, not the old entry


# ---------------------------------------------------------------------------
# Refresh when a call ends (docs/plans/phase4-context-refresh-after-call.md): a call that stays open upstream for as long as the
# lifetime must not leave the NEXT call waiting for core.
# ---------------------------------------------------------------------------


def after_call(h: Harness, agent: UUID) -> None:
    h.gateway.contexts.refresh_if_ageing(agent, ORG, "xero")


def stage_count(h: Harness, stage: str) -> int:
    prefix = f'redhand_gateway_stage_ms_count{{stage="{stage}"}} '
    for line in h.metrics.render().splitlines():
        if line.startswith(prefix):
            return int(float(line[len(prefix):]))
    return 0


async def test_after_a_slow_call_the_next_call_is_a_hit_not_a_lookup() -> None:
    h, agent = setup()
    await get(h, agent)                 # the call starts: lookup at t=0
    h.clock.now += 2.5                  # the upstream tool takes 2.5 s
    after_call(h, agent)                # the call ends
    await settle(h)
    h.clock.now += 0.2
    calls_before = h.core.calls
    await get(h, agent)                 # the next call
    assert h.core.calls == calls_before  # served from the cache: the call itself did not go to core
    assert stage_count(h, "context_miss") == 1  # only the very first lookup was a miss
    assert stage_count(h, "context_hit") == 1


async def test_a_young_entry_starts_no_refresh_when_a_call_ends() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += TTL * REFRESH_AHEAD_FRACTION - 0.01
    after_call(h, agent)
    assert h.gateway.contexts._refreshing == {}
    await settle(h)
    assert h.core.calls == 1


async def test_an_ageing_entry_starts_one_refresh_when_a_call_ends() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.1
    after_call(h, agent)
    after_call(h, agent)                # a second call ending at once does not start another
    assert len(h.gateway.contexts._refreshing) == 1
    await settle(h)
    assert h.core.calls == 2


async def test_an_expired_entry_is_refreshed_when_a_call_ends() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 5.0
    after_call(h, agent)
    await settle(h)
    assert h.core.calls == 2


async def test_with_no_entry_nothing_is_started_when_a_call_ends() -> None:
    h, agent = setup()
    after_call(h, agent)                # no lookup was ever made for this key (a call denied before the passport lookup)
    assert h.gateway.contexts._refreshing == {} and h.core.calls == 0


async def test_with_no_cache_lifetime_nothing_is_started_when_a_call_ends() -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    await get(h, agent)
    h.clock.now += 5.0
    after_call(h, agent)
    assert h.gateway.contexts._refreshing == {} and h.core.calls == 1


async def test_the_number_of_refreshes_started_when_calls_end_is_bounded() -> None:
    h, _ = setup()
    agents = [h.add_agent(INVOICES_READ) for _ in range(MAX_BACKGROUND_REFRESHES + 20)]
    for a in agents:
        await get(h, a)
    h.clock.now += 3.0
    for a in agents:
        after_call(h, a)
    assert len(h.gateway.contexts._refreshing) <= MAX_BACKGROUND_REFRESHES
    await settle(h)


async def test_a_freeze_is_still_seen_within_the_lifetime_when_refreshes_start_at_the_end_of_calls() -> None:
    h, agent = setup()
    fetched_at = h.clock.now
    assert (await get(h, agent)).status == "active"
    h.core.agents[str(agent)]["status"] = "frozen"
    seen_frozen_at = None
    for step in range(1, 40):
        h.clock.now = fetched_at + step * 0.1
        after_call(h, agent)
        await settle(h)
        context = await get(h, agent)
        if context.status == "frozen" and seen_frozen_at is None:
            seen_frozen_at = h.clock.now - fetched_at
        if h.clock.now - fetched_at >= TTL:
            assert context.status == "frozen", "an entry older than the TTL was served"
    assert seen_frozen_at is not None and seen_frozen_at < TTL


@pytest.mark.parametrize("mode", ["down", "error", "malformed"])
async def test_a_failed_refresh_at_the_end_of_a_call_never_extends_the_old_entry(mode: str) -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    h.core.mode = mode
    after_call(h, agent)
    await settle(h)
    h.clock.now += 1.0                  # past the original lifetime
    with pytest.raises(ContextUnavailableError):
        await get(h, agent)             # denied, never served stale


async def test_invalidate_discards_a_refresh_started_at_the_end_of_a_call() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 1.2
    after_call(h, agent)
    h.gateway.contexts.invalidate()
    await settle(h)
    assert h.gateway.contexts._cache == {}


async def test_a_refresh_started_at_the_end_of_a_call_is_stamped_with_when_it_was_requested() -> None:
    h, agent = setup()
    await get(h, agent)
    requested_at = h.clock.now + 2.5
    h.clock.now = requested_at
    real = h.core.handler

    def slow(request: httpx.Request) -> httpx.Response:
        h.clock.now += 0.8
        return real(request)

    h.gateway.contexts._http = httpx.AsyncClient(transport=httpx.MockTransport(slow))
    after_call(h, agent)
    await settle(h)
    key = (str(agent), str(ORG), "xero")
    assert h.gateway.contexts._cache[key][0] == requested_at


async def test_the_next_call_during_an_end_of_call_refresh_waits_for_it_and_does_not_look_up_again() -> None:
    h, agent = setup()
    await get(h, agent)
    h.clock.now += 2.5
    after_call(h, agent)                # refresh started, not yet run
    h.clock.now += 0.05
    served = await get(h, agent)        # arrives while it runs
    assert served.status == "active" and h.core.calls == 2
    assert 'stage="context_wait_refresh"' in h.metrics.render()


async def test_the_wait_for_a_stuck_refresh_is_limited_and_the_call_then_looks_up_for_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentwall.src.gateway import context as context_module

    monkeypatch.setattr(context_module, "REFRESH_WAIT_SECONDS", 0.05)
    h, agent = setup()
    await get(h, agent)
    release = asyncio.Event()
    real = h.core.handler
    state = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:  # the background refresh hangs until the test lets it go
            await release.wait()
        return real(request)

    h.gateway.contexts._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    h.clock.now += 1.5
    await get(h, agent)  # starts the refresh, which will hang
    await asyncio.sleep(0)  # let it begin
    h.clock.now += 0.6  # the original entry has expired
    served = await asyncio.wait_for(get(h, agent), timeout=3)  # would hang for good if the wait were not limited
    assert served.status == "active" and state["n"] == 2  # the call did its own lookup
    release.set()
    await settle(h)


# --- the worst case when core hangs (D1 PR 4) -------------------------------------------------------------------------------------------

def test_the_worst_case_with_a_hanging_core_stays_under_the_five_second_promise() -> None:
    """A call arriving as the entry expires may wait for a refresh already running (REFRESH_WAIT_SECONDS) and then look up for itself (the lookup timeout):
    the first refusal can come that late. TTL cap + wait + lookup must keep a second of headroom under the 5 s revocation promise (CLAUDE.md 4.5)."""
    from agentwall.src.gateway.context import LOOKUP_TIMEOUT_SECONDS, MAX_CONTEXT_TTL_SECONDS, REFRESH_WAIT_SECONDS

    assert MAX_CONTEXT_TTL_SECONDS + REFRESH_WAIT_SECONDS + LOOKUP_TIMEOUT_SECONDS <= 4.5


def test_the_settings_cap_on_the_cache_lifetime_is_the_clients_cap() -> None:
    from agentwall.config.settings import Settings
    from agentwall.src.gateway.context import MAX_CONTEXT_TTL_SECONDS

    with pytest.raises(ValueError):
        Settings(CONTEXT_CACHE_TTL_SECONDS=MAX_CONTEXT_TTL_SECONDS + 0.5)
    assert Settings(CONTEXT_CACHE_TTL_SECONDS=MAX_CONTEXT_TTL_SECONDS).CONTEXT_CACHE_TTL_SECONDS == MAX_CONTEXT_TTL_SECONDS


async def test_the_default_client_gives_up_on_a_hanging_core_within_the_lookup_timeout() -> None:
    from agentwall.src.gateway.context import LOOKUP_TIMEOUT_SECONDS, CoreContextClient

    client = CoreContextClient(core_url="http://core.invalid", service_token="t", ttl_seconds=2.0, instance_id="gw-test")
    timeout = client._http.timeout
    assert timeout.read == LOOKUP_TIMEOUT_SECONDS and timeout.write == LOOKUP_TIMEOUT_SECONDS and timeout.pool == LOOKUP_TIMEOUT_SECONDS
    assert timeout.connect is not None and timeout.connect <= LOOKUP_TIMEOUT_SECONDS
    await client._http.aclose()
