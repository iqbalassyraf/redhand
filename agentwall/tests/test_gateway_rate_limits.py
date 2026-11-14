"""
Gateway rate limits (H3.3): memory-bounded, the live scan limited per organization (one tenant's scans cannot use up another's), and the vet
endpoint limited per real caller instead of per proxy.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from agentwall.src import main as gateway_main
from agentwall.src.gateway.rate_limit import SlidingWindowLimiter
from agentwall.src.gateway.source import client_source

TOKEN = "scan-limit-service-token-0123456789"
ORG_A = "00000000-0000-0000-0000-0000000000a1"
ORG_B = "00000000-0000-0000-0000-0000000000b2"
URL = "https://mcp.example.com/mcp"


# --- the limiter --------------------------------------------------------------------------------------------------------------------

def test_a_key_is_limited_inside_its_window_and_free_after_it() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0)
    assert [limiter.allow("k", 2, now) for now in (0.0, 1.0)] == [True, True]
    assert limiter.allow("k", 2, 2.0) is False
    assert limiter.allow("k", 2, 60.5) is True


def test_a_flood_of_distinct_keys_cannot_grow_memory_past_the_bound() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0, max_keys=500)
    for n in range(20_000):
        limiter.allow(f"ip-{n}", 5, now=n * 0.001)
    assert len(limiter._hits) <= 500  # noqa: SLF001


def test_expired_keys_are_swept_when_the_table_is_full() -> None:
    limiter = SlidingWindowLimiter(window_seconds=10.0, max_keys=100)
    for n in range(100):
        limiter.allow(f"old-{n}", 5, now=0.0)
    assert limiter.allow("fresh", 5, now=1000.0) is True
    assert len(limiter._hits) == 1  # noqa: SLF001


def test_a_key_being_limited_keeps_its_count_while_idle_keys_are_evicted() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0, max_keys=20)
    assert limiter.allow("busy", 2, 0.0) and limiter.allow("busy", 2, 0.1)
    for n in range(100):
        limiter.allow(f"noise-{n}", 5, 1.0 + n * 0.01)
        limiter.allow("busy", 2, 1.0 + n * 0.01)
    assert limiter.allow("busy", 2, 3.0) is False


# --- the source address -------------------------------------------------------------------------------------------------------------

def scope(peer: str, forwarded: str | None = None) -> dict[str, Any]:
    return {"client": (peer, 1), "headers": [(b"x-forwarded-for", forwarded.encode())] if forwarded else []}


def test_the_forwarded_header_is_ignored_without_a_trusted_proxy() -> None:
    assert client_source(scope("10.0.0.1", "203.0.113.7"), 0) == "10.0.0.1"


def test_behind_one_trusted_proxy_the_last_entry_counts_and_a_forged_left_part_does_not() -> None:
    assert client_source(scope("35.1.1.1", "1.2.3.4, 203.0.113.7"), 1) == "203.0.113.7"


def test_too_few_or_unreadable_entries_fall_back_to_the_peer() -> None:
    assert client_source(scope("35.1.1.1", "203.0.113.7"), 2) == "35.1.1.1"
    assert client_source(scope("35.1.1.1", "x, <b>"), 1) == "35.1.1.1"


# --- the endpoints ------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_main.settings, "CORE_SERVICE_TOKEN", SecretStr(TOKEN))
    gateway_main._scan_limiter._hits.clear()  # noqa: SLF001
    gateway_main._vet_limiter._hits.clear()  # noqa: SLF001
    monkeypatch.setattr(gateway_main, "SCAN_REQUESTS_PER_MINUTE", 2)
    monkeypatch.setattr(gateway_main, "VET_REQUESTS_PER_MINUTE", 2)

    async def fake_list_tools(forwarder: Any, url: str) -> tuple[list[dict[str, Any]], bool]:
        return [], False

    monkeypatch.setattr(gateway_main, "list_tools", fake_list_tools)


async def scan(org: str | None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if org is not None:
        headers["X-RedHand-Organization"] = org
    async with AsyncClient(transport=ASGITransport(app=gateway_main.app), base_url="http://test") as client:
        return await client.post("/internal/v1/scan", json={"server_url": URL}, headers=headers)


@pytest.mark.asyncio
async def test_one_organization_using_up_its_scans_does_not_block_another(wired: None) -> None:
    assert [(await scan(ORG_A)).status_code for _ in range(3)] == [200, 200, 429]
    assert (await scan(ORG_B)).status_code == 200


@pytest.mark.asyncio
async def test_a_missing_or_malformed_organization_shares_one_fixed_bucket(wired: None) -> None:
    assert [(await scan(None)).status_code for _ in range(2)] == [200, 200]
    assert (await scan("not-a-uuid")).status_code == 429, "a made-up value must not open a fresh bucket"
    assert (await scan("x" * 500)).status_code == 429


async def vet(forwarded: str | None) -> httpx.Response:
    headers = {"X-Forwarded-For": forwarded} if forwarded else {}
    async with AsyncClient(transport=ASGITransport(app=gateway_main.app), base_url="http://test") as client:
        return await client.post("/v1/mcp/vet", json={"name": "x", "tools": []}, headers=headers)


@pytest.mark.asyncio
async def test_vet_is_limited_per_real_caller_behind_a_trusted_proxy(wired: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_main.settings, "TRUSTED_PROXY_HOPS", 1)
    assert [(await vet(f"{n}.1.1.1, 203.0.113.7")).status_code for n in range(3)] == [200, 200, 429], "forged left part, same real caller"
    assert (await vet("1.1.1.1, 203.0.113.8")).status_code == 200


@pytest.mark.asyncio
async def test_vet_ignores_the_header_when_no_proxy_is_trusted(wired: None) -> None:
    assert [(await vet(f"203.0.113.{n}")).status_code for n in range(3)] == [200, 200, 429]
