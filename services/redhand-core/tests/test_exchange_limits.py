"""
Token exchange limits (H3.3): per agent key (as before), and now per source address, checked BEFORE the database is touched. A caller guessing
keys used to be limited only per guess, and each distinct well-formed key cost a database lookup.
"""

from __future__ import annotations

from typing import Any

import pytest

from redhand_core.routers import agent_auth
from redhand_core.services.local_store import LocalSupabaseAdapter

from core_helpers import make_client

KEY = "rh_agent_" + "a" * 40


def fake_key(n: int) -> str:
    return "rh_agent_" + f"{n:040d}"


def setup(**settings: Any) -> Any:
    store = LocalSupabaseAdapter()
    reads: list[str] = []
    original = store.table

    def counting(name: str) -> Any:
        reads.append(name)
        return original(name)

    store.table = counting  # type: ignore[method-assign]
    client, _ = make_client(store, **settings)
    agent_auth._exchange_limiter._events.clear()  # noqa: SLF001
    agent_auth._source_limiter._events.clear()  # noqa: SLF001
    return client, reads


def post(client: Any, key: str, forwarded: str | None = None) -> Any:
    headers = {"Authorization": f"Bearer {key}"}
    if forwarded:
        headers["X-Forwarded-For"] = forwarded
    return client.post("/v1/agent-auth/token", headers=headers)


def test_one_source_is_limited_however_many_different_keys_it_tries() -> None:
    client, _ = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=5)
    statuses = [post(client, fake_key(n)).status_code for n in range(8)]
    assert statuses[:5] == [401] * 5
    assert statuses[5:] == [429] * 3


def test_the_source_limit_is_checked_before_the_database() -> None:
    client, reads = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=2)
    for n in range(10):
        post(client, fake_key(n))
    assert len([name for name in reads if name == "agent_keys"]) == 2, "refused callers must not cost a database read"


def test_a_refused_source_gets_a_retry_after_and_a_stable_message() -> None:
    client, _ = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=1)
    post(client, fake_key(1))
    response = post(client, fake_key(2))
    assert response.status_code == 429 and response.headers["retry-after"] == "60"
    assert response.json() == {"detail": "Too many token requests from this address."}


def test_a_forged_forwarded_for_header_cannot_step_round_the_limit_when_no_proxy_is_trusted() -> None:
    client, _ = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=3, TRUSTED_PROXY_HOPS=0)
    statuses = [post(client, fake_key(n), forwarded=f"198.51.100.{n}").status_code for n in range(6)]
    assert statuses == [401, 401, 401, 429, 429, 429]


def test_a_forged_left_part_cannot_step_round_the_limit_behind_one_trusted_proxy() -> None:
    client, _ = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=3, TRUSTED_PROXY_HOPS=1)
    statuses = [post(client, fake_key(n), forwarded=f"198.51.100.{n}, 203.0.113.7").status_code for n in range(6)]
    assert statuses == [401, 401, 401, 429, 429, 429], "the caller rotated the left part; the proxy-added address is the same"


def test_different_real_sources_behind_the_proxy_have_their_own_budgets() -> None:
    client, _ = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=1, TRUSTED_PROXY_HOPS=1)
    assert post(client, fake_key(1), forwarded="203.0.113.7").status_code == 401
    assert post(client, fake_key(2), forwarded="203.0.113.7").status_code == 429
    assert post(client, fake_key(3), forwarded="203.0.113.8").status_code == 401


def test_the_per_key_limit_still_applies_on_its_own() -> None:
    client, _ = setup(AGENT_TOKEN_EXCHANGES_PER_MINUTE=2, AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE=100)
    assert [post(client, KEY).status_code for _ in range(4)] == [401, 401, 429, 429]


@pytest.mark.parametrize("hops", [-1, 6])
def test_the_trusted_proxy_count_is_bounded(hops: int) -> None:
    from pydantic import ValidationError

    from redhand_core.config import Settings

    with pytest.raises(ValidationError):
        Settings(TRUSTED_PROXY_HOPS=hops)  # type: ignore[arg-type]
