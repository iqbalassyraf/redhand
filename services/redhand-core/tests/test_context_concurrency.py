"""
The gateway-context lookup runs on every passport cache miss (every 2 s per agent and server per gateway instance), so its round trips are on the
hot path. After the first parallel batch, the destination list, the usage by other instances and the last-seen write are independent of each
other and now run together (H1.5). These tests wrap the database to record when each call starts and ends.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import SecretStr

from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_telegram import Env as TelegramEnv

SERVICE_TOKEN = "context-core-test-internal-service-token-0123456789"
GATEWAY = {"Authorization": f"Bearer {SERVICE_TOKEN}"}


class Recording:
    """Delegates to the real twin, adds latency to every execute() and logs ("start" | "end", what) so overlap can be asserted."""

    def __init__(self, store: Any, log: list[tuple[str, str]]) -> None:
        self._store, self._log = store, log

    def table(self, name: str) -> Any:
        return _Query(self._store.table(name), f"table:{name}", self._log)

    def rpc(self, name: str, params: dict[str, Any] | None = None) -> Any:
        return _Query(self._store.rpc(name, params), f"rpc:{name}", self._log)


class _Query:
    def __init__(self, inner: Any, label: str, log: list[tuple[str, str]]) -> None:
        self._inner, self._label, self._log = inner, label, log
        self._op = "select"

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr) or name == "execute":
            return attr

        def chain(*args: Any, **kwargs: Any) -> "_Query":
            result = attr(*args, **kwargs)
            if name in ("update", "insert", "upsert"):
                self._op = name
            self._inner = result
            return self

        return chain

    async def execute(self) -> Any:
        what = f"{self._label}:{self._op}"
        self._log.append(("start", what))
        await asyncio.sleep(0.03)
        try:
            return await self._inner.execute()
        finally:
            self._log.append(("end", what))


@pytest.fixture
def env() -> TelegramEnv:
    return TelegramEnv(INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE_TOKEN))


def _context(env: TelegramEnv, agent: str) -> Any:
    return env.client.get("/internal/v1/gateway-context", params={"agent_id": agent, "organization_id": DEFAULT_ORG_ID, "server": "xero"}, headers=GATEWAY)


def test_the_independent_lookups_after_the_first_batch_overlap(env: TelegramEnv) -> None:
    from redhand_core.routers.telemetry import get_supabase_service_client

    agent = env.register("Concurrent bot")["id"]
    next(a for a in env.store.tables["agents"] if a["id"] == agent)["destination_mode"] = "observe"  # so the destination list is read
    log: list[tuple[str, str]] = []
    env.client.app.dependency_overrides[get_supabase_service_client] = lambda: Recording(env.store, log)  # type: ignore[attr-defined]
    assert _context(env, agent).status_code == 200
    tail = ["rpc:usage_by_others:select", "table:agent_destinations:select", "table:agents:update"]
    starts = {w: i for i, (kind, w) in enumerate(log) if kind == "start" and w in tail}
    ends = {w: i for i, (kind, w) in enumerate(log) if kind == "end" and w in tail}
    assert set(starts) == set(tail), log  # all three ran
    assert max(starts.values()) < min(ends.values()), log  # every one started before any finished: they overlap


def test_a_failed_independent_lookup_still_fails_the_whole_lookup_closed(env: TelegramEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services import local_rpc

    agent = env.register("Failing bot")["id"]

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("database down")

    monkeypatch.setitem(local_rpc.HANDLERS, "usage_by_others", boom)
    assert _context(env, agent).status_code == 503  # the gateway treats this as "deny"


def test_the_context_still_carries_everything_the_gateway_requires(env: TelegramEnv) -> None:
    agent = env.register("Complete bot")["id"]
    body = _context(env, agent).json()["agent"]
    for field in ("status", "version", "scopes", "expires_at", "safe_mode", "budget", "loop_mode", "destination_mode", "allowed_destinations"):
        assert field in body, field
    assert body["status"] == "active" and body["version"] >= 1


def test_a_failed_last_seen_write_never_denies_the_lookup(env: TelegramEnv, caplog: pytest.LogCaptureFixture) -> None:
    """"Last seen" is shown on the dashboard only. A failure to write it used to fail the whole lookup, which the gateway reads as "deny"."""
    import logging

    from redhand_core.routers.telemetry import get_supabase_service_client
    from redhand_core.services.local_store import LocalSupabaseAdapter

    agent = env.register("Cosmetic bot")["id"]

    class FailingUpdate:
        def __init__(self, store: LocalSupabaseAdapter) -> None:
            self._store = store

        def table(self, name: str) -> Any:
            query = self._store.table(name)
            if name == "agents":
                original = query.update

                def update(values: dict[str, Any]) -> Any:
                    class Boom:
                        def eq(self, *_: Any) -> "Boom":
                            return self

                        async def execute(self) -> Any:
                            raise RuntimeError("write failed")

                    return Boom()

                query.update = update  # type: ignore[method-assign]
                del original
            return query

        def rpc(self, name: str, params: dict[str, Any] | None = None) -> Any:
            return self._store.rpc(name, params)

    env.client.app.dependency_overrides[get_supabase_service_client] = lambda: FailingUpdate(env.store)  # type: ignore[attr-defined]
    caplog.set_level(logging.WARNING)
    assert _context(env, agent).status_code == 200
    assert "Last-seen update failed: RuntimeError" in caplog.text
