"""
First-use check for tool pinning in enforce mode (H4.2, docs/adr/0021-hardening-round.md).

A gateway instance that has not seen a tool listed has no checked version of it. Judging such a call by the tool's name alone trusted a server
that had changed an approved tool (a rug pull) on any instance that started empty. This module fetches the server's tool list itself, with the
agent's own upstream credentials, records every version it sees (the same memory a normal `tools/list` fills), and answers with the tool's
CURRENT digest, or None when it cannot be known (the caller then refuses the call).

Bounded on every side: one check per (organization, server) at a time (simultaneous callers share it), at most 50 checks at once, a hard
deadline, the scan module's page and tool caps, and after a failure the same server is refused quickly for a short pause instead of being asked
again on every call. Nothing the server says is kept beyond what the normal listing path already keeps (name, description, schema digest).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import time
from uuid import UUID

import structlog

from .metrics import GatewayMetrics
from .pins import PinCoordinator
from .scan import ScanError, list_tools
from .upstream import UpstreamForwarder

logger = structlog.get_logger(__name__)

FIRST_USE_TIMEOUT_SECONDS = 10.0
FIRST_USE_FAILURE_PAUSE_SECONDS = 10.0
MAX_CHECKS_AT_ONCE = 50
MAX_FAILURES_REMEMBERED = 1000


class FirstUseChecker:
    def __init__(self, *, pins: PinCoordinator, metrics: GatewayMetrics, now: Callable[[], float] = time.monotonic) -> None:
        self._pins = pins
        self._metrics = metrics
        self._now = now
        self._inflight: dict[tuple[UUID, str], asyncio.Task[None]] = {}
        self._failed_until: dict[tuple[UUID, str], float] = {}

    async def digest_for(
        self, forwarder: UpstreamForwarder, organization_id: UUID, server: str, url: str, tool: str, upstream_authorization: str | None
    ) -> str | None:
        """The current digest of `tool` on this server, or None if it could not be established (refuse the call)."""
        known = self._pins.last_digest(organization_id, server, tool)
        if known is not None:
            return known
        key = (organization_id, server)
        pause = self._failed_until.get(key)
        if pause is not None and self._now() < pause:
            self._metrics.record_pin_event("first_use_skipped")
            return None
        task = self._inflight.get(key)
        if task is None:
            if len(self._inflight) >= MAX_CHECKS_AT_ONCE:
                self._metrics.record_pin_event("first_use_busy")
                return None
            task = asyncio.ensure_future(self._check(forwarder, key, url, upstream_authorization))
            self._inflight[key] = task
            task.add_done_callback(lambda _t, k=key: self._inflight.pop(k, None))  # type: ignore[misc]  # k default binds the loop variable
        try:
            await asyncio.shield(task)  # a caller that goes away must not cancel the check others are waiting for
        except Exception as exc:  # noqa: BLE001  the check never raises into the enforcement path: it fails closed
            logger.warning("Tool pin first-use check failed unexpectedly", error_type=type(exc).__name__)
            return None
        return self._pins.last_digest(organization_id, server, tool)  # None when the check failed: nothing was recorded

    async def _check(self, forwarder: UpstreamForwarder, key: tuple[UUID, str], url: str, upstream_authorization: str | None) -> None:
        organization_id, server = key
        try:
            tools, _truncated = await asyncio.wait_for(
                list_tools(forwarder, url, upstream_authorization), timeout=FIRST_USE_TIMEOUT_SECONDS
            )
        except (ScanError, TimeoutError) as exc:
            logger.warning("Tool pin first-use check could not list the server's tools", error_type=type(exc).__name__)
            self._fail(key)
            return
        self._pins.observe(organization_id, server, [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)])
        self._metrics.record_pin_event("first_use_check")

    def _fail(self, key: tuple[UUID, str]) -> None:
        if len(self._failed_until) >= MAX_FAILURES_REMEMBERED:
            self._failed_until.clear()  # bounded; forgetting a pause only allows one more check
        self._failed_until[key] = self._now() + FIRST_USE_FAILURE_PAUSE_SECONDS
        self._metrics.record_pin_event("first_use_failed")
