"""
Per-call authorization context from redhand-core, with a short bounded cache.

The cache TTL is capped so that a freeze or revoke in core reaches the gateway within
the 5-second revocation SLO (CLAUDE.md §4.5): TTL (<= 2 s by default, never more than
4 s) plus one lookup. Failures are never cached and always surface as
`ContextUnavailableError`, which the gateway turns into a deny.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
import time
from typing import Any, Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError
import structlog

from .budget import BudgetState
from .honeytokens import HoneytokenRef

logger = structlog.get_logger(__name__)

MAX_CONTEXT_TTL_SECONDS = 4.0
CACHE_MAX_ENTRIES = 10_000
# Once a cached passport is this fraction of its lifetime old, the next call that uses it also starts a background refresh, so
# a busy agent's next call finds a fresh entry instead of waiting for core. This never makes a served entry older than the TTL.
REFRESH_AHEAD_FRACTION = 0.25
# When an entry has expired while its refresh is still running, a call waits for that refresh for at most this long (instead of
# starting a second lookup) and otherwise looks up for itself.
REFRESH_WAIT_SECONDS = 1.0
MAX_BACKGROUND_REFRESHES = 200


class Scope(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    server: str
    tool: str
    access: Literal["read", "write"] = "read"


class _BudgetPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    daily_call_limit: StrictInt | None = Field(ge=0)  # 0 is what core sends for a malformed stored limit
    used_by_other_instances: StrictInt = Field(ge=0)
    day_key: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    resets_at: datetime
    action: str = Field(pattern=r"^(deny|freeze)$")


class _HoneytokenPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: UUID
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class _HoneyToolPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: UUID
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{2,63}$")
    description: str = Field(min_length=1, max_length=300)


class HoneyTool(BaseModel):
    """A decoy tool for this agent on this server. Calling it is never forwarded."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    name: str
    description: str


class _AgentPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: UUID
    organization_id: UUID
    status: Literal["active", "frozen", "revoked", "expired"]
    version: int = Field(ge=1)
    scopes: list[Scope]
    # Required, with no default: a core that does not send the flag (an older version) makes the
    # lookup fail and the gateway deny, rather than silently skipping Safe Mode.
    safe_mode: StrictBool
    # Required, with no default, for the same reason: a core that does not send it (an older version) makes the
    # lookup fail and the gateway deny, rather than capturing payloads the organization never agreed to, or
    # silently not capturing ones it did. Deploy core before the gateway.
    payload_capture: StrictBool
    # Also required with no default, for the same reason: an older core that sends no budget makes the
    # lookup fail and the call is denied rather than running with no limit.
    budget: _BudgetPayload
    # Required, with no default, like the fields above: an older core that does not send them makes the lookup
    # fail and the call is denied, rather than running with no bait checks. Deploy core before the gateway.
    honeytokens: list[_HoneytokenPayload]
    honey_tools: list[_HoneyToolPayload]
    # Required, with no default, like the fields above: an older core that does not send the Radar modes makes the lookup fail
    # and the call is denied. Deploy core before the gateway. "block" does not exist and is not accepted.
    radar_mode: Literal["off", "observe"]
    output_check_mode: Literal["off", "observe"]
    # Required, with no default, like the fields above: an older core that does not send loop detection's settings makes the lookup
    # fail and the call is denied, rather than running with no loop checks. Deploy core before the gateway. `loop_exempt` is true while
    # a suppression of the loop rule is live for this agent.
    loop_mode: Literal["off", "observe", "throttle"]
    loop_limit: StrictInt = Field(ge=3, le=1000)
    loop_window_seconds: StrictInt = Field(ge=10, le=600)
    loop_exempt: StrictBool


class _ApprovedToolPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tool: str = Field(min_length=1, max_length=128)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class _ServerPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    slug: str
    url: str
    # Required, with no default: a core that does not send them (an older version) makes the lookup fail and the gateway
    # deny, rather than running with no pin checks. `approved_tools` is only filled in enforce mode.
    pin_mode: Literal["off", "alert", "enforce"]
    approved_tools: list[_ApprovedToolPayload]


class _ContextPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent: _AgentPayload
    server: _ServerPayload | None


@dataclass(frozen=True, slots=True)
class GatewayContext:
    agent_id: UUID
    organization_id: UUID
    status: str
    passport_version: int
    scopes: tuple[Scope, ...]
    server_slug: str
    server_url: str | None
    safe_mode: bool
    budget: BudgetState
    payload_capture: bool
    honeytokens: tuple[HoneytokenRef, ...]
    honey_tools: tuple[HoneyTool, ...]
    pin_mode: str = "off"
    approved_tools: frozenset[tuple[str, str]] = frozenset()
    radar_mode: str = "off"
    output_check_mode: str = "off"
    loop_mode: str = "off"
    loop_limit: int = 20
    loop_window_seconds: int = 60
    loop_exempt: bool = False

    def honey_tool(self, name: str) -> HoneyTool | None:
        return next((t for t in self.honey_tools if t.name == name), None)

    def covers_tool(self, tool: str) -> bool:
        """True when any scope covers the tool, ignoring Safe Mode."""
        return any(s.server == self.server_slug and s.tool in ("*", tool) for s in self.scopes)

    def allows_tool(self, tool: str) -> bool:
        """
        True when the tool may be called now. In Safe Mode only scopes the operator declared as
        'read' count, so a tool covered only by a 'write' scope is refused. RedHand cannot verify
        that a tool really is read-only: the declaration is the operator's.
        """
        return any(
            s.server == self.server_slug
            and s.tool in ("*", tool)
            and (not self.safe_mode or s.access == "read")
            for s in self.scopes
        )


class ContextUnavailableError(Exception):
    """Core could not provide a trustworthy answer. The caller must deny."""


class AgentUnknownError(Exception):
    """Core does not know this agent in this organization."""


class CoreContextClient:
    def __init__(
        self,
        *,
        core_url: str,
        service_token: str | None,
        ttl_seconds: float,
        instance_id: str,
        http_client: httpx.AsyncClient | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/gateway-context"
        self._token = service_token
        self._instance_id = instance_id
        self._ttl = max(0.0, min(ttl_seconds, MAX_CONTEXT_TTL_SECONDS))
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(2.0, connect=1.0))
        self._clock = clock
        self._cache: OrderedDict[tuple[str, str, str], tuple[float, GatewayContext]] = OrderedDict()
        self._refreshing: dict[tuple[str, str, str], asyncio.Task[None]] = {}
        self._generation = 0
        self._metrics: Any = None

    def attach_metrics(self, metrics: Any) -> None:
        """Lets the gateway time lookups (hit, miss, background refresh). Optional: without it nothing is timed."""
        self._metrics = metrics

    def _stage(self, stage: str, started: float) -> None:
        if self._metrics is not None:
            self._metrics.record_stage(stage, (time.perf_counter() - started) * 1000)

    def invalidate(self) -> None:
        self._generation += 1  # a refresh already running must not put its (older) answer back
        self._cache.clear()

    async def aclose(self) -> None:
        for task in list(self._refreshing.values()):
            task.cancel()
        self._refreshing.clear()

    async def get(self, agent_id: UUID, organization_id: UUID, server: str) -> GatewayContext:
        key = (str(agent_id), str(organization_id), server)
        now = self._clock()
        timer = time.perf_counter()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self._ttl:
            if now - cached[0] >= self._ttl * REFRESH_AHEAD_FRACTION:
                self._start_refresh(key, agent_id, organization_id, server)
            self._stage("context_hit", timer)
            return cached[1]

        running = self._refreshing.get(key)
        if running is not None:
            await asyncio.wait({running}, timeout=REFRESH_WAIT_SECONDS)
            refreshed = self._cache.get(key)
            if refreshed is not None and self._clock() - refreshed[0] < self._ttl:  # still inside its lifetime: usable
                self._stage("context_wait_refresh", timer)
                return refreshed[1]

        context = await self._fetch(agent_id, organization_id, server)
        self._stage("context_miss", timer)
        self._cache[key] = (now, context)
        self._cache.move_to_end(key)
        while len(self._cache) > CACHE_MAX_ENTRIES:
            self._cache.popitem(last=False)
        return context

    def refresh_if_ageing(self, agent_id: UUID, organization_id: UUID, server: str) -> None:
        """
        Called when a call ends upstream. A refresh is otherwise only started at the START of a call, so a call that stays open
        for about the whole lifetime (a slow tool) would leave the NEXT call with an expired entry and a wait for core. This starts
        the same background refresh when the entry is at least REFRESH_AHEAD_FRACTION of its lifetime old, or has expired.
        Synchronous, does no I/O, never raises. It does not make any served entry older than the TTL: the refresh is stamped with the
        time it was requested, a failure changes nothing, and an unknown key (no lookup was made) starts nothing.
        """
        if self._ttl <= 0:
            return
        key = (str(agent_id), str(organization_id), server)
        cached = self._cache.get(key)
        if cached is None:
            return
        if self._clock() - cached[0] >= self._ttl * REFRESH_AHEAD_FRACTION:
            self._start_refresh(key, agent_id, organization_id, server)

    def _start_refresh(self, key: tuple[str, str, str], agent_id: UUID, organization_id: UUID, server: str) -> None:
        """Starts one background refresh per key. Never raises or waits; a failed refresh changes nothing (the old entry just expires)."""
        if key in self._refreshing or len(self._refreshing) >= MAX_BACKGROUND_REFRESHES:
            return
        try:
            # Stamp and generation are taken NOW, not when the task first runs: a later start must not look fresher, and an
            # invalidate() between now and then must discard the result.
            task = asyncio.get_running_loop().create_task(
                self._refresh(key, agent_id, organization_id, server, self._clock(), self._generation)
            )
        except RuntimeError:  # no running loop: only possible outside a request
            return
        self._refreshing[key] = task
        task.add_done_callback(lambda _t: self._refreshing.pop(key, None))

    async def _refresh(
        self, key: tuple[str, str, str], agent_id: UUID, organization_id: UUID, server: str, started: float, generation: int,
    ) -> None:
        # The entry is stamped with the time the refresh was REQUESTED, so it is never treated as fresher than it is (revocation SLO).
        timer = time.perf_counter()
        try:
            context = await self._fetch(agent_id, organization_id, server)
        except (ContextUnavailableError, AgentUnknownError):
            self._stage("context_refresh_failed", timer)
            return  # a failure is never cached and never extends the old entry's life
        except Exception as exc:  # noqa: BLE001  background work: log the type only, keep the old entry, never raise into the loop
            logger.warning("Passport refresh failed", error_type=type(exc).__name__)
            self._stage("context_refresh_failed", timer)
            return
        self._stage("context_refresh", timer)
        current = self._cache.get(key)
        if generation != self._generation or (current is not None and current[0] >= started):
            return
        self._cache[key] = (started, context)
        self._cache.move_to_end(key)

    async def _fetch(self, agent_id: UUID, organization_id: UUID, server: str) -> GatewayContext:
        if not self._token:
            raise ContextUnavailableError("Gateway is not configured with a core service token.")
        try:
            resp = await self._http.get(
                self._url,
                params={
                    "agent_id": str(agent_id), "organization_id": str(organization_id), "server": server,
                    "instance_id": self._instance_id,
                },
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            logger.error("Passport lookup failed: core unreachable", error_type=type(exc).__name__)
            raise ContextUnavailableError("Passport service unavailable.") from exc

        if resp.status_code == 404:
            raise AgentUnknownError("Agent is not registered.")
        if resp.status_code != 200:
            logger.error("Passport lookup failed", status=resp.status_code)
            raise ContextUnavailableError("Passport service unavailable.")
        try:
            payload = _ContextPayload.model_validate(resp.json())
        except (ValueError, ValidationError) as exc:
            logger.error("Passport lookup returned malformed data")
            raise ContextUnavailableError("Passport service returned malformed data.") from exc

        if payload.agent.id != agent_id or payload.agent.organization_id != organization_id:
            raise ContextUnavailableError("Passport service returned a mismatched agent.")
        if payload.server is not None and payload.server.slug != server:
            raise ContextUnavailableError("Passport service returned a mismatched server.")

        return GatewayContext(
            agent_id=agent_id,
            organization_id=organization_id,
            status=payload.agent.status,
            passport_version=payload.agent.version,
            scopes=tuple(payload.agent.scopes),
            server_slug=server,
            server_url=payload.server.url if payload.server else None,
            safe_mode=payload.agent.safe_mode,
            budget=BudgetState(
                daily_call_limit=payload.agent.budget.daily_call_limit,
                used_by_other_instances=payload.agent.budget.used_by_other_instances,
                day_key=payload.agent.budget.day_key,
                resets_at=payload.agent.budget.resets_at,
            ),
            payload_capture=payload.agent.payload_capture,
            pin_mode=payload.server.pin_mode if payload.server else "off",
            approved_tools=frozenset((t.tool, t.digest) for t in payload.server.approved_tools) if payload.server else frozenset(),
            honeytokens=tuple(HoneytokenRef(h.id, h.digest) for h in payload.agent.honeytokens),
            honey_tools=tuple(HoneyTool(id=t.id, name=t.name, description=t.description) for t in payload.agent.honey_tools),
            radar_mode=payload.agent.radar_mode,
            output_check_mode=payload.agent.output_check_mode,
            loop_mode=payload.agent.loop_mode,
            loop_limit=payload.agent.loop_limit,
            loop_window_seconds=payload.agent.loop_window_seconds,
            loop_exempt=payload.agent.loop_exempt,
        )
