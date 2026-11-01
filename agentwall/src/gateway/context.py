"""
Per-call authorization context from redhand-core, with a short bounded cache.

The cache TTL is capped so that a freeze or revoke in core reaches the gateway within
the 5-second revocation SLO (CLAUDE.md §4.5): TTL (<= 2 s by default, never more than
4 s) plus one lookup. Failures are never cached and always surface as
`ContextUnavailableError`, which the gateway turns into a deny.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import time
from typing import Any, Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError
import structlog

logger = structlog.get_logger(__name__)

MAX_CONTEXT_TTL_SECONDS = 4.0
CACHE_MAX_ENTRIES = 10_000


class Scope(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    server: str
    tool: str
    access: Literal["read", "write"] = "read"


class _AgentPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: UUID
    organization_id: UUID
    status: Literal["active", "frozen", "revoked", "expired"]
    version: int = Field(ge=1)
    scopes: list[Scope]


class _ServerPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    slug: str
    url: str


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

    def allows_tool(self, tool: str) -> bool:
        return any(s.server == self.server_slug and s.tool in ("*", tool) for s in self.scopes)


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
        http_client: httpx.AsyncClient | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/gateway-context"
        self._token = service_token
        self._ttl = max(0.0, min(ttl_seconds, MAX_CONTEXT_TTL_SECONDS))
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(2.0, connect=1.0))
        self._clock = clock
        self._cache: OrderedDict[tuple[str, str, str], tuple[float, GatewayContext]] = OrderedDict()

    def invalidate(self) -> None:
        self._cache.clear()

    async def get(self, agent_id: UUID, organization_id: UUID, server: str) -> GatewayContext:
        key = (str(agent_id), str(organization_id), server)
        now = self._clock()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self._ttl:
            return cached[1]

        context = await self._fetch(agent_id, organization_id, server)
        self._cache[key] = (now, context)
        self._cache.move_to_end(key)
        while len(self._cache) > CACHE_MAX_ENTRIES:
            self._cache.popitem(last=False)
        return context

    async def _fetch(self, agent_id: UUID, organization_id: UUID, server: str) -> GatewayContext:
        if not self._token:
            raise ContextUnavailableError("Gateway is not configured with a core service token.")
        try:
            resp = await self._http.get(
                self._url,
                params={"agent_id": str(agent_id), "organization_id": str(organization_id), "server": server},
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
        )
