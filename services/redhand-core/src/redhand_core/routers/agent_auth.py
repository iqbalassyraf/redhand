"""
Agent authentication.

- POST /v1/agent-auth/token: an agent exchanges its agent key for a short-lived access
  token. Refused unless the passport is currently active (not frozen, revoked or expired).
- GET  /v1/agent-auth/jwks: public verification key for the gateway (public data).
- GET  /internal/v1/gateway-context: the gateway's per-call authorization lookup,
  authenticated with the internal service token.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
import hashlib
import hmac
import logging
import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel

from redhand_core.auth import bearer_token
from redhand_core.config import Settings, get_settings
from redhand_core.passports.credentials import AgentTokenSigner, hash_agent_key, looks_like_agent_key
from redhand_core.passports.models import (
    SERVER_SLUG_PATTERN,
    PassportStatus,
    Scope,
    effective_status,
    parse_scopes,
    parse_timestamp,
    utcnow,
)
from redhand_core.routers.telemetry import get_supabase_service_client

logger = logging.getLogger("redhand.core.agent_auth")

router = APIRouter(tags=["Agent Authentication"])
SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]

# -----------------------------------------------------------------------------
# Signer
# -----------------------------------------------------------------------------

_signers: dict[str, AgentTokenSigner] = {}
_DEV_SIGNER_KEY = "__development__"


def get_agent_token_signer(settings: Annotated[Settings, Depends(get_settings)]) -> AgentTokenSigner:
    configured = settings.AGENT_TOKEN_SIGNING_KEY
    if configured is not None:
        pem = configured.get_secret_value()
        cache_key = hashlib.sha256(pem.encode("utf-8")).hexdigest()
        if cache_key not in _signers:
            _signers[cache_key] = AgentTokenSigner.from_pem(pem)
        return _signers[cache_key]
    if settings.ENVIRONMENT in ("development", "test"):
        if _DEV_SIGNER_KEY not in _signers:
            logger.warning("AGENT_TOKEN_SIGNING_KEY not set; using a random per-process dev key")
            _signers[_DEV_SIGNER_KEY] = AgentTokenSigner.generate()
        return _signers[_DEV_SIGNER_KEY]
    logger.error("AGENT_TOKEN_SIGNING_KEY is not configured; agent token issuance is disabled")
    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Agent authentication is not configured.")


SignerDep = Annotated[AgentTokenSigner, Depends(get_agent_token_signer)]

# -----------------------------------------------------------------------------
# Rate limiting (per agent key). In-process; adequate for a single core instance.
# -----------------------------------------------------------------------------


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str, limit: int, now: float) -> bool:
        events = self._events.setdefault(key, deque())
        while events and now - events[0] >= self._window:
            events.popleft()
        if len(events) >= limit:
            return False
        events.append(now)
        return True


_exchange_limiter = SlidingWindowLimiter()

# -----------------------------------------------------------------------------
# Token exchange
# -----------------------------------------------------------------------------


class AgentTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    expires_at: datetime
    agent_id: UUID
    organization_id: UUID
    passport_version: int


def _invalid_key() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid agent key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/v1/agent-auth/token", response_model=AgentTokenResponse)
async def exchange_agent_key(
    supabase: SupabaseDep,
    settings: Annotated[Settings, Depends(get_settings)],
    signer: SignerDep,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AgentTokenResponse:
    presented = bearer_token(authorization) or ""
    if not looks_like_agent_key(presented):
        raise _invalid_key()
    key_hash = hash_agent_key(presented)

    if not _exchange_limiter.allow(key_hash, settings.AGENT_TOKEN_EXCHANGES_PER_MINUTE, time.monotonic()):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many token requests for this agent key.",
            headers={"Retry-After": "60"},
        )

    key_res = await (
        supabase.table("agent_keys")
        .select("id, agent_id, organization_id, is_active")
        .eq("key_hash", key_hash)
        .eq("is_active", True)
        .maybe_single()
        .execute()
    )
    key_row = key_res.data if key_res else None
    if not key_row:
        raise _invalid_key()

    agent_res = await (
        supabase.table("agents")
        .select("*")
        .eq("id", str(key_row["agent_id"]))
        .eq("organization_id", str(key_row["organization_id"]))
        .maybe_single()
        .execute()
    )
    agent = agent_res.data if agent_res else None
    if not agent:
        raise _invalid_key()

    now = utcnow()
    current = effective_status(str(agent.get("status")), agent.get("expires_at"), now)
    if current != "active":
        logger.info("Token exchange refused: agent=%s status=%s", agent["id"], current)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent passport is {current}.",
        )

    ttl = timedelta(seconds=settings.AGENT_TOKEN_TTL_SECONDS)
    token, jti, expires_at = signer.issue(
        agent_id=UUID(str(agent["id"])),
        organization_id=UUID(str(agent["organization_id"])),
        passport_version=int(agent.get("version") or 1),
        now=now,
        ttl=ttl,
    )
    await (
        supabase.table("agent_keys")
        .update({"last_used_at": now.isoformat()})
        .eq("id", str(key_row["id"]))
        .execute()
    )
    logger.info("Issued agent access token: agent=%s jti=%s", agent["id"], jti)
    return AgentTokenResponse(
        access_token=token,
        expires_in=int(ttl.total_seconds()),
        expires_at=expires_at,
        agent_id=UUID(str(agent["id"])),
        organization_id=UUID(str(agent["organization_id"])),
        passport_version=int(agent.get("version") or 1),
    )


@router.get("/v1/agent-auth/jwks")
async def agent_token_jwks(signer: SignerDep) -> dict[str, list[dict[str, str]]]:
    return {"keys": [signer.public_jwk()]}


# -----------------------------------------------------------------------------
# Internal: gateway authorization context
# -----------------------------------------------------------------------------


def require_internal_service(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> None:
    expected = settings.INTERNAL_SERVICE_TOKEN
    if expected is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Internal API is not configured.")
    presented = bearer_token(authorization)
    if not presented or not hmac.compare_digest(presented, expected.get_secret_value()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid service credentials.")


class GatewayAgentContext(BaseModel):
    id: UUID
    organization_id: UUID
    status: PassportStatus
    version: int
    scopes: list[Scope]
    expires_at: datetime
    safe_mode: bool


class GatewayServerContext(BaseModel):
    slug: str
    url: str


class GatewayContextResponse(BaseModel):
    agent: GatewayAgentContext
    server: GatewayServerContext | None


@router.get(
    "/internal/v1/gateway-context",
    response_model=GatewayContextResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def gateway_context(
    supabase: SupabaseDep,
    agent_id: UUID,
    organization_id: UUID,
    server: Annotated[str, Query(pattern=SERVER_SLUG_PATTERN)],
) -> GatewayContextResponse:
    """
    Everything the gateway needs to authorize one call: the passport's current status,
    version and scopes, and the upstream URL of the requested MCP server in that tenant.
    Malformed stored data yields status 'revoked' so the gateway denies (fail closed).
    """
    agent_res = await (
        supabase.table("agents")
        .select("*")
        .eq("id", str(agent_id))
        .eq("organization_id", str(organization_id))
        .maybe_single()
        .execute()
    )
    agent = agent_res.data if agent_res else None
    if not agent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.")

    now = utcnow()
    try:
        scopes = parse_scopes(agent.get("scopes", []))
        expires_at = parse_timestamp(agent["expires_at"])
        current: PassportStatus = effective_status(str(agent.get("status")), agent["expires_at"], now)
    except (KeyError, TypeError, ValueError):
        logger.error("Malformed passport data for agent %s; reporting revoked", agent_id)
        scopes, expires_at, current = [], now, "revoked"

    server_res = await (
        supabase.table("mcp_servers")
        .select("slug, url, is_active")
        .eq("organization_id", str(organization_id))
        .eq("slug", server)
        .eq("is_active", True)
        .maybe_single()
        .execute()
    )
    server_row = server_res.data if server_res else None

    # Safe Mode is on when the agent's flag OR the organization's flag is on. Anything that is not
    # an explicit false (a missing row, null, a non-boolean) counts as ON: the restrictive reading.
    org_res = await (
        supabase.table("organizations").select("safe_mode").eq("id", str(organization_id)).maybe_single().execute()
    )
    org_row = org_res.data if org_res else None
    safe_mode = not (
        agent.get("safe_mode") is False and org_row is not None and org_row.get("safe_mode") is False
    )

    await (
        supabase.table("agents")
        .update({"last_seen_at": now.isoformat()})
        .eq("id", str(agent_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )

    return GatewayContextResponse(
        agent=GatewayAgentContext(
            id=agent_id,
            organization_id=organization_id,
            status=current,
            version=int(agent.get("version") or 1),
            scopes=scopes,
            expires_at=expires_at,
            safe_mode=safe_mode,
        ),
        server=GatewayServerContext(slug=server_row["slug"], url=server_row["url"]) if server_row else None,
    )
