"""
Operator API for Agent Passports, MCP servers and the control audit log.

Roles:
- viewer: read passports, servers and audit log
- security_operator: register agents, freeze, unfreeze (with confirmation), rotate keys
- admin/owner: revoke, freeze-all, change scopes, renew, register MCP servers
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep, ViewerDep
from redhand_core.config import Settings, get_settings
from redhand_core.passports import service
from redhand_core.passports.models import (
    MAX_REASON_LENGTH,
    ConfirmedControlActionRequest,
    ControlActionRequest,
    ControlActionResponse,
    ControlAuditEntry,
    FreezeAllResponse,
    KeyRotationResponse,
    McpServerCreateRequest,
    McpServerView,
    PassportCreateRequest,
    PassportCreateResponse,
    PassportView,
    RenewRequest,
    ScopesUpdateRequest,
    utcnow,
)
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(prefix="/v1", tags=["Agent Passports & Control Actions"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


def _audit_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="The action was applied, but its audit record could not be written. Contact support.",
    )


# -----------------------------------------------------------------------------
# Passports
# -----------------------------------------------------------------------------


@router.post("/passports", response_model=PassportCreateResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    payload: PassportCreateRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> PassportCreateResponse:
    try:
        passport, key = await service.create_passport(supabase, operator, payload, utcnow())
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return PassportCreateResponse(passport=passport, agent_key=key)


@router.get("/passports", response_model=list[PassportView])
async def list_passports(operator: ViewerDep, supabase: SupabaseDep) -> list[PassportView]:
    now = utcnow()
    return [PassportView.from_row(r, now) for r in await service.list_passport_rows(supabase, operator)]


@router.get("/passports/{agent_id}", response_model=PassportView)
async def get_passport(agent_id: UUID, operator: ViewerDep, supabase: SupabaseDep) -> PassportView:
    return PassportView.from_row(await service.get_passport_row(supabase, operator, agent_id), utcnow())


@router.post("/passports/{agent_id}/freeze", response_model=ControlActionResponse)
async def freeze_agent(
    agent_id: UUID, payload: ControlActionRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> ControlActionResponse:
    try:
        passport, changed = await service.freeze(supabase, operator, agent_id, payload.reason, utcnow())
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/unfreeze", response_model=ControlActionResponse)
async def unfreeze_agent(
    agent_id: UUID,
    payload: ConfirmedControlActionRequest,
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
) -> ControlActionResponse:
    try:
        passport, changed = await service.unfreeze(
            supabase, operator, agent_id, payload.reason, payload.confirm, utcnow()
        )
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/revoke", response_model=ControlActionResponse)
async def revoke_agent(
    agent_id: UUID, payload: ConfirmedControlActionRequest, operator: AdminDep, supabase: SupabaseDep
) -> ControlActionResponse:
    try:
        passport, changed = await service.revoke(
            supabase, operator, agent_id, payload.reason, payload.confirm, utcnow()
        )
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return ControlActionResponse(passport=passport, changed=changed)


class FreezeAllRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: bool = False


@router.post("/passports/freeze-all", response_model=FreezeAllResponse)
async def freeze_all_agents(
    payload: FreezeAllRequest, operator: AdminDep, supabase: SupabaseDep
) -> FreezeAllResponse:
    """Kill switch: freezes every active agent in the organization in one statement."""
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Freeze-all requires explicit confirmation: send "confirm": true.',
        )
    try:
        frozen = await service.freeze_all(supabase, operator, payload.reason, utcnow())
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return FreezeAllResponse(
        organization_id=operator.organization_id, frozen_count=len(frozen), frozen_agent_ids=frozen
    )


@router.put("/passports/{agent_id}/scopes", response_model=ControlActionResponse)
async def update_agent_scopes(
    agent_id: UUID, payload: ScopesUpdateRequest, operator: AdminDep, supabase: SupabaseDep
) -> ControlActionResponse:
    try:
        passport, changed = await service.update_scopes(
            supabase, operator, agent_id, payload.scopes, payload.reason, payload.confirm, utcnow()
        )
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/renew", response_model=PassportView)
async def renew_agent(
    agent_id: UUID, payload: RenewRequest, operator: AdminDep, supabase: SupabaseDep
) -> PassportView:
    try:
        return await service.renew(
            supabase, operator, agent_id, payload.expires_in_days, payload.reason, utcnow()
        )
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc


@router.post("/passports/{agent_id}/rotate-key", response_model=KeyRotationResponse)
async def rotate_agent_key(
    agent_id: UUID, payload: ControlActionRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> KeyRotationResponse:
    try:
        passport, key = await service.rotate_key(supabase, operator, agent_id, payload.reason, utcnow())
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return KeyRotationResponse(passport=passport, agent_key=key)


# -----------------------------------------------------------------------------
# Control audit log
# -----------------------------------------------------------------------------


@router.get("/audit/control", response_model=list[ControlAuditEntry])
async def list_control_audit(
    operator: ViewerDep, supabase: SupabaseDep, limit: int = Query(default=100, ge=1, le=500)
) -> list[ControlAuditEntry]:
    return await service.list_audit(supabase, operator, limit)


# -----------------------------------------------------------------------------
# MCP servers (gateway upstreams)
# -----------------------------------------------------------------------------


def validate_mcp_server_url(url: str, allow_insecure: bool) -> None:
    """
    Static checks at registration time. The gateway repeats a resolve-then-check on
    every connection (DNS can change), so this is a first line, not the only one.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP server URL must be an absolute http(s) URL.")
    if parts.username or parts.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP server URL must not contain credentials.")
    if allow_insecure:
        return
    if parts.scheme != "https":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP server URL must use https.")
    host = parts.hostname.lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".internal"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP server URL must be publicly reachable.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if not ip.is_global:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP server URL must be publicly reachable.")


def _server_view(row: dict[str, Any]) -> McpServerView:
    return McpServerView.model_validate(
        {k: row.get(k) for k in ("id", "organization_id", "slug", "name", "url")}
        | {"is_active": bool(row.get("is_active", True))}
    )


@router.post("/mcp-servers", response_model=McpServerView, status_code=status.HTTP_201_CREATED)
async def register_mcp_server(
    payload: McpServerCreateRequest,
    operator: AdminDep,
    supabase: SupabaseDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> McpServerView:
    validate_mcp_server_url(payload.url, settings.ALLOW_INSECURE_MCP_URLS)
    existing = await (
        supabase.table("mcp_servers")
        .select("id")
        .eq("organization_id", str(operator.organization_id))
        .eq("slug", payload.slug)
        .execute()
    )
    if existing.data:
        raise HTTPException(status.HTTP_409_CONFLICT, f"An MCP server with slug '{payload.slug}' exists.")
    server_id = uuid4()
    res = await supabase.table("mcp_servers").insert(
        {
            "id": str(server_id),
            "organization_id": str(operator.organization_id),
            "slug": payload.slug,
            "name": payload.name,
            "url": payload.url,
            "is_active": True,
            "created_by": str(operator.user_id),
        }
    ).execute()
    try:
        await service.write_audit(
            supabase, operator=operator, action="mcp_server.registered", target_type="mcp_server",
            target_id=server_id, reason=None, details={"slug": payload.slug, "url": payload.url},
        )
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return _server_view(dict(res.data[0]))


@router.get("/mcp-servers", response_model=list[McpServerView])
async def list_mcp_servers(operator: ViewerDep, supabase: SupabaseDep) -> list[McpServerView]:
    res = await (
        supabase.table("mcp_servers").select("*").eq("organization_id", str(operator.organization_id)).execute()
    )
    return [_server_view(dict(r)) for r in (res.data or [])]


@router.post("/mcp-servers/{server_id}/deactivate", response_model=McpServerView)
async def deactivate_mcp_server(
    server_id: UUID, operator: AdminDep, supabase: SupabaseDep
) -> McpServerView:
    res = await (
        supabase.table("mcp_servers")
        .update({"is_active": False})
        .eq("id", str(server_id))
        .eq("organization_id", str(operator.organization_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"MCP server '{server_id}' not found.")
    try:
        await service.write_audit(
            supabase, operator=operator, action="mcp_server.deactivated", target_type="mcp_server",
            target_id=server_id, reason=None,
        )
    except service.AuditWriteError as exc:
        raise _audit_failed() from exc
    return _server_view(dict(res.data[0]))
