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
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from redhand_core.auth.operator import AdminDep, OperatorContext, OperatorDep, Role, SecurityOperatorDep, ViewerDep
from redhand_core.config import Settings, get_settings
from redhand_core.passports import service
from redhand_core.passports.models import (
    MAX_REASON_LENGTH,
    AgentSafeModeResponse,
    ConfirmedControlActionRequest,
    ControlActionRequest,
    ControlActionResponse,
    ControlAuditEntry,
    FreezeAllResponse,
    KeyRotationResponse,
    McpServerCreateRequest,
    McpServerView,
    OrganizationSafeModeResponse,
    PassportCreateRequest,
    PassportCreateResponse,
    PassportView,
    RenewRequest,
    SafeModeRequest,
    ScopesUpdateRequest,
    utcnow,
)
from redhand_core.routers.telegram import OptionalClientDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.telegram.bot import notify_organization
from redhand_core.telegram.client import TelegramClient

router = APIRouter(prefix="/v1", tags=["Agent Passports & Control Actions"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


async def _alert(
    supabase: Any, telegram: TelegramClient | None, operator: OperatorContext, what: str, reason: str | None
) -> None:
    """Tells linked Telegram chats about a stopping or restoring action. Best effort, never raises."""
    who = operator.email or "An operator"
    text = f"RedHand: {what} in the dashboard by {who}." + (f" Reason: {reason}" if reason else "")
    await notify_organization(supabase, telegram, operator.organization_id, text)


# -----------------------------------------------------------------------------
# Passports
# -----------------------------------------------------------------------------


@router.post("/passports", response_model=PassportCreateResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    payload: PassportCreateRequest, operator: AdminDep, supabase: SupabaseDep
) -> PassportCreateResponse:
    """Registering an agent issues its key, so it is a credential-issuing action: admin (owner's decision, 2026-11-17)."""
    now = utcnow()
    passport, key = await service.create_passport(supabase, operator, payload, now)
    passport = await service.apply_default_budget(supabase, operator, passport, now)
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
    agent_id: UUID,
    payload: ControlActionRequest,
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    telegram: OptionalClientDep,
) -> ControlActionResponse:
    passport, changed = await service.freeze(supabase, operator, agent_id, payload.reason, utcnow())
    if changed:
        await _alert(supabase, telegram, operator, f"{passport.name} was frozen", payload.reason)
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/unfreeze", response_model=ControlActionResponse)
async def unfreeze_agent(
    agent_id: UUID,
    payload: ConfirmedControlActionRequest,
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    telegram: OptionalClientDep,
) -> ControlActionResponse:
    passport, changed = await service.unfreeze(
        supabase, operator, agent_id, payload.reason, payload.confirm, utcnow()
    )
    if changed:
        await _alert(supabase, telegram, operator, f"{passport.name} was unfrozen", payload.reason)
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/promote", response_model=ControlActionResponse)
async def promote_agent(
    agent_id: UUID,
    payload: ConfirmedControlActionRequest,
    operator: AdminDep,
    supabase: SupabaseDep,
    telegram: OptionalClientDep,
) -> ControlActionResponse:
    passport, changed = await service.promote(supabase, operator, agent_id, payload.reason, payload.confirm, utcnow())
    if changed:
        await _alert(supabase, telegram, operator, f"{passport.name} was promoted from reported only to a managed passport", payload.reason)
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/revoke", response_model=ControlActionResponse)
async def revoke_agent(
    agent_id: UUID,
    payload: ConfirmedControlActionRequest,
    operator: AdminDep,
    supabase: SupabaseDep,
    telegram: OptionalClientDep,
) -> ControlActionResponse:
    passport, changed = await service.revoke(
        supabase, operator, agent_id, payload.reason, payload.confirm, utcnow()
    )
    if changed:
        await _alert(supabase, telegram, operator, f"{passport.name} was permanently revoked", payload.reason)
    return ControlActionResponse(passport=passport, changed=changed)


class FreezeAllRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: bool = False


@router.post("/passports/freeze-all", response_model=FreezeAllResponse)
async def freeze_all_agents(
    payload: FreezeAllRequest, operator: AdminDep, supabase: SupabaseDep, telegram: OptionalClientDep
) -> FreezeAllResponse:
    """Kill switch: freezes every active agent in the organization in one statement."""
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Freeze-all requires explicit confirmation: send "confirm": true.',
        )
    frozen = await service.freeze_all(supabase, operator, payload.reason)
    await _alert(supabase, telegram, operator, f"All agents were frozen ({len(frozen)} stopped)", payload.reason)
    return FreezeAllResponse(
        organization_id=operator.organization_id, frozen_count=len(frozen), frozen_agent_ids=frozen
    )


def _require_safe_mode_role(operator: OperatorContext, enabled: bool) -> None:
    """Turning Safe Mode ON is a stopping action (security operator); OFF restores access (admin)."""
    needed = Role.SECURITY_OPERATOR if enabled else Role.ADMIN
    if operator.role < needed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This action requires the '{needed.name.lower()}' role or higher.",
        )


@router.post("/passports/{agent_id}/safe-mode", response_model=AgentSafeModeResponse)
async def set_agent_safe_mode(
    agent_id: UUID, payload: SafeModeRequest, operator: OperatorDep, supabase: SupabaseDep, telegram: OptionalClientDep
) -> AgentSafeModeResponse:
    """Safe Mode: while on, the gateway allows this agent only tools its scopes declare as read."""
    _require_safe_mode_role(operator, payload.enabled)
    passport, changed = await service.set_agent_safe_mode(
        supabase, operator, agent_id, payload.enabled, payload.reason, payload.confirm, utcnow()
    )
    if changed:
        state = "on" if payload.enabled else "off"
        await _alert(supabase, telegram, operator, f"Safe Mode was turned {state} for {passport.name}", payload.reason)
    return AgentSafeModeResponse(passport=passport, changed=changed)


@router.get("/organization/safe-mode", response_model=OrganizationSafeModeResponse)
async def get_organization_safe_mode(operator: ViewerDep, supabase: SupabaseDep) -> OrganizationSafeModeResponse:
    return OrganizationSafeModeResponse(
        enabled=await service.get_org_safe_mode(supabase, operator.organization_id), changed=False
    )


@router.post("/organization/safe-mode", response_model=OrganizationSafeModeResponse)
async def set_organization_safe_mode(
    payload: SafeModeRequest, operator: OperatorDep, supabase: SupabaseDep, telegram: OptionalClientDep
) -> OrganizationSafeModeResponse:
    """Safe Mode for every agent of the organization."""
    _require_safe_mode_role(operator, payload.enabled)
    changed = await service.set_org_safe_mode(supabase, operator, payload.enabled, payload.reason, payload.confirm)
    if changed:
        state = "on" if payload.enabled else "off"
        await _alert(supabase, telegram, operator, f"Safe Mode was turned {state} for all agents", payload.reason)
    return OrganizationSafeModeResponse(enabled=payload.enabled, changed=changed)


@router.put("/passports/{agent_id}/scopes", response_model=ControlActionResponse)
async def update_agent_scopes(
    agent_id: UUID, payload: ScopesUpdateRequest, operator: AdminDep, supabase: SupabaseDep
) -> ControlActionResponse:
    passport, changed = await service.update_scopes(
        supabase, operator, agent_id, payload.scopes, payload.reason, payload.confirm, utcnow()
    )
    return ControlActionResponse(passport=passport, changed=changed)


@router.post("/passports/{agent_id}/renew", response_model=PassportView)
async def renew_agent(
    agent_id: UUID, payload: RenewRequest, operator: AdminDep, supabase: SupabaseDep
) -> PassportView:
    return await service.renew(
        supabase, operator, agent_id, payload.expires_in_days, payload.reason, utcnow()
    )


@router.post("/passports/{agent_id}/rotate-key", response_model=KeyRotationResponse)
async def rotate_agent_key(
    agent_id: UUID, payload: ControlActionRequest, operator: AdminDep, supabase: SupabaseDep
) -> KeyRotationResponse:
    """A new agent key is a working credential: admin (owner's decision, 2026-11-17)."""
    passport, key = await service.rotate_key(supabase, operator, agent_id, payload.reason, utcnow())
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
    return _server_view(await service.register_mcp_server(supabase, operator, payload))


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
    return _server_view(await service.deactivate_mcp_server(supabase, operator, server_id))
