"""
Per-agent destination allowlist (Phase 4 M7). See docs/plans/phase4-m7-destination-allowlist.md.

GET    /v1/passports/{id}/destinations              the agent's mode and allowed hosts (security operator)
POST   /v1/passports/{id}/destinations              allow one host (admin, confirmation, audited)
DELETE /v1/passports/{id}/destinations/{entry_id}   stop allowing a host (admin, audited; the last one cannot go while enforcing)
PUT    /v1/passports/{id}/destination-mode          off, observe or enforce (admin; enforce and off need a confirmation; compare and set)

The gateway reads the list through /internal/v1/gateway-context. The UI is never a security boundary: every change is authorized here.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.destinations import service
from redhand_core.destinations.models import (
    DestinationAddRequest,
    DestinationAddResponse,
    DestinationModeRequest,
    DestinationRemoveResponse,
    DestinationSettingsResponse,
)
from redhand_core.passports.models import MAX_REASON_LENGTH
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Destination allowlist"])
SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/passports/{agent_id}/destinations", response_model=DestinationSettingsResponse)
async def get_destinations(agent_id: UUID, operator: SecurityOperatorDep, supabase: SupabaseDep) -> DestinationSettingsResponse:
    return await service.get_settings(supabase, operator, agent_id)


@router.post("/v1/passports/{agent_id}/destinations", response_model=DestinationAddResponse)
async def add_destination(
    agent_id: UUID, payload: DestinationAddRequest, operator: AdminDep, supabase: SupabaseDep
) -> DestinationAddResponse:
    """Allows one host (a name or an address, nothing else). Needs confirm: true. Adding the same host again changes nothing."""
    return await service.add_destination(supabase, operator, agent_id, payload)


@router.delete("/v1/passports/{agent_id}/destinations/{entry_id}", response_model=DestinationRemoveResponse)
async def remove_destination(
    agent_id: UUID, entry_id: UUID, operator: AdminDep, supabase: SupabaseDep,
    reason: str | None = Query(default=None, max_length=MAX_REASON_LENGTH),
) -> DestinationRemoveResponse:
    return await service.remove_destination(supabase, operator, agent_id, entry_id, reason)


@router.put("/v1/passports/{agent_id}/destination-mode", response_model=DestinationSettingsResponse)
async def put_destination_mode(
    agent_id: UUID, payload: DestinationModeRequest, operator: AdminDep, supabase: SupabaseDep
) -> DestinationSettingsResponse:
    """observe records addresses outside the list and refuses nothing. enforce also refuses the call (needs a non-empty list and confirm: true).
    off checks nothing (needs confirm: true). The body carries the mode the caller saw."""
    return await service.set_mode(supabase, operator, agent_id, payload)
