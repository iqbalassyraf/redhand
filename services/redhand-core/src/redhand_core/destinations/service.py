"""
The per-agent destination allowlist: tenant-scoped reads and audited changes (in SQL). See docs/plans/phase4-m7-destination-allowlist.md.

Who may do what is decided by the router's role dependencies; the organization comes from the verified operator, never from the request.
Adding a host widens what the agent may reach and turning enforcement on refuses calls, so both need an explicit confirmation.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.destinations.hosts import normalize_host
from redhand_core.destinations.models import (
    DestinationAddRequest,
    DestinationAddResponse,
    DestinationCapabilities,
    DestinationEntry,
    DestinationModeRequest,
    DestinationRemoveResponse,
    DestinationSettingsResponse,
)
from redhand_core.passports.service import _require_confirmation, _rpc

logger = logging.getLogger("redhand.core.destinations")

BAD_HOST_MESSAGE = (
    "Enter a host name or address only, for example files.example.com: no http://, no path, no port and no wildcard."
)


async def get_settings(supabase: Any, operator: OperatorContext, agent_id: UUID) -> DestinationSettingsResponse:
    data = await _rpc(
        supabase, "destination_settings", {"p_org": str(operator.organization_id), "p_agent": str(agent_id)},
        not_found_detail="Agent not found.", conflict_detail="The allowed destinations could not be read.",
    )
    return DestinationSettingsResponse(
        destination_mode=data["destination_mode"], destination_mode_changed_at=data.get("destination_mode_changed_at"),
        entries=[DestinationEntry(id=e["id"], host=e["host"], created_at=e["created_at"]) for e in data.get("entries") or []],
        last_7_days=dict(data.get("last_7_days") or {}),
        capabilities=DestinationCapabilities(can_change=operator.role is not None and operator.role >= Role.ADMIN),
    )


async def add_destination(supabase: Any, operator: OperatorContext, agent_id: UUID, request: DestinationAddRequest) -> DestinationAddResponse:
    _require_confirmation(request.confirm, "Adding an allowed destination")
    host = normalize_host(request.host)  # the same function the gateway applies to a call, so what is stored is what will be compared
    if host is None:
        raise HTTPException(422, BAD_HOST_MESSAGE)
    data = await _rpc(
        supabase, "control_destination_add",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_agent": str(agent_id), "p_host": host,
         "p_reason": request.reason},
        not_found_detail="Agent not found.", conflict_detail="The destination could not be added.",
    )
    if data.get("limit"):
        raise HTTPException(status.HTTP_409_CONFLICT, "This agent already has 100 allowed destinations. Remove one first.")
    return DestinationAddResponse(id=data["id"], host=host, added=bool(data["added"]))


async def remove_destination(
    supabase: Any, operator: OperatorContext, agent_id: UUID, entry_id: UUID, reason: str | None
) -> DestinationRemoveResponse:
    data = await _rpc(
        supabase, "control_destination_remove",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_agent": str(agent_id), "p_entry": str(entry_id),
         "p_reason": reason},
        not_found_detail="Destination not found.", conflict_detail="The destination could not be removed.",
    )
    if data.get("last_entry_in_enforce"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This is the last allowed destination and the agent is enforcing: an empty list would refuse every address. Switch it to Watch or Off first.",
        )
    return DestinationRemoveResponse(removed=bool(data["removed"]))


async def set_mode(supabase: Any, operator: OperatorContext, agent_id: UUID, request: DestinationModeRequest) -> DestinationSettingsResponse:
    """Compare-and-set against the mode the caller saw. Enforce refuses calls and off removes a safeguard: both need the confirmation."""
    if request.destination_mode == "enforce" and request.expected_mode != "enforce":
        _require_confirmation(request.confirm, "Turning destination enforcement on (calls with an address that is not on the list are refused)")
    if request.destination_mode == "off" and request.expected_mode != "off":
        _require_confirmation(request.confirm, "Turning the destination check off")
    data = await _rpc(
        supabase, "control_destination_mode",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_agent": str(agent_id),
         "p_mode": request.destination_mode, "p_expected_mode": request.expected_mode, "p_reason": request.reason},
        not_found_detail="Agent not found.", conflict_detail="The mode could not be changed.",
    )
    if data.get("conflict"):
        raise HTTPException(status.HTTP_409_CONFLICT, "The mode was changed by someone else. Reload and try again.")
    if data.get("empty_list"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Add at least one allowed destination before turning enforcement on.")
    return await get_settings(supabase, operator, agent_id)
