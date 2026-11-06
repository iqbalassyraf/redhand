"""
Tool pinning (Phase 4 M3). See docs/adr/0014-tool-pinning.md.

GET  /v1/mcp-servers/{id}/tool-pins              the server's tool versions, pending first (security operator)
POST /v1/tool-pins/{pin_id}/decision             approve or reject a pending version (admin)
POST /v1/mcp-servers/{id}/tool-pins/approve-all  approve the newest pending version of every tool (admin, confirmation)
PUT  /v1/mcp-servers/{id}/pin-mode               off, alert or enforce (admin, confirmation, audited)
POST /internal/v1/tool-observations              gateway -> core: tool versions it saw (service token)
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.telegram import OptionalClientDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.toolpins import service
from redhand_core.toolpins.models import (
    ApproveAllRequest,
    ApproveAllResponse,
    ObservationReport,
    ObservationResponse,
    PinDecisionRequest,
    PinDecisionResponse,
    PinModeRequest,
    PinModeResponse,
    ToolPinsResponse,
)

router = APIRouter(tags=["Tool pinning"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/mcp-servers/{server_id}/tool-pins", response_model=ToolPinsResponse)
async def list_tool_pins(server_id: UUID, operator: SecurityOperatorDep, supabase: SupabaseDep) -> ToolPinsResponse:
    return await service.list_pins(supabase, operator.organization_id, server_id)


@router.post("/v1/tool-pins/{pin_id}/decision", response_model=PinDecisionResponse)
async def decide_tool_pin(pin_id: UUID, payload: PinDecisionRequest, operator: AdminDep, supabase: SupabaseDep) -> PinDecisionResponse:
    """Approve or reject one pending tool version. Approving it supersedes the previously approved version of that tool."""
    return await service.decide(supabase, operator, pin_id, payload)


@router.post("/v1/mcp-servers/{server_id}/tool-pins/approve-all", response_model=ApproveAllResponse)
async def approve_all_tool_pins(
    server_id: UUID, payload: ApproveAllRequest, operator: AdminDep, supabase: SupabaseDep
) -> ApproveAllResponse:
    """For the first baseline: approves the newest pending version of every tool on the server. Needs confirm: true."""
    return await service.approve_all(supabase, operator, server_id, payload)


@router.put("/v1/mcp-servers/{server_id}/pin-mode", response_model=PinModeResponse)
async def set_pin_mode(server_id: UUID, payload: PinModeRequest, operator: AdminDep, supabase: SupabaseDep) -> PinModeResponse:
    """off: no checks. alert (default): changes are reported. enforce: tools whose current version is not approved are hidden
    from agents and refused. Every change needs confirm: true."""
    return await service.set_pin_mode(supabase, operator, server_id, payload)


@router.post(
    "/internal/v1/tool-observations",
    response_model=ObservationResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def report_tool_observations(report: ObservationReport, supabase: SupabaseDep, telegram: OptionalClientDep) -> ObservationResponse:
    return await service.record_observation(supabase, telegram, report)
