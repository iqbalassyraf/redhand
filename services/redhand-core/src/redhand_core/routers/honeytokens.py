"""
Honeytokens and honey tools (Phase 3 M3/M4). See docs/adr/0012-honeytokens.md.

GET  /v1/honeytokens               list (security operator)
POST /v1/honeytokens               create; the value is returned once (admin)
POST /v1/honeytokens/{id}/retire   retire (admin)
GET  /v1/honey-tools               list, optionally for one agent (security operator)
POST /v1/honey-tools               add a decoy tool to one agent's tools/list on one server (admin)
POST /v1/honey-tools/{id}/retire   retire (admin)
POST /internal/v1/trips            gateway -> core: a honeytoken or decoy tool was tripped (service token)
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.honeytokens import service
from redhand_core.honeytokens.models import (
    HoneytokenCreated,
    HoneytokenCreateRequest,
    HoneytokenView,
    HoneyToolCreateRequest,
    HoneyToolView,
    RetireResponse,
    TripReport,
    TripResponse,
)
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.telegram import OptionalClientDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.passports.models import utcnow
from redhand_core.risk import service as risk_service
from redhand_core.telegram.bot import AlertBatch

router = APIRouter(tags=["Honeytokens"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/honeytokens", response_model=list[HoneytokenView])
async def list_honeytokens(operator: SecurityOperatorDep, supabase: SupabaseDep) -> list[HoneytokenView]:
    return await service.list_honeytokens(supabase, operator.organization_id)


@router.post("/v1/honeytokens", response_model=HoneytokenCreated, status_code=201)
async def create_honeytoken(
    payload: HoneytokenCreateRequest, response: Response, operator: AdminDep, supabase: SupabaseDep
) -> HoneytokenCreated:
    """Creates a honeytoken. The response is the ONLY time the value is shown (like an agent key)."""
    response.headers["Cache-Control"] = "no-store"
    return await service.create_honeytoken(supabase, operator, payload)


@router.post("/v1/honeytokens/{honeytoken_id}/retire", response_model=RetireResponse)
async def retire_honeytoken(honeytoken_id: UUID, operator: AdminDep, supabase: SupabaseDep) -> RetireResponse:
    return await service.retire_honeytoken(supabase, operator, honeytoken_id)


@router.get("/v1/honey-tools", response_model=list[HoneyToolView])
async def list_honey_tools(
    operator: SecurityOperatorDep, supabase: SupabaseDep, agent_id: UUID | None = None
) -> list[HoneyToolView]:
    return await service.list_honey_tools(supabase, operator.organization_id, agent_id)


@router.post("/v1/honey-tools", response_model=HoneyToolView, status_code=201)
async def create_honey_tool(payload: HoneyToolCreateRequest, operator: AdminDep, supabase: SupabaseDep) -> HoneyToolView:
    """Adds a decoy tool to one agent's tool list on one MCP server. A call to it is never forwarded. An honest
    agent can call a tempting tool when a user asks for exactly that, so the default action is alert, not freeze."""
    return await service.create_honey_tool(supabase, operator, payload)


@router.post("/v1/honey-tools/{honey_tool_id}/retire", response_model=RetireResponse)
async def retire_honey_tool(honey_tool_id: UUID, operator: AdminDep, supabase: SupabaseDep) -> RetireResponse:
    return await service.retire_honey_tool(supabase, operator, honey_tool_id)


@router.post(
    "/internal/v1/trips",
    response_model=TripResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def report_trip(report: TripReport, supabase: SupabaseDep, telegram: OptionalClientDep) -> TripResponse:
    alerts = AlertBatch()  # the trip alert and any risk alert leave as one Telegram message
    recorded = await service.handle_trip(supabase, telegram, report, alerts)
    if recorded:
        await risk_service.evaluate_agents(supabase, telegram, report.organization_id, [report.agent_id], utcnow(), alerts)  # never raises
    await alerts.flush(supabase, telegram)
    return TripResponse(recorded=recorded)
