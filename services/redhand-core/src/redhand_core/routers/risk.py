"""
The Risk Engine (Phase 4.5 B1, ADR 0019). See docs/runbooks/risk-engine.md.

GET /v1/risk/agents        every agent's score, level and short reason, and the ladder (security operator)
GET /v1/risk/agents/{id}   one agent: each signal with its points, the published weights (security operator)
GET /v1/risk/ladder        the response ladder and how many agents reach each rung now (security operator)
GET /v1/risk/behaviour/summary   how noisy the behaviour baseline would be for this organization, counts only (security operator)
PUT /v1/risk/ladder        change it (admin; turning Safe Mode or freeze on, or lowering it, needs confirm: true; audited)

The engine itself runs inside core after gateway reports; it has no endpoint of its own. The UI is never a security boundary.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.passports.models import utcnow
from redhand_core.risk import service
from redhand_core.risk.models import BehaviourSummaryResponse, LadderRequest, LadderView, RiskDetailResponse, RiskListResponse
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Risk Engine"])
SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/risk/agents", response_model=RiskListResponse)
async def list_agent_risk(operator: SecurityOperatorDep, supabase: SupabaseDep) -> RiskListResponse:
    return await service.list_agent_risk(supabase, operator, utcnow())


@router.get("/v1/risk/agents/{agent_id}", response_model=RiskDetailResponse)
async def get_agent_risk(agent_id: UUID, operator: SecurityOperatorDep, supabase: SupabaseDep) -> RiskDetailResponse:
    return await service.get_agent_risk(supabase, operator, agent_id, utcnow())


@router.get("/v1/risk/behaviour/summary", response_model=BehaviourSummaryResponse)
async def behaviour_summary(operator: SecurityOperatorDep, supabase: SupabaseDep) -> BehaviourSummaryResponse:
    """Phase 4.5 B2, watch only: for every active agent, whether its behaviour is unusual now, and how often it would have been flagged
    over the last 168 hours. Counts and agent names only. Read this before giving behaviour any weight in the score."""
    return await service.behaviour_summary(supabase, operator, utcnow())


@router.get("/v1/risk/ladder", response_model=LadderView)
async def get_ladder(operator: SecurityOperatorDep, supabase: SupabaseDep) -> LadderView:
    return await service.get_ladder(supabase, operator, utcnow())


@router.put("/v1/risk/ladder", response_model=LadderView)
async def put_ladder(payload: LadderRequest, operator: AdminDep, supabase: SupabaseDep) -> LadderView:
    """Send all three rungs; null turns one off. The ladder acts on the next signal, not on what is already recorded."""
    return await service.set_ladder(supabase, operator, payload, utcnow())
