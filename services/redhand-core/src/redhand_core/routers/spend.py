"""
Model spend (Phase 4.5 B4a, ADR 0023): what each agent's SDK reported, as an estimate, and an optional daily dollar limit that only alerts.

- GET /v1/spend/agents              viewer: today's estimated spend per agent, per model
- GET /v1/spend/agents/{id}         viewer: one agent, today and the last 7 days
- PUT /v1/passports/{id}/spend-limit admin: set, lower, raise or remove the agent's limit (audited; raising or removing needs "confirm")

Numbers are self-reported by the agent's SDK and are never used to refuse a call.

Measured usage (B5b, ADR 0025): the gateway's model proxy (off by default) reports what the PROVIDER counted.
- POST /internal/v1/model-usage     gateway -> core, service token only: a batch of at most 500 aggregates; idempotent per batch id; the tenant comes from each agent's own row
The spend views carry it as `measured`, apart from the reported figures.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends

from redhand_core.auth.operator import AdminDep, ViewerDep
from redhand_core.passports.models import utcnow
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.spend import service
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.spend.models import (
    AgentSpendDetailResponse,
    ModelUsageBatch,
    ModelUsageBatchResponse,
    SpendLimitRequest,
    SpendLimitResponse,
    SpendTodayResponse,
)

router = APIRouter(tags=["Model spend"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/spend/agents", response_model=SpendTodayResponse)
async def get_spend(operator: ViewerDep, supabase: SupabaseDep) -> SpendTodayResponse:
    return await service.list_today(supabase, operator, utcnow())


@router.get("/v1/spend/agents/{agent_id}", response_model=AgentSpendDetailResponse)
async def get_agent_spend(agent_id: UUID, operator: ViewerDep, supabase: SupabaseDep) -> AgentSpendDetailResponse:
    return await service.agent_detail(supabase, operator, agent_id, utcnow())


@router.put("/v1/passports/{agent_id}/spend-limit", response_model=SpendLimitResponse)
async def set_spend_limit(agent_id: UUID, payload: SpendLimitRequest, operator: AdminDep, supabase: SupabaseDep) -> SpendLimitResponse:
    limit, changed = await service.set_limit(supabase, operator, agent_id, payload.spend_limit_micro_usd, payload.reason, payload.confirm)
    return SpendLimitResponse(agent_id=agent_id, spend_limit_micro_usd=limit, changed=changed)


@router.post("/internal/v1/model-usage", response_model=ModelUsageBatchResponse, dependencies=[Depends(require_internal_service)], include_in_schema=False)
async def post_model_usage(batch: ModelUsageBatch, supabase: SupabaseDep) -> ModelUsageBatchResponse:
    return await service.record_measured(supabase, batch)
