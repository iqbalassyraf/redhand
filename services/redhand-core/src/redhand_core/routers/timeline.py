"""
GET /v1/agents/{agent_id}/timeline: the incident view (Phase 4.5 B3). Security operator and above, like findings and risk scores; the
organization comes from the operator's login, never from the request.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from redhand_core.auth.operator import SecurityOperatorDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.timeline import service
from redhand_core.timeline.models import TimelineResponse

router = APIRouter(tags=["Incident view"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/agents/{agent_id}/timeline", response_model=TimelineResponse)
async def agent_timeline(
    agent_id: UUID,
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    before: datetime | None = None,
    limit: int = Query(default=service.DEFAULT_PAGE, ge=1, le=service.MAX_PAGE),
) -> TimelineResponse:
    return await service.agent_timeline(supabase, operator, agent_id, before, limit)
