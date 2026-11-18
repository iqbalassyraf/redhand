"""
GET /v1/insights/summary: the dashboard's home page numbers (dashboard redesign S2, ADR 0031). Viewer and above, like the Black Box events it is
computed from. The organization comes from the operator's login, never from the request.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from redhand_core.auth.operator import ViewerDep
from redhand_core.insights import service
from redhand_core.insights.models import InsightsResponse, Window
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Insights"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/insights/summary", response_model=InsightsResponse)
async def insights_summary(operator: ViewerDep, supabase: SupabaseDep, window: Annotated[Window, Query()] = "24h") -> InsightsResponse:
    return await service.summary(supabase, operator.organization_id, window)
