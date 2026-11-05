"""
Black Box Recorder ingest: the gateway reports batches of allowed/refused/failed tool calls here.
See docs/plans/phase3-plan.md and agentwall/src/gateway/recorder.py (the sender).

POST /internal/v1/events   gateway -> core (internal service token only)

Each batch belongs to one organization (EventIngestRequest.organization_id): the chain is per
organization and record_events() locks that organization's chain head for the whole batch, so the
gateway's recorder groups its buffer by organization before flushing. The organization claimed here
is re-checked per item against the agent's real organization inside record_events() itself, so a
wrong or stale value can only cause rejections, never a cross-tenant write (CLAUDE.md §5.3).
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from redhand_core.blackbox import service as blackbox_service
from redhand_core.blackbox.models import EventIngestRequest, EventIngestResponse
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Black Box Recorder"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.post(
    "/internal/v1/events",
    response_model=EventIngestResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def ingest_events(report: EventIngestRequest, supabase: SupabaseDep) -> EventIngestResponse:
    accepted, rejected = await blackbox_service.ingest_events(
        supabase, report.instance_id, report.batch_id, report.organization_id, report.items
    )
    return EventIngestResponse(accepted=accepted, rejected=rejected)
