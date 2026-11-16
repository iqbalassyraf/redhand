"""
GET /v1/agents/{agent_id}/timeline: the incident view (Phase 4.5 B3). Security operator and above, like findings and risk scores; the
organization comes from the operator's login, never from the request.
"""

from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from redhand_core.auth.operator import SecurityOperatorDep
from redhand_core.blackbox.service import csv_cell
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.rate_limit import SlidingWindowLimiter
from redhand_core.timeline import service
from redhand_core.timeline.models import TimelineResponse

router = APIRouter(tags=["Incident view"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]

# Per operator, in process, like the Black Box export: bulk reading through this endpoint is slow and visible.
_export_limiter = SlidingWindowLimiter(window_seconds=3600.0)
EXPORTS_PER_HOUR = 10
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.get("/v1/agents/{agent_id}/timeline", response_model=TimelineResponse)
async def agent_timeline(
    agent_id: UUID,
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    before: datetime | None = None,
    limit: int = Query(default=service.DEFAULT_PAGE, ge=1, le=service.MAX_PAGE),
) -> TimelineResponse:
    return await service.agent_timeline(supabase, operator, agent_id, before, limit)


@router.get("/v1/agents/{agent_id}/timeline/export")
async def export_agent_timeline(
    agent_id: UUID,
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    fmt: Annotated[str, Query(alias="format", pattern="^(json|csv)$")] = "json",
) -> Response:
    """The incident summary: the agent's whole timeline (newest first, at most 5,000 items) as a download, for a report or a ticket. The same
    fields as the page, never a payload. Audited before anything is read; 10 per hour per operator."""
    if not _export_limiter.allow(f"{operator.organization_id}:{operator.user_id}", EXPORTS_PER_HOUR, time.monotonic()):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many exports; try again later.")
    timeline, truncated = await service.export_timeline(supabase, operator, agent_id, fmt)
    now = datetime.now(timezone.utc)
    filename = f"redhand-timeline-{now.strftime('%Y%m%d-%H%M%S')}.{fmt}"
    headers = {**_NO_STORE, "Content-Disposition": f'attachment; filename="{filename}"'}
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\r\n")
        writer.writerow(service.CSV_COLUMNS)
        for row in service.csv_rows(timeline.items):
            writer.writerow([csv_cell(cell) for cell in row])
        return Response(buffer.getvalue(), media_type="text/csv; charset=utf-8", headers=headers)
    body = {
        "agent": timeline.agent.model_dump(mode="json"), "exported_at": now.isoformat(), "truncated": truncated,
        "items": [item.model_dump(mode="json") for item in timeline.items],
    }
    return Response(json.dumps(body), media_type="application/json", headers=headers)
