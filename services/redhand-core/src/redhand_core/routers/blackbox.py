"""
Black Box Recorder: operator-facing reads. See docs/plans/phase3-plan.md.

GET /v1/blackbox/events    the organization's timeline, newest first, paginated by seq
GET /v1/blackbox/verify    recomputes a seq range's hash chain and reports the first mismatch, if any
GET /v1/blackbox/settings  retention periods and whether payload capture is on
PUT /v1/blackbox/retention changes the retention periods (admin, with confirmation, audited)
PUT /v1/blackbox/payload-capture turns payload capture on (admin, confirmation) or off (security operator)
GET /v1/blackbox/events/{seq}/payload one event's captured payload (admin; audited with the read)
POST /v1/blackbox/payloads/clear deletes every captured payload now (admin, confirmation, audited)
GET /v1/blackbox/export    the timeline as JSON Lines or CSV (security operator; payloads need admin; audited)

Every read is scoped to the caller's organization (never a client-supplied tenant id).
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from fastapi.responses import StreamingResponse

from redhand_core.auth.operator import AdminDep, Role, SecurityOperatorDep, ViewerDep
from redhand_core.blackbox import service as blackbox_service
from redhand_core.blackbox.models import (
    BlackBoxRetentionRequest,
    BlackBoxSettingsResponse,
    BlackBoxTimelineResponse,
    ClearPayloadsRequest,
    ClearPayloadsResponse,
    EventPayloadResponse,
    PayloadCaptureRequest,
    VerifyResponse,
)
from redhand_core.services.rate_limit import SlidingWindowLimiter
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Black Box Recorder"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]

# Per operator, in process (the same approach as the other limiters). Payload views are individually audited;
# the limit makes bulk reading through this endpoint slow and visible. Exports are capped at 50,000 rows each.
_payload_limiter = SlidingWindowLimiter(window_seconds=60.0)
_export_limiter = SlidingWindowLimiter(window_seconds=3600.0)
PAYLOAD_VIEWS_PER_MINUTE = 60
EXPORTS_PER_HOUR = 10
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.get("/v1/blackbox/events", response_model=BlackBoxTimelineResponse)
async def get_events(
    operator: ViewerDep,
    supabase: SupabaseDep,
    agent_id: UUID | None = None,
    decision: str | None = Query(default=None, pattern="^(ALLOW|BLOCK|ERROR)$"),
    before_seq: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
) -> BlackBoxTimelineResponse:
    events, next_before_seq = await blackbox_service.list_events(
        supabase, operator.organization_id, agent_id=agent_id, decision=decision, before_seq=before_seq, limit=limit
    )
    return BlackBoxTimelineResponse(events=events, next_before_seq=next_before_seq)


@router.get("/v1/blackbox/verify", response_model=VerifyResponse)
async def verify_chain(
    operator: ViewerDep, supabase: SupabaseDep, from_seq: int = Query(ge=1), to_seq: int = Query(ge=1)
) -> VerifyResponse:
    return await blackbox_service.verify(supabase, operator.organization_id, from_seq, to_seq)


@router.get("/v1/blackbox/settings", response_model=BlackBoxSettingsResponse)
async def get_settings(operator: ViewerDep, supabase: SupabaseDep) -> BlackBoxSettingsResponse:
    settings = await blackbox_service.get_settings(supabase, operator.organization_id)
    return settings.model_copy(update={"capabilities": blackbox_service.capabilities_for(operator.role)})


@router.put("/v1/blackbox/retention", response_model=BlackBoxSettingsResponse)
async def set_retention(
    payload: BlackBoxRetentionRequest, operator: AdminDep, supabase: SupabaseDep
) -> BlackBoxSettingsResponse:
    """How long events and captured payloads are kept. A shorter retention deletes events at the next daily
    purge and cannot be undone, so every change needs "confirm": true."""
    return await blackbox_service.set_retention(supabase, operator, payload)


@router.put("/v1/blackbox/payload-capture", response_model=BlackBoxSettingsResponse)
async def set_payload_capture(
    payload: PayloadCaptureRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> BlackBoxSettingsResponse:
    """Payload capture stores redacted excerpts of tool call arguments and results. Turning it ON needs the
    admin role and "confirm": true; turning it OFF needs the security operator role. Off by default."""
    return await blackbox_service.set_payload_capture(supabase, operator, payload)


@router.get("/v1/blackbox/events/{seq}/payload", response_model=EventPayloadResponse)
async def get_event_payload(
    response: Response, operator: AdminDep, supabase: SupabaseDep, seq: Annotated[int, Path(ge=1)]
) -> EventPayloadResponse:
    """The redacted payload captured for one event. Reading it is itself audited, in the same transaction."""
    if not _payload_limiter.allow(f"{operator.organization_id}:{operator.user_id}", PAYLOAD_VIEWS_PER_MINUTE, time.monotonic()):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many payload views; wait a minute.")
    response.headers.update(_NO_STORE)
    return await blackbox_service.read_payload(supabase, operator, seq)


@router.get("/v1/blackbox/export")
async def export_events(
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    fmt: Annotated[str, Query(alias="format", pattern="^(jsonl|csv)$")] = "jsonl",
    include_payloads: bool = False,
    agent_id: UUID | None = None,
    decision: str | None = Query(default=None, pattern="^(ALLOW|BLOCK|ERROR)$"),
    since: datetime | None = None,
    until: datetime | None = None,
) -> StreamingResponse:
    """
    Downloads the organization's timeline (oldest first, at most 50,000 rows). Metadata only by default;
    include_payloads adds the captured redacted excerpts and needs the admin role. The export is audited
    before the first row is read.
    """
    if include_payloads and operator.role < Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Exporting payloads requires the 'admin' role or higher.")
    if since is not None and until is not None and since > until:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "'since' must not be after 'until'.")
    if not _export_limiter.allow(f"{operator.organization_id}:{operator.user_id}", EXPORTS_PER_HOUR, time.monotonic()):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many exports; try again later.")
    export_format: blackbox_service.ExportFormat = "csv" if fmt == "csv" else "jsonl"
    await blackbox_service.audit_export(
        supabase,
        operator,
        {
            "format": export_format, "include_payloads": include_payloads, "max_rows": blackbox_service.MAX_EXPORT_ROWS,
            "agent_id": str(agent_id) if agent_id else None, "decision": decision,
            "since": since.isoformat() if since else None, "until": until.isoformat() if until else None,
        },
    )
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return StreamingResponse(
        blackbox_service.export_events(
            supabase, operator.organization_id, fmt=export_format, include_payloads=include_payloads,
            agent_id=agent_id, decision=decision, since=since, until=until,
        ),
        media_type="text/csv; charset=utf-8" if export_format == "csv" else "application/x-ndjson",
        headers={**_NO_STORE, "Content-Disposition": f'attachment; filename="redhand-blackbox-{stamp}.{export_format}"'},
    )


@router.post("/v1/blackbox/payloads/clear", response_model=ClearPayloadsResponse)
async def clear_payloads(
    payload: ClearPayloadsRequest, operator: AdminDep, supabase: SupabaseDep
) -> ClearPayloadsResponse:
    """Deletes every captured payload of the organization now. It cannot be undone; events and the hash chain stay."""
    return await blackbox_service.clear_payloads(supabase, operator, payload)
