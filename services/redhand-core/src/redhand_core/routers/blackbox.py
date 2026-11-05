"""
Black Box Recorder: operator-facing reads. See docs/plans/phase3-plan.md.

GET /v1/blackbox/events    the organization's timeline, newest first, paginated by seq
GET /v1/blackbox/verify    recomputes a seq range's hash chain and reports the first mismatch, if any
GET /v1/blackbox/settings  retention periods and whether payload capture is on
PUT /v1/blackbox/retention changes the retention periods (admin, with confirmation, audited)

Every read is scoped to the caller's organization (never a client-supplied tenant id).
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from redhand_core.auth.operator import AdminDep, ViewerDep
from redhand_core.blackbox import service as blackbox_service
from redhand_core.blackbox.models import (
    BlackBoxRetentionRequest,
    BlackBoxSettingsResponse,
    BlackBoxTimelineResponse,
    VerifyResponse,
)
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Black Box Recorder"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


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
    return await blackbox_service.get_settings(supabase, operator.organization_id)


@router.put("/v1/blackbox/retention", response_model=BlackBoxSettingsResponse)
async def set_retention(
    payload: BlackBoxRetentionRequest, operator: AdminDep, supabase: SupabaseDep
) -> BlackBoxSettingsResponse:
    """How long events and captured payloads are kept. A shorter retention deletes events at the next daily
    purge and cannot be undone, so every change needs "confirm": true."""
    return await blackbox_service.set_retention(supabase, operator, payload)
