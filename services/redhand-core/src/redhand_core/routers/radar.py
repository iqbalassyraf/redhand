"""
Prompt Injection Radar and output checks, data and control API (Phase 4 M4.2). See docs/plans/phase4-m4-plan.md.

GET    /v1/radar/settings               modes, the last 7 days at a glance, and what you may do (security operator)
PUT    /v1/radar/settings               off or observe per kind (admin; turning a check off needs confirmation; block is not offered)
GET    /v1/findings                     findings, newest first, filterable (security operator)
POST   /v1/findings/{id}/review         confirm a finding or mark it a false alarm (security operator, audited)
GET    /v1/radar/suppressions           live suppressions (security operator)
POST   /v1/radar/suppressions           suppress one rule for one agent for 1 to 90 days (admin, confirmation, reason, audited)
DELETE /v1/radar/suppressions/{id}      revoke a suppression (admin, audited)
POST   /internal/v1/findings            gateway -> core: findings it raised (service token)
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.radar import service
from redhand_core.radar.models import (
    MAX_NOTE_LENGTH,
    FindingReport,
    FindingReportResponse,
    FindingReviewRequest,
    FindingReviewResponse,
    FindingsResponse,
    RadarSettingsRequest,
    RadarSettingsResponse,
    SuppressionCreateRequest,
    SuppressionCreateResponse,
    SuppressionRevokeRequest,
    SuppressionRevokeResponse,
    SuppressionsResponse,
)
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.telegram import OptionalClientDep
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Prompt Injection Radar"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/radar/settings", response_model=RadarSettingsResponse)
async def get_radar_settings(operator: SecurityOperatorDep, supabase: SupabaseDep) -> RadarSettingsResponse:
    return await service.get_settings(supabase, operator)


@router.put("/v1/radar/settings", response_model=RadarSettingsResponse)
async def put_radar_settings(payload: RadarSettingsRequest, operator: AdminDep, supabase: SupabaseDep) -> RadarSettingsResponse:
    """off: no checks of that kind and nothing stored. observe (default): findings are recorded and alerted; nothing is
    changed or blocked. Block mode is not available yet. Turning a check off needs confirm: true."""
    return await service.set_settings(supabase, operator, payload)


@router.get("/v1/findings", response_model=FindingsResponse)
async def get_findings(
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    agent_id: UUID | None = None,
    review_status: str | None = Query(default=None, pattern="^(open|confirmed|false_alarm)$"),
    kind: str | None = Query(default=None, pattern="^(injection|output)$"),
    rule_id: str | None = Query(default=None, pattern=r"^RAD-(INJ|OUT)-[0-9]{3}$"),
    would_block: bool | None = None,
    before: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=service.MAX_FINDINGS_RETURNED),
) -> FindingsResponse:
    return await service.list_findings(
        supabase, operator.organization_id, agent_id=agent_id, review_status=review_status, kind=kind, rule_id=rule_id,
        would_block=would_block, before=before, limit=limit,
    )


@router.post("/v1/findings/{finding_id}/review", response_model=FindingReviewResponse)
async def review_finding(
    finding_id: UUID, payload: FindingReviewRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> FindingReviewResponse:
    return await service.review_finding(supabase, operator, finding_id, payload)


@router.get("/v1/radar/suppressions", response_model=SuppressionsResponse)
async def get_suppressions(operator: SecurityOperatorDep, supabase: SupabaseDep) -> SuppressionsResponse:
    return await service.list_suppressions(supabase, operator.organization_id)


@router.post("/v1/radar/suppressions", response_model=SuppressionCreateResponse)
async def post_suppression(payload: SuppressionCreateRequest, operator: AdminDep, supabase: SupabaseDep) -> SuppressionCreateResponse:
    """Stops one Radar rule from recording findings for one agent for a limited time. Needs confirm: true and a reason."""
    return await service.create_suppression(supabase, operator, payload)


@router.delete("/v1/radar/suppressions/{suppression_id}", response_model=SuppressionRevokeResponse)
async def delete_suppression(
    suppression_id: UUID,
    operator: AdminDep,
    supabase: SupabaseDep,
    reason: Annotated[str | None, Query(max_length=MAX_NOTE_LENGTH)] = None,
) -> SuppressionRevokeResponse:
    return await service.revoke_suppression(supabase, operator, suppression_id, SuppressionRevokeRequest(reason=reason))


@router.post(
    "/internal/v1/findings",
    response_model=FindingReportResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def report_findings(report: FindingReport, supabase: SupabaseDep, telegram: OptionalClientDep) -> FindingReportResponse:
    return await service.record_findings(supabase, telegram, report)
