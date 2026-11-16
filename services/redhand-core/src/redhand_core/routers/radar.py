"""
Prompt Injection Radar and output checks, data and control API (Phase 4 M4.2). See docs/plans/phase4-m4-plan.md.

GET    /v1/radar/settings               modes, the last 7 days at a glance, and what you may do (security operator)
PUT    /v1/radar/settings               off or observe per kind (admin; turning a check off needs confirmation; block is not offered)
GET    /v1/radar/loop-settings          loop detection: mode, limit, window, the last 7 days (security operator)
PUT    /v1/radar/loop-settings          off, observe or throttle, limit and window (admin; throttle and off need confirmation)
GET    /v1/findings                     findings, newest first, filterable (security operator)
POST   /v1/findings/{id}/review         confirm a finding or mark it a false alarm (security operator, audited)
GET    /v1/radar/suppressions           live suppressions (security operator)
POST   /v1/radar/suppressions           suppress one rule for one agent for 1 to 90 days (admin, confirmation, reason, audited)
DELETE /v1/radar/suppressions/{id}      revoke a suppression (admin, audited)
POST   /v1/radar/self-test              run the Radar over the bundled held-out samples in the gateway (security operator, once a minute)
GET    /v1/radar/readiness              has your own traffic produced enough clean evidence to CONSIDER blocking? display only (security operator)
POST   /internal/v1/findings            gateway -> core: findings it raised (service token)
POST   /internal/v1/radar/scan-counts   gateway -> core: how many results it scanned and flagged, numbers only (service token)
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
import httpx
from pydantic import ValidationError

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.radar import service
from redhand_core.radar.models import (
    MAX_NOTE_LENGTH,
    FindingReport,
    FindingReportResponse,
    FindingReviewRequest,
    FindingReviewResponse,
    FindingsResponse,
    GatewaySelfTest,
    LoopSettingsRequest,
    LoopSettingsResponse,
    RadarSettingsRequest,
    RadarSettingsResponse,
    ReadinessResponse,
    ScanCountsReport,
    ScanCountsResponse,
    SuppressionCreateRequest,
    SuppressionCreateResponse,
    SuppressionRevokeRequest,
    SuppressionRevokeResponse,
    SelfTestResponse,
    SuppressionsResponse,
)
from redhand_core.config import Settings, get_settings
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.mcp_scan import GatewayClientDep
from redhand_core.routers.telegram import OptionalClientDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.passports.models import utcnow
from redhand_core.risk import service as risk_service
from redhand_core.telegram.bot import AlertBatch

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Prompt Injection Radar"])

SELF_TEST_INTERVAL_SECONDS = 60.0
MAX_TRACKED_ORGANIZATIONS = 10_000
_self_test_last_run: dict[UUID, float] = {}  # per instance, like the other in-memory limiters; one entry per organization


def _self_test_wait(organization_id: UUID, now: float) -> float:
    """Seconds an organization must still wait before another self-test (0 means go ahead, and the attempt is recorded)."""
    last = _self_test_last_run.get(organization_id)
    if last is not None and now - last < SELF_TEST_INTERVAL_SECONDS:
        return SELF_TEST_INTERVAL_SECONDS - (now - last)
    _self_test_last_run[organization_id] = now
    while len(_self_test_last_run) > MAX_TRACKED_ORGANIZATIONS:
        _self_test_last_run.pop(next(iter(_self_test_last_run)))
    return 0.0

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/radar/settings", response_model=RadarSettingsResponse)
async def get_radar_settings(operator: SecurityOperatorDep, supabase: SupabaseDep) -> RadarSettingsResponse:
    return await service.get_settings(supabase, operator)


@router.put("/v1/radar/settings", response_model=RadarSettingsResponse)
async def put_radar_settings(payload: RadarSettingsRequest, operator: AdminDep, supabase: SupabaseDep) -> RadarSettingsResponse:
    """off: no checks of that kind and nothing stored. observe (default): findings are recorded and alerted; nothing is
    changed or blocked. Block mode is not available yet. Turning a check off needs confirm: true."""
    return await service.set_settings(supabase, operator, payload)


@router.get("/v1/radar/loop-settings", response_model=LoopSettingsResponse)
async def get_loop_settings(operator: SecurityOperatorDep, supabase: SupabaseDep) -> LoopSettingsResponse:
    return await service.get_loop_settings(supabase, operator)


@router.put("/v1/radar/loop-settings", response_model=LoopSettingsResponse)
async def put_loop_settings(payload: LoopSettingsRequest, operator: AdminDep, supabase: SupabaseDep) -> LoopSettingsResponse:
    """observe (default): a call repeated `loop_limit` times inside `loop_window_seconds` is recorded and alerted; nothing is refused.
    throttle: the repeat is also refused until the window moves on (needs confirm: true). off: nothing is counted (needs confirm: true).
    A live suppression of RAD-LOOP-001 for an agent exempts that agent."""
    return await service.set_loop_settings(supabase, operator, payload)


@router.post("/v1/radar/self-test", response_model=SelfTestResponse)
async def run_self_test(
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    gateway: GatewayClientDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SelfTestResponse:
    """
    Asks the deployed gateway to run its Radar over the bundled held-out samples and shows the counts next to this organization's switches.
    It proves the gateway's Radar code behaves as measured; it does not prove an agent's traffic goes through the gateway. Changes nothing,
    takes no input, one run per organization per minute. A gateway that does not answer is an error: no result is ever invented.
    """
    if gateway is None or settings.INTERNAL_SERVICE_TOKEN is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The self-test is not configured.")
    wait = _self_test_wait(operator.organization_id, time.monotonic())
    if wait > 0:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, f"A self-test ran a moment ago; try again in {int(wait) + 1} seconds.",
            headers={"Retry-After": str(int(wait) + 1)},
        )
    try:
        response = await gateway.post(
            "/internal/v1/radar/self-test", headers={"Authorization": f"Bearer {settings.INTERNAL_SERVICE_TOKEN.get_secret_value()}"}
        )
    except httpx.HTTPError as exc:
        logger.error("Radar self-test: gateway unreachable: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The gateway could not be reached for the self-test.") from None
    if response.status_code == 429:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "A self-test is already running; try again in a moment.")
    if response.status_code == 401:
        logger.error("Gateway refused core's service token for the self-test")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The self-test is misconfigured.")
    if response.status_code != 200:
        logger.error("Radar self-test: gateway answered HTTP %s", response.status_code)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The self-test could not be completed.")
    try:
        result = GatewaySelfTest.model_validate(response.json())
    except (ValueError, ValidationError):
        logger.error("Radar self-test: the gateway answered with an unexpected shape")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The self-test could not be completed.") from None
    current = await service.get_settings(supabase, operator)
    return SelfTestResponse(
        **result.model_dump(), radar_mode=current.radar_mode, output_check_mode=current.output_check_mode, ran_at=datetime.now(timezone.utc)
    )


@router.get("/v1/radar/readiness", response_model=ReadinessResponse)
async def get_radar_readiness(operator: SecurityOperatorDep, supabase: SupabaseDep) -> ReadinessResponse:
    """Per check: what your own traffic shows over the last 7 UTC days (results scanned, strong findings, false alarms counted the hard way)
    and which conditions for even considering blocking hold. Blocking is not available and this grants nothing."""
    return await service.get_readiness(supabase, operator)


@router.get("/v1/findings", response_model=FindingsResponse)
async def get_findings(
    operator: SecurityOperatorDep,
    supabase: SupabaseDep,
    agent_id: UUID | None = None,
    review_status: str | None = Query(default=None, pattern="^(open|confirmed|false_alarm)$"),
    kind: str | None = Query(default=None, pattern="^(injection|output|loop|destination|model)$"),
    rule_id: str | None = Query(default=None, pattern=r"^RAD-(INJ|OUT|LOOP|DST|MDL)-[0-9]{3}$"),
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
    finding_id: UUID, payload: FindingReviewRequest, operator: SecurityOperatorDep, supabase: SupabaseDep, telegram: OptionalClientDep
) -> FindingReviewResponse:
    result = await service.review_finding(supabase, operator, finding_id, payload)
    if result.changed and result.review_status == "confirmed":
        # A finding a person marks as real weighs more in the agent's risk score, so the ladder is evaluated again.
        res = await (
            supabase.table("security_findings").select("agent_id")
            .eq("id", str(finding_id)).eq("organization_id", str(operator.organization_id)).execute()
        )
        rows = list(res.data or [])
        if rows:
            await risk_service.evaluate_agents(supabase, telegram, operator.organization_id, [UUID(str(rows[0]["agent_id"]))], utcnow())
    return result


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
    alerts = AlertBatch()  # the findings alert and any risk alert leave as one Telegram message
    result = await service.record_findings(supabase, telegram, report, alerts)
    await risk_service.evaluate_agents(supabase, telegram, report.organization_id, [report.agent_id], utcnow(), alerts)  # never raises
    await alerts.flush(supabase, telegram)
    return result


@router.post(
    "/internal/v1/radar/scan-counts",
    response_model=ScanCountsResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def report_scan_counts(report: ScanCountsReport, supabase: SupabaseDep) -> ScanCountsResponse:
    return await service.record_scan_counts(supabase, report)
