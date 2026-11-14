"""
Radar findings, settings, review and suppression: tenant-scoped reads, audited changes (in SQL) and the gateway's reports.

Findings contain no scanned text (the database enforces the shape), so alerts and API responses carry rule ids, counts and the
agent's own name only. Block mode does not exist yet: it needs the measured gate (plan section 11.2), and every path here refuses it.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError
from pydantic import ValidationError

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.passports.service import StateConflictError, _require_confirmation, _rpc, retry_once_on_conflict
from redhand_core.radar import readiness
from redhand_core.radar.models import (
    FindingReport,
    FindingReportResponse,
    FindingReviewRequest,
    FindingReviewResponse,
    FindingsResponse,
    FindingView,
    LoopSettingsRequest,
    LoopSettingsResponse,
    RadarCapabilities,
    RadarSettingsRequest,
    RadarSettingsResponse,
    ReadinessInputs,
    ReadinessResponse,
    ScanCountsReport,
    ScanCountsResponse,
    SuppressionCreateRequest,
    SuppressionCreateResponse,
    SuppressionRevokeRequest,
    SuppressionRevokeResponse,
    SuppressionsResponse,
    SuppressionView,
)
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.bot import AlertBatch, send_alert
from redhand_core.telegram.client import TelegramClient

logger = logging.getLogger("redhand.core.radar")

MAX_FINDINGS_RETURNED = 100
_SAFE_TOOL_NAME = re.compile(r"[^A-Za-z0-9_.:-]")
_SAFE_HOST = re.compile(r"[^a-z0-9_.:-]")
_FINDING_COLUMNS = (
    "id,agent_id,rule_id,family,kind,severity,confidence,place,evasion,tool_name,server_slug,would_block,occurrences,detail,"
    "first_seen_at,last_seen_at,review_status,reviewed_at,review_note"
)


def capabilities_for(role: Role | None) -> RadarCapabilities:
    """role is None in Supabase mode (the UI cannot see it): then nothing is offered and the server decides per request."""
    return RadarCapabilities(
        can_change_modes=role is not None and role >= Role.ADMIN,
        can_review=role is not None and role >= Role.SECURITY_OPERATOR,
        can_suppress=role is not None and role >= Role.ADMIN,
    )


async def _agent_names(supabase: Any, organization_id: UUID, agent_ids: set[str]) -> dict[str, str]:
    if not agent_ids:
        return {}
    res = await supabase.table("agents").select("id,name").eq("organization_id", str(organization_id)).execute()
    return {str(r["id"]): str(r["name"]) for r in (res.data or []) if str(r["id"]) in agent_ids}


async def get_settings(supabase: Any, operator: OperatorContext) -> RadarSettingsResponse:
    data = await _rpc(
        supabase, "radar_summary", {"p_org": str(operator.organization_id)},
        not_found_detail="Organization not found.", conflict_detail="The summary could not be read.",
    )
    return RadarSettingsResponse(
        radar_mode=data["radar_mode"], output_check_mode=data["output_check_mode"],
        radar_mode_changed_at=data.get("radar_mode_changed_at"), output_check_mode_changed_at=data.get("output_check_mode_changed_at"),
        block_available=False, last_7_days=dict(data.get("last_7_days") or {}), capabilities=capabilities_for(operator.role),
    )


@retry_once_on_conflict
async def set_settings(supabase: Any, operator: OperatorContext, request: RadarSettingsRequest) -> RadarSettingsResponse:
    """Compare-and-set against the modes the decision was made on. Turning a check off needs confirmation; block is not offered."""
    current = await get_settings(supabase, operator)
    turning_off = (request.radar_mode == "off" and current.radar_mode != "off") or (
        request.output_check_mode == "off" and current.output_check_mode != "off"
    )
    if turning_off:
        _require_confirmation(request.confirm, "Turning a Radar check off")
    data = await _rpc(
        supabase, "control_radar_settings",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_injection": request.radar_mode,
         "p_output": request.output_check_mode, "p_expected_injection": current.radar_mode,
         "p_expected_output": current.output_check_mode, "p_reason": request.reason},
        not_found_detail="Organization not found.", conflict_detail="The Radar settings conflicted with another change; try again.",
    )
    if data.get("conflict"):
        raise StateConflictError
    return await get_settings(supabase, operator)


async def get_loop_settings(supabase: Any, operator: OperatorContext) -> LoopSettingsResponse:
    data = await _rpc(
        supabase, "loop_settings", {"p_org": str(operator.organization_id)},
        not_found_detail="Organization not found.", conflict_detail="The loop settings could not be read.",
    )
    return LoopSettingsResponse(
        loop_mode=data["loop_mode"], loop_limit=int(data["loop_limit"]), loop_window_seconds=int(data["loop_window_seconds"]),
        loop_mode_changed_at=data.get("loop_mode_changed_at"), last_7_days=dict(data.get("last_7_days") or {}),
        capabilities=capabilities_for(operator.role),
    )


@retry_once_on_conflict
async def set_loop_settings(supabase: Any, operator: OperatorContext, request: LoopSettingsRequest) -> LoopSettingsResponse:
    """Compare-and-set against the settings read just now (and, when the caller says which mode it saw, against that too).
    Turning throttling on refuses calls, and turning detection off removes a safeguard: both need confirmation."""
    current = await get_loop_settings(supabase, operator)
    if request.expected_mode is not None and request.expected_mode != current.loop_mode:
        raise HTTPException(status.HTTP_409_CONFLICT, "The loop settings were changed by someone else. Reload and try again.")
    if request.loop_mode == "throttle" and current.loop_mode != "throttle":
        _require_confirmation(request.confirm, "Turning loop throttling on (repeated identical calls are refused)")
    if request.loop_mode == "off" and current.loop_mode != "off":
        _require_confirmation(request.confirm, "Turning loop detection off")
    data = await _rpc(
        supabase, "control_loop_settings",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_mode": request.loop_mode,
         "p_limit": request.loop_limit, "p_window": request.loop_window_seconds, "p_expected_mode": current.loop_mode,
         "p_expected_limit": current.loop_limit, "p_expected_window": current.loop_window_seconds, "p_reason": request.reason},
        not_found_detail="Organization not found.", conflict_detail="The loop settings conflicted with another change; try again.",
    )
    if data.get("conflict"):
        raise StateConflictError
    return await get_loop_settings(supabase, operator)


async def list_findings(
    supabase: Any, organization_id: UUID, *, agent_id: UUID | None, review_status: str | None, kind: str | None,
    rule_id: str | None, would_block: bool | None, before: datetime | None, limit: int,
) -> FindingsResponse:
    query = supabase.table("security_findings").select(_FINDING_COLUMNS).eq("organization_id", str(organization_id))
    if agent_id is not None:
        query = query.eq("agent_id", str(agent_id))
    if review_status is not None:
        query = query.eq("review_status", review_status)
    if kind is not None:
        query = query.eq("kind", kind)
    if rule_id is not None:
        query = query.eq("rule_id", rule_id)
    if would_block is not None:
        query = query.eq("would_block", would_block)
    if before is not None:
        query = query.lt("last_seen_at", before.astimezone(timezone.utc).isoformat())
    size = max(1, min(limit, MAX_FINDINGS_RETURNED))
    rows = list((await query.order("last_seen_at", desc=True).limit(size + 1).execute()).data or [])
    page, more = rows[:size], len(rows) > size
    names = await _agent_names(supabase, organization_id, {str(r["agent_id"]) for r in page})
    views = [FindingView(**r, agent_name=names.get(str(r["agent_id"]))) for r in page]
    return FindingsResponse(findings=views, next_before=views[-1].last_seen_at if more and views else None)


@retry_once_on_conflict
async def review_finding(
    supabase: Any, operator: OperatorContext, finding_id: UUID, request: FindingReviewRequest
) -> FindingReviewResponse:
    res = await (
        supabase.table("security_findings").select("review_status")
        .eq("id", str(finding_id)).eq("organization_id", str(operator.organization_id)).execute()
    )
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found.")
    data = await _rpc(
        supabase, "control_finding_review",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_finding": str(finding_id),
         "p_status": request.status, "p_expected": rows[0]["review_status"], "p_note": request.note},
        not_found_detail="Finding not found.", conflict_detail="The finding could not be reviewed.",
    )
    if data.get("conflict"):
        raise StateConflictError
    return FindingReviewResponse(review_status=data["review_status"], changed=bool(data["changed"]))


async def list_suppressions(supabase: Any, organization_id: UUID) -> SuppressionsResponse:
    now = datetime.now(timezone.utc).isoformat()
    res = await (
        supabase.table("radar_suppressions").select("id,agent_id,rule_id,reason,created_at,expires_at,revoked_at")
        .eq("organization_id", str(organization_id)).gt("expires_at", now).order("created_at", desc=True).limit(200).execute()
    )
    rows = [r for r in (res.data or []) if r.get("revoked_at") is None]
    names = await _agent_names(supabase, organization_id, {str(r["agent_id"]) for r in rows})
    return SuppressionsResponse(suppressions=[
        SuppressionView(
            id=r["id"], agent_id=r["agent_id"], agent_name=names.get(str(r["agent_id"])), rule_id=r["rule_id"],
            reason=r["reason"], created_at=r["created_at"], expires_at=r["expires_at"],
        )
        for r in rows
    ])


async def create_suppression(supabase: Any, operator: OperatorContext, request: SuppressionCreateRequest) -> SuppressionCreateResponse:
    _require_confirmation(request.confirm, "Suppressing a Radar rule for an agent")
    data = await _rpc(
        supabase, "control_radar_suppression_create",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_agent": str(request.agent_id),
         "p_rule": request.rule_id, "p_days": request.days, "p_reason": request.reason},
        not_found_detail="Agent not found.", conflict_detail="The suppression could not be created.",
    )
    if data.get("limit"):
        raise HTTPException(status.HTTP_409_CONFLICT, "This organization already has 100 live suppressions. Revoke one first.")
    return SuppressionCreateResponse(id=data["id"], created=bool(data["created"]), expires_at=data["expires_at"])


async def revoke_suppression(
    supabase: Any, operator: OperatorContext, suppression_id: UUID, request: SuppressionRevokeRequest
) -> SuppressionRevokeResponse:
    data = await _rpc(
        supabase, "control_radar_suppression_revoke",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_suppression": str(suppression_id),
         "p_reason": request.reason},
        not_found_detail="Suppression not found.", conflict_detail="The suppression could not be revoked.",
    )
    return SuppressionRevokeResponse(revoked=bool(data["revoked"]))


async def record_findings(
    supabase: Any, telegram: TelegramClient | None, report: FindingReport, alerts: AlertBatch | None = None
) -> FindingReportResponse:
    """Stores the gateway's findings (coalesced) and alerts the organization, at most once per agent per ten minutes, with rule ids
    and counts only. The organization claimed is checked against the agent's real owner in SQL."""
    items = [i.model_dump(mode="json") for i in report.items]
    try:
        response = await supabase.rpc(
            "record_security_findings", {"p_org": str(report.organization_id), "p_agent": str(report.agent_id), "p_items": items}
        ).execute()
    except APIError as exc:
        logger.error("Radar findings could not be recorded: sqlstate=%s", exc.code)
        if exc.code == "P0002":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.") from None
        if exc.code == "22023":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid findings report.") from None
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The findings could not be recorded.") from None
    data = response.data
    metrics = get_metrics()
    for kind in ("injection", "output", "loop", "destination"):
        count = sum(1 for i in report.items if i.kind == kind)
        if count and int(data["new"]):
            metrics.increment_counter("redhand_radar_findings_total", float(min(count, int(data["new"]))), labels={"kind": kind})
    for key in ("suppressed", "capped", "disabled"):
        if int(data[key]):
            metrics.increment_counter("redhand_radar_findings_not_stored_total", float(data[key]), labels={"reason": key})
    if data.get("alert"):
        rules = ", ".join(str(r) for r in data.get("rules") or [])
        await send_alert(
            alerts, supabase, telegram, report.organization_id, agent_id=report.agent_id, text=
            f"Radar: agent '{data.get('agent')}' has {int(data['new'])} new finding(s) in tool results ({rules}). "
            "Open the dashboard, MCP Scanner, Runtime findings. These are known-pattern checks: a clean result is not a guarantee.",
        )
    if data.get("loop_alert"):
        # The tool name came from the agent's own call: keep only plain characters and a short length before it reaches a chat.
        tool = _SAFE_TOOL_NAME.sub("", str(data.get("loop_tool") or ""))[:64] or "a tool"
        await send_alert(
            alerts, supabase, telegram, report.organization_id, agent_id=report.agent_id, text=
            f"Loop: agent '{data.get('agent')}' sent the same call to {tool} more often than the loop limit allows. "
            "Open the dashboard, Radar, Repeated calls. If throttling is on, the extra repeats were refused. Counts only: no call details are sent.",
        )
    if data.get("destination_alert"):
        tool = _SAFE_TOOL_NAME.sub("", str(data.get("destination_tool") or ""))[:64] or "a tool"
        host = _SAFE_HOST.sub("", str(data.get("destination_detail") or ""))[:64] or "an address"
        outcome = "The call was refused." if data.get("destination_mode") == "enforce" else "Recorded only: nothing was refused."
        await send_alert(
            alerts, supabase, telegram, report.organization_id, agent_id=report.agent_id, text=
            f"Destination: agent '{data.get('agent')}' put an address outside its allowed list ({host}) in a call to {tool}. {outcome} "
            "Open the dashboard, Passports, Allowed destinations. Only the last two parts of the address are shown: no call details are sent.",
        )
    return FindingReportResponse(
        new=int(data["new"]), coalesced=int(data["coalesced"]), suppressed=int(data["suppressed"]),
        capped=int(data["capped"]), skipped=int(data["skipped"]), disabled=int(data["disabled"]),
    )


async def get_readiness(supabase: Any, operator: OperatorContext) -> ReadinessResponse:
    """Whether this organization's own traffic is good enough evidence to consider block mode. Display only. Unreadable or unexpected
    inputs are an error, never a verdict."""
    data = await _rpc(
        supabase, "radar_readiness_inputs", {"p_org": str(operator.organization_id)},
        not_found_detail="Organization not found.", conflict_detail="The readiness figures could not be read.",
    )
    try:
        return readiness.judge(ReadinessInputs.model_validate(data))
    except (ValidationError, KeyError):
        logger.error("Radar readiness inputs had an unexpected shape")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The readiness figures could not be read.") from None


async def record_scan_counts(supabase: Any, report: ScanCountsReport) -> ScanCountsResponse:
    """Stores the gateway's totals (numbers only). Items that do not fit are skipped in SQL and counted, never partly stored."""
    items = [i.model_dump(mode="json") for i in report.items]
    try:
        response = await supabase.rpc(
            "record_radar_scan_counts",
            {"p_report_id": str(report.report_id), "p_fingerprint": report.rules_fingerprint, "p_items": items},
        ).execute()
    except APIError as exc:
        logger.error("Radar scan counts could not be recorded: sqlstate=%s", exc.code)
        if exc.code == "22023":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid scan counts report.") from None
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The scan counts could not be recorded.") from None
    data = response.data
    if int(data["skipped"]):
        get_metrics().increment_counter("redhand_radar_scan_counts_skipped_total", float(data["skipped"]))
    return ScanCountsResponse(recorded=int(data["recorded"]), skipped=int(data["skipped"]), duplicate=bool(data["duplicate"]))
