"""
Black Box Recorder service: tenant-scoped reads and writes against the `agent_events` chain
(supabase/migrations/20261110000000_blackbox.sql). Every read is scoped by the caller's
organization in SQL (`verify_events`/`agent_events` RLS and explicit `.eq("organization_id", ...)`
filters here), never by trusting a client-supplied tenant id (CLAUDE.md §5.3).
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext
from redhand_core.blackbox.models import (
    BlackBoxEventView,
    BlackBoxRetentionRequest,
    BlackBoxSettingsResponse,
    GatewayEventItem,
    VerifyResponse,
)
# The control-action helpers are shared with the passport control actions so every control endpoint maps
# database errors, confirmation and compare-and-set conflicts the same way.
from redhand_core.passports.service import (
    StateConflictError,
    _require_confirmation,
    _rpc,
    retry_once_on_conflict,
)

logger = logging.getLogger("redhand.core.blackbox")

MAX_VERIFY_RANGE = 50_000
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


async def ingest_events(
    supabase: Any, instance_id: str, batch_id: UUID, organization_id: UUID, items: list[GatewayEventItem]
) -> tuple[int, int]:
    """Appends a batch to the organization's chain. Never raises for ordinary rejections (those come
    back as a count); raises only if the batch itself could not be processed at all."""
    payload = [
        {
            "agent_id": str(item.agent_id),
            "occurred_at": item.occurred_at.isoformat(),
            "gateway_instance": item.gateway_instance,
            "server": item.server,
            "method": item.method,
            "tool_name": item.tool_name,
            "decision": item.decision,
            "reasons": item.reasons,
            "upstream_status": item.upstream_status,
            "latency_ms": item.latency_ms,
            "argument_keys": item.argument_keys,
            "arguments_sha256": item.arguments_sha256,
            "result_size_bytes": item.result_size_bytes,
            "redaction_count": item.redaction_count,
            "credential_jti": item.credential_jti,
        }
        for item in items
    ]
    try:
        response = await supabase.rpc(
            "record_events",
            {"p_instance": instance_id, "p_batch_id": str(batch_id), "p_org": str(organization_id), "p_items": payload},
        ).execute()
    except APIError as exc:
        logger.error("Event batch could not be recorded: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Events could not be recorded.") from None
    data = response.data
    accepted, rejected = int(data["accepted"]), int(data["rejected"])
    if rejected:
        # record_events() refuses bad items one by one instead of failing the batch, so a rejection is
        # otherwise invisible; a database fault once made it reject every event without any error.
        logger.warning(
            "Event batch partly rejected: organization=%s instance=%s accepted=%d rejected=%d",
            organization_id, instance_id, accepted, rejected,
        )
    return accepted, rejected


async def list_events(
    supabase: Any,
    organization_id: UUID,
    *,
    agent_id: UUID | None = None,
    decision: str | None = None,
    before_seq: int | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[BlackBoxEventView], int | None]:
    """The organization's events, newest first, paginated by seq. Always scoped to organization_id."""
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    query = (
        supabase.table("agent_events")
        .select("seq,agent_id,occurred_at,server,method,tool_name,decision,reasons,upstream_status,latency_ms,argument_keys")
        .eq("organization_id", str(organization_id))
    )
    if agent_id is not None:
        query = query.eq("agent_id", str(agent_id))
    if decision is not None:
        query = query.eq("decision", decision)
    if before_seq is not None:
        query = query.lt("seq", before_seq)
    res = await query.order("seq", desc=True).limit(limit + 1).execute()
    rows = list(res.data or [])
    next_before_seq = None
    if len(rows) > limit:
        next_before_seq = int(rows[limit - 1]["seq"])
        rows = rows[:limit]
    views = [
        BlackBoxEventView(
            seq=int(r["seq"]),
            agent_id=UUID(str(r["agent_id"])),
            occurred_at=r["occurred_at"],
            server=r.get("server") or "",
            method=r["method"],
            tool_name=r.get("tool_name") or "",
            decision=r["decision"],
            reasons=list(r.get("reasons") or []),
            upstream_status=r.get("upstream_status"),
            latency_ms=r.get("latency_ms"),
            argument_keys=list(r.get("argument_keys") or []),
        )
        for r in rows
    ]
    return views, next_before_seq


async def verify(supabase: Any, organization_id: UUID, from_seq: int, to_seq: int) -> VerifyResponse:
    if to_seq < from_seq or to_seq - from_seq >= MAX_VERIFY_RANGE:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Range must cover 1 to {MAX_VERIFY_RANGE} events.")
    try:
        response = await supabase.rpc(
            "verify_events", {"p_org": str(organization_id), "p_from_seq": from_seq, "p_to_seq": to_seq}
        ).execute()
    except APIError as exc:
        if exc.code == "22023":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid verification range.") from None
        logger.error("Verify failed: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification could not be completed.") from None
    data = response.data
    return VerifyResponse(
        ok=bool(data["ok"]), checked=int(data.get("checked") or 0),
        broken_seq=data.get("broken_seq"), reason=data.get("reason"),
    )


async def get_settings(supabase: Any, organization_id: UUID) -> BlackBoxSettingsResponse:
    res = await (
        supabase.table("organizations")
        .select("blackbox_retention_days,payload_retention_days,payload_capture_enabled")
        .eq("id", str(organization_id))
        .execute()
    )
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found.")
    row = rows[0]
    return BlackBoxSettingsResponse(
        retention_days=int(row["blackbox_retention_days"]),
        payload_retention_days=int(row["payload_retention_days"]),
        payload_capture_enabled=bool(row["payload_capture_enabled"]),
        changed=False,
    )


@retry_once_on_conflict
async def set_retention(
    supabase: Any, operator: OperatorContext, request: BlackBoxRetentionRequest
) -> BlackBoxSettingsResponse:
    """
    Changes how long the organization's events and captured payloads are kept. Any change needs explicit
    confirmation: a shorter retention deletes events at the next daily purge (it cannot be undone), a
    longer one keeps more data. Compare-and-set against the values the decision was based on.
    """
    current = await get_settings(supabase, operator.organization_id)
    unchanged = (
        current.retention_days == request.retention_days
        and current.payload_retention_days == request.payload_retention_days
    )
    if not unchanged:
        _require_confirmation(request.confirm, "Changing the Black Box retention")
    data = await _rpc(
        supabase,
        "control_blackbox_retention",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id),
            "p_retention_days": request.retention_days, "p_payload_retention_days": request.payload_retention_days,
            "p_reason": request.reason, "p_expected_retention_days": current.retention_days,
            "p_expected_payload_retention_days": current.payload_retention_days,
        },
        not_found_detail="Organization not found.",
        conflict_detail="The retention conflicted with another change; try again.",
    )
    if isinstance(data, dict) and data.get("conflict"):
        raise StateConflictError
    return BlackBoxSettingsResponse(
        retention_days=request.retention_days,
        payload_retention_days=request.payload_retention_days,
        payload_capture_enabled=current.payload_capture_enabled,
        changed=bool(data["changed"]),
    )
