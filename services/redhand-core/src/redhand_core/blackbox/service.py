"""
Black Box Recorder service: tenant-scoped reads and writes against the `agent_events` chain
(supabase/migrations/20261110000000_blackbox.sql). Every read is scoped by the caller's
organization in SQL (`verify_events`/`agent_events` RLS and explicit `.eq("organization_id", ...)`
filters here), never by trusting a client-supplied tenant id (CLAUDE.md §5.3).
"""

from __future__ import annotations

import logging
import csv
import io
import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.blackbox.models import (
    BlackBoxCapabilities,
    BlackBoxEventView,
    BlackBoxRetentionRequest,
    BlackBoxSettingsResponse,
    ClearPayloadsRequest,
    ClearPayloadsResponse,
    EventPayloadResponse,
    GatewayEventItem,
    PayloadCaptureRequest,
    PayloadExcerpt,
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
            "arguments_redacted": item.arguments_redacted.model_dump() if item.arguments_redacted else None,
            "result_excerpt": item.result_excerpt.model_dump() if item.result_excerpt else None,
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


@retry_once_on_conflict
async def set_payload_capture(
    supabase: Any, operator: OperatorContext, request: PayloadCaptureRequest
) -> BlackBoxSettingsResponse:
    """
    Turns payload capture on or off. ON is the data-collecting direction, so it needs the admin role and
    explicit confirmation; OFF is the protective direction, so a security operator may do it without
    confirmation (the same split as Safe Mode). Turning capture off does not delete what was captured: that
    is cleared at the payload retention (or sooner by shortening it).
    """
    needed = Role.ADMIN if request.enabled else Role.SECURITY_OPERATOR
    if operator.role < needed:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"This action requires the '{needed.name.lower()}' role or higher."
        )
    current = await get_settings(supabase, operator.organization_id)
    if request.enabled and not current.payload_capture_enabled:
        _require_confirmation(request.confirm, "Turning on payload capture")
    data = await _rpc(
        supabase,
        "control_payload_capture",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id),
            "p_enabled": request.enabled, "p_reason": request.reason,
            "p_expected": current.payload_capture_enabled,  # compare-and-set against what the decision used
        },
        not_found_detail="Organization not found.",
        conflict_detail="Payload capture conflicted with another change; try again.",
    )
    if isinstance(data, dict) and data.get("conflict"):
        raise StateConflictError
    return BlackBoxSettingsResponse(
        retention_days=current.retention_days,
        payload_retention_days=current.payload_retention_days,
        payload_capture_enabled=request.enabled,
        changed=bool(data["changed"]),
    )


def capabilities_for(role: Role) -> BlackBoxCapabilities:
    """Mirrors the role checks below and in the router, for the dashboard to hide buttons. Never an authority."""
    return BlackBoxCapabilities(
        can_manage=role >= Role.ADMIN,
        can_turn_capture_off=role >= Role.SECURITY_OPERATOR,
        can_view_payloads=role >= Role.ADMIN,
        can_export=role >= Role.SECURITY_OPERATOR,
        can_export_payloads=role >= Role.ADMIN,
    )


async def read_payload(supabase: Any, operator: OperatorContext, seq: int) -> EventPayloadResponse:
    """
    One event's captured payload. The database function audits and reads in one transaction: no payload is
    returned without an audit row, and a failed audit write returns nothing. Admin only (checked here too,
    so a caller that forgets the router dependency is still refused).
    """
    if operator.role < Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This action requires the 'admin' role or higher.")
    try:
        response = await supabase.rpc(
            "read_event_payload",
            {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_seq": seq},
        ).execute()
    except APIError as exc:
        logger.error("Payload read failed: sqlstate=%s", exc.code)  # never the message: it can echo data
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The payload could not be read.") from None
    data = response.data
    if not isinstance(data, dict) or not data.get("found"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found.")
    return EventPayloadResponse(
        seq=int(data["seq"]),
        arguments_redacted=PayloadExcerpt(**data["arguments_redacted"]) if data.get("arguments_redacted") else None,
        result_excerpt=PayloadExcerpt(**data["result_excerpt"]) if data.get("result_excerpt") else None,
    )


MAX_EXPORT_ROWS = 50_000
EXPORT_CHUNK = 500
ExportFormat = Literal["jsonl", "csv"]
_EXPORT_COLUMNS = "seq,agent_id,occurred_at,server,method,tool_name,decision,reasons,upstream_status,latency_ms,argument_keys"
_CSV_HEADER = [
    "seq", "occurred_at", "agent_id", "server", "method", "tool_name", "decision", "reasons", "upstream_status",
    "latency_ms", "argument_keys",
]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: Any) -> Any:
    """Text that a spreadsheet would run as a formula (starts with = + - @ tab CR) is prefixed with an
    apostrophe so it opens as text. Numbers and empty cells pass through."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_line(cells: list[Any]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\r\n").writerow([csv_cell(c) for c in cells])
    return buffer.getvalue()


def _row_cells(row: dict[str, Any], include_payloads: bool) -> list[Any]:
    cells: list[Any] = [
        row["seq"], row["occurred_at"], row["agent_id"], row.get("server") or "", row["method"],
        row.get("tool_name") or "", row["decision"], "; ".join(row.get("reasons") or []),
        row.get("upstream_status"), row.get("latency_ms"), "; ".join(row.get("argument_keys") or []),
    ]
    if include_payloads:
        args, result = row.get("arguments_redacted"), row.get("result_excerpt")
        cells += [(args or {}).get("text", ""), (result or {}).get("text", "")]
    return cells


async def audit_export(supabase: Any, operator: OperatorContext, details: dict[str, Any]) -> None:
    """Records that an export is starting. Called BEFORE any row is read: if it fails, nothing is exported."""
    try:
        await supabase.rpc(
            "audit_blackbox_export",
            {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_details": details},
        ).execute()
    except APIError as exc:
        logger.error("Export audit failed: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The export could not be started.") from None


async def export_events(
    supabase: Any,
    organization_id: UUID,
    *,
    fmt: ExportFormat,
    include_payloads: bool,
    agent_id: UUID | None,
    decision: str | None,
    since: datetime | None,
    until: datetime | None,
) -> AsyncIterator[str]:
    """
    The organization's events, oldest first, as JSON Lines or CSV, at most MAX_EXPORT_ROWS. Read in chunks of
    EXPORT_CHUNK by keyset (seq), so memory is bounded by the chunk size, not the export size. JSON Lines ends
    with a trailer line saying how many rows were written and whether the cap cut the export short.
    """
    columns = _EXPORT_COLUMNS + (",arguments_redacted,result_excerpt" if include_payloads else "")
    if fmt == "csv":
        yield _csv_line(_CSV_HEADER + (["arguments_redacted", "result_excerpt"] if include_payloads else []))
    written, last_seq, capped = 0, 0, False
    while True:
        remaining = MAX_EXPORT_ROWS - written
        if remaining <= 0:
            probe = await _export_query(
                supabase, organization_id, "seq", last_seq, 1, agent_id, decision, since, until
            )
            capped = bool(probe)
            break
        rows = await _export_query(
            supabase, organization_id, columns, last_seq, min(EXPORT_CHUNK, remaining), agent_id, decision, since, until
        )
        if not rows:
            break
        for row in rows:
            if fmt == "csv":
                yield _csv_line(_row_cells(row, include_payloads))
            else:
                yield json.dumps(_jsonl_record(row, include_payloads), ensure_ascii=False, separators=(",", ":")) + "\n"
        written += len(rows)
        last_seq = int(rows[-1]["seq"])
        if len(rows) < min(EXPORT_CHUNK, remaining):
            break
    if fmt == "jsonl":
        yield json.dumps({"export_complete": not capped, "rows": written, "capped_at": MAX_EXPORT_ROWS if capped else None}) + "\n"


def _jsonl_record(row: dict[str, Any], include_payloads: bool) -> dict[str, Any]:
    record = {key: row.get(key) for key in _EXPORT_COLUMNS.split(",")}
    if include_payloads:
        record["arguments_redacted"] = row.get("arguments_redacted")
        record["result_excerpt"] = row.get("result_excerpt")
    return record


async def _export_query(
    supabase: Any, organization_id: UUID, columns: str, after_seq: int, size: int,
    agent_id: UUID | None, decision: str | None, since: datetime | None, until: datetime | None,
) -> list[dict[str, Any]]:
    query = supabase.table("agent_events").select(columns).eq("organization_id", str(organization_id)).gt("seq", after_seq)
    if agent_id is not None:
        query = query.eq("agent_id", str(agent_id))
    if decision is not None:
        query = query.eq("decision", decision)
    if since is not None:
        query = query.gte("occurred_at", since.isoformat())
    if until is not None:
        query = query.lte("occurred_at", until.isoformat())
    res = await query.order("seq").limit(size).execute()
    return list(res.data or [])


async def clear_payloads(supabase: Any, operator: OperatorContext, request: ClearPayloadsRequest) -> ClearPayloadsResponse:
    """Removes every captured payload of the caller's organization at once (admin, confirmation, audited with
    the count). Events and the hash chain are untouched. Idempotent: a repeat clears nothing."""
    if operator.role < Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This action requires the 'admin' role or higher.")
    _require_confirmation(request.confirm, "Deleting captured payloads")
    data = await _rpc(
        supabase,
        "control_clear_payloads",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_reason": request.reason},
        not_found_detail="Organization not found.",
        conflict_detail="Payloads could not be cleared; try again.",
    )
    return ClearPayloadsResponse(cleared=int(data["cleared"]))
