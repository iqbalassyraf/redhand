"""
Tool pinning: tenant-scoped reads, decisions (audited in SQL) and the gateway's observation reports.

Everything stored here about a tool came from an MCP server and is untrusted: it is capped by the database, returned to
admins and operators as data, and never put into an alert (alerts carry counts and the server slug only).
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext
from redhand_core.passports.service import StateConflictError, _require_confirmation, _rpc, retry_once_on_conflict
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.bot import notify_organization
from redhand_core.telegram.client import TelegramClient
from redhand_core.toolpins.models import (
    ApproveAllRequest,
    ApproveAllResponse,
    ObservationReport,
    ObservationResponse,
    PinDecisionRequest,
    PinDecisionResponse,
    PinModeRequest,
    PinModeResponse,
    ToolPinsResponse,
    ToolPinView,
)

logger = logging.getLogger("redhand.core.toolpins")

MAX_PINS_RETURNED = 500
_PIN_COLUMNS = "id,tool_name,status,change_kind,description,schema_text,rules,first_seen_at,last_seen_at"


async def _server(supabase: Any, organization_id: UUID, server_id: UUID) -> dict[str, Any]:
    res = await (
        supabase.table("mcp_servers").select("id,slug,pin_mode").eq("id", str(server_id)).eq("organization_id", str(organization_id)).execute()
    )
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP server not found.")
    return dict(rows[0])


async def list_pins(supabase: Any, organization_id: UUID, server_id: UUID) -> ToolPinsResponse:
    server = await _server(supabase, organization_id, server_id)
    res = await (
        supabase.table("mcp_tool_pins").select(_PIN_COLUMNS)
        .eq("organization_id", str(organization_id)).eq("server_id", str(server_id))
        .order("last_seen_at", desc=True).limit(MAX_PINS_RETURNED * 2).execute()
    )
    rows = [r for r in (res.data or []) if r["status"] != "superseded"][:MAX_PINS_RETURNED]
    approved = {r["tool_name"]: r for r in rows if r["status"] == "approved"}
    order = {"pending": 0, "approved": 1, "rejected": 2}
    views = [
        ToolPinView(
            **r,
            approved_description=approved[r["tool_name"]]["description"] if r["status"] == "pending" and r["tool_name"] in approved else None,
            approved_schema_text=approved[r["tool_name"]]["schema_text"] if r["status"] == "pending" and r["tool_name"] in approved else None,
        )
        for r in sorted(rows, key=lambda r: (order.get(r["status"], 3), r["tool_name"]))
    ]
    return ToolPinsResponse(
        server_id=server_id, server_slug=server["slug"], pin_mode=server["pin_mode"],
        pending_count=sum(1 for v in views if v.status == "pending"), pins=views,
    )


async def decide(supabase: Any, operator: OperatorContext, pin_id: UUID, request: PinDecisionRequest) -> PinDecisionResponse:
    data = await _rpc(
        supabase, "control_tool_pin",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_pin": str(pin_id),
         "p_decision": request.decision, "p_reason": request.reason},
        not_found_detail="Tool version not found.", conflict_detail="That tool version could not be updated.",
    )
    if data.get("conflict"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"That version was already {data.get('status')}.")
    return PinDecisionResponse(status=data["status"])


async def approve_all(supabase: Any, operator: OperatorContext, server_id: UUID, request: ApproveAllRequest) -> ApproveAllResponse:
    _require_confirmation(request.confirm, "Approving every pending tool")
    data = await _rpc(
        supabase, "control_tool_pins_approve_all",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_server": str(server_id), "p_reason": request.reason},
        not_found_detail="MCP server not found.", conflict_detail="The tools could not be approved.",
    )
    return ApproveAllResponse(approved=int(data["approved"]))


@retry_once_on_conflict
async def set_pin_mode(supabase: Any, operator: OperatorContext, server_id: UUID, request: PinModeRequest) -> PinModeResponse:
    """Compare-and-set against the mode the decision was made on. Every change needs confirmation: off removes the check and
    enforce can hide tools from agents, so neither happens by accident."""
    server = await _server(supabase, operator.organization_id, server_id)
    if server["pin_mode"] != request.mode:
        _require_confirmation(request.confirm, "Changing tool pinning")
    data = await _rpc(
        supabase, "control_server_pin_mode",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_server": str(server_id),
         "p_mode": request.mode, "p_expected": server["pin_mode"], "p_reason": request.reason},
        not_found_detail="MCP server not found.", conflict_detail="The pin mode conflicted with another change; try again.",
    )
    if data.get("conflict"):
        raise StateConflictError
    return PinModeResponse(pin_mode=data["pin_mode"], changed=bool(data["changed"]))


async def record_observation(supabase: Any, telegram: TelegramClient | None, report: ObservationReport) -> ObservationResponse:
    """Stores the tool versions the gateway saw (idempotent) and alerts the organization about new or changed ones, at most
    once per server per ten minutes. The organization claimed is checked against the server's real owner in SQL."""
    res = await (
        supabase.table("mcp_servers").select("id").eq("organization_id", str(report.organization_id))
        .eq("slug", report.server).eq("is_active", True).execute()
    )
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP server not found.")
    tools = [
        {"name": t.name, "digest": t.digest, "description": t.description, "schema": t.schema_text, "rules": t.rules}
        for t in report.tools
    ]
    try:
        response = await supabase.rpc(
            "record_tool_observation", {"p_org": str(report.organization_id), "p_server": str(rows[0]["id"]), "p_tools": tools}
        ).execute()
    except APIError as exc:
        logger.error("Tool observation could not be recorded: sqlstate=%s", exc.code)
        if exc.code == "P0002":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP server not found.") from None
        if exc.code == "22023":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid tool report.") from None
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The tool report could not be recorded.") from None
    data = response.data
    new, changed = int(data["new"]), int(data["changed"])
    if new + changed:
        get_metrics().increment_counter("redhand_tool_pins_total", labels={"kind": "changed" if changed else "new"})
    if data.get("alert"):
        parts = []
        if changed:
            parts.append(f"{changed} changed since you approved the tool")
        if new:
            parts.append(f"{new} new")
        await notify_organization(
            supabase, telegram, report.organization_id,
            f"Tool pinning: server '{report.server}' has tool changes waiting for your review ({', '.join(parts)}). "
            "Open the dashboard, MCP Scanner, Tool pins.",
        )
    return ObservationResponse(new=new, changed=changed)
