"""
Honeytokens and honey tools: tenant-scoped control actions (audited in SQL) and trip handling. Values are
generated here, returned once, and never stored or logged; only a digest and the last four characters are.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.honeytokens import generator
from redhand_core.honeytokens.models import (
    HoneytokenCreated,
    HoneytokenCreateRequest,
    HoneytokenView,
    HoneyToolCreateRequest,
    HoneyToolView,
    RetireResponse,
    TripReport,
)
from redhand_core.passports import service as passport_service
from redhand_core.passports.budget import SYSTEM_ACTOR_ID
from redhand_core.passports.models import utcnow
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.bot import AlertBatch, send_alert
from redhand_core.telegram.client import TelegramClient

logger = logging.getLogger("redhand.core.honeytokens")

_HONEYTOKEN_COLUMNS = "id,label,kind,hint,action_on_use,action_on_read,status,created_at,last_tripped_at,trip_count"
_HONEY_TOOL_COLUMNS = "id,agent_id,server_slug,name,description,action,status,created_at,last_tripped_at,trip_count"


async def list_honeytokens(supabase: Any, organization_id: UUID) -> list[HoneytokenView]:
    res = await (
        supabase.table("honeytokens").select(_HONEYTOKEN_COLUMNS).eq("organization_id", str(organization_id))
        .order("created_at", desc=True).execute()
    )
    return [HoneytokenView(**row) for row in (res.data or []) if row.get("status") in ("active", "retired")]


async def create_honeytoken(supabase: Any, operator: OperatorContext, request: HoneytokenCreateRequest) -> HoneytokenCreated:
    value = generator.generate_value(request.kind)
    row = await passport_service._rpc(
        supabase,
        "control_honeytoken_create",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_label": request.label,
            "p_kind": request.kind, "p_digest": generator.digest_of(value), "p_hint": generator.hint_of(value),
            "p_action_on_use": request.action_on_use, "p_action_on_read": request.action_on_read,
        },
        not_found_detail="Organization not found.",
        conflict_detail="At most 50 active honeytokens per organization; retire one first.",
    )
    return HoneytokenCreated(**row, value=value)


async def retire_honeytoken(supabase: Any, operator: OperatorContext, honeytoken_id: UUID) -> RetireResponse:
    data = await passport_service._rpc(
        supabase,
        "control_honeytoken_retire",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_id": str(honeytoken_id)},
        not_found_detail="Honeytoken not found.",
        conflict_detail="The honeytoken could not be retired.",
    )
    return RetireResponse(changed=bool(data["changed"]))


def _tool_view(row: dict[str, Any]) -> HoneyToolView:
    return HoneyToolView(**{**row, "server": row.get("server", row.get("server_slug"))})


async def list_honey_tools(supabase: Any, organization_id: UUID, agent_id: UUID | None) -> list[HoneyToolView]:
    query = supabase.table("honey_tools").select(_HONEY_TOOL_COLUMNS).eq("organization_id", str(organization_id))
    if agent_id is not None:
        query = query.eq("agent_id", str(agent_id))
    res = await query.order("created_at", desc=True).execute()
    return [_tool_view(row) for row in (res.data or [])]


async def create_honey_tool(supabase: Any, operator: OperatorContext, request: HoneyToolCreateRequest) -> HoneyToolView:
    row = await passport_service._rpc(
        supabase,
        "control_honey_tool_create",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_agent": str(request.agent_id),
            "p_server": request.server, "p_name": request.name, "p_description": request.description,
            "p_action": request.action,
        },
        not_found_detail="Agent not found.",
        conflict_detail="That decoy tool already exists for this agent, or the agent has 5 already.",
    )
    return _tool_view(row)


async def retire_honey_tool(supabase: Any, operator: OperatorContext, honey_tool_id: UUID) -> RetireResponse:
    data = await passport_service._rpc(
        supabase,
        "control_honey_tool_retire",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_id": str(honey_tool_id)},
        not_found_detail="Honey tool not found.",
        conflict_detail="The honey tool could not be retired.",
    )
    return RetireResponse(changed=bool(data["changed"]))


def _alert_text(report: TripReport, label: str, agent_name: str, frozen: bool, honeytoken_kind: str | None = None) -> str:
    where = f"on {report.server}" if report.server else "through RedHand"
    tool = f" in a call to {report.tool_name}" if report.tool_name else ""
    if report.kind == "honey_tool":
        text = f"Decoy tool called: {agent_name} called '{label}' {where}. The call was not forwarded."
    elif honeytoken_kind == "canary":
        # A canary sits in the agent's own system prompt, so its appearing here means prompt text leaked, not that bait was taken.
        # "Appears to": RedHand cannot tell a leak from an agent that legitimately passed its instructions to a tool.
        if report.seen_in == "arguments":
            text = (f"Prompt canary seen: {agent_name} sent the canary '{label}'{tool} {where}, so its system prompt text appears to have leaked "
                    "into a tool call. The call was refused.")
        else:
            text = (f"Prompt canary seen: the canary '{label}' appeared in a result {where}{tool} for {agent_name}, so system prompt text "
                    "appears to have leaked into a tool answer.")
    elif report.seen_in == "arguments":
        text = f"Honeytoken used: {agent_name} sent the decoy '{label}'{tool} {where}. The call was refused."
    else:
        text = f"Honeytoken read: the decoy '{label}' appeared in a result {where}{tool} for {agent_name}."
    if frozen:
        text += " The agent has been frozen; unfreeze it from the dashboard when ready."
    return text


async def handle_trip(supabase: Any, telegram: TelegramClient | None, report: TripReport, alerts: AlertBatch | None = None) -> bool:
    """
    Records one trip (idempotent), then does what the STORED action says: alert the organization and, if the
    action is freeze, freeze the agent as the system actor. The gateway's claims are never trusted: it sends
    only identifiers, and record_trip() checks them against the database. Returns True when the trip was new.
    """
    try:
        response = await supabase.rpc(
            "record_trip",
            {
                "p_org": str(report.organization_id), "p_trip_id": str(report.trip_id), "p_agent": str(report.agent_id),
                "p_kind": report.kind, "p_ref": str(report.ref_id), "p_seen_in": report.seen_in,
                "p_tool": report.tool_name, "p_server": report.server,
            },
        ).execute()
    except APIError as exc:
        # A claim that does not match the database is the sender's fault and retrying cannot fix it (the gateway
        # drops 4xx answers); anything else is ours, and the gateway retries a 503.
        logger.error("Trip could not be recorded: sqlstate=%s", exc.code)
        if exc.code == "P0002":
            raise HTTPException(404, "Agent not found.") from None
        if exc.code == "22023":
            raise HTTPException(422, "Invalid trip.") from None
        raise HTTPException(503, "The trip could not be recorded.") from None
    data = response.data
    if not isinstance(data, dict) or not data.get("recorded"):
        return False
    get_metrics().increment_counter("redhand_trips_total", labels={"kind": report.kind, "seen_in": report.seen_in})

    frozen = False
    if data.get("action") == "freeze":
        system = OperatorContext(user_id=SYSTEM_ACTOR_ID, organization_id=report.organization_id, role=Role.SECURITY_OPERATOR)
        try:
            await passport_service.freeze(
                supabase, system, report.agent_id, f"Honeytoken trip: {data.get('label')}", utcnow()
            )
            frozen = True
        except HTTPException as exc:
            logger.warning("Trip freeze refused for agent %s: %s", report.agent_id, exc.status_code)
    if data.get("alert"):
        await send_alert(
            alerts, supabase, telegram, report.organization_id, agent_id=report.agent_id, text=
            _alert_text(report, str(data.get("label")), str(data.get("agent_name")), frozen,
                        str(data["kind"]) if isinstance(data.get("kind"), str) else None),
        )
    return True
