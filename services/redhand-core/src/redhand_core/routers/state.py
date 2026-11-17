"""
RedHand Core - Live State Snapshot, Agent Posture Control & SSE Stream Router
File: services/redhand-core/src/redhand_core/routers/state.py

Bridges `redhand-ui` directly to `redhand-core` via:
- `GET /v1/state/snapshot`: Full dashboard state hydration.
- `GET /v1/state/stream`: Server-Sent Events (SSE) push stream for real-time canvas updates.
- Agent control actions (freeze, revoke, scopes) live in routers/passports.py.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
import json
import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from redhand_core.auth.operator import Role, ViewerDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.local_store import get_local_store

# What an agent thought, was given and sent: kept from viewers (security operators and above still see it).
CONTENT_FIELDS = frozenset({"thought_content", "observation_payload", "tool_arguments"})
HITL_CONTENT_FIELDS = frozenset({"proposed_tool_arguments", "modified_tool_arguments"})

router = APIRouter(
    prefix="/v1/state",
    tags=["Real-Time State & Posture Control"],
)


@router.get(
    "/snapshot",
    summary="Fetch Live Topology State Snapshot (Agents, Traces, Security Events, HITL Queue)",
)
async def get_state_snapshot(
    operator: ViewerDep,
    supabase: Annotated[Any, Depends(get_supabase_service_client)],
) -> dict[str, Any]:
    org = str(operator.organization_id)
    agents_res = await supabase.table("agents").select("*").eq("organization_id", org).execute()
    traces_res = await (
        supabase.table("execution_traces").select("*").eq("organization_id", org).execute()
    )
    events_res = await (
        supabase.table("security_events").select("*").eq("organization_id", org).execute()
    )
    hitl_res = await (
        supabase.table("hitl_interventions").select("*").eq("organization_id", org).execute()
    )

    traces = (traces_res.data or [])[:100]
    hitl = hitl_res.data or []
    if operator.role < Role.SECURITY_OPERATOR:
        # A viewer sees the shape of what happened, not what the agent thought or was given: the Black Box payload view is admin-only and opt-in, and
        # these fields hold the same kind of text (route sweep finding, owner decision 2026-11-17).
        traces = [{k: v for k, v in row.items() if k not in CONTENT_FIELDS} for row in traces]
        hitl = [{k: v for k, v in row.items() if k not in HITL_CONTENT_FIELDS} for row in hitl]
    return {
        "organization_id": org,
        "agents": agents_res.data or [],
        "execution_traces": traces,
        "security_events": (events_res.data or [])[:100],
        "hitl_interventions": hitl,
    }


# =============================================================================
# Real-time stream. Browsers' EventSource cannot send an Authorization header, so the
# dashboard first exchanges its operator token for a single-use ticket (60 s) and
# opens the stream with it. Tickets are bound to one organization; events for other
# tenants are never sent. Tickets are held in process memory, which is sufficient for
# a single core instance (multi-instance deployments need a shared store).
# =============================================================================

STREAM_TICKET_TTL = timedelta(seconds=60)
_stream_tickets: dict[str, tuple[str, datetime]] = {}


class StreamTicketResponse(BaseModel):
    ticket: str
    expires_in_seconds: int


@router.post("/stream-ticket", response_model=StreamTicketResponse, summary="Issue SSE ticket")
async def issue_stream_ticket(operator: ViewerDep) -> StreamTicketResponse:
    now = datetime.now(timezone.utc)
    for key, (_, expiry) in list(_stream_tickets.items()):
        if expiry < now:
            _stream_tickets.pop(key, None)
    ticket = secrets.token_urlsafe(32)
    _stream_tickets[ticket] = (str(operator.organization_id), now + STREAM_TICKET_TTL)
    return StreamTicketResponse(
        ticket=ticket, expires_in_seconds=int(STREAM_TICKET_TTL.total_seconds())
    )


def _redeem_stream_ticket(ticket: str) -> str:
    entry = _stream_tickets.pop(ticket, None)
    if entry is None or entry[1] < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid stream ticket.")
    return entry[0]


def filter_event_for_org(message: dict[str, Any], org_id: str) -> dict[str, Any] | None:
    """Keeps only rows belonging to `org_id`; drops the message if none remain."""
    data = message.get("data")
    rows = data if isinstance(data, list) else [data]
    kept = [r for r in rows if isinstance(r, dict) and str(r.get("organization_id")) == org_id]
    if not kept:
        return None
    return {**message, "data": kept if isinstance(data, list) else kept[0]}


@router.get(
    "/stream",
    summary="Server-Sent Events (SSE) Real-Time Telemetry & HITL Stream",
)
async def stream_realtime_events(request: Request, ticket: str) -> StreamingResponse:
    org_id = _redeem_stream_ticket(ticket)
    store = get_local_store()
    queue = store.subscribe()

    async def event_generator() -> AsyncIterator[str]:
        try:
            yield f"data: {json.dumps({'event': 'connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    continue
                scoped = filter_event_for_org(msg, org_id)
                if scoped is not None:
                    yield f"data: {json.dumps(scoped)}\n\n"
        finally:
            store.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
