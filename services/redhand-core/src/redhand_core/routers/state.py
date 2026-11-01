"""
RedHand Core - Live State Snapshot, Agent Posture Control & SSE Stream Router
File: services/redhand-core/src/redhand_core/routers/state.py

Bridges `redhand-ui` directly to `redhand-core` via:
- `GET /v1/state/snapshot`: Full dashboard state hydration.
- `GET /v1/state/stream`: Server-Sent Events (SSE) push stream for real-time canvas updates.
- `PATCH /v1/state/agents/{agent_id}/posture`: Live agent quarantine / un-quarantine & tool allowlist updates.
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.local_store import get_local_store

router = APIRouter(
    prefix="/v1/state",
    tags=["Real-Time State & Posture Control"],
)


class AgentPostureUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str | None = Field(
        default=None,
        pattern="^(active|suspended|quarantined|decommissioned)$",
    )
    allowed_tools: list[str] | None = None


@router.get(
    "/snapshot",
    summary="Fetch Live Topology State Snapshot (Agents, Traces, Security Events, HITL Queue)",
)
async def get_state_snapshot(
    supabase: Annotated[Any, Depends(get_supabase_service_client)],
) -> dict[str, Any]:
    agents_res = await supabase.table("agents").select("*").execute()
    traces_res = await supabase.table("execution_traces").select("*").execute()
    events_res = await supabase.table("security_events").select("*").execute()
    hitl_res = await supabase.table("hitl_interventions").select("*").execute()

    return {
        "agents": agents_res.data or [],
        "execution_traces": (traces_res.data or [])[:100],
        "security_events": (events_res.data or [])[:100],
        "hitl_interventions": hitl_res.data or [],
    }


@router.patch(
    "/agents/{agent_id}/posture",
    summary="Quarantine, Suspend, Activate, or Update Allowed Tools for an Agent",
)
async def update_agent_posture(
    agent_id: UUID,
    payload: AgentPostureUpdateRequest,
    supabase: Annotated[Any, Depends(get_supabase_service_client)],
) -> dict[str, Any]:
    update_fields: dict[str, Any] = {}
    if payload.status is not None:
        update_fields["status"] = payload.status
    if payload.allowed_tools is not None:
        update_fields["allowed_tools"] = payload.allowed_tools

    if not update_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of 'status' or 'allowed_tools' must be provided.",
        )

    res = await (
        supabase.table("agents")
        .update(update_fields)
        .eq("id", str(agent_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found.",
        )

    return {"status": "updated", "agent": res.data[0]}


@router.get(
    "/stream",
    summary="Server-Sent Events (SSE) Real-Time Telemetry & HITL Stream",
)
async def stream_realtime_events(request: Request) -> StreamingResponse:
    store = get_local_store()
    queue = store.subscribe()

    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
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

