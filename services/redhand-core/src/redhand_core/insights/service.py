"""
Insights summary: the SQL function does the aggregation over the Black Box (`insights_summary`, organization-scoped); this module adds the
agent names, the passport counts and the organization's control state, all read for the same organization, and validates the shape.

The organization always comes from the authenticated operator. A failed read is a 503, never a response full of zeros (a zero would
look like "nothing happened").
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError
from pydantic import ValidationError

from redhand_core.insights.models import WINDOWS, Controls, InsightsResponse, Passports, Window

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _unreadable() -> HTTPException:
    return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Insights could not be read.")


async def _agent_rows(supabase: Any, organization_id: UUID) -> list[dict[str, Any]]:
    res = await supabase.table("agents").select("id,name,framework,status,reported_only").eq("organization_id", str(organization_id)).execute()
    return list(res.data or [])


def passport_counts(rows: list[dict[str, Any]]) -> Passports:
    """Reported-only agents (telemetry only, no gateway access) are counted apart from managed passports."""
    reported = [r for r in rows if r.get("reported_only")]
    managed = [r for r in rows if not r.get("reported_only")]
    return Passports(
        managed_active=sum(1 for r in managed if r.get("status") == "active"),
        frozen=sum(1 for r in managed if r.get("status") == "frozen"),
        revoked=sum(1 for r in managed if r.get("status") == "revoked"),
        reported_only=len(reported),
    )


async def _controls(supabase: Any, organization_id: UUID) -> Controls:
    res = await supabase.table("organizations").select("safe_mode,radar_mode").eq("id", str(organization_id)).execute()
    rows = list(res.data or [])
    if len(rows) != 1:
        raise _unreadable()
    return Controls(safe_mode=bool(rows[0].get("safe_mode")), radar_mode=rows[0].get("radar_mode") or "observe")


async def summary(supabase: Any, organization_id: UUID, window: Window, *, now: Clock = _utc_now) -> InsightsResponse:
    seconds, bucket = WINDOWS[window]
    until = now()
    since = until - timedelta(seconds=seconds)
    try:
        rpc = await supabase.rpc(
            "insights_summary",
            {"p_org": str(organization_id), "p_since": since.isoformat(), "p_until": until.isoformat(), "p_bucket_seconds": bucket},
        ).execute()
        agents = await _agent_rows(supabase, organization_id)
        controls = await _controls(supabase, organization_id)
    except APIError as exc:
        logger.error("Insights read failed: sqlstate=%s", exc.code)
        raise _unreadable() from None
    data = rpc.data
    if not isinstance(data, dict):
        logger.error("Insights read failed: unexpected answer shape")
        raise _unreadable()
    names = {str(a["id"]): a for a in agents}
    for row in data.get("agents", []):
        known = names.get(str(row.get("agent_id")))
        row["name"] = known.get("name") if known else None
        row["framework"] = known.get("framework") if known else None
    try:
        return InsightsResponse(window=window, passports=passport_counts(agents), controls=controls, **data)
    except ValidationError:
        logger.error("Insights read failed: the summary did not match its contract")
        raise _unreadable() from None
