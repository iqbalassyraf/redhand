"""
The incident view (Phase 4.5 B3, docs/adr/0022-incident-view.md): one timeline per agent from what RedHand already records. No new data.

Six reads, run together, each scoped by organization AND agent and bounded to one page:
  refused calls and failed calls (Black Box), allowed activity per hour (the B2 roll-up, so thousands of calls are a few rows),
  findings (Radar), trips (honeytokens and decoy tools), control actions (audit rows whose target is this agent).
They are merged newest first and cut to the page size. The cursor is a time: the next page is everything strictly older than the last
item kept, so items that share the cut-off moment are kept together on one page (never split, never repeated).
If any read fails the whole answer is refused: a timeline with a missing part would read as "nothing happened".
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext
from redhand_core.passports.budget import SYSTEM_ACTOR_ID
from redhand_core.timeline.models import TimelineAgent, TimelineItem, TimelineResponse

logger = logging.getLogger("redhand.core.timeline")

DEFAULT_PAGE = 50
MAX_PAGE = 200
MAX_HOURLY_ROWS = 2000
TIE_LIMIT = 1000  # items of one source at one exact moment; beyond this a page can still split them (logged)  # one row per agent, hour and tool: enough for a busy page; aggregated per hour below
FAILED = "The timeline could not be read. Try again shortly."

Row = dict[str, Any]


def _time(value: Any) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _scoped(supabase: Any, table: str, columns: str, organization_id: UUID, agent_column: str, agent_id: UUID) -> Any:
    return supabase.table(table).select(columns).eq("organization_id", str(organization_id)).eq(agent_column, str(agent_id))


def _window(query: Any, column: str, before: datetime | None, exactly: datetime | None) -> Any:
    """Older than `before`, or (to complete a tie at the cut-off) exactly at `exactly`."""
    if exactly is not None:
        return query.gte(column, exactly.isoformat()).lte(column, exactly.isoformat())
    if before is not None:
        return query.lt(column, before.isoformat())
    return query


async def _events(
    supabase: Any, org: UUID, agent: UUID, decision: str, before: datetime | None, limit: int, exactly: datetime | None = None
) -> list[Row]:
    query = _scoped(supabase, "agent_events", "seq, occurred_at, server, tool_name, decision, reasons", org, "agent_id", agent)
    query = _window(query.eq("decision", decision), "occurred_at", before, exactly)
    return list((await query.order("occurred_at", desc=True).limit(limit).execute()).data or [])


async def _hourly(supabase: Any, org: UUID, agent: UUID, before: datetime | None) -> list[Row]:
    query = _scoped(supabase, "agent_tool_hourly", "hour, calls, refused", org, "agent_id", agent)
    if before is not None:
        query = query.lt("hour", before.isoformat())
    return list((await query.order("hour", desc=True).limit(MAX_HOURLY_ROWS).execute()).data or [])


async def _findings(
    supabase: Any, org: UUID, agent: UUID, before: datetime | None, limit: int, exactly: datetime | None = None
) -> list[Row]:
    query = _scoped(
        supabase, "security_findings", "id, rule_id, kind, confidence, review_status, occurrences, tool_name, server_slug, first_seen_at",
        org, "agent_id", agent,
    )
    query = _window(query, "first_seen_at", before, exactly)
    return list((await query.order("first_seen_at", desc=True).limit(limit).execute()).data or [])


async def _trips(
    supabase: Any, org: UUID, agent: UUID, before: datetime | None, limit: int, exactly: datetime | None = None
) -> list[Row]:
    query = _scoped(supabase, "honeytrips", "kind, seen_in, tool_name, server_slug, occurred_at", org, "agent_id", agent)
    query = _window(query, "occurred_at", before, exactly)
    return list((await query.order("occurred_at", desc=True).limit(limit).execute()).data or [])


async def _actions(
    supabase: Any, org: UUID, agent: UUID, before: datetime | None, limit: int, exactly: datetime | None = None
) -> list[Row]:
    query = _scoped(supabase, "control_audit_log", "action, actor_user_id, reason, created_at", org, "target_id", agent)
    query = _window(query, "created_at", before, exactly)
    return list((await query.order("created_at", desc=True).limit(limit).execute()).data or [])


def _activity(rows: list[Row]) -> list[TimelineItem]:
    """Allowed and refused tool calls added up per hour (all tools). An hour with no calls is not shown."""
    per_hour: dict[datetime, list[int]] = {}
    for row in rows:
        totals = per_hour.setdefault(_time(row["hour"]), [0, 0])
        totals[0] += int(row.get("calls") or 0)
        totals[1] += int(row.get("refused") or 0)
    return [TimelineItem(at=hour, kind="activity", calls=c, refused=r) for hour, (c, r) in per_hour.items() if c > 0]


def _event_fields(r: Row) -> dict[str, Any]:
    return {"seq": int(r["seq"]), "tool_name": r.get("tool_name") or "", "server": r.get("server") or "",
            "reasons": [str(x) for x in (r.get("reasons") or [])]}


def _items(blocks: list[Row], errors: list[Row], hourly: list[Row], findings: list[Row], trips: list[Row], actions: list[Row]) -> list[TimelineItem]:
    items: list[TimelineItem] = []
    for r in blocks:
        items.append(TimelineItem(at=_time(r["occurred_at"]), kind="refusal", **_event_fields(r)))
    for r in errors:
        items.append(TimelineItem(at=_time(r["occurred_at"]), kind="error", **_event_fields(r)))
    items.extend(_activity(hourly))
    items.extend(
        TimelineItem(at=_time(r["first_seen_at"]), kind="finding", finding_id=UUID(str(r["id"])), rule_id=str(r["rule_id"]),
                     finding_kind=str(r["kind"]), confidence=str(r["confidence"]), review_status=str(r["review_status"]),
                     occurrences=int(r.get("occurrences") or 1), tool_name=r.get("tool_name") or "", server=r.get("server_slug") or "")
        for r in findings
    )
    items.extend(
        TimelineItem(at=_time(r["occurred_at"]), kind="trip", trip_kind=str(r["kind"]), seen_in=str(r["seen_in"]),
                     tool_name=r.get("tool_name") or "", server=r.get("server_slug") or "")
        for r in trips
    )
    items.extend(
        TimelineItem(at=_time(r["created_at"]), kind="action", action=str(r["action"]), reason=r.get("reason"),
                     automatic=str(r.get("actor_user_id")) == str(SYSTEM_ACTOR_ID))
        for r in actions
    )
    return items


def _cut(items: list[TimelineItem], limit: int) -> datetime | None:
    """The moment a page of `limit` items would end at, or None when everything fits."""
    if len(items) <= limit:
        return None
    return sorted((i.at for i in items), reverse=True)[limit - 1]


def _page(items: list[TimelineItem], limit: int, more_possible: bool) -> tuple[list[TimelineItem], datetime | None]:
    """Newest first, at most `limit`, except that items sharing the cut-off moment stay together."""
    items.sort(key=lambda i: i.at, reverse=True)
    if len(items) <= limit:
        return items, (items[-1].at if more_possible and items else None)
    cut = items[limit - 1].at
    kept = [i for i in items if i.at >= cut]
    return kept, cut


async def agent_timeline(
    supabase: Any, operator: OperatorContext, agent_id: UUID, before: datetime | None, limit: int = DEFAULT_PAGE
) -> TimelineResponse:
    limit = max(1, min(limit, MAX_PAGE))
    org = operator.organization_id
    try:
        agent_rows = list((await supabase.table("agents").select("id, name, status").eq("organization_id", str(org))
                           .eq("id", str(agent_id)).limit(1).execute()).data or [])
        if not agent_rows:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.")
        fetch = limit + 1  # one more than a page tells whether an older page exists
        blocks, errors, hourly, findings, trips, actions = await asyncio.gather(
            _events(supabase, org, agent_id, "BLOCK", before, fetch),
            _events(supabase, org, agent_id, "ERROR", before, fetch),
            _hourly(supabase, org, agent_id, before),
            _findings(supabase, org, agent_id, before, fetch),
            _trips(supabase, org, agent_id, before, fetch),
            _actions(supabase, org, agent_id, before, fetch),
        )
        cut = _cut(_items(blocks, errors, [], findings, trips, actions), limit)
        if cut is not None:
            # A source that filled its fetch may hold more rows at exactly the cut-off moment; read that moment in full, so the page keeps
            # every item of it and the next page (strictly older) misses none.
            sources: dict[str, tuple[list[Row], str, Callable[[], Awaitable[list[Row]]]]] = {
                "blocks": (blocks, "occurred_at", lambda: _events(supabase, org, agent_id, "BLOCK", None, TIE_LIMIT, cut)),
                "errors": (errors, "occurred_at", lambda: _events(supabase, org, agent_id, "ERROR", None, TIE_LIMIT, cut)),
                "findings": (findings, "first_seen_at", lambda: _findings(supabase, org, agent_id, None, TIE_LIMIT, cut)),
                "trips": (trips, "occurred_at", lambda: _trips(supabase, org, agent_id, None, TIE_LIMIT, cut)),
                "actions": (actions, "created_at", lambda: _actions(supabase, org, agent_id, None, TIE_LIMIT, cut)),
            }
            completed: dict[str, list[Row]] = {}
            for name, (rows, column, read_moment) in sources.items():
                if len(rows) >= fetch and _time(rows[-1][column]) == cut:
                    at_cut = await read_moment()
                    if len(at_cut) >= TIE_LIMIT:
                        logger.warning("Timeline tie at one moment exceeds %d rows for one source; a page may split it", TIE_LIMIT)
                    completed[name] = [r for r in rows if _time(r[column]) != cut] + at_cut
            blocks = completed.get("blocks", blocks)
            errors = completed.get("errors", errors)
            findings = completed.get("findings", findings)
            trips = completed.get("trips", trips)
            actions = completed.get("actions", actions)
    except APIError as exc:
        logger.error("Timeline could not be read: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, FAILED) from None
    more_possible = any(len(rows) >= fetch for rows in (blocks, errors, findings, trips, actions)) or len(hourly) >= MAX_HOURLY_ROWS
    items, next_before = _page(_items(blocks, errors, hourly, findings, trips, actions), limit, more_possible)
    row = agent_rows[0]
    return TimelineResponse(
        agent=TimelineAgent(id=UUID(str(row["id"])), name=str(row["name"]), status=str(row["status"])),
        items=items,
        next_before=next_before,
    )
