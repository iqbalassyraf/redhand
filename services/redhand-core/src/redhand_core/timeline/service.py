"""
The incident view (Phase 4.5 B3, docs/adr/0022-incident-view.md): one timeline per agent from what RedHand already records. No new data.

Reads run together, each scoped by organization (and by agent where the record names one) and bounded to one page:
  refused calls and failed calls (Black Box), allowed activity per hour (the B2 roll-up, so thousands of calls are a few rows),
  findings (Radar), trips (honeytokens and decoy tools), control actions on this agent, and the organization-wide actions that change
  what every agent may do (freeze all, Safe Mode for all). Audit rows that only repeat a trip are not shown twice.
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

# Recorded against the organization, but they change what every agent may do: shown in each agent's timeline.
ORGANIZATION_WIDE_ACTIONS = ("organization.frozen_all", "organization.safe_mode_enabled", "organization.safe_mode_disabled")
# Audit rows the timeline already shows from their own source (the trip itself): not shown twice.
SHOWN_ELSEWHERE = frozenset({"honeytoken.tripped", "honey_tool.tripped"})

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


def _org_audit(supabase: Any, org: UUID, action: str) -> Any:
    return (supabase.table("control_audit_log").select("action, actor_user_id, reason, created_at")
            .eq("organization_id", str(org)).eq("target_type", "organization").eq("action", action))


async def _organization_actions(
    supabase: Any, org: UUID, before: datetime | None, limit: int, exactly: datetime | None = None, since: datetime | None = None
) -> list[Row]:
    """Freeze all and organization-wide Safe Mode while the agent existed (from `since`, its registration), newest first. One read per
    action (the in-memory twin has no IN filter)."""
    rows: list[Row] = []
    for action in ORGANIZATION_WIDE_ACTIONS:
        query = _window(_org_audit(supabase, org, action), "created_at", before, exactly)
        if since is not None:
            query = query.gte("created_at", since.isoformat())
        rows.extend((await query.order("created_at", desc=True).limit(limit).execute()).data or [])
    rows.sort(key=lambda r: _time(r["created_at"]), reverse=True)
    return rows[:limit]


async def _safe_mode_in_effect(supabase: Any, org: UUID, registered: datetime) -> Row | None:
    """The organization Safe Mode "turned on" that was still in force when the agent was registered, or None. Safe Mode for all also
    restricts agents registered later, so it stays on the agent's timeline; an older freeze all froze only the agents that existed then."""
    latest: dict[str, Row] = {}
    for action in ("organization.safe_mode_enabled", "organization.safe_mode_disabled"):
        query = _org_audit(supabase, org, action).lt("created_at", registered.isoformat())
        found = (await query.order("created_at", desc=True).limit(1).execute()).data or []
        if found:
            latest[action] = found[0]
    enabled, disabled = latest.get("organization.safe_mode_enabled"), latest.get("organization.safe_mode_disabled")
    if enabled is None or (disabled is not None and _time(disabled["created_at"]) >= _time(enabled["created_at"])):
        return None
    return {**enabled, "in_effect_at_registration": True}


def _with_carried(rows: list[Row], carried: Row | None, before: datetime | None, exactly: datetime | None = None) -> list[Row]:
    """Adds the carried-over Safe Mode row when it falls inside the page window, so it is shown once, on the page that reaches its time."""
    if carried is None:
        return rows
    at = _time(carried["created_at"])
    inside = at == exactly if exactly is not None else (before is None or at < before)
    return [*rows, carried] if inside else rows


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


def _items(
    blocks: list[Row], errors: list[Row], hourly: list[Row], findings: list[Row], trips: list[Row], actions: list[Row],
    org_actions: list[Row],
) -> list[TimelineItem]:
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
        for r in actions if str(r["action"]) not in SHOWN_ELSEWHERE
    )
    items.extend(
        TimelineItem(at=_time(r["created_at"]), kind="action", action=str(r["action"]), reason=r.get("reason"),
                     automatic=str(r.get("actor_user_id")) == str(SYSTEM_ACTOR_ID), organization_wide=True,
                     in_effect_at_registration=r.get("in_effect_at_registration") is True)
        for r in org_actions
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
        agent_rows = list((await supabase.table("agents").select("id, name, status, created_at").eq("organization_id", str(org))
                           .eq("id", str(agent_id)).limit(1).execute()).data or [])
        if not agent_rows:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.")
        # Organization-wide actions from before the agent existed are not its history (G4). An agent without a registration time (old
        # data) keeps its full organization history: nothing is hidden on a guess.
        registered = _time(agent_rows[0]["created_at"]) if agent_rows[0].get("created_at") else None
        carried = await _safe_mode_in_effect(supabase, org, registered) if registered is not None else None
        fetch = limit + 1  # one more than a page tells whether an older page exists
        blocks, errors, hourly, findings, trips, actions, org_actions = await asyncio.gather(
            _events(supabase, org, agent_id, "BLOCK", before, fetch),
            _events(supabase, org, agent_id, "ERROR", before, fetch),
            _hourly(supabase, org, agent_id, before),
            _findings(supabase, org, agent_id, before, fetch),
            _trips(supabase, org, agent_id, before, fetch),
            _actions(supabase, org, agent_id, before, fetch),
            _organization_actions(supabase, org, before, fetch, since=registered),
        )
        org_actions = _with_carried(org_actions, carried, before)
        cut = _cut(_items(blocks, errors, [], findings, trips, actions, org_actions), limit)
        if cut is not None:
            # A source that filled its fetch may hold more rows at exactly the cut-off moment; read that moment in full, so the page keeps
            # every item of it and the next page (strictly older) misses none.
            async def _org_actions_at(moment: datetime) -> list[Row]:
                rows = await _organization_actions(supabase, org, None, TIE_LIMIT, moment, since=registered)
                return _with_carried(rows, carried, None, moment)

            sources: dict[str, tuple[list[Row], str, Callable[[], Awaitable[list[Row]]]]] = {
                "blocks": (blocks, "occurred_at", lambda: _events(supabase, org, agent_id, "BLOCK", None, TIE_LIMIT, cut)),
                "errors": (errors, "occurred_at", lambda: _events(supabase, org, agent_id, "ERROR", None, TIE_LIMIT, cut)),
                "findings": (findings, "first_seen_at", lambda: _findings(supabase, org, agent_id, None, TIE_LIMIT, cut)),
                "trips": (trips, "occurred_at", lambda: _trips(supabase, org, agent_id, None, TIE_LIMIT, cut)),
                "actions": (actions, "created_at", lambda: _actions(supabase, org, agent_id, None, TIE_LIMIT, cut)),
                "org_actions": (org_actions, "created_at", lambda: _org_actions_at(cut)),
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
            org_actions = completed.get("org_actions", org_actions)
    except APIError as exc:
        logger.error("Timeline could not be read: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, FAILED) from None
    more_possible = (
        any(len(rows) >= fetch for rows in (blocks, errors, findings, trips, actions, org_actions)) or len(hourly) >= MAX_HOURLY_ROWS
    )
    items, next_before = _page(_items(blocks, errors, hourly, findings, trips, actions, org_actions), limit, more_possible)
    row = agent_rows[0]
    return TimelineResponse(
        agent=TimelineAgent(id=UUID(str(row["id"])), name=str(row["name"]), status=str(row["status"])),
        items=items,
        next_before=next_before,
    )


# --- the incident summary export -------------------------------------------------------------------------------------------------------

MAX_EXPORT_ITEMS = 5000
EXPORT_PAGE = MAX_PAGE
EXPORT_FAILED = "The export could not be started."

CSV_COLUMNS = (
    "at", "kind", "tool_name", "server", "reasons", "seq", "calls", "refused", "rule_id", "finding_kind", "confidence", "review_status",
    "occurrences", "trip_kind", "seen_in", "action", "reason", "automatic", "organization_wide",
    "in_effect_at_registration",
)


async def audit_export(supabase: Any, operator: OperatorContext, agent_id: UUID, details: dict[str, Any]) -> None:
    """Records that a timeline export is starting, BEFORE anything is read: if this fails, nothing is exported."""
    await supabase.table("control_audit_log").insert({
        "organization_id": str(operator.organization_id), "actor_user_id": str(operator.user_id), "action": "passport.timeline_exported",
        "target_type": "agent", "target_id": str(agent_id), "reason": None, "details": details,
    }).execute()


async def export_timeline(
    supabase: Any, operator: OperatorContext, agent_id: UUID, fmt: str
) -> tuple[TimelineResponse, bool]:
    """The agent's timeline, newest first, at most MAX_EXPORT_ITEMS items, and whether it was cut. The agent must exist in the operator's
    organization (404 otherwise, and no audit row is written for it); the export is audited before the first read."""
    first = await agent_timeline(supabase, operator, agent_id, None, EXPORT_PAGE)  # also the 404 for another organization's agent
    try:
        await audit_export(supabase, operator, agent_id, {"format": fmt, "max_items": MAX_EXPORT_ITEMS})
    except APIError as exc:
        logger.error("Timeline export audit failed: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, EXPORT_FAILED) from None
    items = list(first.items)
    cursor = first.next_before
    while cursor is not None and len(items) <= MAX_EXPORT_ITEMS:
        page = await agent_timeline(supabase, operator, agent_id, cursor, EXPORT_PAGE)
        items.extend(page.items)
        cursor = page.next_before
    truncated = len(items) > MAX_EXPORT_ITEMS or cursor is not None
    return TimelineResponse(agent=first.agent, items=items[:MAX_EXPORT_ITEMS], next_before=None), truncated


def csv_rows(items: list[TimelineItem]) -> list[list[Any]]:
    """One row per item in CSV_COLUMNS order. Formula-looking text is defused by the caller (blackbox.service.csv_cell)."""
    rows: list[list[Any]] = []
    for item in items:
        data = item.model_dump(mode="json")
        data["reasons"] = "; ".join(item.reasons)
        rows.append([data.get(column) if data.get(column) is not None else "" for column in CSV_COLUMNS])
    return rows
