"""
The Risk Engine (Phase 4.5 B1, ADR 0019): reads the signals SQL counts per agent, scores them with `scoring.py`, and applies the
organization's response ladder.

Where it runs: after core has recorded a gateway report (findings, a trip, usage, Black Box events) and after a person confirms a finding.
Never on the gateway's call path, and never able to fail the report that triggered it: `evaluate_agents` catches everything, logs the type
only, and counts it. What it may do: alert, turn Safe Mode on, freeze. All three only tighten, all three go through the existing audited
control functions with the system actor, and nothing here ever unfreezes or turns Safe Mode off.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.passports import service as passport_service
from redhand_core.passports.budget import SYSTEM_ACTOR_ID
from redhand_core.passports.service import _require_confirmation, _rpc
from redhand_core.risk.models import (
    AgentRiskDetail,
    AgentRiskSummary,
    LadderCapabilities,
    LadderRequest,
    LadderView,
    RiskDetailResponse,
    RiskListResponse,
    RiskSignalView,
    RiskWeightView,
)
from redhand_core.risk.scoring import (
    LABELS,
    RISK_MODEL,
    WEIGHTS,
    Action,
    Assessment,
    Counts,
    Ladder,
    Signal,
    actions_for,
    assess,
)
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.bot import notify_organization
from redhand_core.telegram.client import TelegramClient

logger = logging.getLogger("redhand.core.risk")

ALERT_COOLDOWN_SECONDS = 3600
EVALUATION_TIMEOUT_SECONDS = 5.0
ACTIVE = "active"
SIGNAL_BY_KEY = {s.value: s for s in Signal}
AGENT_COLUMNS = "id,name,status,safe_mode,risk_released_at"


# --- reading ----------------------------------------------------------------------------------------------------------------------

async def load_ladder(supabase: Any, organization_id: UUID) -> Ladder:
    res = await (
        supabase.table("organizations").select("risk_alert_threshold,risk_safe_mode_threshold,risk_freeze_threshold")
        .eq("id", str(organization_id)).execute()
    )
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found.")
    row = rows[0]
    return Ladder(row.get("risk_alert_threshold"), row.get("risk_safe_mode_threshold"), row.get("risk_freeze_threshold"))


async def _agents(supabase: Any, organization_id: UUID, agent_ids: list[UUID] | None = None) -> list[dict[str, Any]]:
    if agent_ids is None:
        res = await supabase.table("agents").select(AGENT_COLUMNS).eq("organization_id", str(organization_id)).execute()
        return list(res.data or [])
    rows: list[dict[str, Any]] = []
    for agent_id in agent_ids:  # a report names one agent, a Black Box batch a few: one indexed lookup each
        res = await (
            supabase.table("agents").select(AGENT_COLUMNS).eq("organization_id", str(organization_id)).eq("id", str(agent_id)).execute()
        )
        rows.extend(res.data or [])
    return rows


async def load_counts(
    supabase: Any, organization_id: UUID, agent_id: UUID | None, now: datetime
) -> dict[str, tuple[dict[Signal, Counts], dict[Signal, Counts]]]:
    """Per agent id: (counts for the shown score, counts after the last release for the action score). Unknown signal keys are
    dropped: a newer database must not break an older core."""
    try:
        res = await supabase.rpc(
            "agent_risk_signals", {"p_org": str(organization_id), "p_agent": str(agent_id) if agent_id else None, "p_now": now.isoformat()}
        ).execute()
    except APIError as exc:
        # A score that could not be read must never look like a clean agent: refuse instead of showing zero.
        logger.error("Risk signals could not be read: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Risk scores could not be read. Try again shortly.") from None
    out: dict[str, tuple[dict[Signal, Counts], dict[Signal, Counts]]] = {}
    for row in res.data or []:
        signal = SIGNAL_BY_KEY.get(str(row.get("signal")))
        if signal is None:
            continue
        shown, action = out.setdefault(str(row["agent_id"]), ({}, {}))
        shown[signal] = Counts(int(row["recent_all"]), int(row["older_all"]))
        action[signal] = Counts(int(row["recent_action"]), int(row["older_action"]))
    return out


def _signals(assessment: Assessment) -> list[RiskSignalView]:
    return [
        RiskSignalView(signal=c.signal.value, label=c.label, recent=c.recent, older=c.older, points=c.points, capped=c.capped)
        for c in assessment.contributions
    ]


def _summary(row: dict[str, Any], shown: Assessment, action: Assessment) -> AgentRiskSummary:
    return AgentRiskSummary(
        agent_id=row["id"], name=str(row.get("name") or ""), status=str(row.get("status")), safe_mode=bool(row.get("safe_mode")),
        score=shown.score, level=shown.level.value, action_score=action.score, reason=shown.reason(),
        released_at=row.get("risk_released_at"),
    )


def _ladder_view(ladder: Ladder, action_scores: list[int], operator: OperatorContext) -> LadderView:
    reaching = {"alert": 0, "safe_mode": 0, "freeze": 0}
    for score in action_scores:
        for action in actions_for(score, ladder):
            reaching[action.value] += 1
    return LadderView(
        alert_at=ladder.alert_at, safe_mode_at=ladder.safe_mode_at, freeze_at=ladder.freeze_at, reaching=reaching,
        capabilities=LadderCapabilities(can_change=operator.role >= Role.ADMIN),
    )


async def list_agent_risk(supabase: Any, operator: OperatorContext, now: datetime) -> RiskListResponse:
    rows = await _agents(supabase, operator.organization_id)
    counts = await load_counts(supabase, operator.organization_id, None, now)
    summaries: list[AgentRiskSummary] = []
    action_scores: list[int] = []
    for row in rows:
        shown_counts, action_counts = counts.get(str(row["id"]), ({}, {}))
        shown, action = assess(shown_counts), assess(action_counts)
        summaries.append(_summary(row, shown, action))
        if row.get("status") == ACTIVE:
            action_scores.append(action.score)
    summaries.sort(key=lambda s: (-s.score, s.name))
    ladder = await load_ladder(supabase, operator.organization_id)
    return RiskListResponse(model=RISK_MODEL, agents=summaries, ladder=_ladder_view(ladder, action_scores, operator))


async def get_agent_risk(supabase: Any, operator: OperatorContext, agent_id: UUID, now: datetime) -> RiskDetailResponse:
    rows = await _agents(supabase, operator.organization_id, [agent_id])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.")
    shown_counts, action_counts = (await load_counts(supabase, operator.organization_id, agent_id, now)).get(str(agent_id), ({}, {}))
    shown, action = assess(shown_counts), assess(action_counts)
    summary = _summary(rows[0], shown, action)
    return RiskDetailResponse(
        model=RISK_MODEL,
        agent=AgentRiskDetail(**summary.model_dump(), signals=_signals(shown), action_signals=_signals(action)),
        weights=[RiskWeightView(signal=s.value, label=LABELS[s], points=w.points, cap=w.cap) for s, w in WEIGHTS.items()],
    )


async def get_ladder(supabase: Any, operator: OperatorContext, now: datetime) -> LadderView:
    return (await list_agent_risk(supabase, operator, now)).ladder


# --- changing the ladder --------------------------------------------------------------------------------------------------------

def _widens_automatic_action(old: int | None, new: int | None) -> bool:
    """True when the change makes an automatic action happen to more agents: a rung turned on, or its threshold lowered."""
    return new is not None and (old is None or new < old)


async def set_ladder(supabase: Any, operator: OperatorContext, request: LadderRequest, now: datetime) -> LadderView:
    current = await load_ladder(supabase, operator.organization_id)
    if _widens_automatic_action(current.safe_mode_at, request.safe_mode_at):
        _require_confirmation(request.confirm, "Letting the Risk Engine turn Safe Mode on by itself")
    if _widens_automatic_action(current.freeze_at, request.freeze_at):
        _require_confirmation(request.confirm, "Letting the Risk Engine freeze agents by itself")
    await _rpc(
        supabase, "control_risk_ladder",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_alert": request.alert_at,
         "p_safe_mode": request.safe_mode_at, "p_freeze": request.freeze_at, "p_reason": request.reason},
        not_found_detail="Organization not found.", conflict_detail="The thresholds must rise: alert, then Safe Mode, then freeze.",
    )
    return await get_ladder(supabase, operator, now)


# --- acting -----------------------------------------------------------------------------------------------------------------------

def _audit_reason(action: Assessment) -> str:
    return f"Risk Engine: score {action.score} ({action.level.value}): {action.reason()}"[:300]


def _alert_text(name: str, shown: Assessment, action: Assessment, done: str | None) -> str:
    what = f" RedHand has {done}." if done else " Nothing was changed automatically."
    return (
        f"Risk: agent '{name}' reached a risk score of {action.score} ({action.level.value}): {action.reason()}.{what} "
        "Open the dashboard, Passports, Risk, to see why. Counts only: no call details are sent."
    )


async def _act_on(supabase: Any, telegram: TelegramClient | None, org: UUID, row: dict[str, Any], counts: tuple[
        dict[Signal, Counts], dict[Signal, Counts]], ladder: Ladder, now: datetime) -> None:
    shown, action = assess(counts[0]), assess(counts[1])
    reached = actions_for(action.score, ladder)
    if not reached or row.get("status") != ACTIVE:
        return  # nothing to do, or a frozen, revoked or expired agent: the engine never changes those
    agent_id = UUID(str(row["id"]))
    system = OperatorContext(user_id=SYSTEM_ACTOR_ID, organization_id=org, role=Role.SECURITY_OPERATOR)
    metrics = get_metrics()
    done: str | None = None
    try:
        # One tightening per evaluation, the strongest reached: freeze already stops every call, so Safe Mode on top adds nothing.
        if Action.FREEZE in reached:
            _, changed = await passport_service.freeze(supabase, system, agent_id, _audit_reason(action), now)
            done = "frozen it" if changed else None
        elif Action.SAFE_MODE in reached and not row.get("safe_mode"):
            _, changed = await passport_service.set_agent_safe_mode(
                supabase, system, agent_id, True, _audit_reason(action), confirm=True, now=now
            )
            done = "turned Safe Mode on for it (read-only tools only)" if changed else None
    except HTTPException as exc:  # a concurrent change (409) or a vanished agent (404): the next report evaluates again
        logger.warning("Risk Engine action refused for agent %s: %s", agent_id, exc.status_code)
    if done:
        metrics.increment_counter("risk_actions_total", labels={"action": "freeze" if done.startswith("frozen") else "safe_mode"})
    # An automatic action is always reported (and starts the cooldown); a plain alert only when its rung is on and the cooldown allows.
    if done or Action.ALERT in reached:
        marked = await supabase.rpc(
            "risk_mark_alerted", {"p_org": str(org), "p_agent": str(agent_id), "p_cooldown_seconds": ALERT_COOLDOWN_SECONDS}
        ).execute()
        if done or marked.data is True:
            await notify_organization(supabase, telegram, org, _alert_text(str(row.get("name") or "an agent"), shown, action, done))
            metrics.increment_counter("risk_actions_total", labels={"action": "alert"})


async def _evaluate(supabase: Any, telegram: TelegramClient | None, org: UUID, agent_ids: list[UUID], now: datetime) -> None:
    rows = await _agents(supabase, org, agent_ids)  # an agent of another organization is simply not found
    if not rows:
        return
    ladder = await load_ladder(supabase, org)
    if ladder.alert_at is None and ladder.safe_mode_at is None and ladder.freeze_at is None:
        return
    for row in rows:
        counts = await load_counts(supabase, org, UUID(str(row["id"])), now)
        await _act_on(supabase, telegram, org, row, counts.get(str(row["id"]), ({}, {})), ladder, now)


async def evaluate_agents(supabase: Any, telegram: TelegramClient | None, org: UUID, agent_ids: list[UUID], now: datetime) -> None:
    """Re-scores these agents and applies the ladder. Never raises and is bounded in time: the report that triggered it is already
    recorded, and a failure here must cost only this evaluation (the next report evaluates again)."""
    unique = list(dict.fromkeys(agent_ids))
    if not unique:
        return
    metrics = get_metrics()
    try:
        await asyncio.wait_for(_evaluate(supabase, telegram, org, unique, now), EVALUATION_TIMEOUT_SECONDS)
        metrics.increment_counter("risk_evaluations_total", labels={"outcome": "ok"})
    except asyncio.TimeoutError:
        logger.error("Risk Engine evaluation timed out for %d agent(s)", len(unique))
        metrics.increment_counter("risk_evaluations_total", labels={"outcome": "timeout"})
    except Exception as exc:  # noqa: BLE001  the report is already stored; nothing here may turn it into an error (logged, counted)
        logger.error("Risk Engine evaluation failed: %s", type(exc).__name__)
        metrics.increment_counter("risk_evaluations_total", labels={"outcome": "error"})
