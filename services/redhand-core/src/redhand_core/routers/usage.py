"""
Budget Guard: daily call limits per agent (Phase 2, M3). See docs/adr/0010-budget-guard.md.

- POST /internal/v1/usage        gateway -> core: cumulative call counts per agent and day (service token)
- PUT  /v1/passports/{id}/budget operator: set or change an agent's daily limit and action
- GET  /v1/usage                 operator: today's calls against each agent's limit

Counts are calls the gateway forwards. RedHand does not see LLM tokens or money.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from redhand_core.auth.operator import OperatorContext, Role, SecurityOperatorDep, ViewerDep
from redhand_core.passports import budget as budget_rules
from redhand_core.passports import service
from redhand_core.passports.models import AgentBudgetResponse, BudgetUpdateRequest, PassportView, utcnow
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.telegram import OptionalClientDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.bot import notify_organization
from redhand_core.telegram.client import TelegramClient

logger = logging.getLogger("redhand.core.usage")

router = APIRouter(tags=["Budget Guard"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]

MAX_REPORT_ITEMS = 1000
INSTANCE_ID_PATTERN = r"^[A-Za-z0-9-]{8,64}$"
FREEZE_REASON = "Budget Guard: daily call limit reached"


class UsageItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    day_key: date
    calls: int = Field(ge=0, le=10**12)


class UsageReport(BaseModel):
    """Cumulative totals, so resending is harmless and a stale report cannot lower a count."""

    model_config = ConfigDict(extra="forbid")

    instance_id: str = Field(pattern=INSTANCE_ID_PATTERN)
    items: list[UsageItem] = Field(max_length=MAX_REPORT_ITEMS)


class UsageReportResponse(BaseModel):
    accepted: int
    rejected: int


class AgentUsageView(BaseModel):
    agent_id: UUID
    name: str
    calls: int
    daily_call_limit: int | None
    budget_action: str
    percent: int | None = Field(description="Calls as a percentage of the limit; null when there is no limit.")


class UsageSummary(BaseModel):
    day_key: date
    resets_at: datetime
    utc_offset_minutes: int
    agents: list[AgentUsageView]


def _event_text(event: dict[str, Any]) -> str:
    name, used, limit = event["name"], int(event["used"]), int(event["daily_call_limit"])
    zone = budget_rules.format_offset(budget_rules.normalize_offset(event.get("utc_offset_minutes")))
    if event["kind"] == "warn":
        return f"Budget Guard: {name} has used {used} of its {limit} daily tool calls (80%)."
    text = (
        f"Budget Guard: {name} reached its daily limit of {limit} tool calls and is now refused "
        f"until the next day begins ({zone})."
    )
    if event.get("budget_action") == "freeze":
        text += " It has also been frozen; unfreeze it from the dashboard when ready."
    return text


async def _handle_event(supabase: Any, telegram: TelegramClient | None, event: dict[str, Any]) -> None:
    """Alerts the organization once and carries out the optional auto-freeze. Never raises."""
    try:
        org_id = UUID(str(event["organization_id"]))
        agent_id = UUID(str(event["agent_id"]))
        frozen = False
        if event["kind"] == "limit" and event.get("budget_action") == "freeze":
            system = OperatorContext(user_id=budget_rules.SYSTEM_ACTOR_ID, organization_id=org_id, role=Role.SECURITY_OPERATOR)
            try:
                await service.freeze(supabase, system, agent_id, FREEZE_REASON, utcnow())
                await supabase.rpc(
                    "mark_budget_frozen", {"p_agent": str(agent_id), "p_day": str(event["day_key"])}
                ).execute()
                frozen = True
            except HTTPException as exc:
                logger.warning("Budget auto-freeze refused for agent %s: %s", agent_id, exc.status_code)
        get_metrics().increment_counter(
            "redhand_budget_events_total", labels={"kind": str(event["kind"]), "frozen": str(frozen).lower()}
        )
        await notify_organization(supabase, telegram, org_id, _event_text(event))
    except Exception as exc:  # noqa: BLE001  one bad event must not lose the others or fail the report
        logger.error("Budget event handling failed: %s", type(exc).__name__)


@router.post(
    "/internal/v1/usage",
    response_model=UsageReportResponse,
    dependencies=[Depends(require_internal_service)],
    include_in_schema=False,
)
async def report_usage(report: UsageReport, supabase: SupabaseDep, telegram: OptionalClientDep) -> UsageReportResponse:
    items = [{"agent_id": str(i.agent_id), "day_key": i.day_key.isoformat(), "calls": i.calls} for i in report.items]
    try:
        response = await supabase.rpc("record_usage", {"p_instance": report.instance_id, "p_items": items}).execute()
    except Exception as exc:  # noqa: BLE001
        logger.error("Usage report failed: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Usage could not be recorded.") from None
    data = response.data
    for event in list(data.get("events") or []):
        await _handle_event(supabase, telegram, event)
    return UsageReportResponse(accepted=int(data["accepted"]), rejected=int(data["rejected"]))


@router.put("/v1/passports/{agent_id}/budget", response_model=AgentBudgetResponse)
async def set_agent_budget(
    agent_id: UUID, payload: BudgetUpdateRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> AgentBudgetResponse:
    passport, changed = await service.set_agent_budget(
        supabase, operator, agent_id, payload.daily_call_limit, payload.action, payload.reason, payload.confirm, utcnow()
    )
    return AgentBudgetResponse(passport=passport, changed=changed)


@router.get("/v1/usage", response_model=UsageSummary)
async def get_usage(operator: ViewerDep, supabase: SupabaseDep) -> UsageSummary:
    now = utcnow()
    offset = await service.get_org_utc_offset(supabase, operator.organization_id)
    day = budget_rules.local_day(now, offset)
    calls = await service.get_org_usage(supabase, operator.organization_id, day)
    rows = [PassportView.from_row(r, now) for r in await service.list_passport_rows(supabase, operator)]
    agents = [
        AgentUsageView(
            agent_id=p.id, name=p.name, calls=calls.get(p.id, 0), daily_call_limit=p.daily_call_limit,
            budget_action=p.budget_action,
            percent=None if p.daily_call_limit is None else min(999, calls.get(p.id, 0) * 100 // p.daily_call_limit),
        )
        for p in rows
        if p.status != "revoked"
    ]
    return UsageSummary(day_key=day, resets_at=budget_rules.next_reset_utc(now, offset), utc_offset_minutes=offset, agents=agents)
