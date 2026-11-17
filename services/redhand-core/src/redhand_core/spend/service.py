"""
Model spend (Phase 4.5 B4a, ADR 0023): reads the roll-up of what each agent's SDK reported, estimates cost with prices.py, keeps the optional
per-agent dollar limit, and raises one alert per agent per day when the estimate reaches it.

Detective only. The numbers are SELF-REPORTED (an organization's SDK key can name any of its agents), so they are labelled as estimates
everywhere and are never used to refuse a call. No prompt, completion or thought text is read: only counts and model names from the roll-up.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.passports import budget as budget_rules
from redhand_core.passports import service as passport_service
from redhand_core.passports.service import StateConflictError, _conflict, _require_confirmation, _rpc, retry_once_on_conflict
from redhand_core.services.metrics import get_metrics
from redhand_core.spend.models import (
    AgentSpendDetailResponse,
    AgentSpendView,
    DaySpendView,
    GatewayModelSpend,
    MeasuredSpendView,
    ModelUsageBatch,
    ModelUsageBatchResponse,
    ModelUseView,
    SpendTodayResponse,
)
from redhand_core.spend.prices import (
    PRICES,
    PRICES_AS_OF_TEXT,
    Estimate,
    Usage,
    estimate,
    format_dollars,
    price_for,
)
from redhand_core.telegram.bot import notify_organization
from redhand_core.telegram.client import TelegramClient

logger = logging.getLogger("redhand.core.spend")

BASIS = (
    "Estimated from the token counts each agent's own SDK reported, at the provider's public prices on the date shown. "
    "Not measured by RedHand and not an invoice."
)
DETAIL_DAYS = 7
CHECK_TIMEOUT_SECONDS = 5.0
# Checks running at once in this process. Above it a new one is skipped and counted (the next report that carries usage checks again): a
# flood of ingest batches must not pile up reads behind the database. A plain counter, not a semaphore, which binds to one event loop.
MAX_CHECKS_IN_FLIGHT = 8
_in_flight = 0


# --- reading ------------------------------------------------------------------------------------------------------------------------

async def read_usage(supabase: Any, organization_id: UUID, agent_id: UUID | None, since: date, until: date) -> list[dict[str, Any]]:
    """Roll-up rows for the days since..until. A read that fails is an error, never an empty list: no spend must not look like zero spend."""
    try:
        res = await supabase.rpc(
            "agent_model_usage",
            {"p_org": str(organization_id), "p_agent": str(agent_id) if agent_id else None, "p_since": since.isoformat(), "p_until": until.isoformat()},
        ).execute()
    except Exception as exc:  # noqa: BLE001  any failure, whatever the driver raised, must be shown as "could not be read"
        logger.error("Spend could not be read: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Spend could not be read. Try again shortly.") from None
    return list(res.data or [])


async def read_measured(supabase: Any, organization_id: UUID, agent_id: UUID | None, since: date, until: date) -> list[dict[str, Any]] | None:
    """Rows the model proxy measured. None means "could not be read" (shown as such, with the reported figures intact), never an empty list standing in for zero."""
    try:
        res = await supabase.rpc(
            "agent_model_measured_usage",
            {"p_org": str(organization_id), "p_agent": str(agent_id) if agent_id else None, "p_since": since.isoformat(), "p_until": until.isoformat()},
        ).execute()
    except Exception as exc:  # noqa: BLE001  any failure, whatever the driver raised, must be shown as "could not be read"
        logger.error("Measured spend could not be read: %s", type(exc).__name__)
        return None
    return list(res.data or [])


async def record_measured(supabase: Any, batch: ModelUsageBatch) -> ModelUsageBatchResponse:
    """Hands the gateway's batch to the database function. The tenant is decided there from each agent's own row; a failure is a plain 503 (the gateway retries the same batch id)."""
    rows = [
        {"agent_id": str(i.agent_id), "provider": i.provider, "model": i.model, "calls": i.calls, "input_tokens": i.input_tokens, "output_tokens": i.output_tokens,
         "calls_without_usage": i.calls_without_usage, "occurred_at": i.occurred_at.isoformat()}
        for i in batch.items
    ]
    try:
        res = await supabase.rpc("record_model_usage", {"p_batch": str(batch.batch_id), "p_rows": rows}).execute()
    except Exception as exc:  # noqa: BLE001
        logger.error("Measured usage could not be recorded: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Usage could not be recorded.") from None
    data = res.data
    return ModelUsageBatchResponse(accepted=int(data["accepted"]), rejected=int(data["rejected"]), duplicate=bool(data["duplicate"]))


MODEL_SERVER_NAME = "model"  # the server name the model proxy uses for its passport lookup (agentwall/src/gateway/model_proxy.py)


async def model_spend_context(supabase: Any, organization_id: UUID, agent_id: UUID, raw_limit: Any, day: date) -> Any:
    """The model proxy's view of the agent's daily dollar limit (B5c), or None when there is no limit (nothing to check, nothing looked up).

    Fails closed: a stored limit that is not a plain integer of at least 1 reads as limit 0 (the proxy refuses everything), and a measured-usage read that fails raises 503 (the proxy
    cannot decide, so it denies). Only MEASURED usage counts, priced at the public table; tokens of a model with no known price make the spend unknown, never zero."""
    if raw_limit is None:
        return None
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) and raw_limit >= 1 else 0
    rows = await read_measured(supabase, organization_id, agent_id, day, day)
    if rows is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Measured spend lookup failed.")
    est = estimate(_usage(rows))
    return GatewayModelSpend(
        limit_micro_usd=limit, measured_micro_usd=est.micro_usd, spend_known=est.unpriced_tokens == 0,
        priced_models=sorted(p.model for p in PRICES if p.provider == "anthropic"),
    )


def _measured_view(rows: list[dict[str, Any]]) -> MeasuredSpendView | None:
    if not rows:
        return None
    est = estimate(_usage(rows))
    models = sorted((_model_view(r) for r in rows), key=lambda m: (-(m.estimated_micro_usd or 0), -m.prompt_tokens, m.provider, m.model))
    return MeasuredSpendView(
        calls=est.calls, calls_without_usage=sum(int(r.get("calls_without_usage") or 0) for r in rows),
        prompt_tokens=sum(int(r["prompt_tokens"]) for r in rows), completion_tokens=sum(int(r["completion_tokens"]) for r in rows),
        estimated_micro_usd=est.micro_usd, estimated_text=format_dollars(est.micro_usd), lower_bound=est.lower_bound,
        unpriced_tokens=est.unpriced_tokens, unpriced_models=list(est.unpriced_models), models=models,
    )


def _usage(rows: Iterable[Mapping[str, Any]]) -> list[Usage]:
    return [Usage(str(r["provider"]), str(r["model"]), int(r["calls"]), int(r["prompt_tokens"]), int(r["completion_tokens"])) for r in rows]


def _model_view(row: Mapping[str, Any]) -> ModelUseView:
    usage = Usage(str(row["provider"]), str(row["model"]), int(row["calls"]), int(row["prompt_tokens"]), int(row["completion_tokens"]))
    priced = price_for(usage.provider, usage.model)
    est = estimate([usage]) if priced is not None else None
    return ModelUseView(
        provider=usage.provider, model=usage.model, calls=usage.calls, prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens, price_known=priced is not None,
        estimated_micro_usd=est.micro_usd if est else None, estimated_text=format_dollars(est.micro_usd) if est else None,
        lower_bound=bool(priced and priced.lower_bound),
    )


def _agent_view(agent: Mapping[str, Any], rows: list[dict[str, Any]], measured_rows: list[dict[str, Any]] | None = None, measured_unavailable: bool = False) -> AgentSpendView:
    est = estimate(_usage(rows))
    limit = agent.get("spend_limit_micro_usd")
    limit = limit if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 1 else None
    models = sorted((_model_view(r) for r in rows), key=lambda m: (-(m.estimated_micro_usd or 0), -m.prompt_tokens, m.provider, m.model))
    return AgentSpendView(
        agent_id=UUID(str(agent["id"])), name=str(agent["name"]), status=str(agent["status"]), usage_reported=bool(rows),
        calls=est.calls, prompt_tokens=sum(int(r["prompt_tokens"]) for r in rows), completion_tokens=sum(int(r["completion_tokens"]) for r in rows),
        estimated_micro_usd=est.micro_usd, estimated_text=format_dollars(est.micro_usd), lower_bound=est.lower_bound,
        unpriced_tokens=est.unpriced_tokens, unpriced_models=list(est.unpriced_models),
        spend_limit_micro_usd=limit, spend_limit_text=format_dollars(limit) if limit else None,
        percent_of_limit=None if limit is None else min(999, est.micro_usd * 100 // limit), models=models,
        measured=_measured_view(measured_rows or []), measured_unavailable=measured_unavailable,
    )


async def list_today(supabase: Any, operator: OperatorContext, now: datetime) -> SpendTodayResponse:
    offset = await passport_service.get_org_utc_offset(supabase, operator.organization_id)
    day = budget_rules.local_day(now, offset)
    agents = [a for a in await passport_service.list_passport_rows(supabase, operator) if a.get("status") != "revoked"]
    by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in await read_usage(supabase, operator.organization_id, None, day, day):
        by_agent[str(row["agent_id"])].append(row)
    measured = await read_measured(supabase, operator.organization_id, None, day, day)
    measured_by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in measured or []:
        measured_by_agent[str(row["agent_id"])].append(row)
    return SpendTodayResponse(
        day=day, resets_at=budget_rules.next_reset_utc(now, offset), utc_offset_minutes=offset, prices_as_of=PRICES_AS_OF_TEXT, basis=BASIS,
        agents=[_agent_view(a, by_agent.get(str(a["id"]), []), measured_by_agent.get(str(a["id"]), []), measured is None) for a in agents],
    )


async def agent_detail(supabase: Any, operator: OperatorContext, agent_id: UUID, now: datetime) -> AgentSpendDetailResponse:
    agent = await passport_service.get_passport_row(supabase, operator, agent_id)
    offset = await passport_service.get_org_utc_offset(supabase, operator.organization_id)
    today = budget_rules.local_day(now, offset)
    rows = await read_usage(supabase, operator.organization_id, agent_id, today - timedelta(days=DETAIL_DAYS - 1), today)
    by_day: dict[date, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_day[date.fromisoformat(str(row["day"]))].append(row)
    days: list[DaySpendView] = []
    for offset_days in range(DETAIL_DAYS - 1, -1, -1):
        day = today - timedelta(days=offset_days)
        day_rows = by_day.get(day, [])
        est = estimate(_usage(day_rows))
        days.append(DaySpendView(
            day=day, usage_reported=bool(day_rows), calls=est.calls, estimated_micro_usd=est.micro_usd, estimated_text=format_dollars(est.micro_usd),
            lower_bound=est.lower_bound, unpriced_tokens=est.unpriced_tokens, models=[_model_view(r) for r in day_rows],
        ))
    measured = await read_measured(supabase, operator.organization_id, agent_id, today, today)
    return AgentSpendDetailResponse(
        prices_as_of=PRICES_AS_OF_TEXT, basis=BASIS, agent=_agent_view(agent, by_day.get(today, []), measured or [], measured is None), days=days,
    )


# --- the limit ----------------------------------------------------------------------------------------------------------------------

@retry_once_on_conflict
async def set_limit(
    supabase: Any, operator: OperatorContext, agent_id: UUID, limit: int | None, reason: str | None, confirm: bool
) -> tuple[int | None, bool]:
    """Sets an agent's daily estimated-spend limit (the caller is already an admin). Raising or removing it silences an alert, so it needs
    explicit confirmation; setting a first limit or lowering one only adds alerts."""
    row = await passport_service.get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot be changed.")
    current = row.get("spend_limit_micro_usd")
    current = current if isinstance(current, int) and not isinstance(current, bool) else None
    if current is not None and (limit is None or limit > current):
        _require_confirmation(confirm, "Raising or removing a spend limit")
    data = await _rpc(
        supabase,
        "control_agent_spend_limit",
        {
            "p_org": str(operator.organization_id), "p_agent": str(agent_id), "p_actor": str(operator.user_id), "p_limit": limit,
            "p_reason": reason,
            # Compare-and-set: the confirmation decision above was made against this value.
            "p_expected_limit": current,
        },
        not_found_detail="Agent passport not found.",
        conflict_detail="The spend limit conflicted with another change; try again.",
    )
    if isinstance(data, dict) and data.get("conflict"):
        raise StateConflictError
    return limit, bool(data["changed"])


# --- the alert ----------------------------------------------------------------------------------------------------------------------

def alert_text(name: str, est: Estimate, limit_micro_usd: int) -> str:
    text = (
        f"Spend alert: {name} has an estimated {format_dollars(est.micro_usd)}{' or more' if est.lower_bound else ''} of model use today, "
        f"at or over its {format_dollars(limit_micro_usd)} daily limit. Estimated from what its SDK reported, at provider prices "
        f"as of {PRICES_AS_OF_TEXT}; it is not an invoice. Nothing was refused: RedHand does not stop model calls."
    )
    if est.unpriced_tokens:
        text += f" Models with no known price ({est.unpriced_tokens} tokens) are not included."
    return text


def summarize_batch(trace_rows: Iterable[Mapping[str, Any]]) -> tuple[bool, int]:
    """(did the batch report any model use, how many distinct models in it have no known price). Pure; names are never kept."""
    reported = False
    unpriced: set[tuple[str, str]] = set()
    for row in trace_rows:
        model = row.get("model_name")
        prompt, completion = row.get("prompt_tokens") or 0, row.get("completion_tokens") or 0
        if not isinstance(model, str) or not model.strip() or not (prompt > 0 or completion > 0):
            continue
        reported = True
        provider = str(row.get("model_provider") or "")
        if price_for(provider, model) is None:
            unpriced.add((provider.strip().lower(), model.strip().lower()))
    return reported, len(unpriced)


def note_unpriced_models(count: int) -> None:
    if count:
        get_metrics().increment_counter("spend_unpriced_models_total", value=float(count))


async def check_spend(supabase: Any, telegram: TelegramClient | None, organization_id: UUID, agent_id: UUID, now: datetime) -> None:
    """After an ingest batch that reported model use: alerts (once per agent per day) when the agent's estimated spend today has reached its
    limit. Runs after the SDK has its reply, never raises, is bounded in time, and never refuses anything."""
    global _in_flight
    metrics = get_metrics()
    if _in_flight >= MAX_CHECKS_IN_FLIGHT:
        logger.warning("Spend check skipped: %d already running", _in_flight)
        metrics.increment_counter("spend_checks_total", labels={"outcome": "skipped"})
        return
    _in_flight += 1
    try:
        await asyncio.wait_for(_check(supabase, telegram, organization_id, agent_id, now), CHECK_TIMEOUT_SECONDS)
        metrics.increment_counter("spend_checks_total", labels={"outcome": "ok"})
    except asyncio.TimeoutError:
        logger.error("Spend check timed out")
        metrics.increment_counter("spend_checks_total", labels={"outcome": "timeout"})
    except Exception as exc:  # noqa: BLE001  the batch is already stored; nothing here may turn it into an error (logged by type, counted)
        logger.error("Spend check failed: %s", type(exc).__name__)
        metrics.increment_counter("spend_checks_total", labels={"outcome": "error"})
    finally:
        _in_flight -= 1


async def _check(supabase: Any, telegram: TelegramClient | None, organization_id: UUID, agent_id: UUID, now: datetime) -> None:
    res = await (
        supabase.table("agents").select("id,name,spend_limit_micro_usd").eq("organization_id", str(organization_id)).eq("id", str(agent_id)).execute()
    )
    rows = list(res.data or [])
    limit = rows[0].get("spend_limit_micro_usd") if len(rows) == 1 else None
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return
    offset = await passport_service.get_org_utc_offset(supabase, organization_id)
    day = budget_rules.local_day(now, offset)
    est = estimate(_usage(await read_usage(supabase, organization_id, agent_id, day, day)))
    if est.micro_usd < limit:
        return
    marked = await supabase.rpc("spend_mark_alerted", {"p_org": str(organization_id), "p_agent": str(agent_id), "p_day": day.isoformat()}).execute()
    if marked.data is not True:
        return  # another report (or core instance) already alerted today
    get_metrics().increment_counter("spend_alerts_total")
    logger.info("Spend limit reached: agent=%s day=%s", agent_id, day.isoformat())
    await notify_organization(supabase, telegram, organization_id, alert_text(str(rows[0]["name"]), est, limit))
