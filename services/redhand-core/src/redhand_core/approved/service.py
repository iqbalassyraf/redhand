"""
Approved models (Phase 4.5 B4b, ADR 0023): the organization's list, and the check that turns a model outside a non-empty list into one RAD-MDL-001
finding and one alert. Detective only: it never refuses a call, an empty list means no check, and the finding adds nothing to the Risk score.

The check runs after the SDK has its reply, is bounded in time and in concurrency, and never raises. The model names it reports come from an agent, so
the database reduces them to plain characters before they are stored or sent to a chat.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.passports.service import _conflict, _require_confirmation, _rpc
from redhand_core.approved.models import MAX_APPROVED_MODELS, ApprovedModel, ApprovedModelsRequest, ApprovedModelsResponse
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.bot import notify_organization
from redhand_core.telegram.client import TelegramClient

logger = logging.getLogger("redhand.core.approved")

MAX_MODELS_PER_REPORT = 20  # the database refuses more
CHECK_TIMEOUT_SECONDS = 5.0
# Checks running at once in this process. Above it a new one is skipped and counted (the next batch that names the model checks again). A plain
# counter, not a semaphore, which binds to one event loop.
MAX_CHECKS_IN_FLIGHT = 8
_in_flight = 0


# --- the list -----------------------------------------------------------------------------------------------------------------------

async def read_list(supabase: Any, organization_id: UUID) -> tuple[list[ApprovedModel], int]:
    """The list and its version. A read that fails is an error: an unreadable list must not look like "no list, nothing flagged"."""
    try:
        listing = await supabase.rpc("approved_models_list", {"p_org": str(organization_id)}).execute()
        org = await supabase.table("organizations").select("approved_models_version").eq("id", str(organization_id)).execute()
    except Exception as exc:  # noqa: BLE001  any failure must read as "could not be read"
        logger.error("Approved models could not be read: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The approved models could not be read. Try again shortly.") from None
    rows = list(org.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found.")
    version = rows[0].get("approved_models_version")
    items = [ApprovedModel(provider=str(r["provider"]), model=str(r["model"])) for r in listing.data or []]
    return items, version if isinstance(version, int) and not isinstance(version, bool) else 0


async def get_list(supabase: Any, organization_id: UUID) -> ApprovedModelsResponse:
    items, version = await read_list(supabase, organization_id)
    return ApprovedModelsResponse(items=items, version=version, check_active=bool(items))


async def set_list(supabase: Any, operator: OperatorContext, payload: ApprovedModelsRequest) -> ApprovedModelsResponse:
    """Replaces the list (the caller is already an admin). Clearing a non-empty list turns the check off, so it needs explicit confirmation. The
    version the caller read must still be the current one, and the database checks it again when it applies the change."""
    current, version = await read_list(supabase, operator.organization_id)
    if payload.version != version:
        raise _conflict("The list was changed by someone else. Reload and try again.")
    if current and not payload.items:
        _require_confirmation(payload.confirm, "Clearing the approved models (this turns the check off)")
    data = await _rpc(
        supabase,
        "control_approved_models",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id),
            "p_items": [{"provider": i.provider, "model": i.model} for i in payload.items], "p_reason": payload.reason,
            "p_expected_version": version,
        },
        not_found_detail="Organization not found.",
        conflict_detail="The list could not be saved. Reload and try again.",
    )
    if isinstance(data, dict) and data.get("conflict"):
        raise _conflict("The list was changed by someone else. Reload and try again.")
    items, new_version = await read_list(supabase, operator.organization_id)
    return ApprovedModelsResponse(items=items, version=new_version, check_active=bool(items), changed=bool(data["changed"]))


# --- the check ----------------------------------------------------------------------------------------------------------------------

def models_in_batch(trace_rows: Iterable[Mapping[str, Any]]) -> list[tuple[str, str]]:
    """The distinct (provider, model) pairs an ingest batch named, lower-cased, at most MAX_MODELS_PER_REPORT. Pure; spans with no model are ignored."""
    seen: dict[tuple[str, str], None] = {}
    for row in trace_rows:
        model = row.get("model_name")
        if not isinstance(model, str) or not model.strip():
            continue
        provider = row.get("model_provider")
        seen.setdefault((provider.strip().lower() if isinstance(provider, str) else "", model.strip().lower()), None)
        if len(seen) >= MAX_MODELS_PER_REPORT:
            break
    return list(seen)


def alert_text(agent_name: str, model: str) -> str:
    return (
        f"Model alert: {agent_name} used a model that is not on the approved list: {model}. Recorded only: nothing was refused. "
        "Open the dashboard, Radar, findings filter: Model not on the approved list."
    )


async def check_models(
    supabase: Any, telegram: TelegramClient | None, organization_id: UUID, agent_id: UUID, pairs: list[tuple[str, str]], now: datetime
) -> None:
    """After an ingest batch that named models: records a finding for each one outside a non-empty approved list, and alerts (once per agent per
    10 minutes). Runs after the SDK has its reply, never raises, is bounded in time, and never refuses anything."""
    global _in_flight
    metrics = get_metrics()
    if _in_flight >= MAX_CHECKS_IN_FLIGHT:
        logger.warning("Approved-model check skipped: %d already running", _in_flight)
        metrics.increment_counter("model_checks_total", labels={"outcome": "skipped"})
        return
    _in_flight += 1
    try:
        await asyncio.wait_for(_check(supabase, telegram, organization_id, agent_id, pairs), CHECK_TIMEOUT_SECONDS)
        metrics.increment_counter("model_checks_total", labels={"outcome": "ok"})
    except asyncio.TimeoutError:
        logger.error("Approved-model check timed out")
        metrics.increment_counter("model_checks_total", labels={"outcome": "timeout"})
    except Exception as exc:  # noqa: BLE001  the batch is already stored; nothing here may turn it into an error (logged by type, counted)
        logger.error("Approved-model check failed: %s", type(exc).__name__)
        metrics.increment_counter("model_checks_total", labels={"outcome": "error"})
    finally:
        _in_flight -= 1


async def _check(supabase: Any, telegram: TelegramClient | None, organization_id: UUID, agent_id: UUID, pairs: list[tuple[str, str]]) -> None:
    items = [{"provider": provider, "model": model} for provider, model in pairs[:MAX_MODELS_PER_REPORT]]
    res = await supabase.rpc("record_model_findings", {"p_org": str(organization_id), "p_agent": str(agent_id), "p_items": items}).execute()
    data = res.data
    if not isinstance(data, dict) or not int(data.get("new") or 0):
        return
    get_metrics().increment_counter("model_findings_total", float(int(data["new"])))
    if data.get("alert"):
        get_metrics().increment_counter("model_alerts_total")
        await notify_organization(supabase, telegram, organization_id, alert_text(str(data.get("agent") or "an agent"), str(data.get("model") or "a model")))


__all__ = ["MAX_APPROVED_MODELS", "check_models", "get_list", "models_in_batch", "read_list", "set_list"]
