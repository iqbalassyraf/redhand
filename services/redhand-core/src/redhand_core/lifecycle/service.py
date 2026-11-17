"""
Export and deletion of an organization's data. The rules (owner only, audit in the same transaction, one export per hour, slug typed back, grace period, freezing agents)
live in the database functions; this module calls them and turns refusals into plain answers. The export is built and returned by the database function from the
tenant data manifest, so the secret columns are left out where the data is read, not by a filter after the fact.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.lifecycle.models import DeletionRequested, DeletionStatus
from redhand_core.passports.service import _conflict, _rpc
from redhand_core.services.metrics import get_metrics

logger = logging.getLogger("redhand.core.lifecycle")


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = (
        value
        if isinstance(value, datetime)
        else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    )
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


async def export_organization(supabase: Any, operator: OperatorContext) -> bytes:
    """The whole export as UTF-8 JSON. Raises 429 with Retry-After when this organization exported in the last hour."""
    data = await _rpc(
        supabase,
        "control_org_export",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id)},
        not_found_detail="Organization not found.",
        conflict_detail="The export could not be created. Try again.",
    )
    if not isinstance(data, dict) or not data.get("exported"):
        retry = int(data.get("retry_after_seconds", 3600)) if isinstance(data, dict) else 3600
        get_metrics().increment_counter(
            "tenant_lifecycle_total", labels={"event": "export_throttled"}
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "This organization already exported its data in the last hour. Try again later.",
            headers={"Retry-After": str(retry)},
        )
    get_metrics().increment_counter("tenant_lifecycle_total", labels={"event": "export"})
    logger.info("organization export produced organization=%s", operator.organization_id)
    return json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")


async def deletion_status(supabase: Any, operator: OperatorContext) -> DeletionStatus:
    res = (
        await supabase.table("organizations")
        .select("deletion_requested_at,deletion_purge_after")
        .eq("id", str(operator.organization_id))
        .execute()
    )
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found.")
    requested = _parse(rows[0].get("deletion_requested_at"))
    return DeletionStatus(
        requested=requested is not None,
        requested_at=requested,
        purge_after=_parse(rows[0].get("deletion_purge_after")),
    )


async def request_deletion(
    supabase: Any, operator: OperatorContext, confirm_slug: str
) -> DeletionRequested:
    data = await _rpc(
        supabase,
        "control_org_request_deletion",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_confirm_slug": confirm_slug,
        },
        not_found_detail="Organization not found.",
        conflict_detail="The request could not be recorded. Try again.",
    )
    if not isinstance(data, dict) or not data.get("requested"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "The address name you typed does not match this organization.",
        )
    get_metrics().increment_counter(
        "tenant_lifecycle_total", labels={"event": "deletion_requested"}
    )
    return DeletionRequested(
        requested=True,
        already=bool(data.get("already")),
        requested_at=_parse(data.get("requested_at")),
        purge_after=_parse(data.get("purge_after")),
    )


async def cancel_deletion(supabase: Any, operator: OperatorContext) -> DeletionStatus:
    data = await _rpc(
        supabase,
        "control_org_cancel_deletion",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id)},
        not_found_detail="Organization not found.",
        conflict_detail="The request could not be cancelled. Try again.",
    )
    if not isinstance(data, dict) or not data.get("cancelled"):
        raise _conflict("No deletion is pending for this organization.")
    get_metrics().increment_counter(
        "tenant_lifecycle_total", labels={"event": "deletion_cancelled"}
    )
    return DeletionStatus(requested=False)
