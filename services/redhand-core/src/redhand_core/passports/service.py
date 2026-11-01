"""
Passport control logic: registration, freeze / unfreeze / revoke / freeze-all, scope
changes, renewal, key rotation, and the control audit trail.

Every query is filtered by the operator's organization. A passport in another tenant
is indistinguishable from one that does not exist (404).

Known limitation (tracked in docs/plans/phase1-plan.md follow-ups): the state change
and its audit row are two statements, not one transaction. The state change is applied
first because stopping an agent matters more than recording it; if the audit insert then
fails we return 500 and log at error level so the gap is visible. Moving each action
into a single SQL function removes this window.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.passports.credentials import NewAgentKey, generate_agent_key
from redhand_core.passports.models import (
    ControlAuditEntry,
    PassportCreateRequest,
    PassportView,
    Scope,
    is_scope_expansion,
    parse_scopes,
)

logger = logging.getLogger("redhand.core.passports")


class AuditWriteError(Exception):
    """The control action was applied but its audit record could not be written."""


def _not_found(agent_id: UUID) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Passport '{agent_id}' not found.")


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _require_confirmation(confirm: bool, action: str) -> None:
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{action} requires explicit confirmation: send \"confirm\": true.",
        )


async def write_audit(
    supabase: Any,
    *,
    operator: OperatorContext,
    action: str,
    target_type: str,
    target_id: UUID,
    reason: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    row = {
        "id": str(uuid4()),
        "organization_id": str(operator.organization_id),
        "actor_user_id": str(operator.user_id),
        "action": action,
        "target_type": target_type,
        "target_id": str(target_id),
        "reason": reason,
        "details": details or {},
    }
    try:
        await supabase.table("control_audit_log").insert(row).execute()
    except Exception as exc:  # noqa: BLE001 - any storage failure must surface as AuditWriteError
        logger.error(
            "Control action applied but audit write failed: action=%s target=%s org=%s error=%s",
            action,
            target_id,
            operator.organization_id,
            type(exc).__name__,
        )
        raise AuditWriteError(action) from exc


async def get_passport_row(supabase: Any, operator: OperatorContext, agent_id: UUID) -> dict[str, Any]:
    res = await (
        supabase.table("agents")
        .select("*")
        .eq("id", str(agent_id))
        .eq("organization_id", str(operator.organization_id))
        .maybe_single()
        .execute()
    )
    row = res.data if res else None
    if not row:
        raise _not_found(agent_id)
    return dict(row)


async def list_passport_rows(supabase: Any, operator: OperatorContext) -> list[dict[str, Any]]:
    res = await (
        supabase.table("agents")
        .select("*")
        .eq("organization_id", str(operator.organization_id))
        .order("created_at", desc=True)
        .execute()
    )
    return list(res.data or [])


async def _update_passport(
    supabase: Any, operator: OperatorContext, agent_id: UUID, changes: dict[str, Any]
) -> dict[str, Any]:
    res = await (
        supabase.table("agents")
        .update(changes)
        .eq("id", str(agent_id))
        .eq("organization_id", str(operator.organization_id))
        .execute()
    )
    if not res.data:
        raise _not_found(agent_id)
    return dict(res.data[0])


async def _assert_members(supabase: Any, operator: OperatorContext, user_ids: list[UUID]) -> None:
    for uid in user_ids:
        res = await (
            supabase.table("organization_members")
            .select("user_id")
            .eq("organization_id", str(operator.organization_id))
            .eq("user_id", str(uid))
            .execute()
        )
        if not res.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User '{uid}' is not a member of this organization.",
            )


async def _insert_agent_key(
    supabase: Any, operator: OperatorContext, agent_id: UUID, key: NewAgentKey
) -> None:
    await supabase.table("agent_keys").insert(
        {
            "id": str(uuid4()),
            "organization_id": str(operator.organization_id),
            "agent_id": str(agent_id),
            "key_prefix": key.display_prefix,
            "key_hash": key.key_hash,
            "is_active": True,
            "created_by": str(operator.user_id),
        }
    ).execute()


async def _deactivate_agent_keys(
    supabase: Any, operator: OperatorContext, agent_id: UUID, now: datetime
) -> None:
    await (
        supabase.table("agent_keys")
        .update({"is_active": False, "deactivated_at": now.isoformat()})
        .eq("agent_id", str(agent_id))
        .eq("organization_id", str(operator.organization_id))
        .eq("is_active", True)
        .execute()
    )


# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------


async def create_passport(
    supabase: Any, operator: OperatorContext, req: PassportCreateRequest, now: datetime
) -> tuple[PassportView, str]:
    owner_id = req.owner_id or operator.user_id
    members = [owner_id] + ([req.backup_owner_id] if req.backup_owner_id else [])
    await _assert_members(supabase, operator, members)

    agent_id = uuid4()
    external_id = req.external_agent_id or f"agent-{agent_id.hex[:12]}"
    existing = await (
        supabase.table("agents")
        .select("id")
        .eq("organization_id", str(operator.organization_id))
        .eq("external_agent_id", external_id)
        .eq("environment", req.environment)
        .execute()
    )
    if existing.data:
        raise _conflict(f"An agent with external ID '{external_id}' already exists in {req.environment}.")

    row = {
        "id": str(agent_id),
        "organization_id": str(operator.organization_id),
        "external_agent_id": external_id,
        "name": req.name,
        "framework": req.framework,
        "environment": req.environment,
        "status": "active",
        "owner_id": str(owner_id),
        "backup_owner_id": str(req.backup_owner_id) if req.backup_owner_id else None,
        "scopes": [s.model_dump() for s in req.scopes],
        "expires_at": (now + timedelta(days=req.expires_in_days)).isoformat(),
        "version": 1,
        "created_at": now.isoformat(),
    }
    res = await supabase.table("agents").insert(row).execute()
    created = dict(res.data[0])

    key = generate_agent_key()
    await _insert_agent_key(supabase, operator, agent_id, key)
    await write_audit(
        supabase,
        operator=operator,
        action="passport.created",
        target_type="agent",
        target_id=agent_id,
        reason=None,
        details={
            "name": req.name,
            "scopes": row["scopes"],
            "expires_at": row["expires_at"],
            "key_prefix": key.display_prefix,
        },
    )
    return PassportView.from_row(created, now), key.plaintext


async def freeze(
    supabase: Any, operator: OperatorContext, agent_id: UUID, reason: str | None, now: datetime
) -> tuple[PassportView, bool]:
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot be frozen; it is already permanently disabled.")
    if row["status"] == "frozen":
        return PassportView.from_row(row, now), False
    updated = await _update_passport(
        supabase, operator, agent_id, {"status": "frozen", "status_reason": reason}
    )
    await write_audit(
        supabase, operator=operator, action="passport.frozen", target_type="agent",
        target_id=agent_id, reason=reason,
    )
    return PassportView.from_row(updated, now), True


async def unfreeze(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    reason: str | None,
    confirm: bool,
    now: datetime,
) -> tuple[PassportView, bool]:
    _require_confirmation(confirm, "Unfreeze")
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot be reactivated. Register a new agent instead.")
    if row["status"] == "active":
        return PassportView.from_row(row, now), False
    view = PassportView.from_row({**row, "status": "active"}, now)
    if view.status == "expired":
        raise _conflict("The passport has expired. Renew it before unfreezing.")
    updated = await _update_passport(
        supabase, operator, agent_id, {"status": "active", "status_reason": reason}
    )
    await write_audit(
        supabase, operator=operator, action="passport.unfrozen", target_type="agent",
        target_id=agent_id, reason=reason,
    )
    return PassportView.from_row(updated, now), True


async def revoke(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    reason: str | None,
    confirm: bool,
    now: datetime,
) -> tuple[PassportView, bool]:
    _require_confirmation(confirm, "Revoke")
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        return PassportView.from_row(row, now), False
    updated = await _update_passport(
        supabase, operator, agent_id, {"status": "revoked", "status_reason": reason}
    )
    await _deactivate_agent_keys(supabase, operator, agent_id, now)
    await write_audit(
        supabase, operator=operator, action="passport.revoked", target_type="agent",
        target_id=agent_id, reason=reason,
    )
    return PassportView.from_row(updated, now), True


async def freeze_all(
    supabase: Any, operator: OperatorContext, reason: str | None, now: datetime
) -> list[UUID]:
    """Freezes every active passport in the tenant with one UPDATE statement."""
    res = await (
        supabase.table("agents")
        .update({"status": "frozen", "status_reason": reason})
        .eq("organization_id", str(operator.organization_id))
        .eq("status", "active")
        .execute()
    )
    frozen_ids = [UUID(str(r["id"])) for r in (res.data or [])]
    await write_audit(
        supabase,
        operator=operator,
        action="organization.frozen_all",
        target_type="organization",
        target_id=operator.organization_id,
        reason=reason,
        details={"frozen_count": len(frozen_ids), "frozen_agent_ids": [str(i) for i in frozen_ids]},
    )
    return frozen_ids


async def update_scopes(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    scopes: list[Scope],
    reason: str | None,
    confirm: bool,
    now: datetime,
) -> tuple[PassportView, bool]:
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("Scopes of a revoked passport cannot be changed.")
    old = parse_scopes(row.get("scopes", []))
    if set(old) == set(scopes):
        return PassportView.from_row(row, now), False
    expansion = is_scope_expansion(old, scopes)
    if expansion:
        _require_confirmation(confirm, "Granting new access")
    new_raw = [s.model_dump() for s in scopes]
    updated = await _update_passport(supabase, operator, agent_id, {"scopes": new_raw})
    await write_audit(
        supabase,
        operator=operator,
        action="passport.scopes_changed",
        target_type="agent",
        target_id=agent_id,
        reason=reason,
        details={"old": [s.model_dump() for s in old], "new": new_raw, "expansion": expansion},
    )
    return PassportView.from_row(updated, now), True


async def renew(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    days: int,
    reason: str | None,
    now: datetime,
) -> PassportView:
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot be renewed.")
    new_expiry = (now + timedelta(days=days)).isoformat()
    updated = await _update_passport(supabase, operator, agent_id, {"expires_at": new_expiry})
    await write_audit(
        supabase, operator=operator, action="passport.renewed", target_type="agent",
        target_id=agent_id, reason=reason,
        details={"old_expires_at": str(row.get("expires_at")), "new_expires_at": new_expiry},
    )
    return PassportView.from_row(updated, now)


async def rotate_key(
    supabase: Any, operator: OperatorContext, agent_id: UUID, reason: str | None, now: datetime
) -> tuple[PassportView, str]:
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot receive a new key.")
    await _deactivate_agent_keys(supabase, operator, agent_id, now)
    key = generate_agent_key()
    await _insert_agent_key(supabase, operator, agent_id, key)
    await write_audit(
        supabase, operator=operator, action="passport.key_rotated", target_type="agent",
        target_id=agent_id, reason=reason, details={"key_prefix": key.display_prefix},
    )
    return PassportView.from_row(row, now), key.plaintext


async def list_audit(supabase: Any, operator: OperatorContext, limit: int) -> list[ControlAuditEntry]:
    res = await (
        supabase.table("control_audit_log")
        .select("*")
        .eq("organization_id", str(operator.organization_id))
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return [ControlAuditEntry.model_validate(r) for r in (res.data or [])]
