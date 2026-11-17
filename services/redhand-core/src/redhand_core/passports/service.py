"""
Passport control logic: registration, freeze / unfreeze / revoke / freeze-all, scope
changes, renewal, key rotation, MCP server registration, and the control audit trail.

Every query is filtered by the operator's organization. A passport in another tenant
is indistinguishable from one that does not exist (404).

Atomicity: each action is ONE call to a database function (`control_*`, see
supabase/migrations/20261102000000_atomic_control_actions.sql) that applies the change and
writes its `control_audit_log` row in a single transaction. If anything fails, including the
audit insert, nothing is applied and the caller gets an error. This module keeps the
decisions (state machine, confirmations, scope-expansion rule); the database functions only
apply the result, guarded by a compare-and-set on the status read here. A concurrent change
makes the guard fail; the action is then re-decided once from fresh state before giving up
with 409.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import date, datetime, timedelta
import functools
import logging
from typing import Any, ParamSpec, TypeVar
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.passports import budget as budget_rules
from redhand_core.passports.credentials import generate_agent_key
from redhand_core.passports.models import (
    ControlAuditEntry,
    McpServerCreateRequest,
    PassportCreateRequest,
    PassportView,
    Scope,
    is_scope_expansion,
    parse_scopes,
)

logger = logging.getLogger("redhand.core.passports")

P = ParamSpec("P")
T = TypeVar("T")

# PostgreSQL SQLSTATE codes raised by the control_* functions and the passport triggers.
SQLSTATE_NOT_FOUND = "P0002"  # no_data_found: the row is missing or belongs to another tenant
SQLSTATE_UNIQUE_VIOLATION = "23505"
SQLSTATE_CHECK_VIOLATION = "23514"  # e.g. reactivating a revoked passport
SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"  # a database function refused the actor (a role ceiling): the caller's role is not enough


class StateConflictError(Exception):
    """The passport changed between reading it and applying the action (compare-and-set)."""


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


def retry_once_on_conflict(fn: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
    """Re-runs an action once, from fresh state, if another operator changed the passport."""

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        for _ in range(2):
            try:
                return await fn(*args, **kwargs)
            except StateConflictError:
                continue
        raise _conflict("The passport was changed by someone else at the same time. Reload and try again.")

    return wrapper


async def _rpc(
    supabase: Any,
    function: str,
    params: dict[str, Any],
    *,
    not_found_detail: str,
    conflict_detail: str,
) -> Any:
    """Calls one control_* database function and maps its errors to HTTP responses."""
    try:
        response = await supabase.rpc(function, params).execute()
    except APIError as exc:
        if exc.code == SQLSTATE_NOT_FOUND:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=not_found_detail) from exc
        if exc.code == SQLSTATE_INSUFFICIENT_PRIVILEGE:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your role does not allow this.") from exc
        if exc.code in (SQLSTATE_UNIQUE_VIOLATION, SQLSTATE_CHECK_VIOLATION):
            raise _conflict(conflict_detail) from exc
        # The message is not logged: database messages can echo submitted values.
        logger.error("Control action failed and was rolled back: function=%s sqlstate=%s", function, exc.code)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The action could not be completed. Reload to see the current state.",
        ) from exc
    return response.data


async def _agent_change(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    *,
    action: str,
    expected_status: str,
    changes: dict[str, Any],
    reason: str | None,
    details: dict[str, Any] | None = None,
    deactivate_keys: bool = False,
    new_key: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Applies one change to one passport together with its audit row. Raises
    StateConflictError when the passport no longer has `expected_status`."""
    data = await _rpc(
        supabase,
        "control_agent_change",
        {
            "p_org": str(operator.organization_id),
            "p_agent": str(agent_id),
            "p_actor": str(operator.user_id),
            "p_action": action,
            "p_expected_status": expected_status,
            "p_changes": changes,
            "p_deactivate_keys": deactivate_keys,
            "p_new_key": new_key,
            "p_reason": reason,
            "p_details": details or {},
        },
        not_found_detail=f"Passport '{agent_id}' not found.",
        conflict_detail="A revoked passport cannot be reactivated. Register a new agent instead.",
    )
    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected database response.")
    if data.get("conflict"):
        raise StateConflictError
    return dict(data["agent"])


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
    key = generate_agent_key()
    scopes = [s.model_dump() for s in req.scopes]
    expires_at = (now + timedelta(days=req.expires_in_days)).isoformat()

    created = await _rpc(
        supabase,
        "control_create_passport",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_agent": {
                "id": str(agent_id),
                "external_agent_id": external_id,
                "name": req.name,
                "framework": req.framework,
                "environment": req.environment,
                "owner_id": str(owner_id),
                "backup_owner_id": str(req.backup_owner_id) if req.backup_owner_id else None,
                "scopes": scopes,
                "expires_at": expires_at,
            },
            # Only the hash reaches the database; the plaintext key is returned once to the caller.
            "p_key": {"key_prefix": key.display_prefix, "key_hash": key.key_hash},
            "p_details": {
                "name": req.name,
                "scopes": scopes,
                "expires_at": expires_at,
                "key_prefix": key.display_prefix,
            },
        },
        not_found_detail="Organization not found.",
        conflict_detail=f"An agent with external ID '{external_id}' already exists in {req.environment}.",
    )
    return PassportView.from_row(dict(created), now), key.plaintext


@retry_once_on_conflict
async def freeze(
    supabase: Any, operator: OperatorContext, agent_id: UUID, reason: str | None, now: datetime
) -> tuple[PassportView, bool]:
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot be frozen; it is already permanently disabled.")
    if row["status"] == "frozen":
        return PassportView.from_row(row, now), False
    updated = await _agent_change(
        supabase, operator, agent_id, action="passport.frozen", expected_status=row["status"],
        changes={"status": "frozen", "status_reason": reason}, reason=reason,
    )
    return PassportView.from_row(updated, now), True


@retry_once_on_conflict
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
    updated = await _agent_change(
        supabase, operator, agent_id, action="passport.unfrozen", expected_status=row["status"],
        changes={"status": "active", "status_reason": reason}, reason=reason,
    )
    return PassportView.from_row(updated, now), True


async def promote(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    reason: str | None,
    confirm: bool,
    now: datetime,
) -> tuple[PassportView, bool]:
    """Turns a reported-only passport (created by telemetry, C1b) into an ordinary one. Admin-only at the route, confirmed, audited as
    passport.promoted. It grants nothing by itself: the passport still needs scopes and an agent key to call a tool."""
    _require_confirmation(confirm, "Promote")
    data = await _rpc(
        supabase,
        "control_passport_promote",
        {"p_org": str(operator.organization_id), "p_agent": str(agent_id), "p_actor": str(operator.user_id), "p_reason": reason},
        not_found_detail=f"Passport '{agent_id}' not found.",
        conflict_detail="A revoked passport cannot be promoted. Register a new agent instead.",
    )
    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected database response.")
    row = await get_passport_row(supabase, operator, agent_id)
    return PassportView.from_row(row, now), data.get("changed") is True


@retry_once_on_conflict
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
    updated = await _agent_change(
        supabase, operator, agent_id, action="passport.revoked", expected_status=row["status"],
        changes={"status": "revoked", "status_reason": reason}, reason=reason, deactivate_keys=True,
    )
    return PassportView.from_row(updated, now), True


async def freeze_all(supabase: Any, operator: OperatorContext, reason: str | None) -> list[UUID]:
    """Freezes every active passport in the tenant and records it, in one transaction."""
    data = await _rpc(
        supabase,
        "control_freeze_all",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_reason": reason},
        not_found_detail="Organization not found.",
        conflict_detail="Freeze-all conflicted with another change; try again.",
    )
    return [UUID(str(agent_id)) for agent_id in data["frozen_agent_ids"]]


async def set_agent_safe_mode(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    enabled: bool,
    reason: str | None,
    confirm: bool,
    now: datetime,
) -> tuple[PassportView, bool]:
    """Turns Safe Mode on or off for one agent. Turning it off needs explicit confirmation."""
    if not enabled:
        _require_confirmation(confirm, "Turning Safe Mode off")
    data = await _rpc(
        supabase,
        "control_agent_safe_mode",
        {
            "p_org": str(operator.organization_id), "p_agent": str(agent_id),
            "p_actor": str(operator.user_id), "p_enabled": enabled, "p_reason": reason,
        },
        not_found_detail="Agent passport not found.",
        conflict_detail="Safe Mode change conflicted with another change; try again.",
    )
    row = await get_passport_row(supabase, operator, agent_id)
    return PassportView.from_row(row, now), bool(data["changed"])


@retry_once_on_conflict
async def set_agent_budget(
    supabase: Any,
    operator: OperatorContext,
    agent_id: UUID,
    daily_call_limit: int | None,
    action: str,
    reason: str | None,
    confirm: bool,
    now: datetime,
) -> tuple[PassportView, bool]:
    """
    Sets an agent's daily call limit and what happens at the limit. Lowering a limit (or setting one)
    only restricts, so any security operator may. Raising or removing a limit, or turning auto-freeze
    off, relaxes the restriction: it needs an admin and explicit confirmation.
    """
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot be changed.")
    current = PassportView.from_row(row, now)
    if budget_rules.is_relaxation(current.daily_call_limit, daily_call_limit, current.budget_action, action):
        if operator.role < Role.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Raising or removing a limit, or turning auto-freeze off, requires the 'admin' role or higher.",
            )
        _require_confirmation(confirm, "Raising or removing a limit")
    data = await _rpc(
        supabase,
        "control_agent_budget",
        {
            "p_org": str(operator.organization_id), "p_agent": str(agent_id), "p_actor": str(operator.user_id),
            "p_limit": daily_call_limit, "p_action": action, "p_reason": reason,
            # Compare-and-set: the role and confirmation decision above was made against these values.
            "p_expected_limit": current.daily_call_limit, "p_expected_action": current.budget_action,
        },
        not_found_detail="Agent passport not found.",
        conflict_detail="Budget change conflicted with another change; try again.",
    )
    if isinstance(data, dict) and data.get("conflict"):
        raise StateConflictError
    updated = await get_passport_row(supabase, operator, agent_id)
    return PassportView.from_row(updated, now), bool(data["changed"])


async def get_org_budget_default(supabase: Any, organization_id: UUID) -> int | None:
    res = await supabase.table("organizations").select("default_daily_call_limit").eq("id", str(organization_id)).execute()
    rows = list(res.data or [])
    raw = rows[0].get("default_daily_call_limit") if len(rows) == 1 else None
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 1 else None


@retry_once_on_conflict
async def set_org_budget_default(
    supabase: Any, operator: OperatorContext, limit: int | None, reason: str | None, confirm: bool
) -> tuple[int | None, bool]:
    """
    Sets the daily limit that new agents start with. Raising or removing it relaxes the protection of
    agents registered later, so it needs explicit confirmation (the caller is already an admin).
    """
    current = await get_org_budget_default(supabase, operator.organization_id)
    if current is not None and (limit is None or limit > current):
        _require_confirmation(confirm, "Raising or removing the default limit")
    data = await _rpc(
        supabase,
        "control_org_budget_default",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_limit": limit,
            "p_reason": reason, "p_expected": current,  # compare-and-set against what the decision used
        },
        not_found_detail="Organization not found.",
        conflict_detail="The default limit conflicted with another change; try again.",
    )
    if isinstance(data, dict) and data.get("conflict"):
        raise StateConflictError
    return limit, bool(data["changed"])


async def apply_default_budget(
    supabase: Any, operator: OperatorContext, passport: PassportView, now: datetime
) -> PassportView:
    """
    Gives a newly registered agent the organization's default daily limit, if one is set (an audited budget
    change). Best effort: the agent exists either way, and a failure here is logged and leaves it with no limit,
    which the dashboard flags. Existing agents are never touched by the default.
    """
    try:
        default = await get_org_budget_default(supabase, operator.organization_id)
        if default is None:
            return passport
        updated, _ = await set_agent_budget(
            supabase, operator, passport.id, default, passport.budget_action,
            "Organization default daily limit", False, now,
        )
        return updated
    except Exception as exc:  # noqa: BLE001  registration must not fail because of the default
        logger.warning("Could not apply the organization default limit: %s", type(exc).__name__)
        return passport


async def get_org_utc_offset(supabase: Any, organization_id: UUID) -> int:
    res = await supabase.table("organizations").select("utc_offset_minutes").eq("id", str(organization_id)).execute()
    rows = list(res.data or [])
    return budget_rules.normalize_offset(rows[0].get("utc_offset_minutes") if len(rows) == 1 else None)


async def get_org_usage(supabase: Any, organization_id: UUID, day: date) -> dict[UUID, int]:
    """Calls so far on `day` for each agent of the organization that reported any."""
    data = await _rpc(
        supabase,
        "org_usage",
        {"p_org": str(organization_id), "p_day": day.isoformat()},
        not_found_detail="Organization not found.",
        conflict_detail="Usage lookup conflicted; try again.",
    )
    return {UUID(str(item["agent_id"])): int(item["calls"]) for item in (data or [])}


async def get_org_safe_mode(supabase: Any, organization_id: UUID) -> bool:
    res = await supabase.table("organizations").select("safe_mode").eq("id", str(organization_id)).execute()
    rows = list(res.data or [])
    return len(rows) == 1 and rows[0].get("safe_mode") is True


async def set_org_safe_mode(
    supabase: Any, operator: OperatorContext, enabled: bool, reason: str | None, confirm: bool
) -> bool:
    """Turns Safe Mode on or off for every agent of the organization. Returns True if it changed."""
    if not enabled:
        _require_confirmation(confirm, "Turning Safe Mode off")
    data = await _rpc(
        supabase,
        "control_org_safe_mode",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id),
            "p_enabled": enabled, "p_reason": reason,
        },
        not_found_detail="Organization not found.",
        conflict_detail="Safe Mode change conflicted with another change; try again.",
    )
    return bool(data["changed"])


@retry_once_on_conflict
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
    updated = await _agent_change(
        supabase, operator, agent_id, action="passport.scopes_changed", expected_status=row["status"],
        changes={"scopes": new_raw}, reason=reason,
        details={"old": [s.model_dump() for s in old], "new": new_raw, "expansion": expansion},
    )
    return PassportView.from_row(updated, now), True


@retry_once_on_conflict
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
    updated = await _agent_change(
        supabase, operator, agent_id, action="passport.renewed", expected_status=row["status"],
        changes={"expires_at": new_expiry}, reason=reason,
        details={"old_expires_at": str(row.get("expires_at")), "new_expires_at": new_expiry},
    )
    return PassportView.from_row(updated, now)


@retry_once_on_conflict
async def rotate_key(
    supabase: Any, operator: OperatorContext, agent_id: UUID, reason: str | None, now: datetime
) -> tuple[PassportView, str]:
    row = await get_passport_row(supabase, operator, agent_id)
    if row["status"] == "revoked":
        raise _conflict("A revoked passport cannot receive a new key.")
    key = generate_agent_key()
    updated = await _agent_change(
        supabase, operator, agent_id, action="passport.key_rotated", expected_status=row["status"],
        changes={}, reason=reason, details={"key_prefix": key.display_prefix}, deactivate_keys=True,
        new_key={"key_prefix": key.display_prefix, "key_hash": key.key_hash},
    )
    return PassportView.from_row(updated, now), key.plaintext


async def register_mcp_server(
    supabase: Any, operator: OperatorContext, req: McpServerCreateRequest
) -> dict[str, Any]:
    data = await _rpc(
        supabase,
        "control_mcp_server",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_op": "register",
            "p_server": {"slug": req.slug, "name": req.name, "url": req.url},
            "p_server_id": None,
        },
        not_found_detail="Organization not found.",
        conflict_detail=f"An MCP server with slug '{req.slug}' exists.",
    )
    return dict(data)


async def deactivate_mcp_server(supabase: Any, operator: OperatorContext, server_id: UUID) -> dict[str, Any]:
    data = await _rpc(
        supabase,
        "control_mcp_server",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_op": "deactivate",
            "p_server": None,
            "p_server_id": str(server_id),
        },
        not_found_detail=f"MCP server '{server_id}' not found.",
        conflict_detail="MCP server could not be deactivated.",
    )
    return dict(data)


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
