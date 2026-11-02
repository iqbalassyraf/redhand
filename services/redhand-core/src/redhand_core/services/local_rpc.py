"""
Local-store emulation of the `control_*` database functions
(supabase/migrations/20261102000000_atomic_control_actions.sql).

The real functions run as one transaction. Here every call works on the in-memory tables and,
if any step raises, the tables are restored from a snapshot taken before the call, so a failure
anywhere (including the audit insert) leaves nothing applied. Errors use the same SQLSTATE
codes the database raises so redhand-core's error mapping is exercised identically.

Used only by the in-memory store, which redhand-core refuses to run outside development/test.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from postgrest.exceptions import APIError

from redhand_core.services.local_store import (
    LocalStoreConstraintError,
    LocalSupabaseAdapter,
    QueryResult,
    _apply_update_triggers,
    _check_update_rules,
    apply_insert_defaults,
)

AGENT_ACTIONS = frozenset(
    {
        "passport.frozen",
        "passport.unfrozen",
        "passport.revoked",
        "passport.scopes_changed",
        "passport.renewed",
        "passport.key_rotated",
    }
)
CHANGEABLE_COLUMNS = frozenset({"status", "status_reason", "scopes", "expires_at"})
AGENT_STATUSES = frozenset({"active", "frozen", "revoked", "expired"})

RpcHandler = Callable[[LocalSupabaseAdapter, dict[str, Any]], Any]


def _error(code: str, message: str) -> APIError:
    return APIError({"code": code, "message": message, "hint": None, "details": None})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_audit(
    store: LocalSupabaseAdapter,
    *,
    org: str,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    reason: str | None,
    details: dict[str, Any] | None,
) -> None:
    store.tables.setdefault("control_audit_log", []).insert(
        0,
        {
            "id": str(uuid4()),
            "organization_id": org,
            "actor_user_id": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "reason": reason,
            "details": details or {},
            "created_at": _now(),
        },
    )


def _find(store: LocalSupabaseAdapter, table: str, org: str, row_id: str) -> dict[str, Any] | None:
    return next(
        (
            r
            for r in store.tables.get(table, [])
            if str(r.get("id")) == row_id and str(r.get("organization_id")) == org
        ),
        None,
    )


def _insert_key(
    store: LocalSupabaseAdapter, org: str, agent_id: str, actor: str, key: dict[str, Any] | None
) -> None:
    key = key or {}
    if not key.get("key_prefix") or not key.get("key_hash"):
        raise _error("23502", "null value in column of agent_keys violates not-null constraint")
    keys = store.tables.setdefault("agent_keys", [])
    if any(k.get("key_hash") == key["key_hash"] for k in keys):
        raise _error("23505", "duplicate key value violates unique constraint on agent_keys.key_hash")
    keys.insert(
        0,
        {
            "id": str(uuid4()),
            "organization_id": org,
            "agent_id": agent_id,
            "key_prefix": key["key_prefix"],
            "key_hash": key["key_hash"],
            "is_active": True,
            "created_by": actor,
            "created_at": _now(),
        },
    )


def _control_agent_change(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, agent_id, actor = str(p["p_org"]), str(p["p_agent"]), str(p["p_actor"])
    changes: dict[str, Any] = p.get("p_changes") or {}

    if p["p_action"] not in AGENT_ACTIONS:
        raise _error("22023", f"unsupported control action {p['p_action']}")
    for column in changes:
        if column not in CHANGEABLE_COLUMNS:
            raise _error("22023", f"column {column} cannot be changed by a control action")

    agent = _find(store, "agents", org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")

    expected = p.get("p_expected_status")
    if expected is not None and str(agent.get("status")) != expected:
        return {"conflict": True, "status": str(agent.get("status"))}

    new_status = changes.get("status")
    if new_status is not None and new_status not in AGENT_STATUSES:
        raise _error("22P02", f"invalid input value for enum agent_status: {new_status}")
    try:
        _check_update_rules("agents", agent, changes)
    except LocalStoreConstraintError as exc:
        raise _error("23514", str(exc)) from exc

    before = dict(agent)
    for column in CHANGEABLE_COLUMNS & changes.keys():
        # A JSON null status keeps the current status, like COALESCE in the SQL function.
        if column == "status" and changes[column] is None:
            continue
        agent[column] = changes[column]
    _apply_update_triggers("agents", before, agent)
    agent["updated_at"] = _now()

    if p.get("p_deactivate_keys"):
        for key in store.tables.get("agent_keys", []):
            if (
                str(key.get("agent_id")) == agent_id
                and str(key.get("organization_id")) == org
                and key.get("is_active")
            ):
                key["is_active"] = False
                key["deactivated_at"] = _now()
    if p.get("p_new_key") is not None:
        _insert_key(store, org, agent_id, actor, p["p_new_key"])

    _append_audit(
        store, org=org, actor=actor, action=p["p_action"], target_type="agent", target_id=agent_id,
        reason=p.get("p_reason"), details=p.get("p_details"),
    )
    result = dict(agent)
    store.publish_event("agents.updated", [result])
    return {"conflict": False, "agent": result}


def _control_freeze_all(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    frozen: list[dict[str, Any]] = []
    for agent in store.tables.get("agents", []):
        if str(agent.get("organization_id")) == org and agent.get("status") == "active":
            before = dict(agent)
            agent["status"] = "frozen"
            agent["status_reason"] = p.get("p_reason")
            _apply_update_triggers("agents", before, agent)
            agent["updated_at"] = _now()
            frozen.append(dict(agent))
    ids = [str(a["id"]) for a in frozen]
    _append_audit(
        store, org=org, actor=actor, action="organization.frozen_all", target_type="organization",
        target_id=org, reason=p.get("p_reason"), details={"frozen_count": len(ids), "frozen_agent_ids": ids},
    )
    if frozen:
        store.publish_event("agents.updated", frozen)
    return {"frozen_agent_ids": ids}


def _control_create_passport(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    spec: dict[str, Any] = p["p_agent"]
    agents = store.tables.setdefault("agents", [])
    if any(
        str(a.get("organization_id")) == org
        and a.get("external_agent_id") == spec["external_agent_id"]
        and a.get("environment") == spec["environment"]
        for a in agents
    ):
        raise _error("23505", "duplicate key value violates unique constraint on agents")

    row: dict[str, Any] = {
        "id": str(spec["id"]),
        "organization_id": org,
        "external_agent_id": spec["external_agent_id"],
        "name": spec["name"],
        "framework": spec.get("framework") or "custom",
        "environment": spec["environment"],
        "status": "active",
        "owner_id": spec["owner_id"],
        "backup_owner_id": spec.get("backup_owner_id") or None,
        "scopes": spec.get("scopes") or [],
        "expires_at": spec["expires_at"],
        "created_at": _now(),
    }
    apply_insert_defaults("agents", row)
    agents.insert(0, row)
    _insert_key(store, org, row["id"], actor, p.get("p_key"))
    _append_audit(
        store, org=org, actor=actor, action="passport.created", target_type="agent", target_id=row["id"],
        reason=None, details=p.get("p_details"),
    )
    created = dict(row)
    store.publish_event("agents.inserted", [created])
    return created


def _control_mcp_server(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, op = str(p["p_org"]), str(p["p_actor"]), p["p_op"]
    servers = store.tables.setdefault("mcp_servers", [])
    if op == "register":
        spec: dict[str, Any] = p["p_server"]
        if any(str(s.get("organization_id")) == org and s.get("slug") == spec["slug"] for s in servers):
            raise _error("23505", "duplicate key value violates unique constraint on mcp_servers")
        server: dict[str, Any] = {
            "id": str(uuid4()),
            "organization_id": org,
            "slug": spec["slug"],
            "name": spec["name"],
            "url": spec["url"],
            "is_active": True,
            "created_by": actor,
            "created_at": _now(),
        }
        servers.insert(0, server)
        _append_audit(
            store, org=org, actor=actor, action="mcp_server.registered", target_type="mcp_server",
            target_id=server["id"], reason=None, details={"slug": server["slug"], "url": server["url"]},
        )
        return dict(server)
    if op == "deactivate":
        found = _find(store, "mcp_servers", org, str(p["p_server_id"]))
        if found is None:
            raise _error("P0002", "MCP server not found")
        found["is_active"] = False
        _append_audit(
            store, org=org, actor=actor, action="mcp_server.deactivated", target_type="mcp_server",
            target_id=found["id"], reason=None, details={"slug": found["slug"]},
        )
        return dict(found)
    raise _error("22023", f"unsupported MCP server operation {op}")


HANDLERS: dict[str, RpcHandler] = {
    "control_agent_change": _control_agent_change,
    "control_freeze_all": _control_freeze_all,
    "control_create_passport": _control_create_passport,
    "control_mcp_server": _control_mcp_server,
}


class LocalRpcBuilder:
    """Mimics `client.rpc(name, params)`; `execute()` is all-or-nothing."""

    def __init__(self, store: LocalSupabaseAdapter, function: str, params: dict[str, Any]) -> None:
        self._store = store
        self._function = function
        self._params = params

    async def execute(self) -> QueryResult:
        handler = HANDLERS.get(self._function)
        if handler is None:
            raise _error("PGRST202", f"Could not find the function public.{self._function}")
        snapshot = copy.deepcopy(self._store.tables)
        try:
            data = handler(self._store, dict(self._params))
        except Exception:
            self._store.tables.clear()
            self._store.tables.update(snapshot)
            raise
        return QueryResult(data=data)
