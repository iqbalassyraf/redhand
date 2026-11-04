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
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID, uuid4

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


def _control_agent_safe_mode(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, agent_id, actor, enabled = str(p["p_org"]), str(p["p_agent"]), str(p["p_actor"]), p["p_enabled"]
    if not isinstance(enabled, bool):
        raise _error("22P02", "p_enabled must be a boolean")
    agent = _find(store, "agents", org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")
    if bool(agent.get("safe_mode")) == enabled:
        return {"changed": False, "agent_id": agent_id, "enabled": enabled}
    agent["safe_mode"] = enabled
    _append_audit(
        store, org=org, actor=actor,
        action="passport.safe_mode_enabled" if enabled else "passport.safe_mode_disabled",
        target_type="agent", target_id=agent_id, reason=p.get("p_reason"), details={"enabled": enabled},
    )
    return {"changed": True, "agent_id": agent_id, "enabled": enabled}


def _control_org_safe_mode(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, enabled = str(p["p_org"]), str(p["p_actor"]), p["p_enabled"]
    if not isinstance(enabled, bool):
        raise _error("22P02", "p_enabled must be a boolean")
    row = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == org), None)
    if row is None:
        raise _error("P0002", "organization not found")
    if bool(row.get("safe_mode")) == enabled:
        return {"changed": False, "enabled": enabled}
    row["safe_mode"] = enabled
    _append_audit(
        store, org=org, actor=actor,
        action="organization.safe_mode_enabled" if enabled else "organization.safe_mode_disabled",
        target_type="organization", target_id=org, reason=p.get("p_reason"), details={"enabled": enabled},
    )
    return {"changed": True, "enabled": enabled}


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


def _control_agent_budget(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, agent_id, actor = str(p["p_org"]), str(p["p_agent"]), str(p["p_actor"])
    limit, action = p["p_limit"], p["p_action"]
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000_000):
        raise _error("23514", "daily_call_limit violates check constraint")
    if action not in ("deny", "freeze"):
        raise _error("23514", "budget_action violates check constraint")
    agent = _find(store, "agents", org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")
    old_limit, old_action = agent.get("daily_call_limit"), agent.get("budget_action") or "deny"
    if old_limit != p.get("p_expected_limit") or old_action != p.get("p_expected_action"):
        return {"conflict": True}  # the caller decided against a state that has since changed
    if old_limit == limit and old_action == action:
        return {"changed": False, "agent_id": agent_id, "daily_call_limit": old_limit, "budget_action": old_action}
    agent["daily_call_limit"], agent["budget_action"] = limit, action
    if old_limit != limit:  # a new limit alerts (and auto-freezes) afresh
        cutoff = (_utc_today() - timedelta(days=1)).isoformat()
        for st in store.tables.get("agent_budget_state", []):
            if st["agent_id"] == agent_id and st["day_key"] >= cutoff:
                st["warned_at"] = st["limit_reached_at"] = st["frozen_at"] = None
    _append_audit(
        store, org=org, actor=actor, action="passport.budget_changed", target_type="agent", target_id=agent_id,
        reason=p.get("p_reason"),
        details={"old_limit": old_limit, "new_limit": limit, "old_action": old_action, "new_action": action},
    )
    return {"changed": True, "agent_id": agent_id, "daily_call_limit": limit, "budget_action": action}


def _record_usage(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    instance, items = p["p_instance"], p["p_items"]
    if not isinstance(instance, str) or not 8 <= len(instance) <= 64:
        raise _error("22023", "invalid instance id")
    if not isinstance(items, list) or len(items) > 1000:
        raise _error("22023", "items must be an array of at most 1000 entries")
    usage = store.tables.setdefault("agent_usage_daily", [])
    state = store.tables.setdefault("agent_budget_state", [])
    today = _utc_today()
    accepted = rejected = 0
    events: list[dict[str, Any]] = []
    for item in items:
        try:
            day = date.fromisoformat(str(item["day_key"]))
            calls = item["calls"]
            agent_id = str(UUID(str(item["agent_id"])))
        except (KeyError, ValueError, TypeError):
            rejected += 1
            continue
        if isinstance(calls, bool) or not isinstance(calls, int) or not 0 <= calls <= 10**12 or abs((day - today).days) > 2:
            rejected += 1
            continue
        agent = next((a for a in store.tables.get("agents", []) if str(a.get("id")) == agent_id), None)
        if agent is None:
            rejected += 1
            continue
        row = next(
            (u for u in usage if u["agent_id"] == agent_id and u["day_key"] == day.isoformat() and u["instance_id"] == instance),
            None,
        )
        if row is None:
            usage.append({"agent_id": agent_id, "organization_id": str(agent["organization_id"]),
                          "day_key": day.isoformat(), "instance_id": instance, "calls": calls})
        else:
            row["calls"] = max(int(row["calls"]), calls)
        accepted += 1

        limit = agent.get("daily_call_limit")
        if limit is None:
            continue
        total = sum(int(u["calls"]) for u in usage if u["agent_id"] == agent_id and u["day_key"] == day.isoformat())
        st = next((s for s in state if s["agent_id"] == agent_id and s["day_key"] == day.isoformat()), None)
        if st is None:
            st = {"agent_id": agent_id, "day_key": day.isoformat(), "warned_at": None, "limit_reached_at": None, "frozen_at": None}
            state.append(st)
        kind = None
        if total >= limit:
            if st["limit_reached_at"] is None:
                st["limit_reached_at"] = _now()
                st["warned_at"] = st["warned_at"] or _now()
                kind = "limit"
        elif total * 100 >= int(limit) * 80 and st["warned_at"] is None:
            st["warned_at"] = _now()
            kind = "warn"
        if kind:
            org = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == str(agent["organization_id"])), {})
            events.append({
                "kind": kind, "agent_id": agent_id, "organization_id": str(agent["organization_id"]),
                "name": agent["name"], "day_key": day.isoformat(), "used": total, "daily_call_limit": limit,
                "budget_action": agent.get("budget_action") or "deny", "utc_offset_minutes": org.get("utc_offset_minutes", 480),
            })
    return {"accepted": accepted, "rejected": rejected, "events": events}


def _mark_budget_frozen(store: LocalSupabaseAdapter, p: dict[str, Any]) -> bool:
    for s in store.tables.get("agent_budget_state", []):
        if s["agent_id"] == str(p["p_agent"]) and s["day_key"] == str(p["p_day"]) and s["frozen_at"] is None:
            s["frozen_at"] = _now()
            return True
    return False


def _usage_by_others(store: LocalSupabaseAdapter, p: dict[str, Any]) -> int:
    return sum(
        int(u["calls"]) for u in store.tables.get("agent_usage_daily", [])
        if u["organization_id"] == str(p["p_org"]) and u["agent_id"] == str(p["p_agent"])
        and u["day_key"] == str(p["p_day"]) and u["instance_id"] != p["p_instance"]
    )


def _org_usage(store: LocalSupabaseAdapter, p: dict[str, Any]) -> list[dict[str, Any]]:
    totals: dict[str, int] = {}
    for u in store.tables.get("agent_usage_daily", []):
        if u["organization_id"] == str(p["p_org"]) and u["day_key"] == str(p["p_day"]):
            totals[u["agent_id"]] = totals.get(u["agent_id"], 0) + int(u["calls"])
    return [{"agent_id": a, "calls": c} for a, c in totals.items()]


def _telegram_link_chat(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    code_hash, chat_id = str(p["p_code_hash"]), int(p["p_chat_id"])
    code = next(
        (c for c in store.tables.setdefault("telegram_link_codes", []) if c.get("code_hash") == code_hash), None
    )
    if (
        code is None
        or code.get("used_at") is not None
        or datetime.fromisoformat(str(code["expires_at"])) <= datetime.now(timezone.utc)
    ):
        raise _error("P0002", "link code is invalid or expired")
    org, user = str(code["organization_id"]), str(code["user_id"])
    member = next(
        (
            m
            for m in store.tables.get("organization_members", [])
            if str(m.get("organization_id")) == org and str(m.get("user_id")) == user
        ),
        None,
    )
    role = str(member.get("role")) if member else None
    if role not in ("admin", "owner"):
        raise _error("42501", "operator may not use the panic command")

    links = store.tables.setdefault("telegram_links", [])
    for link in links:
        if link.get("chat_id") == chat_id and link.get("revoked_at") is None:
            link["revoked_at"] = _now()
    code["used_at"] = _now()
    link_id = str(uuid4())
    new_link: dict[str, Any] = {
        "id": link_id, "organization_id": org, "user_id": user, "chat_id": chat_id,
        "created_at": _now(), "revoked_at": None,
    }
    links.insert(0, new_link)
    _append_audit(
        store, org=org, actor=user, action="telegram.linked", target_type="telegram_link",
        target_id=link_id, reason=None, details={"channel": "telegram"},
    )
    return {"link_id": link_id, "organization_id": org, "user_id": user, "role": role}


def _telegram_unlink(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, link_id = str(p["p_org"]), str(p["p_actor"]), str(p["p_link_id"])
    link = _find(store, "telegram_links", org, link_id)
    if link is None:
        raise _error("P0002", "telegram link not found")
    if link.get("revoked_at") is not None:
        return {"link_id": link_id, "changed": False}
    link["revoked_at"] = _now()
    _append_audit(
        store, org=org, actor=actor, action="telegram.unlinked", target_type="telegram_link",
        target_id=link_id, reason=None, details={"linked_user_id": str(link["user_id"])},
    )
    return {"link_id": link_id, "changed": True}


def _telegram_claim_update(store: LocalSupabaseAdapter, p: dict[str, Any]) -> bool:
    update_id = int(p["p_update_id"])
    seen = store.tables.setdefault("telegram_updates", [])
    if any(row.get("update_id") == update_id for row in seen):
        return False
    seen.append({"update_id": update_id, "received_at": _now()})
    return True


HANDLERS: dict[str, RpcHandler] = {
    "control_agent_change": _control_agent_change,
    "control_freeze_all": _control_freeze_all,
    "control_create_passport": _control_create_passport,
    "control_mcp_server": _control_mcp_server,
    "control_agent_budget": _control_agent_budget,
    "record_usage": _record_usage,
    "mark_budget_frozen": _mark_budget_frozen,
    "usage_by_others": _usage_by_others,
    "org_usage": _org_usage,
    "control_agent_safe_mode": _control_agent_safe_mode,
    "control_org_safe_mode": _control_org_safe_mode,
    "telegram_link_chat": _telegram_link_chat,
    "telegram_unlink": _telegram_unlink,
    "telegram_claim_update": _telegram_claim_update,
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
