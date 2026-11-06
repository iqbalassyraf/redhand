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
import hashlib
import json
import re
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
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


def _control_org_budget_default(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, limit = str(p["p_org"]), str(p["p_actor"]), p["p_limit"]
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000_000):
        raise _error("23514", "default_daily_call_limit violates check constraint")
    row = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == org), None)
    if row is None:
        raise _error("P0002", "organization not found")
    old = row.get("default_daily_call_limit")
    if old != p.get("p_expected"):
        return {"conflict": True}
    if old == limit:
        return {"changed": False, "default_daily_call_limit": old}
    row["default_daily_call_limit"] = limit
    _append_audit(
        store, org=org, actor=actor, action="organization.budget_default_changed", target_type="organization",
        target_id=org, reason=p.get("p_reason"), details={"old_limit": old, "new_limit": limit},
    )
    return {"changed": True, "default_daily_call_limit": limit}


def _control_blackbox_retention(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    days, payload_days = p["p_retention_days"], p["p_payload_retention_days"]
    if not (isinstance(days, int) and 7 <= days <= 90 and isinstance(payload_days, int) and 1 <= payload_days <= 30):
        raise _error("23514", "retention violates check constraint")
    row = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == org), None)
    if row is None:
        raise _error("P0002", "organization not found")
    old_days, old_payload = row.get("blackbox_retention_days", 30), row.get("payload_retention_days", 7)
    if old_days != p.get("p_expected_retention_days") or old_payload != p.get("p_expected_payload_retention_days"):
        return {"conflict": True}
    if old_days == days and old_payload == payload_days:
        return {"changed": False, "retention_days": days, "payload_retention_days": payload_days}
    row["blackbox_retention_days"], row["payload_retention_days"] = days, payload_days
    _append_audit(
        store, org=org, actor=actor, action="organization.blackbox_retention_changed", target_type="organization",
        target_id=org, reason=p.get("p_reason"),
        details={"old_retention_days": old_days, "new_retention_days": days,
                 "old_payload_retention_days": old_payload, "new_payload_retention_days": payload_days},
    )
    return {"changed": True, "retention_days": days, "payload_retention_days": payload_days}


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


# ---------------------------------------------------------------------------------------------------
# Black Box Recorder (Phase 3, M1): an in-memory emulation of the per-organization hash chain in
# supabase/migrations/20261110000000_blackbox.sql. The hash here need not match the real SQL
# function byte for byte (different stores compute it independently); it only needs to be internally
# consistent, so a value stored at _record_events time always recomputes the same way at
# _verify_events time.
# ---------------------------------------------------------------------------------------------------

BLACKBOX_GENESIS_HASH = "GENESIS_BLOCK_AGENT_EVENTS_V1"
MAX_EVENTS_PER_BATCH = 500
MAX_VERIFY_RANGE = 50_000


def _event_hash(
    prev_hash: str, org: str, agent_id: str, seq: int, occurred_at: str, instance: str, server: str,
    method: str, tool: str, decision: str, reasons: list[str], upstream_status: Any, latency_ms: Any,
    argument_keys: list[str], arguments_sha256: str, result_size: Any, redaction_count: int, credential_jti: Any,
) -> str:
    try:
        latency_text = "" if latency_ms is None else str(Decimal(str(latency_ms)).quantize(Decimal("0.01")))
    except InvalidOperation:
        latency_text = ""
    parts = [
        prev_hash, org, agent_id, str(seq), str(occurred_at), instance, server, method, tool, decision,
        ",".join(reasons), "" if upstream_status is None else str(upstream_status), latency_text,
        ",".join(argument_keys), arguments_sha256 or "", "" if result_size is None else str(result_size),
        str(redaction_count), credential_jti or "",
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _usable_payload(value: Any) -> bool:
    """Mirrors record_events(): a payload must be a JSON object of at most 16 KB, else it is dropped."""
    return isinstance(value, dict) and len(json.dumps(value)) <= 16384


def _control_payload_capture(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, enabled = str(p["p_org"]), str(p["p_actor"]), p["p_enabled"]
    if not isinstance(enabled, bool):
        raise _error("22023", "enabled must be true or false")
    row = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == org), None)
    if row is None:
        raise _error("P0002", "organization not found")
    old = row.get("payload_capture_enabled", False)
    if old != p.get("p_expected"):
        return {"conflict": True}
    if old == enabled:
        return {"changed": False, "payload_capture_enabled": enabled}
    row["payload_capture_enabled"] = enabled
    _append_audit(
        store, org=org, actor=actor, action="organization.payload_capture_changed", target_type="organization",
        target_id=org, reason=p.get("p_reason"), details={"old_enabled": old, "new_enabled": enabled},
    )
    return {"changed": True, "payload_capture_enabled": enabled}


def _read_event_payload(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, seq = str(p["p_org"]), str(p["p_actor"]), p["p_seq"]
    if not isinstance(seq, int) or seq < 1:
        raise _error("22023", "organization, actor and a positive seq are required")
    row = next(
        (e for e in store.tables.get("agent_events", []) if str(e["organization_id"]) == org and e["seq"] == seq), None
    )
    if row is None:
        return {"found": False}
    _append_audit(
        store, org=org, actor=actor, action="organization.blackbox_payload_viewed", target_type="organization",
        target_id=org, reason=None,
        details={
            "seq": seq, "had_arguments": row.get("arguments_redacted") is not None,
            "had_result": row.get("result_excerpt") is not None,
        },
    )
    return {
        "found": True, "seq": seq,
        "arguments_redacted": row.get("arguments_redacted"), "result_excerpt": row.get("result_excerpt"),
    }


def _control_clear_payloads(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    if not any(str(o.get("id")) == org for o in store.tables.get("organizations", [])):
        raise _error("P0002", "organization not found")
    cleared = 0
    for event in store.tables.get("agent_events", []):
        if str(event["organization_id"]) == org and (event.get("arguments_redacted") or event.get("result_excerpt")):
            event["arguments_redacted"] = None
            event["result_excerpt"] = None
            cleared += 1
    if cleared:
        _append_audit(
            store, org=org, actor=actor, action="organization.blackbox_payloads_cleared", target_type="organization",
            target_id=org, reason=p.get("p_reason"), details={"events_cleared": cleared},
        )
    return {"cleared": cleared}


def _audit_blackbox_export(store: LocalSupabaseAdapter, p: dict[str, Any]) -> None:
    org, actor, details = str(p["p_org"]), str(p["p_actor"]), p["p_details"]
    if not isinstance(details, dict):
        raise _error("22023", "organization, actor and details are required")
    if not any(str(o.get("id")) == org for o in store.tables.get("organizations", [])):
        raise _error("P0002", "organization not found")
    _append_audit(
        store, org=org, actor=actor, action="organization.blackbox_exported", target_type="organization",
        target_id=org, reason=None, details=details,
    )


_HONEY_KINDS = ("api_key", "aws_key", "password")
_ACTIONS = ("alert", "freeze")
_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}$")
_SYSTEM_ACTOR = "00000000-0000-0000-0000-000000000000"


def _org_exists(store: LocalSupabaseAdapter, org: str) -> bool:
    return any(str(o.get("id")) == org for o in store.tables.get("organizations", []))


def _agent_of(store: LocalSupabaseAdapter, org: str, agent: str) -> dict[str, Any] | None:
    return next(
        (a for a in store.tables.get("agents", []) if str(a.get("id")) == agent and str(a.get("organization_id")) == org), None
    )


def _public_honeytoken(row: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "label", "kind", "hint", "action_on_use", "action_on_read", "status", "created_at", "last_tripped_at", "trip_count")
    return {k: row.get(k) for k in keys}


def _control_honeytoken_create(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    if not _org_exists(store, org):
        raise _error("P0002", "organization not found")
    rows = store.tables.setdefault("honeytokens", [])
    if sum(1 for r in rows if r["organization_id"] == org and r["status"] == "active") >= 50:
        raise _error("23514", "at most 50 active honeytokens per organization")
    if p["p_kind"] not in _HONEY_KINDS or p["p_action_on_use"] not in _ACTIONS or p["p_action_on_read"] not in _ACTIONS:
        raise _error("23514", "invalid honeytoken")
    if any(r["organization_id"] == org and r["digest"] == p["p_digest"] for r in rows):
        raise _error("23505", "duplicate honeytoken")
    row = {
        "id": str(uuid4()), "organization_id": org, "label": p["p_label"], "kind": p["p_kind"], "digest": p["p_digest"],
        "hint": p["p_hint"], "action_on_use": p["p_action_on_use"], "action_on_read": p["p_action_on_read"],
        "status": "active", "created_by": actor, "created_at": _now(), "retired_at": None, "last_tripped_at": None,
        "trip_count": 0,
    }
    rows.insert(0, row)
    _append_audit(
        store, org=org, actor=actor, action="honeytoken.created", target_type="organization", target_id=org, reason=None,
        details={"honeytoken_id": row["id"], "label": row["label"], "kind": row["kind"],
                 "action_on_use": row["action_on_use"], "action_on_read": row["action_on_read"]},
    )
    return _public_honeytoken(row)


def _control_honeytoken_retire(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, ident = str(p["p_org"]), str(p["p_actor"]), str(p["p_id"])
    row = next((r for r in store.tables.get("honeytokens", []) if r["id"] == ident and r["organization_id"] == org), None)
    if row is None:
        raise _error("P0002", "honeytoken not found")
    if row["status"] == "retired":
        return {"changed": False}
    row["status"], row["retired_at"] = "retired", _now()
    _append_audit(
        store, org=org, actor=actor, action="honeytoken.retired", target_type="organization", target_id=org, reason=None,
        details={"honeytoken_id": ident, "label": row["label"]},
    )
    return {"changed": True}


def _control_honey_tool_create(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, agent = str(p["p_org"]), str(p["p_actor"]), str(p["p_agent"])
    if _agent_of(store, org, agent) is None:
        raise _error("P0002", "agent not found")
    rows = store.tables.setdefault("honey_tools", [])
    if sum(1 for r in rows if r["agent_id"] == agent and r["status"] == "active") >= 5:
        raise _error("23514", "at most 5 active honey tools per agent")
    if not _TOOL_NAME.match(p["p_name"]) or p["p_action"] not in _ACTIONS:
        raise _error("23514", "invalid honey tool")
    if any(r["agent_id"] == agent and r["server_slug"] == p["p_server"] and r["name"] == p["p_name"] and r["status"] == "active" for r in rows):
        raise _error("23505", "duplicate honey tool")
    row = {
        "id": str(uuid4()), "organization_id": org, "agent_id": agent, "server_slug": p["p_server"], "name": p["p_name"],
        "description": p["p_description"], "action": p["p_action"], "status": "active", "created_by": actor,
        "created_at": _now(), "retired_at": None, "last_tripped_at": None, "trip_count": 0,
    }
    rows.insert(0, row)
    _append_audit(
        store, org=org, actor=actor, action="honey_tool.created", target_type="agent", target_id=agent, reason=None,
        details={"honey_tool_id": row["id"], "name": row["name"], "server": row["server_slug"], "action": row["action"]},
    )
    return {k: row[k] for k in ("id", "agent_id", "name", "description", "action", "status", "created_at", "last_tripped_at", "trip_count")} | {"server": row["server_slug"]}


def _control_honey_tool_retire(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, ident = str(p["p_org"]), str(p["p_actor"]), str(p["p_id"])
    row = next((r for r in store.tables.get("honey_tools", []) if r["id"] == ident and r["organization_id"] == org), None)
    if row is None:
        raise _error("P0002", "honey tool not found")
    if row["status"] == "retired":
        return {"changed": False}
    row["status"], row["retired_at"] = "retired", _now()
    _append_audit(
        store, org=org, actor=actor, action="honey_tool.retired", target_type="agent", target_id=row["agent_id"], reason=None,
        details={"honey_tool_id": ident, "name": row["name"]},
    )
    return {"changed": True}


def _record_trip(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, trip_id, agent, kind = str(p["p_org"]), str(p["p_trip_id"]), str(p["p_agent"]), p["p_kind"]
    ref, seen_in = str(p["p_ref"]), p["p_seen_in"]
    if kind not in ("honeytoken", "honey_tool") or (kind == "honeytoken" and seen_in not in ("arguments", "result")) or (
        kind == "honey_tool" and seen_in != "call"
    ):
        raise _error("22023", "invalid trip")
    agent_row = _agent_of(store, org, agent)
    if agent_row is None:
        raise _error("P0002", "agent not found")
    if kind == "honeytoken":
        found = next((r for r in store.tables.get("honeytokens", []) if r["id"] == ref and r["organization_id"] == org and r["status"] == "active"), None)
        action = None if found is None else (found["action_on_use"] if seen_in == "arguments" else found["action_on_read"])
        label = None if found is None else found["label"]
    else:
        found = next(
            (r for r in store.tables.get("honey_tools", []) if r["id"] == ref and r["organization_id"] == org
             and r["agent_id"] == agent and r["status"] == "active"), None,
        )
        action = None if found is None else found["action"]
        label = None if found is None else found["name"]
    if found is None:
        return {"recorded": False, "reason": "unknown_reference"}
    trips = store.tables.setdefault("honeytrips", [])
    now = datetime.now(timezone.utc)
    recent = any(
        t["ref_id"] == ref and t["agent_id"] == agent and t["seen_in"] == seen_in
        and now - datetime.fromisoformat(t["occurred_at"]) < timedelta(minutes=5)
        for t in trips
    )
    if any(t["id"] == trip_id for t in trips):
        return {"recorded": False, "reason": "duplicate"}
    trips.append({
        "id": trip_id, "organization_id": org, "agent_id": agent, "kind": kind, "ref_id": ref, "seen_in": seen_in,
        "tool_name": str(p.get("p_tool") or "")[:128], "server_slug": str(p.get("p_server") or "")[:128],
        "occurred_at": now.isoformat(),
    })
    found["last_tripped_at"] = now.isoformat()
    found["trip_count"] = int(found["trip_count"]) + 1
    _append_audit(
        store, org=org, actor=_SYSTEM_ACTOR, action="honeytoken.tripped" if kind == "honeytoken" else "honey_tool.tripped",
        target_type="agent", target_id=agent, reason=None,
        details={"ref_id": ref, "label": label, "seen_in": seen_in, "tool": str(p.get("p_tool") or "")[:128],
                 "server": str(p.get("p_server") or "")[:128], "action": action},
    )
    return {"recorded": True, "label": label, "action": action, "agent_name": agent_row.get("name"), "alert": not recent}


def _record_events(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    instance, batch_id, org, items = str(p["p_instance"]), str(p["p_batch_id"]), str(p["p_org"]), p["p_items"]
    if not 8 <= len(instance) <= 64:
        raise _error("22023", "invalid instance id")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_EVENTS_PER_BATCH:
        raise _error("22023", f"items must be an array of 1 to {MAX_EVENTS_PER_BATCH} entries")

    batches = store.tables.setdefault("event_batches", [])
    existing = next((b for b in batches if b["batch_id"] == batch_id), None)
    if existing is not None:
        return {
            "accepted": existing["item_count"], "rejected": existing["rejected_count"],
            "first_seq": existing["first_seq"], "last_seq": existing["last_seq"], "duplicate": True,
        }

    heads = store.tables.setdefault("event_chain_heads", [])
    head = next((h for h in heads if h["organization_id"] == org), None)
    if head is None:
        head = {
            "organization_id": org, "last_seq": 0, "last_hash": BLACKBOX_GENESIS_HASH,
            "anchor_seq": 0, "anchor_prev_hash": BLACKBOX_GENESIS_HASH,
        }
        heads.append(head)

    events = store.tables.setdefault("agent_events", [])
    org_row = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == org), None)
    capture = org_row is not None and org_row.get("payload_capture_enabled") is True  # off unless explicitly on
    seq, prev = head["last_seq"], head["last_hash"]
    accepted = rejected = 0
    first_seq: int | None = None
    last_seq: int | None = None

    for item in items:
        try:
            agent_id = str(UUID(str(item["agent_id"])))
        except (KeyError, ValueError, TypeError):
            rejected += 1
            continue
        agent = next((a for a in store.tables.get("agents", []) if str(a.get("id")) == agent_id), None)
        if agent is None or str(agent.get("organization_id")) != org:
            rejected += 1
            continue
        decision, method = item.get("decision"), item.get("method") or ""
        gateway_instance = item.get("gateway_instance") or ""
        if decision not in ("ALLOW", "BLOCK", "ERROR") or not method or len(method) > 64 or not 1 <= len(gateway_instance) <= 64:
            rejected += 1
            continue

        reasons, argument_keys = list(item.get("reasons") or []), list(item.get("argument_keys") or [])
        occurred_at = item.get("occurred_at") or _now()
        server, tool_name = item.get("server") or "", item.get("tool_name") or ""
        upstream_status, latency_ms = item.get("upstream_status"), item.get("latency_ms")
        arguments_sha256, result_size = item.get("arguments_sha256") or "", item.get("result_size_bytes")
        redaction_count, credential_jti = int(item.get("redaction_count") or 0), item.get("credential_jti")
        payloads = {
            key: (item.get(key) if capture and _usable_payload(item.get(key)) else None)
            for key in ("arguments_redacted", "result_excerpt")
        }
        seq += 1
        h = _event_hash(
            prev, org, agent_id, seq, occurred_at, gateway_instance, server, method, tool_name, decision,
            reasons, upstream_status, latency_ms, argument_keys, arguments_sha256, result_size,
            redaction_count, credential_jti,
        )
        events.append({
            "id": str(uuid4()), "organization_id": org, "agent_id": agent_id, "seq": seq,
            "occurred_at": occurred_at, "gateway_instance": gateway_instance, "server": server,
            "method": method, "tool_name": tool_name, "decision": decision, "reasons": reasons,
            "upstream_status": upstream_status, "latency_ms": latency_ms, "argument_keys": argument_keys,
            "arguments_sha256": arguments_sha256, "result_size_bytes": result_size,
            "redaction_count": redaction_count, "credential_jti": credential_jti,
            **payloads, "prev_hash": prev, "hash": h, "batch_id": batch_id,
        })
        prev = h
        accepted += 1
        first_seq = seq if first_seq is None else first_seq
        last_seq = seq

    head["last_seq"], head["last_hash"] = seq, prev
    batches.append({
        "batch_id": batch_id, "organization_id": org, "instance_id": instance,
        "item_count": accepted, "rejected_count": rejected, "first_seq": first_seq, "last_seq": last_seq,
    })
    return {"accepted": accepted, "rejected": rejected, "first_seq": first_seq, "last_seq": last_seq, "duplicate": False}


def _verify_events(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, from_seq, to_seq = str(p["p_org"]), int(p["p_from_seq"]), int(p["p_to_seq"])
    head = next((h for h in store.tables.get("event_chain_heads", []) if h["organization_id"] == org), None)
    if head is None:
        return {"ok": True, "checked": 0}
    if to_seq < from_seq or to_seq - from_seq >= MAX_VERIFY_RANGE:
        raise _error("22023", f"range must cover at most {MAX_VERIFY_RANGE} events")
    if from_seq <= head["anchor_seq"]:
        raise _error("22023", f"range starts at or before the retained anchor (seq {head['anchor_seq']})")

    all_events = store.tables.get("agent_events", [])
    if from_seq == head["anchor_seq"] + 1:
        expected_prev = head["anchor_prev_hash"]
    else:
        predecessor = next((e for e in all_events if e["organization_id"] == org and e["seq"] == from_seq - 1), None)
        if predecessor is None:
            raise _error("22023", f"predecessor of seq {from_seq} is missing")
        expected_prev = predecessor["hash"]

    rows = sorted(
        (e for e in all_events if e["organization_id"] == org and from_seq <= e["seq"] <= to_seq),
        key=lambda e: e["seq"],
    )
    checked = 0
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {"ok": False, "broken_seq": row["seq"], "reason": "prev_hash_mismatch"}
        recomputed = _event_hash(
            row["prev_hash"], row["organization_id"], row["agent_id"], row["seq"], row["occurred_at"],
            row["gateway_instance"], row["server"], row["method"], row["tool_name"], row["decision"],
            row["reasons"], row["upstream_status"], row["latency_ms"], row["argument_keys"],
            row["arguments_sha256"], row["result_size_bytes"], row["redaction_count"], row["credential_jti"],
        )
        if recomputed != row["hash"]:
            return {"ok": False, "broken_seq": row["seq"], "reason": "hash_mismatch"}
        expected_prev = row["hash"]
        checked += 1
    return {"ok": True, "checked": checked}


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
    "control_org_budget_default": _control_org_budget_default,
    "control_blackbox_retention": _control_blackbox_retention,
    "control_payload_capture": _control_payload_capture,
    "read_event_payload": _read_event_payload,
    "audit_blackbox_export": _audit_blackbox_export,
    "control_clear_payloads": _control_clear_payloads,
    "control_honeytoken_create": _control_honeytoken_create,
    "control_honeytoken_retire": _control_honeytoken_retire,
    "control_honey_tool_create": _control_honey_tool_create,
    "control_honey_tool_retire": _control_honey_tool_retire,
    "record_trip": _record_trip,
    "record_usage": _record_usage,
    "mark_budget_frozen": _mark_budget_frozen,
    "usage_by_others": _usage_by_others,
    "org_usage": _org_usage,
    "control_agent_safe_mode": _control_agent_safe_mode,
    "control_org_safe_mode": _control_org_safe_mode,
    "telegram_link_chat": _telegram_link_chat,
    "telegram_unlink": _telegram_unlink,
    "telegram_claim_update": _telegram_claim_update,
    "record_events": _record_events,
    "verify_events": _verify_events,
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
