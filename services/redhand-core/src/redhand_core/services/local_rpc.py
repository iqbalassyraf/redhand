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
            "pin_mode": "alert",
            "pin_last_alert_at": None,
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
    before = dict(agent)
    agent["safe_mode"] = enabled
    _apply_update_triggers("agents", before, agent)  # Safe Mode off stamps the risk release, as the SQL trigger does
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


_HONEY_KINDS = ("api_key", "aws_key", "password", "canary")
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
        honeytoken_kind = None if found is None else found["kind"]
    else:
        honeytoken_kind = None
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
                 "server": str(p.get("p_server") or "")[:128], "action": action,
                 **({"kind": honeytoken_kind} if honeytoken_kind else {})},
    )
    return {"recorded": True, "label": label, "action": action, "agent_name": agent_row.get("name"), "alert": not recent,
            **({"kind": honeytoken_kind} if honeytoken_kind else {})}


_PIN_MODES = ("off", "alert", "enforce")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _pin_server(store: LocalSupabaseAdapter, org: str, server: str) -> dict[str, Any]:
    row = next(
        (s for s in store.tables.get("mcp_servers", []) if str(s.get("id")) == server and str(s.get("organization_id")) == org), None
    )
    if row is None:
        raise _error("P0002", "server not found")
    return row


def _record_tool_observation(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, server_id, tools = str(p["p_org"]), str(p["p_server"]), p["p_tools"]
    if not isinstance(tools, list) or len(tools) > 200:
        raise _error("22023", "tools must be an array of at most 200")
    server = _pin_server(store, org, server_id)
    if server.get("pin_mode", "alert") == "off":
        return {"new": 0, "changed": 0, "skipped": len(tools), "alert": False}
    pins = store.tables.setdefault("mcp_tool_pins", [])
    new = changed = skipped = 0
    for tool in tools:
        name, digest = tool.get("name"), tool.get("digest")
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or not isinstance(digest, str) or not _HEX64.match(digest):
            skipped += 1
            continue
        mine = [x for x in pins if x["server_id"] == server_id and x["tool_name"] == name]
        existing = next((x for x in mine if x["digest"] == digest), None)
        if existing is not None:
            existing["last_seen_at"] = _now()
            continue
        if len({x["tool_name"] for x in pins if x["server_id"] == server_id}) >= 500 and not mine:
            skipped += 1
            continue
        if len(mine) >= 20:
            droppable = sorted((x for x in mine if x["status"] in ("rejected", "superseded")), key=lambda x: x["last_seen_at"])
            if not droppable:
                skipped += 1
                continue
            pins.remove(droppable[0])
        kind = "changed" if any(x["status"] == "approved" for x in mine) else "new"
        rules = tool.get("rules") if isinstance(tool.get("rules"), list) else []
        pins.append({
            "id": str(uuid4()), "organization_id": org, "server_id": server_id, "tool_name": name, "digest": digest,
            "status": "pending", "change_kind": kind, "description": str(tool.get("description") or "")[:2000],
            "schema_text": str(tool.get("schema") or "")[:8000], "rules": [str(r)[:32] for r in rules][:20],
            "first_seen_at": _now(), "last_seen_at": _now(), "decided_by": None, "decided_at": None,
        })
        _append_audit(
            store, org=org, actor=_SYSTEM_ACTOR, action="tool_pin.pending", target_type="mcp_server", target_id=server_id,
            reason=None, details={"tool": name, "kind": kind, "server": server["slug"]},
        )
        if kind == "changed":
            changed += 1
        else:
            new += 1
    alert = False
    last = server.get("pin_last_alert_at")
    if new + changed > 0 and (last is None or datetime.now(timezone.utc) - datetime.fromisoformat(last) > timedelta(minutes=10)):
        server["pin_last_alert_at"] = _now()
        alert = True
    return {"new": new, "changed": changed, "skipped": skipped, "alert": alert, "server": server["slug"]}


def _control_tool_pin(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, pin_id, decision = str(p["p_org"]), str(p["p_actor"]), str(p["p_pin"]), p["p_decision"]
    if decision not in ("approve", "reject"):
        raise _error("22023", "decision must be approve or reject")
    pins = store.tables.setdefault("mcp_tool_pins", [])
    pin = next((x for x in pins if x["id"] == pin_id and x["organization_id"] == org), None)
    if pin is None:
        raise _error("P0002", "tool version not found")
    if pin["status"] != "pending":
        return {"conflict": True, "status": pin["status"]}
    if decision == "approve":
        for other in pins:
            if other["server_id"] == pin["server_id"] and other["tool_name"] == pin["tool_name"] and other["status"] == "approved":
                other["status"] = "superseded"
    pin["status"] = "approved" if decision == "approve" else "rejected"
    pin["decided_by"], pin["decided_at"] = actor, _now()
    _append_audit(
        store, org=org, actor=actor, action="tool_pin.approved" if decision == "approve" else "tool_pin.rejected",
        target_type="mcp_server", target_id=pin["server_id"], reason=p.get("p_reason"),
        details={"tool": pin["tool_name"], "kind": pin["change_kind"], "rules": pin["rules"]},
    )
    return {"conflict": False, "status": pin["status"]}


def _control_tool_pins_approve_all(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, server_id = str(p["p_org"]), str(p["p_actor"]), str(p["p_server"])
    _pin_server(store, org, server_id)
    pins = store.tables.setdefault("mcp_tool_pins", [])
    newest: dict[str, dict[str, Any]] = {}
    for pin in sorted((x for x in pins if x["server_id"] == server_id and x["status"] == "pending"), key=lambda x: x["last_seen_at"]):
        newest[pin["tool_name"]] = pin
    for name, keep in newest.items():
        for other in pins:
            if other["server_id"] != server_id or other["tool_name"] != name:
                continue
            if other["status"] == "approved":
                other["status"] = "superseded"
            elif other["status"] == "pending" and other is not keep:
                other["status"], other["decided_by"], other["decided_at"] = "rejected", actor, _now()
        keep["status"], keep["decided_by"], keep["decided_at"] = "approved", actor, _now()
    if newest:
        _append_audit(
            store, org=org, actor=actor, action="tool_pin.approved_all", target_type="mcp_server", target_id=server_id,
            reason=p.get("p_reason"), details={"tools_approved": len(newest)},
        )
    return {"approved": len(newest)}


def _control_server_pin_mode(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, server_id, mode = str(p["p_org"]), str(p["p_actor"]), str(p["p_server"]), p["p_mode"]
    if mode not in _PIN_MODES:
        raise _error("22023", "mode must be off, alert or enforce")
    server = _pin_server(store, org, server_id)
    current = server.get("pin_mode", "alert")
    if current != p.get("p_expected"):
        return {"conflict": True, "pin_mode": current}
    if current == mode:
        return {"conflict": False, "changed": False, "pin_mode": mode}
    server["pin_mode"] = mode
    _append_audit(
        store, org=org, actor=actor, action="mcp_server.pin_mode_changed", target_type="mcp_server", target_id=server_id,
        reason=p.get("p_reason"), details={"old_mode": current, "new_mode": mode, "server": server["slug"]},
    )
    return {"conflict": False, "changed": True, "pin_mode": mode}


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
        if method == "tools/call":
            _behaviour_rollup(store, org, agent_id, occurred_at, tool_name, decision)  # trg_agent_events_behaviour
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



# --- Prompt Injection Radar (Phase 4 M4.2): emulation of supabase/migrations/20261117000000_radar_findings.sql -------------

_RULE_ID = re.compile(r"^RAD-(INJ|OUT)-[0-9]{3}$")  # scan counts and readiness only know the injection and output rules
_FINDING_RULE = re.compile(r"^RAD-(INJ|OUT|LOOP|DST)-[0-9]{3}$")
_DETAIL = re.compile(r"^[a-z0-9_.:-]{1,64}$")
_HOST = re.compile(r"^[a-z0-9_.:-]{1,253}$")  # every rule a finding or a suppression may name
_LOOP_MODES = ("off", "observe", "throttle")
_FAMILY = re.compile(r"^[a-z][a-z-]{1,23}$")
_LEVELS = ("low", "medium", "high")
_PLACES = ("text", "hidden", "decoded", "call")
_EVASION = ("invisible", "lookalike", "leet", "encoded", "hidden")
_MODES_SETTABLE = ("off", "observe")


def _parse_ts(value: Any) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _org_row(store: LocalSupabaseAdapter, org: str) -> dict[str, Any]:
    row = next((o for o in store.tables.get("organizations", []) if str(o.get("id")) == org), None)
    if row is None:
        raise _error("P0002", "organization not found")
    return row


def _clamped_occurrences(value: Any) -> int:
    raw = str(value)
    if re.fullmatch(r"[0-9]{10,}", raw):
        return 1000
    if re.fullmatch(r"[0-9]{1,9}", raw):
        return min(max(int(raw), 1), 1000)
    return 1


def _record_security_findings(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, agent_id, items = str(p["p_org"]), str(p["p_agent"]), p["p_items"]
    if not isinstance(items, list) or len(items) > 20:
        raise _error("22023", "items must be an array of at most 20")
    org_row = _org_row(store, org)
    agent = _agent_of(store, org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")
    now = datetime.now(timezone.utc)
    window = datetime.fromtimestamp((int(now.timestamp()) // 300) * 300, tz=timezone.utc).isoformat()
    rows = store.tables.setdefault("security_findings", [])
    suppressions = store.tables.get("radar_suppressions", [])
    counts = {"new": 0, "coalesced": 0, "suppressed": 0, "capped": 0, "skipped": 0, "disabled": 0}
    rules: list[str] = []
    new_loop, loop_tool = 0, None
    new_dst, dst_tool, dst_detail = 0, None, None
    for item in items:
        if not isinstance(item, dict):
            counts["skipped"] += 1
            continue
        rule, kind, family = item.get("rule_id"), item.get("kind"), item.get("family")
        sev, conf, place = item.get("severity"), item.get("confidence"), item.get("place")
        expected_kind = "injection" if isinstance(rule, str) and rule.startswith("RAD-INJ-") else (
            "output" if isinstance(rule, str) and rule.startswith("RAD-OUT-") else (
                "loop" if isinstance(rule, str) and rule.startswith("RAD-LOOP-") else "destination"
            )
        )
        if (
            not isinstance(rule, str) or not _FINDING_RULE.match(rule) or kind not in ("injection", "output", "loop", "destination")
            or kind != expected_kind or not isinstance(family, str) or not _FAMILY.match(family)
            or sev not in _LEVELS or conf not in _LEVELS or place not in _PLACES or (kind in ("loop", "destination")) != (place == "call")
        ):
            counts["skipped"] += 1
            continue
        tool, server = str(item.get("tool_name") or "")[:128], str(item.get("server") or "")[:63]
        would = item.get("would_block") is True
        occurrences = _clamped_occurrences(item.get("occurrences", ""))
        raw_detail = item.get("detail")
        detail = raw_detail if kind == "destination" and isinstance(raw_detail, str) and _DETAIL.match(raw_detail) else None
        raw_evasion = item.get("evasion")
        evasion = sorted({e for e in (raw_evasion if isinstance(raw_evasion, list) else []) if e in _EVASION})
        if (
            (kind == "injection" and org_row.get("radar_mode", "observe") == "off")
            or (kind == "output" and org_row.get("output_check_mode", "observe") == "off")
            or (kind == "loop" and org_row.get("loop_mode", "observe") == "off")
            or (kind == "destination" and agent.get("destination_mode", "off") == "off")
        ):
            counts["disabled"] += 1
            continue
        if any(
            str(s["agent_id"]) == agent_id and s["rule_id"] == rule and s.get("revoked_at") is None and _parse_ts(s["expires_at"]) > now
            for s in suppressions
        ):
            counts["suppressed"] += 1
            continue
        existing = next(
            (r for r in rows if str(r["agent_id"]) == agent_id and r["rule_id"] == rule and r["tool_name"] == tool
             and r["place"] == place and r["window_start"] == window), None,
        )
        if existing is None:
            recent = [r for r in rows if str(r["agent_id"]) == agent_id and _parse_ts(r["first_seen_at"]) > now - timedelta(hours=24)]
            if len(recent) >= 2000:
                counts["capped"] += 1
                continue
            rows.append({
                "id": str(uuid4()), "organization_id": org, "agent_id": agent_id, "rule_id": rule, "family": family, "kind": kind,
                "severity": sev, "confidence": conf, "place": place, "evasion": evasion, "tool_name": tool, "server_slug": server,
                "would_block": would, "occurrences": occurrences, "window_start": window, "detail": detail, "first_seen_at": now.isoformat(),
                "last_seen_at": now.isoformat(), "review_status": "open", "reviewed_by": None, "reviewed_at": None, "review_note": None,
            })
            counts["new"] += 1
            if kind == "loop":
                new_loop += 1
                loop_tool = loop_tool if loop_tool is not None else tool
            elif kind == "destination":
                new_dst += 1
                dst_tool = dst_tool if dst_tool is not None else tool
                dst_detail = dst_detail if dst_detail is not None else detail
            elif len(rules) < 5 and rule not in rules:
                rules.append(rule)
        else:
            existing["occurrences"] = min(existing["occurrences"] + occurrences, 1_000_000)
            existing["last_seen_at"] = now.isoformat()
            existing["detail"] = existing.get("detail") if existing.get("detail") is not None else detail
            existing["would_block"] = existing["would_block"] or would
            if _LEVELS.index(sev) > _LEVELS.index(existing["severity"]):
                existing["severity"] = sev
            if _LEVELS.index(conf) > _LEVELS.index(existing["confidence"]):
                existing["confidence"] = conf
            counts["coalesced"] += 1
    # Each kind has its own 10-minute alert cooldown, so a loop alert cannot hide an injection alert (or the other way round).
    alert = loop_alert = dst_alert = False
    last = agent.get("radar_last_alert_at")
    if counts["new"] - new_loop - new_dst > 0 and (last is None or now - _parse_ts(last) > timedelta(minutes=10)):
        agent["radar_last_alert_at"] = now.isoformat()
        alert = True
    last_loop = agent.get("loop_last_alert_at")
    if new_loop > 0 and (last_loop is None or now - _parse_ts(last_loop) > timedelta(minutes=10)):
        agent["loop_last_alert_at"] = now.isoformat()
        loop_alert = True
    last_dst = agent.get("destination_last_alert_at")
    if new_dst > 0 and (last_dst is None or now - _parse_ts(last_dst) > timedelta(minutes=10)):
        agent["destination_last_alert_at"] = now.isoformat()
        dst_alert = True
    return {
        **counts, "alert": alert, "agent": agent.get("name"), "rules": rules,
        "loop_new": new_loop, "loop_alert": loop_alert, "loop_tool": loop_tool,
        "destination_new": new_dst, "destination_alert": dst_alert, "destination_tool": dst_tool,
        "destination_detail": dst_detail, "destination_mode": agent.get("destination_mode", "off"),
    }


def _destination_settings(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, agent_id = str(p["p_org"]), str(p["p_agent"])
    agent = _agent_of(store, org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")
    entries = sorted(
        (e for e in store.tables.get("agent_destinations", []) if str(e["organization_id"]) == org and str(e["agent_id"]) == agent_id),
        key=lambda e: e["host"],
    )
    since = datetime.now(timezone.utc) - timedelta(days=7)
    mine = [
        f for f in store.tables.get("security_findings", [])
        if str(f["organization_id"]) == org and str(f["agent_id"]) == agent_id and f["kind"] == "destination"
        and _parse_ts(f["last_seen_at"]) > since
    ]
    return {
        "destination_mode": agent.get("destination_mode", "off"), "destination_mode_changed_at": agent.get("destination_mode_changed_at"),
        "entries": [{"id": e["id"], "host": e["host"], "created_at": e["created_at"]} for e in entries],
        "last_7_days": {"findings": len(mine), "occurrences": sum(f["occurrences"] for f in mine),
                        "open": sum(1 for f in mine if f["review_status"] == "open")},
    }


def _control_destination_add(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, agent_id, host, reason = str(p["p_org"]), str(p["p_actor"]), str(p["p_agent"]), p["p_host"], p.get("p_reason")
    if not isinstance(host, str) or not _HOST.match(host) or (reason is not None and len(reason) > 300):
        raise _error("22023", "a normalized host of 1 to 253 characters is required")
    if _agent_of(store, org, agent_id) is None:
        raise _error("P0002", "agent not found")
    rows = store.tables.setdefault("agent_destinations", [])
    mine = [e for e in rows if str(e["agent_id"]) == agent_id]
    existing = next((e for e in mine if e["host"] == host), None)
    if existing is not None:
        return {"added": False, "id": existing["id"]}
    if len(mine) >= 100:
        return {"added": False, "limit": True}
    entry_id = str(uuid4())
    rows.append({"id": entry_id, "organization_id": org, "agent_id": agent_id, "host": host, "created_by": actor, "created_at": _now()})
    _append_audit(
        store, org=org, actor=actor, action="passport.destination_added", target_type="agent", target_id=agent_id, reason=reason,
        details={"host": host, "entry": entry_id},
    )
    return {"added": True, "id": entry_id}


def _control_destination_remove(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, agent_id, entry_id, reason = str(p["p_org"]), str(p["p_actor"]), str(p["p_agent"]), str(p["p_entry"]), p.get("p_reason")
    if reason is not None and len(reason) > 300:
        raise _error("22023", "the reason is at most 300 characters")
    agent = _agent_of(store, org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")
    rows = store.tables.setdefault("agent_destinations", [])
    entry = next((e for e in rows if str(e["id"]) == entry_id and str(e["agent_id"]) == agent_id and str(e["organization_id"]) == org), None)
    if entry is None:
        raise _error("P0002", "entry not found")
    if agent.get("destination_mode", "off") == "enforce" and sum(1 for e in rows if str(e["agent_id"]) == agent_id) <= 1:
        return {"removed": False, "last_entry_in_enforce": True}
    rows.remove(entry)
    _append_audit(
        store, org=org, actor=actor, action="passport.destination_removed", target_type="agent", target_id=agent_id, reason=reason,
        details={"host": entry["host"], "entry": entry_id},
    )
    return {"removed": True}


def _control_destination_mode(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, agent_id, mode, reason = str(p["p_org"]), str(p["p_actor"]), str(p["p_agent"]), p["p_mode"], p.get("p_reason")
    if mode not in ("off", "observe", "enforce") or (reason is not None and len(reason) > 300):
        raise _error("22023", "mode must be off, observe or enforce")
    agent = _agent_of(store, org, agent_id)
    if agent is None:
        raise _error("P0002", "agent not found")
    current = agent.get("destination_mode", "off")
    if current != p.get("p_expected_mode"):
        return {"conflict": True, "destination_mode": current}
    if current == mode:
        return {"conflict": False, "changed": False, "destination_mode": mode}
    if mode == "enforce" and not any(str(e["agent_id"]) == agent_id for e in store.tables.get("agent_destinations", [])):
        return {"conflict": False, "changed": False, "empty_list": True, "destination_mode": current}
    agent["destination_mode"], agent["destination_mode_changed_at"] = mode, _now()
    _append_audit(
        store, org=org, actor=actor, action="passport.destination_mode_changed", target_type="agent", target_id=agent_id, reason=reason,
        details={"old_mode": current, "new_mode": mode},
    )
    return {"conflict": False, "changed": True, "destination_mode": mode}


def _control_loop_settings(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    mode, limit, window, reason = p["p_mode"], p["p_limit"], p["p_window"], p.get("p_reason")
    if (
        mode not in _LOOP_MODES or not isinstance(limit, int) or isinstance(limit, bool) or not 3 <= limit <= 1000
        or not isinstance(window, int) or isinstance(window, bool) or not 10 <= window <= 600 or (reason is not None and len(reason) > 300)
    ):
        raise _error("22023", "mode must be off, observe or throttle, the limit 3 to 1000, the window 10 to 600 seconds")
    row = _org_row(store, org)
    cur = (row.get("loop_mode", "observe"), row.get("loop_limit", 20), row.get("loop_window_seconds", 60))
    if cur != (p.get("p_expected_mode"), p.get("p_expected_limit"), p.get("p_expected_window")):
        return {"conflict": True, "loop_mode": cur[0], "loop_limit": cur[1], "loop_window_seconds": cur[2]}
    if cur == (mode, limit, window):
        return {"conflict": False, "changed": False, "loop_mode": mode, "loop_limit": limit, "loop_window_seconds": window}
    if cur[0] != mode:
        row["loop_mode_changed_at"] = _now()
    row["loop_mode"], row["loop_limit"], row["loop_window_seconds"] = mode, limit, window
    _append_audit(
        store, org=org, actor=actor, action="organization.loop_settings_changed", target_type="organization", target_id=org, reason=reason,
        details={"old_mode": cur[0], "new_mode": mode, "old_limit": cur[1], "new_limit": limit,
                 "old_window_seconds": cur[2], "new_window_seconds": window},
    )
    return {"conflict": False, "changed": True, "loop_mode": mode, "loop_limit": limit, "loop_window_seconds": window}


def _loop_settings(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org = str(p["p_org"])
    row = _org_row(store, org)
    since = datetime.now(timezone.utc) - timedelta(days=7)
    mine = [
        f for f in store.tables.get("security_findings", [])
        if str(f["organization_id"]) == org and f["kind"] == "loop" and _parse_ts(f["last_seen_at"]) > since
    ]
    last7: dict[str, Any] = {"findings": len(mine), "occurrences": sum(f["occurrences"] for f in mine),
                             "open": sum(1 for f in mine if f["review_status"] == "open")}
    return {
        "loop_mode": row.get("loop_mode", "observe"), "loop_limit": row.get("loop_limit", 20),
        "loop_window_seconds": row.get("loop_window_seconds", 60), "loop_mode_changed_at": row.get("loop_mode_changed_at"),
        "last_7_days": last7,
    }


def _control_radar_settings(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    injection, output = p["p_injection"], p["p_output"]
    if injection not in _MODES_SETTABLE or output not in _MODES_SETTABLE:
        raise _error("22023", "mode must be off or observe (block is not available yet)")
    row = _org_row(store, org)
    cur_i, cur_o = row.get("radar_mode", "observe"), row.get("output_check_mode", "observe")
    if cur_i != p.get("p_expected_injection") or cur_o != p.get("p_expected_output"):
        return {"conflict": True, "radar_mode": cur_i, "output_check_mode": cur_o}
    if cur_i == injection and cur_o == output:
        return {"conflict": False, "changed": False, "radar_mode": injection, "output_check_mode": output}
    now = _now()
    if cur_i != injection:
        row["radar_mode_changed_at"] = now
    if cur_o != output:
        row["output_check_mode_changed_at"] = now
    row["radar_mode"], row["output_check_mode"] = injection, output
    _append_audit(
        store, org=org, actor=actor, action="organization.radar_settings_changed", target_type="organization", target_id=org,
        reason=p.get("p_reason"), details={"old_injection": cur_i, "new_injection": injection, "old_output": cur_o, "new_output": output},
    )
    return {"conflict": False, "changed": True, "radar_mode": injection, "output_check_mode": output}


def _control_finding_review(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, finding_id, status = str(p["p_org"]), str(p["p_actor"]), str(p["p_finding"]), p["p_status"]
    note = p.get("p_note")
    if status not in ("confirmed", "false_alarm") or (note is not None and len(note) > 300):
        raise _error("22023", "status must be confirmed or false_alarm and the note at most 300 characters")
    row = next(
        (r for r in store.tables.get("security_findings", []) if str(r["id"]) == finding_id and str(r["organization_id"]) == org), None
    )
    if row is None:
        raise _error("P0002", "finding not found")
    if row["review_status"] != p.get("p_expected"):
        return {"conflict": True, "review_status": row["review_status"]}
    if row["review_status"] == status:
        return {"conflict": False, "changed": False, "review_status": status}
    old = row["review_status"]
    row.update({"review_status": status, "reviewed_by": actor, "reviewed_at": _now(), "review_note": note})
    _append_audit(
        store, org=org, actor=actor, action="radar_finding.reviewed", target_type="organization", target_id=org, reason=note,
        details={"finding": finding_id, "rule": row["rule_id"], "agent": str(row["agent_id"]), "old_status": old, "new_status": status},
    )
    return {"conflict": False, "changed": True, "review_status": status}


def _control_radar_suppression_create(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, agent_id = str(p["p_org"]), str(p["p_actor"]), str(p["p_agent"])
    rule, days, reason = p["p_rule"], p["p_days"], p["p_reason"]
    if (
        not isinstance(rule, str) or not _FINDING_RULE.match(rule) or not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 90
        or not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 300
    ):
        raise _error("22023", "a rule id, 1 to 90 days and a reason of 3 to 300 characters are required")
    if _agent_of(store, org, agent_id) is None:
        raise _error("P0002", "agent not found")
    now = datetime.now(timezone.utc)
    rows = store.tables.setdefault("radar_suppressions", [])
    existing = next((s for s in rows if str(s["agent_id"]) == agent_id and s["rule_id"] == rule and s.get("revoked_at") is None), None)
    if existing is not None:
        if _parse_ts(existing["expires_at"]) > now:
            return {"created": False, "id": existing["id"], "expires_at": existing["expires_at"]}
        existing["revoked_at"], existing["revoked_by"] = now.isoformat(), actor
    live = [s for s in rows if str(s["organization_id"]) == org and s.get("revoked_at") is None and _parse_ts(s["expires_at"]) > now]
    if len(live) >= 100:
        return {"created": False, "limit": True}
    sid, expires = str(uuid4()), (now + timedelta(days=days)).isoformat()
    rows.append({
        "id": sid, "organization_id": org, "agent_id": agent_id, "rule_id": rule, "reason": reason.strip(), "created_by": actor,
        "created_at": now.isoformat(), "expires_at": expires, "revoked_at": None, "revoked_by": None,
    })
    _append_audit(
        store, org=org, actor=actor, action="radar_suppression.created", target_type="agent", target_id=agent_id, reason=reason.strip(),
        details={"suppression": sid, "rule": rule, "days": days},
    )
    return {"created": True, "id": sid, "expires_at": expires}


def _control_radar_suppression_revoke(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor, sid = str(p["p_org"]), str(p["p_actor"]), str(p["p_suppression"])
    row = next((s for s in store.tables.get("radar_suppressions", []) if str(s["id"]) == sid and str(s["organization_id"]) == org), None)
    if row is None:
        raise _error("P0002", "suppression not found")
    if row.get("revoked_at") is not None:
        return {"revoked": False}
    row["revoked_at"], row["revoked_by"] = _now(), actor
    _append_audit(
        store, org=org, actor=actor, action="radar_suppression.revoked", target_type="agent", target_id=str(row["agent_id"]),
        reason=p.get("p_reason"), details={"suppression": sid, "rule": row["rule_id"]},
    )
    return {"revoked": True}


def _radar_summary(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org = str(p["p_org"])
    row = _org_row(store, org)
    since = datetime.now(timezone.utc) - timedelta(days=7)
    mine = [
        f for f in store.tables.get("security_findings", [])
        if str(f["organization_id"]) == org and f["kind"] in ("injection", "output") and _parse_ts(f["last_seen_at"]) > since
    ]
    last7: dict[str, Any] = {}
    if mine:
        last7 = {
            "findings": len(mine), "occurrences": sum(f["occurrences"] for f in mine),
            "would_block": sum(1 for f in mine if f["would_block"]),
            "open": sum(1 for f in mine if f["review_status"] == "open"),
            "confirmed": sum(1 for f in mine if f["review_status"] == "confirmed"),
            "false_alarm": sum(1 for f in mine if f["review_status"] == "false_alarm"),
            "would_block_open": sum(1 for f in mine if f["would_block"] and f["review_status"] == "open"),
        }
    return {
        "radar_mode": row.get("radar_mode", "observe"), "output_check_mode": row.get("output_check_mode", "observe"),
        "radar_mode_changed_at": row.get("radar_mode_changed_at"), "output_check_mode_changed_at": row.get("output_check_mode_changed_at"),
        "last_7_days": last7,
    }


# --- Radar evidence from real traffic (Phase 4 M4.6b): emulation of supabase/migrations/20261118000000_radar_scan_counts.sql -----------

_FINGERPRINT = re.compile(r"^(unknown|[0-9a-f]{16}(\+model)?)$")
_UUID_TEXT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_MAX_SCAN_COUNT = 1_000_000


def _count_of(value: Any, maximum: int) -> int | None:
    """Mirrors radar_count_of(): the json value as text must be plain digits (a numeric string passes, a float or a bool does not)."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    text = str(value)
    return min(int(text), maximum) if re.fullmatch(r"[0-9]{1,18}", text) else None


def _scan_count_item(item: Any, org_ids: set[str]) -> dict[str, Any] | None:
    """The validated item, or None when it must be skipped whole (see record_radar_scan_counts in SQL)."""
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    scanned, dropped, errors, flagged, strong = (
        _count_of(item.get(k), _MAX_SCAN_COUNT) for k in ("scanned", "dropped", "errors", "flagged", "strong")
    )
    rules = item.get("rules", [])
    org = item.get("organization_id")
    if (
        kind not in ("injection", "output") or None in (scanned, dropped, errors, flagged, strong)
        or not isinstance(org, str) or not _UUID_TEXT.match(org) or not isinstance(rules, list) or len(rules) > 40
    ):
        return None
    assert scanned is not None and flagged is not None and strong is not None and dropped is not None and errors is not None
    if flagged > scanned or strong > flagged or org.lower() not in org_ids:
        return None
    clean_rules: list[dict[str, Any]] = []
    for rule in rules:
        rid = rule.get("rule_id") if isinstance(rule, dict) else None
        rf = _count_of(rule.get("flagged"), _MAX_SCAN_COUNT) if isinstance(rule, dict) else None
        rs = _count_of(rule.get("strong"), _MAX_SCAN_COUNT) if isinstance(rule, dict) else None
        if (
            not isinstance(rid, str) or not _RULE_ID.match(rid) or (kind == "injection") != rid.startswith("RAD-INJ-")
            or rf is None or rs is None or rf > scanned or rs > rf
        ):
            return None
        clean_rules.append({"rule_id": rid, "flagged": rf, "strong": rs})
    return {
        "organization_id": org.lower(), "kind": kind, "scanned": scanned, "dropped": dropped, "errors": errors,
        "flagged": flagged, "strong": strong, "rules": clean_rules,
    }


def _record_radar_scan_counts(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    report_id, fingerprint, items = p.get("p_report_id"), p["p_fingerprint"], p["p_items"]
    if report_id is None:
        raise _error("22023", "a report id is required")
    if not isinstance(items, list) or len(items) > 50:
        raise _error("22023", "items must be an array of at most 50")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.match(fingerprint):
        raise _error("22023", "invalid rules fingerprint")
    seen_reports = store.tables.setdefault("radar_count_reports", [])
    if any(r["report_id"] == str(report_id) for r in seen_reports):
        return {"recorded": 0, "skipped": 0, "duplicate": True}  # a retry or a double delivery: already counted
    seen_reports.append({"report_id": str(report_id), "received_at": _now()})
    org_ids = {str(o.get("id")).lower() for o in store.tables.get("organizations", [])}
    day = datetime.now(timezone.utc).date().isoformat()
    scan_rows = store.tables.setdefault("radar_scan_counts", [])
    rule_rows = store.tables.setdefault("radar_rule_counts", [])
    recorded = skipped = 0
    for raw in items:
        item = _scan_count_item(raw, org_ids)
        if item is None:
            skipped += 1
            continue
        key = {"organization_id": item["organization_id"], "day": day, "kind": item["kind"], "rules_fingerprint": fingerprint}
        row = next((r for r in scan_rows if all(r[k] == v for k, v in key.items())), None)
        if row is None:
            row = {**key, "scanned": 0, "dropped": 0, "errors": 0, "flagged": 0, "strong": 0}
            scan_rows.append(row)
        for field in ("scanned", "dropped", "errors", "flagged", "strong"):
            row[field] += item[field]
        for rule in item["rules"]:
            rkey = {"organization_id": item["organization_id"], "day": day, "rule_id": rule["rule_id"], "rules_fingerprint": fingerprint}
            rrow = next((r for r in rule_rows if all(r[k] == v for k, v in rkey.items())), None)
            if rrow is None:
                rrow = {**rkey, "flagged": 0, "strong": 0}
                rule_rows.append(rrow)
            rrow["flagged"] += rule["flagged"]
            rrow["strong"] += rule["strong"]
        recorded += 1
    return {"recorded": recorded, "skipped": skipped, "duplicate": False}


def _radar_readiness_inputs(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org = str(p["p_org"])
    row = _org_row(store, org)
    now = datetime.now(timezone.utc)
    first = now.date() - timedelta(days=6)
    window_start = datetime(first.year, first.month, first.day, tzinfo=timezone.utc)
    mine_counts = [c for c in store.tables.get("radar_scan_counts", []) if c["organization_id"] == org.lower() and date.fromisoformat(c["day"]) >= first]
    mine_rules = [c for c in store.tables.get("radar_rule_counts", []) if c["organization_id"] == org.lower() and date.fromisoformat(c["day"]) >= first]
    findings = [
        f for f in store.tables.get("security_findings", [])
        if str(f["organization_id"]) == org and _parse_ts(f["window_start"]) >= window_start
    ]
    silences = [s for s in store.tables.get("radar_suppressions", []) if str(s["organization_id"]) == org]
    per_agent_day: dict[tuple[str, date], int] = {}
    for f in findings:
        key = (str(f["agent_id"]), _parse_ts(f["window_start"]).date())
        per_agent_day[key] = per_agent_day.get(key, 0) + 1
    kinds: dict[str, Any] = {}
    for kind, prefix, mode_key, changed_key in (
        ("injection", "RAD-INJ-", "radar_mode", "radar_mode_changed_at"),
        ("output", "RAD-OUT-", "output_check_mode", "output_check_mode_changed_at"),
    ):
        mine = [c for c in mine_counts if c["kind"] == kind]
        rules: dict[str, dict[str, int]] = {}
        for rr in mine_rules:
            if rr["rule_id"].startswith(prefix):
                slot = rules.setdefault(rr["rule_id"], {"flagged": 0, "strong": 0})
                slot["flagged"] += rr["flagged"]
                slot["strong"] += rr["strong"]
        kind_findings = [f for f in findings if f["kind"] == kind]
        stored: dict[str, int] = {}
        for f in kind_findings:
            stored[f["rule_id"]] = stored.get(f["rule_id"], 0) + f["occurrences"]
        kinds[kind] = {
            "mode": row.get(mode_key, "observe"), "mode_changed_at": row.get(changed_key),
            **{field: sum(c[field] for c in mine) for field in ("scanned", "dropped", "errors", "flagged", "strong")},
            "fingerprints": sorted({c["rules_fingerprint"] for c in mine}),
            "rules": rules, "stored_occurrences": stored,
            "strong_open": sum(1 for f in kind_findings if f["would_block"] and f["review_status"] == "open"),
            "false_alarm_rules": sorted({f["rule_id"] for f in kind_findings if f["would_block"] and f["review_status"] == "false_alarm"}),
            "silences_in_window": sum(
                1 for s in silences
                if s["rule_id"].startswith(prefix) and _parse_ts(s["expires_at"]) >= window_start
                and (s.get("revoked_at") is None or _parse_ts(s["revoked_at"]) >= window_start)
            ),
            "max_findings_per_agent_day": max(per_agent_day.values(), default=0),
        }
    return {"now": now.isoformat(), "window_start": window_start.isoformat(), "kinds": kinds}


# --- Risk Engine (Phase 4.5 B1): emulation of supabase/migrations/20261122000000_risk_engine.sql ------------------------------------

_SCOPE_REFUSAL = "is not in this agent's passport scopes."
_PIN_REFUSAL = "is not approved: its current version has not been reviewed."


def _agent_risk_signals(store: LocalSupabaseAdapter, p: dict[str, Any]) -> list[dict[str, Any]]:
    org = str(p["p_org"])
    only = str(p["p_agent"]) if p.get("p_agent") else None
    now = _parse_ts(p["p_now"])
    week, day = now - timedelta(days=7), now - timedelta(hours=24)
    agents = {
        str(a["id"]): (_parse_ts(a["risk_released_at"]) if a.get("risk_released_at") else None)
        for a in store.tables.get("agents", []) if str(a.get("organization_id")) == org and (only is None or str(a["id"]) == only)
    }
    live = {
        (str(s["agent_id"]), s["rule_id"]) for s in store.tables.get("radar_suppressions", [])
        if s.get("revoked_at") is None and _parse_ts(s["expires_at"]) > now
    }
    events: list[tuple[str, str, datetime]] = []
    for t in store.tables.get("honeytrips", []):
        at = _parse_ts(t["occurred_at"])
        if str(t["organization_id"]) == org and str(t["agent_id"]) in agents and week < at <= now:
            events.append((str(t["agent_id"]), "trip", at))
    for f in store.tables.get("security_findings", []):
        at = _parse_ts(f["last_seen_at"])
        agent = str(f["agent_id"])
        if str(f["organization_id"]) != org or agent not in agents or not week < at <= now:
            continue
        if f["review_status"] == "confirmed":
            events.append((agent, "confirmed_finding", at))
        elif f["review_status"] == "open" and f["confidence"] != "low" and (agent, f["rule_id"]) not in live:
            signal = {"destination": "destination_open", "loop": "loop_open"}.get(f["kind"], "radar_open")
            events.append((agent, signal, at))
    for e in store.tables.get("agent_events", []):
        at = _parse_ts(e["occurred_at"])
        if (str(e["organization_id"]) == org and str(e["agent_id"]) in agents and e["decision"] == "BLOCK" and week < at <= now
                and any(str(r).endswith((_SCOPE_REFUSAL, _PIN_REFUSAL)) for r in e.get("reasons") or [])):
            events.append((str(e["agent_id"]), "refusal", at))
    for b in store.tables.get("agent_budget_state", []):
        if str(b["agent_id"]) in agents and b.get("limit_reached_at"):
            at = _parse_ts(b["limit_reached_at"])
            if day < at <= now:
                events.append((str(b["agent_id"]), "budget_limit", at))
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for agent, signal, at in events:
        row = rows.setdefault((agent, signal), {"agent_id": agent, "signal": signal, "recent_all": 0, "older_all": 0,
                                                "recent_action": 0, "older_action": 0})
        bucket = "recent" if at > day else "older"
        row[f"{bucket}_all"] += 1
        released = agents[agent]
        if released is None or at > released:
            row[f"{bucket}_action"] += 1
    return list(rows.values())


def _control_risk_ladder(store: LocalSupabaseAdapter, p: dict[str, Any]) -> dict[str, Any]:
    org, actor = str(p["p_org"]), str(p["p_actor"])
    row = _org_row(store, org)
    new = {"alert": p.get("p_alert"), "safe_mode": p.get("p_safe_mode"), "freeze": p.get("p_freeze")}
    values = [v for v in new.values() if v is not None]
    if any(not 1 <= int(v) <= 100 for v in values) or values != sorted(values):
        raise _error("23514", "new row for relation organizations violates check constraint organizations_risk_ladder_order")
    old = {"alert": row.get("risk_alert_threshold"), "safe_mode": row.get("risk_safe_mode_threshold"), "freeze": row.get("risk_freeze_threshold")}
    if old == new:
        return {"changed": False, "ladder": new}
    row["risk_alert_threshold"], row["risk_safe_mode_threshold"], row["risk_freeze_threshold"] = new["alert"], new["safe_mode"], new["freeze"]
    _append_audit(store, org=org, actor=actor, action="organization.risk_ladder_changed", target_type="organization", target_id=org,
                  reason=p.get("p_reason"), details={"old": old, "new": new})
    return {"changed": True, "ladder": new}


def _risk_mark_alerted(store: LocalSupabaseAdapter, p: dict[str, Any]) -> bool:
    agent = _find(store, "agents", str(p["p_org"]), str(p["p_agent"]))
    if agent is None:
        return False
    now = datetime.now(timezone.utc)
    last = agent.get("risk_last_alert_at")
    if last is not None and _parse_ts(last) > now - timedelta(seconds=int(p["p_cooldown_seconds"])):
        return False
    agent["risk_last_alert_at"] = now.isoformat()
    return True


# --- Behaviour baseline (Phase 4.5 B2): emulation of supabase/migrations/20261123000000_behaviour_baseline.sql -------------------------

def _utc_hour(value: Any) -> datetime:
    return _parse_ts(value).astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def _behaviour_rollup(store: LocalSupabaseAdapter, org: str, agent_id: str, occurred_at: Any, tool_name: str, decision: Any) -> None:
    hour, tool = _utc_hour(occurred_at), str(tool_name)[:128]
    rows = store.tables.setdefault("agent_tool_hourly", [])
    row = next((r for r in rows if r["agent_id"] == agent_id and r["hour"] == hour and r["tool_name"] == tool), None)
    if row is None:
        row = {"organization_id": org, "agent_id": agent_id, "hour": hour, "tool_name": tool, "calls": 0, "refused": 0}
        rows.append(row)
    row["calls"] += 1
    row["refused"] += 1 if decision == "BLOCK" else 0


def _agent_behaviour_hours(store: LocalSupabaseAdapter, p: dict[str, Any]) -> list[dict[str, Any]]:
    org, only = str(p["p_org"]), (str(p["p_agent"]) if p.get("p_agent") else None)
    since, until = _parse_ts(p["p_since"]), _parse_ts(p["p_until"])
    rows = [
        r for r in store.tables.get("agent_tool_hourly", [])
        if r["organization_id"] == org and (only is None or r["agent_id"] == only) and since <= r["hour"] <= until
    ]
    rows.sort(key=lambda r: (r["agent_id"], r["hour"]))
    return [{"agent_id": r["agent_id"], "hour": r["hour"].isoformat(), "tool_name": r["tool_name"], "calls": r["calls"]} for r in rows]


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
    "record_tool_observation": _record_tool_observation,
    "control_tool_pin": _control_tool_pin,
    "control_tool_pins_approve_all": _control_tool_pins_approve_all,
    "control_server_pin_mode": _control_server_pin_mode,
    "record_security_findings": _record_security_findings,
    "control_radar_settings": _control_radar_settings,
    "control_finding_review": _control_finding_review,
    "control_radar_suppression_create": _control_radar_suppression_create,
    "control_radar_suppression_revoke": _control_radar_suppression_revoke,
    "radar_summary": _radar_summary,
    "control_loop_settings": _control_loop_settings,
    "destination_settings": _destination_settings,
    "control_destination_add": _control_destination_add,
    "control_destination_remove": _control_destination_remove,
    "control_destination_mode": _control_destination_mode,
    "loop_settings": _loop_settings,
    "record_radar_scan_counts": _record_radar_scan_counts,
    "radar_readiness_inputs": _radar_readiness_inputs,
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
    "agent_risk_signals": _agent_risk_signals,
    "control_risk_ladder": _control_risk_ladder,
    "risk_mark_alerted": _risk_mark_alerted,
    "agent_behaviour_hours": _agent_behaviour_hours,
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
