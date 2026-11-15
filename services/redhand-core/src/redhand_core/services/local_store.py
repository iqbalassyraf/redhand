"""
RedHand Core - Dual-Mode Local Durable Store & Realtime Event Broadcaster
File: services/redhand-core/src/redhand_core/services/local_store.py

Provides a zero-config, Supabase-API-compatible durable store (`table().select/insert/upsert/update`)
backed by an in-memory + JSON-checkpointed state engine AND a real-time asyncio pub/sub
event bus for Server-Sent Events (SSE).

When `SUPABASE_URL` is set to a live Supabase project, `redhand-core` uses the remote
Supabase PostgREST client; when running locally with placeholder credentials, it
automatically uses `LocalSupabaseAdapter` so the entire platform works out-of-the-box.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from redhand_core.services.local_rpc import LocalRpcBuilder

logger = logging.getLogger("redhand.core.local_store")

DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000010"


def _sort_key(value: Any) -> Any:
    """Numeric columns (e.g. seq) sort by value, not lexically ("10" < "2"); everything else by text."""
    try:
        return (0, float(value))
    except (TypeError, ValueError):
        return (1, str(value or ""))


def _comparable(value: Any) -> Any:
    """Numbers compare as numbers, ISO timestamps as instants, everything else as text."""
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return str(value)


_ORDERING = {
    "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b, "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b,
}


def _matches_filters(row: dict[str, Any], filters: list[tuple[str, str, Any]]) -> bool:
    for column, op, value in filters:
        current: Any = row.get(column)
        if op in _ORDERING:
            try:
                if not _ORDERING[op](_comparable(current), _comparable(value)):
                    return False
            except TypeError:
                return False
        elif str(current) != str(value):
            return False
    return True


DEFAULT_DEV_API_KEY = "rh_dev_local_key"

# Development operators for the local store. They exist only in the in-memory store,
# which redhand-core refuses to use outside development/test.
DEV_OPERATORS: dict[str, dict[str, str]] = {
    "owner": {"id": "00000000-0000-0000-0000-0000000000a1", "email": "owner@dev.local", "role": "owner"},
    "admin": {"id": "00000000-0000-0000-0000-0000000000a2", "email": "admin@dev.local", "role": "admin"},
    "operator": {"id": "00000000-0000-0000-0000-0000000000a3", "email": "operator@dev.local", "role": "security_operator"},
    "operator2": {"id": "00000000-0000-0000-0000-0000000000a4", "email": "operator2@dev.local", "role": "security_operator"},
    "viewer": {"id": "00000000-0000-0000-0000-0000000000a5", "email": "viewer@dev.local", "role": "viewer"},
}


@dataclass(slots=True)
class QueryResult:
    data: Any


class LocalTableQueryBuilder:
    """
    Implements the fluent async PostgREST builder interface used across RedHand routers:
    `.select()`, `.insert()`, `.upsert()`, `.update()`, `.eq()`, `.maybe_single()`, `.execute()`.
    """

    def __init__(self, store: LocalSupabaseAdapter, table_name: str) -> None:
        self._store = store
        self._table_name = table_name
        self._operation: str = "select"
        self._payload: Any = None
        self._on_conflict: str | None = None
        self._filters: list[tuple[str, str, Any]] = []  # (column, op, value); op is "eq" or "lt"
        self._maybe_single: bool = False
        self._columns: tuple[str, ...] | None = None  # None means every column ("*" or a form this twin does not project)
        self._order: tuple[str, bool] | None = None
        self._limit: int | None = None

    def select(self, columns: str = "*") -> LocalTableQueryBuilder:
        self._operation = "select"
        self._columns = _selected_columns(columns)
        return self

    def insert(self, rows: dict[str, Any] | list[dict[str, Any]]) -> LocalTableQueryBuilder:
        self._operation = "insert"
        self._payload = rows if isinstance(rows, list) else [rows]
        return self

    def upsert(
        self,
        rows: dict[str, Any] | list[dict[str, Any]],
        on_conflict: str | None = None,
    ) -> LocalTableQueryBuilder:
        self._operation = "upsert"
        self._payload = rows if isinstance(rows, list) else [rows]
        self._on_conflict = on_conflict
        return self

    def update(self, values: dict[str, Any]) -> LocalTableQueryBuilder:
        self._operation = "update"
        self._payload = values
        return self

    def eq(self, column: str, value: Any) -> LocalTableQueryBuilder:
        self._filters.append((column, "eq", value))
        return self

    def lt(self, column: str, value: Any) -> LocalTableQueryBuilder:
        self._filters.append((column, "lt", value))
        return self

    def lte(self, column: str, value: Any) -> LocalTableQueryBuilder:
        self._filters.append((column, "lte", value))
        return self

    def gt(self, column: str, value: Any) -> LocalTableQueryBuilder:
        self._filters.append((column, "gt", value))
        return self

    def gte(self, column: str, value: Any) -> LocalTableQueryBuilder:
        self._filters.append((column, "gte", value))
        return self

    def maybe_single(self) -> LocalTableQueryBuilder:
        self._maybe_single = True
        return self

    def order(self, column: str, *, desc: bool = False) -> LocalTableQueryBuilder:
        self._order = (column, desc)
        return self

    def limit(self, size: int) -> LocalTableQueryBuilder:
        self._limit = size
        return self

    async def execute(self) -> QueryResult:
        rows = self._store.tables.setdefault(self._table_name, [])

        if self._operation == "select":
            matched = [dict(r) for r in rows if _matches_filters(r, self._filters)]
            if self._order is not None:
                column, desc = self._order
                matched.sort(key=lambda r: _sort_key(r.get(column)), reverse=desc)
            if self._limit is not None:
                matched = matched[: self._limit]
            if self._columns is not None:
                # Like PostgREST: a column that was not selected is simply not in the answer. Without this, code that reads a column it
                # never selected passes here and fails in production (the budget day ignored the organization's offset that way).
                matched = [{c: r[c] for c in self._columns if c in r} for r in matched]
            if self._maybe_single:
                return QueryResult(data=matched[0] if matched else None)
            return QueryResult(data=matched)

        if self._operation == "insert":
            inserted: list[dict[str, Any]] = []
            for item in self._payload:
                row = dict(item)
                row.setdefault("id", str(uuid4()))
                row.setdefault("created_at", datetime.now(timezone.utc).isoformat())
                apply_insert_defaults(self._table_name, row)
                rows.insert(0, row)
                inserted.append(dict(row))
            self._store.publish_event(
                event_type=f"{self._table_name}.inserted",
                payload=inserted,
            )
            return QueryResult(data=inserted)

        if self._operation == "upsert":
            conflict_cols = (
                [c.strip() for c in self._on_conflict.split(",")]
                if self._on_conflict
                else ["id"]
            )
            upserted: list[dict[str, Any]] = []
            for item in self._payload:
                row = dict(item)
                existing = next(
                    (
                        r
                        for r in rows
                        if all(
                            r.get(c) is not None and str(r.get(c)) == str(row.get(c))
                            for c in conflict_cols
                        )
                    ),
                    None,
                )
                if existing is not None:
                    existing.update(row)
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    upserted.append(dict(existing))
                else:
                    row.setdefault("id", str(uuid4()))
                    row.setdefault("status", "active")
                    row.setdefault("created_at", datetime.now(timezone.utc).isoformat())
                    apply_insert_defaults(self._table_name, row)
                    rows.insert(0, row)
                    upserted.append(dict(row))

            self._store.publish_event(
                event_type=f"{self._table_name}.upserted",
                payload=upserted,
            )
            return QueryResult(data=upserted)

        if self._operation == "update":
            if self._table_name in APPEND_ONLY_TABLES:
                raise LocalStoreConstraintError(f"{self._table_name} is append-only")
            targets = [r for r in rows if _matches_filters(r, self._filters)]
            # Validate every row first so a rejected update changes nothing, like a
            # single SQL statement would.
            for r in targets:
                _check_update_rules(self._table_name, r, self._payload)
            updated: list[dict[str, Any]] = []
            for r in targets:
                before = dict(r)
                r.update(self._payload)
                _apply_update_triggers(self._table_name, before, r)
                r["updated_at"] = datetime.now(timezone.utc).isoformat()
                updated.append(dict(r))
            self._store.publish_event(
                event_type=f"{self._table_name}.updated",
                payload=updated,
            )
            return QueryResult(data=updated)

        return QueryResult(data=[])


# -----------------------------------------------------------------------------
# Database rules mirrored from supabase/migrations/20261101000000_phase1_passport.sql
# so the local store behaves like Postgres for the rules redhand-core relies on.
# -----------------------------------------------------------------------------

APPEND_ONLY_TABLES = frozenset({"control_audit_log"})


def _selected_columns(columns: str) -> tuple[str, ...] | None:
    """The plain column names of a select list, or None for "*" and for forms with embedded relations or casts (not projected)."""
    text = columns.strip()
    if text in ("", "*") or any(ch in text for ch in "(:!>"):
        return None
    names = tuple(part.strip() for part in text.split(",") if part.strip())
    return names if names and all(name.replace("_", "").isalnum() for name in names) else None


class LocalStoreConstraintError(Exception):
    """Raised where the real database would reject a write."""


def _check_update_rules(table: str, row: dict[str, Any], changes: dict[str, Any]) -> None:
    if table == "agents" and row.get("status") == "revoked":
        if "status" in changes and changes["status"] != "revoked":
            raise LocalStoreConstraintError(
                f"Agent passport {row.get('id')} is revoked and cannot be reactivated"
            )


def apply_insert_defaults(table: str, row: dict[str, Any]) -> None:
    """Column defaults the migration declares for new rows."""
    if table == "agents":
        row.setdefault("status", "active")
        row.setdefault("scopes", [])
        row.setdefault("version", 1)
        row.setdefault(
            "expires_at", (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        )
        row.setdefault("allowed_tools", [])
        row.setdefault("safe_mode", False)
        row.setdefault("daily_call_limit", None)
        row.setdefault("budget_action", "deny")
        row.setdefault("destination_mode", "off")
        row.setdefault("risk_last_alert_at", None)
        row.setdefault("risk_released_at", None)
    elif table == "organizations":
        row.setdefault("blackbox_retention_days", 30)
        row.setdefault("payload_capture_enabled", False)
        row.setdefault("payload_retention_days", 7)
        row.setdefault("radar_mode", "observe")
        row.setdefault("output_check_mode", "observe")
        row.setdefault("loop_mode", "observe")
        row.setdefault("risk_alert_threshold", 50)
        row.setdefault("risk_safe_mode_threshold", None)
        row.setdefault("risk_freeze_threshold", None)
        row.setdefault("loop_limit", 20)
        row.setdefault("loop_window_seconds", 60)


def _apply_update_triggers(table: str, before: dict[str, Any], after: dict[str, Any]) -> None:
    if table != "agents":
        return
    if any(before.get(k) != after.get(k) for k in ("status", "scopes", "expires_at")):
        after["version"] = int(before.get("version") or 1) + 1
    if before.get("status") != after.get("status"):
        after["status_changed_at"] = datetime.now(timezone.utc).isoformat()
    # trg_agents_risk_release (20261122000000_risk_engine.sql): an unfreeze or Safe Mode turned off is a human release.
    if (before.get("status") == "frozen" and after.get("status") == "active") or (before.get("safe_mode") and not after.get("safe_mode")):
        after["risk_released_at"] = datetime.now(timezone.utc).isoformat()


class LocalSupabaseAdapter:
    """
    In-memory durable store pre-seeded with RedHand's default sandbox organization,
    SDK API key (`rh_dev_local_key`), initial agents, traces, and HITL intervention.
    Includes a real-time SSE event broadcaster.
    """

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._seed_initial_state()

    def table(self, table_name: str) -> LocalTableQueryBuilder:
        return LocalTableQueryBuilder(self, table_name)

    def rpc(self, function: str, params: dict[str, Any] | None = None) -> LocalRpcBuilder:
        """Calls an emulated database function (all-or-nothing); see local_rpc.py."""
        from redhand_core.services.local_rpc import LocalRpcBuilder

        return LocalRpcBuilder(self, function, params or {})

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(q)

    def publish_event(self, event_type: str, payload: Any) -> None:
        message = {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass

    def _seed_initial_state(self) -> None:
        now = datetime.now(timezone.utc)
        dev_key_hash = hashlib.sha256(DEFAULT_DEV_API_KEY.encode("utf-8")).hexdigest()

        self.tables["organizations"] = [
            {
                "id": DEFAULT_ORG_ID,
                "name": "Archtificial Sdn. Bhd.",
                "slug": "archtificial-prod",
                "siem_webhook_url": None,
                "default_hitl_timeout_seconds": 3600,
                "safe_mode": False,
                "utc_offset_minutes": 480,
                "default_daily_call_limit": None,
                "blackbox_retention_days": 30,
                "payload_capture_enabled": False,
                "payload_retention_days": 7,
                "radar_mode": "observe",
                "output_check_mode": "observe",
                "radar_mode_changed_at": now.isoformat(),
                "output_check_mode_changed_at": now.isoformat(),
                "loop_mode": "observe",
                "loop_limit": 20,
                "risk_alert_threshold": 50,
                "risk_safe_mode_threshold": None,
                "risk_freeze_threshold": None,
                "loop_window_seconds": 60,
                "loop_mode_changed_at": now.isoformat(),
            }
        ]

        self.tables["organization_members"] = [
            {
                "id": f"00000000-0000-0000-0000-0000000000b{idx}",
                "organization_id": DEFAULT_ORG_ID,
                "user_id": op["id"],
                "role": op["role"],
            }
            for idx, op in enumerate(DEV_OPERATORS.values(), start=1)
        ]

        self.tables["sdk_api_keys"] = [
            {
                "id": "00000000-0000-0000-0000-000000000020",
                "organization_id": DEFAULT_ORG_ID,
                "name": "Local Development SDK Key",
                "key_prefix": "rh_dev_",
                "key_hash": dev_key_hash,
                "is_active": True,
                "expires_at": (now + timedelta(days=365)).isoformat(),
                "organizations": {"siem_webhook_url": None},
            }
        ]

        finops_agent_id = "f91d4fae-7dec-11d0-a765-00a0c91e6bf6"
        secops_agent_id = "a82c11bb-44c0-4a91-9b1c-82910fa3b201"
        synth_agent_id = "c19e882a-19d2-411f-b700-991a2c3d4e5f"

        self.tables["agents"] = [
            {
                "id": finops_agent_id,
                "organization_id": DEFAULT_ORG_ID,
                "external_agent_id": "finops-cloudsql-remediator",
                "name": "FinOps CloudSQL Remediator",
                "framework": "LangGraph",
                "environment": "production",
                "status": "active",
                "risk_score": 78,
                "p99_firewall_ms": 14.2,
                "blocked_attacks_count": 14,
                "gcp_service_account_email": "sa-finops-broker@archtificial-prod.iam.gserviceaccount.com",
                "allowed_tools": [
                    "query_cloud_billing_export",
                    "inspect_instance_metrics",
                    "delete_production_database",
                ],
                "last_heartbeat_at": now.isoformat(),
            },
            {
                "id": secops_agent_id,
                "organization_id": DEFAULT_ORG_ID,
                "external_agent_id": "rag-secops-triager",
                "name": "SecOps RAG Incident Triager",
                "framework": "Vertex ADK",
                "environment": "production",
                "status": "active",
                "risk_score": 42,
                "p99_firewall_ms": 11.8,
                "blocked_attacks_count": 31,
                "gcp_service_account_email": "sa-secops-rag@archtificial-prod.iam.gserviceaccount.com",
                "allowed_tools": [
                    "read_gcs_forensic_bundle",
                    "query_chronicle_siem",
                    "quarantine_iam_principal",
                ],
                "last_heartbeat_at": now.isoformat(),
            },
            {
                "id": synth_agent_id,
                "organization_id": DEFAULT_ORG_ID,
                "external_agent_id": "multi-cloud-topology-synth",
                "name": "Topology Synthesizer Crew",
                "framework": "CrewAI",
                "environment": "staging",
                "status": "active",
                "risk_score": 18,
                "p99_firewall_ms": 9.4,
                "blocked_attacks_count": 3,
                "gcp_service_account_email": "sa-topology-synth@archtificial-stg.iam.gserviceaccount.com",
                "allowed_tools": ["read_terraform_state", "list_gke_clusters"],
                "last_heartbeat_at": now.isoformat(),
            },
        ]

        initial_state = {
            "graph_node": "execute_remediation_node",
            "checkpoint_step": 4,
            "thread_id": "lg_run_99481a",
            "retry_count": 0,
        }
        canonical_bytes = json.dumps(
            initial_state, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        valid_checksum = hashlib.sha256(canonical_bytes).hexdigest()

        self.tables["hitl_interventions"] = [
            {
                "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "organization_id": DEFAULT_ORG_ID,
                "agent_id": finops_agent_id,
                "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                "span_id": "00f067aa0ba902b7",
                "status": "pending",
                "risk_tier": "destructive",
                "proposed_tool_name": "delete_production_database",
                "proposed_tool_arguments": {
                    "db_name": "core-ledger-prod-01",
                    "skip_final_snapshot": False,
                    "region": "asia-southeast1",
                },
                "target_cloud_resource": "//sqladmin.googleapis.com/projects/archtificial-prod/instances/core-ledger-prod-01",
                "requested_iam_permissions": ["inRole:roles/cloudsql.admin"],
                "required_approvals": 2,
                "approvals": [],
                "agent_justification": "Observed CPU utilization < 1.2% over trailing 14-day window in FinOps report. Recommending immediate instance termination to save $1,420/mo.",
                "serialized_agent_state": initial_state,
                "state_checksum": valid_checksum,
                "resume_webhook_url": "http://localhost:8099/webhooks/agent-resume",
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
            }
        ]

        self.tables["execution_traces"] = []
        self.tables["security_events"] = []
        self.tables["agent_events"] = []
        self.tables["event_chain_heads"] = []
        self.tables["event_batches"] = []

        # Passport fields for the seeded demo agents (owned by the dev owner).
        owner_id = DEV_OPERATORS["owner"]["id"]
        for agent in self.tables["agents"]:
            agent.setdefault("owner_id", owner_id)
            agent.setdefault("backup_owner_id", DEV_OPERATORS["admin"]["id"])
            apply_insert_defaults("agents", agent)
        self.tables["agent_keys"] = []
        self.tables["mcp_servers"] = []
        self.tables["control_audit_log"] = []


_local_store_singleton: LocalSupabaseAdapter | None = None


def get_local_store() -> LocalSupabaseAdapter:
    global _local_store_singleton
    if _local_store_singleton is None:
        _local_store_singleton = LocalSupabaseAdapter()
    return _local_store_singleton

