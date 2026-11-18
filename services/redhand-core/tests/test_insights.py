"""
Insights summary (dashboard redesign S2): the numbers behind the dashboard's home page, computed from what the gateway reported to the Black Box.
These tests feed events through the real ingest route, then check totals, the window, the ranking, latency, who may read, that nothing from
another organization is ever counted, and that a failed read is an error (never zeros).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest

from redhand_core.services import local_rpc
from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_passports import OTHER_ORG
from test_timeline import Env as TimelineEnv, event


def ago(**delta: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**delta)


class Env(TimelineEnv):
    def summary(self, window: str | None = None, user: str = "viewer", headers: dict[str, str] | None = None) -> Any:
        params = {"window": window} if window else None
        return self.client.get("/v1/insights/summary", params=params, headers=headers or self.h(user))


def with_latency(item: dict[str, Any], ms: float, size: int = 10) -> dict[str, Any]:
    return {**item, "latency_ms": ms, "result_size_bytes": size}


def test_an_organization_with_no_calls_gets_zeros_and_a_full_empty_series() -> None:
    env = Env()
    body = env.summary("1h").json()
    assert body["totals"] == {"decisions": 0, "allowed": 0, "refused": 0, "errors": 0, "bytes_returned": 0}
    assert len(body["series"]) in (12, 13) and all(p["allowed"] == p["refused"] == p["errors"] == 0 for p in body["series"])
    assert body["agents"] == [] and body["reasons"] == [] and body["latency"]["samples"] == 0 and body["latency"]["p50_ms"] is None
    assert body["window"] == "1h" and body["bucket_seconds"] == 300
    assert body["controls"] == {"safe_mode": False, "radar_mode": "observe"}


def test_totals_split_by_decision_with_reasons_latency_and_agent_names() -> None:
    env = Env()
    agent = env.agent
    env.events([
        with_latency(event(agent, ago(minutes=5)), 10, 1000),
        with_latency(event(agent, ago(minutes=4)), 20, 2000),
        with_latency(event(agent, ago(minutes=3)), 30, 3000),
        event(agent, ago(minutes=2), decision="BLOCK", tool="delete_invoice", reasons=["Tool 'delete_invoice' on server 'xero' is not in this agent's passport scopes."]),
        event(agent, ago(minutes=1), decision="BLOCK", tool="delete_invoice", reasons=["Tool 'push' on server 'github' is not in this agent's passport scopes.", "Safe Mode is on: tool 'push' on server 'github' is not declared read-only."]),
        event(agent, ago(minutes=1), decision="ERROR", tool="list_invoices", reasons=["connection refused by 10.0.0.5"]),
    ])
    body = env.summary("1h").json()
    assert body["totals"] == {"decisions": 6, "allowed": 3, "refused": 2, "errors": 1, "bytes_returned": 6000}
    assert sum(p["allowed"] + p["refused"] + p["errors"] for p in body["series"]) == 6
    assert body["reasons"][0] == {"reason": "out_of_scope", "count": 2}
    assert {r["reason"] for r in body["reasons"]} == {"out_of_scope", "safe_mode", "upstream_error"}
    for raw in ("delete_invoice", "10.0.0.5", "passport scopes", "github"):
        assert raw not in str(body["reasons"]), "a reason carries a raw sentence or a name the customer chose"
    assert body["latency"] == {"samples": 3, "p50_ms": 20.0, "p95_ms": 29.0}
    assert body["agents"][0]["agent_id"] == agent and body["agents"][0]["name"] == "Risky bot" and body["agents"][0]["decisions"] == 6
    assert body["tools"][0]["tool"] == "list_invoices" and body["tools"][0]["calls"] == 4 and body["servers"][0]["server"] == "xero"
    assert {(f["decision"], f["count"]) for f in body["flow"]} == {("ALLOW", 3), ("BLOCK", 2), ("ERROR", 1)}


def test_the_window_decides_what_counts() -> None:
    env = Env()
    env.events([event(env.agent, ago(minutes=30)), event(env.agent, ago(hours=3)), event(env.agent, ago(hours=30)), event(env.agent, ago(days=4))])
    assert env.summary("1h").json()["totals"]["decisions"] == 1
    assert env.summary("24h").json()["totals"]["decisions"] == 2
    assert env.summary("7d").json()["totals"]["decisions"] == 4
    assert env.summary().json()["window"] == "24h"  # the default


def test_another_organizations_events_are_never_counted_or_shown() -> None:
    env = Env()
    env.events([event(env.agent, ago(minutes=1))])
    mark = "OTHER-ORG-MARK"
    env.store.tables.setdefault("agent_events", []).append({
        "organization_id": OTHER_ORG, "agent_id": str(uuid4()), "seq": 1, "occurred_at": ago(minutes=1).isoformat(), "server": mark, "tool_name": mark,
        "decision": "BLOCK", "method": "tools/call", "reasons": [mark], "latency_ms": 1, "result_size_bytes": 5})
    resp = env.summary("1h")
    assert resp.json()["totals"]["decisions"] == 1
    assert mark not in resp.text


def test_reported_only_agents_are_counted_apart_from_managed_passports() -> None:
    env = Env()
    before = env.summary().json()["passports"]
    for row in env.store.tables["agents"]:
        if str(row["id"]) == env.agent:
            row["status"] = "frozen"
    env.store.tables["agents"].append({"id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "name": "sdk-only", "status": "active", "reported_only": True})
    after = env.summary().json()["passports"]
    assert after["managed_active"] == before["managed_active"] - 1 and after["frozen"] == before["frozen"] + 1
    assert after["reported_only"] == before["reported_only"] + 1  # not counted as a managed active passport
    assert after["revoked"] == before["revoked"]


def test_the_control_state_is_the_organizations() -> None:
    env = Env()
    for row in env.store.tables["organizations"]:
        if str(row["id"]) == DEFAULT_ORG_ID:
            row["safe_mode"], row["radar_mode"] = True, "block"
    assert env.summary().json()["controls"] == {"safe_mode": True, "radar_mode": "block"}


@pytest.mark.parametrize("user", ["viewer", "operator", "admin", "owner"])
def test_every_role_may_read_it(user: str) -> None:
    assert Env().summary(user=user).status_code == 200


def test_no_token_and_a_forged_organization_header_get_nothing() -> None:
    env = Env()
    assert env.client.get("/v1/insights/summary").status_code == 401
    forged = {**env.h("viewer"), "X-RedHand-Org": OTHER_ORG}
    assert env.summary(headers=forged).status_code in (401, 403)


@pytest.mark.parametrize("window", ["1d", "30d", "", "1h; drop table", "0h"])
def test_only_the_three_windows_are_accepted(window: str) -> None:
    resp = Env().client.get("/v1/insights/summary", params={"window": window}, headers=Env().h("viewer"))
    assert resp.status_code == 422


def test_a_failed_read_is_an_error_never_zeros(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Env()

    def broken(*_: Any, **__: Any) -> Any:
        raise local_rpc._error("XX000", "internal")

    monkeypatch.setitem(local_rpc.HANDLERS, "insights_summary", broken)
    resp = env.summary("1h")
    assert resp.status_code == 503 and resp.json()["detail"] == "Insights could not be read."
    assert "internal" not in resp.text and "XX000" not in resp.text


def test_an_answer_that_breaks_the_contract_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Env()
    monkeypatch.setitem(local_rpc.HANDLERS, "insights_summary", lambda *_: {"totals": "nonsense"})
    assert env.summary("1h").status_code == 503


def test_nothing_but_aggregates_leaves_core() -> None:
    env = Env()
    item = event(env.agent, ago(minutes=1), tool="list_invoices")
    item["argument_keys"] = ["note"]
    env.events([item])
    text = env.summary("1h").text
    for forbidden in ("argument_keys", "arguments_sha256", "credential_jti", "arguments_redacted", "result_excerpt", "note"):
        assert forbidden not in text
