"""
The incident view (Phase 4.5 B3, ADR 0022): one timeline per agent that stitches what RedHand already recorded (refused and failed calls from
the Black Box, hourly activity, findings, honeytoken and decoy trips, and control actions) into one ordered story. These tests feed it through
the real report paths, then check order, paging, who may read it, that nothing crosses organizations or agents, and that no call payload,
argument value or full address leaks into it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest

from redhand_core.services.local_store import DEFAULT_ORG_ID

from core_helpers import operator_headers
from test_risk_engine import GATEWAY, OTHER_OWNER, Env as RiskEnv, finding

SECRET = "sk_live_TimelineSecret0123456789abcdef"
SUBDOMAIN = "collector-secret-token.evil.example.net"


def event(agent: str, at: datetime, decision: str = "ALLOW", tool: str = "list_invoices", reasons: list[str] | None = None) -> dict[str, Any]:
    return {
        "agent_id": agent, "occurred_at": at.isoformat(), "gateway_instance": "gw-test-timeline", "server": "xero", "method": "tools/call",
        "tool_name": tool, "decision": decision, "reasons": reasons or [], "upstream_status": 200 if decision == "ALLOW" else 403,
        "latency_ms": 1.0, "argument_keys": ["note"], "arguments_sha256": "a" * 64, "result_size_bytes": 10, "redaction_count": 0,
        "credential_jti": "jti-1",
    }


class Env(RiskEnv):
    def events(self, items: list[dict[str, Any]]) -> None:
        body = {"instance_id": "gw-test-timeline", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": items}
        resp = self.client.post("/internal/v1/events", json=body, headers=GATEWAY)
        assert resp.status_code == 200, resp.text
        assert resp.json()["accepted"] == len(items), resp.text

    def timeline(self, agent: str | None = None, user: str = "operator", headers: dict[str, str] | None = None, **params: Any) -> Any:
        return self.client.get(f"/v1/agents/{agent or self.agent}/timeline", params=params, headers=headers or self.h(user))


@pytest.fixture
def env() -> Env:
    return Env()


def kinds(body: dict[str, Any]) -> list[str]:
    return [item["kind"] for item in body["items"]]


# --- what it shows ---------------------------------------------------------------------------------------------------------------------

def test_each_source_appears_once_newest_first(env: Env) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    env.events([
        event(env.agent, now - timedelta(minutes=50)),
        event(env.agent, now - timedelta(minutes=40), "BLOCK", "delete_invoice", ["Tool 'delete_invoice' on server 'xero' is not in this agent's passport scopes."]),
        event(env.agent, now - timedelta(minutes=30), "ERROR", "list_invoices", ["Upstream MCP server is unreachable."]),
    ])
    env.report([finding()])
    env.trip(env.honeytoken())
    assert env.client.post(f"/v1/passports/{env.agent}/freeze", json={"reason": "Looks wrong"}, headers=env.h("operator")).status_code == 200

    resp = env.timeline()
    assert resp.status_code == 200, resp.text
    body = resp.json()
    got = kinds(body)
    for kind in ("refusal", "error", "activity", "finding", "trip", "action"):
        assert kind in got, (kind, got)
    times = [item["at"] for item in body["items"]]
    assert times == sorted(times, reverse=True), "newest first"
    assert body["agent"] == {"id": env.agent, "name": "Risky bot", "status": "frozen"}


def test_a_refusal_carries_the_black_box_reason_and_a_link_to_its_event(env: Env) -> None:
    now = datetime.now(timezone.utc)
    reason = "Tool 'delete_invoice' on server 'xero' is not in this agent's passport scopes."
    env.events([event(env.agent, now, "BLOCK", "delete_invoice", [reason])])
    (refusal,) = [i for i in env.timeline().json()["items"] if i["kind"] == "refusal"]
    assert refusal["tool_name"] == "delete_invoice" and refusal["server"] == "xero" and refusal["reasons"] == [reason]
    assert isinstance(refusal["seq"], int) and refusal["seq"] >= 1


def test_allowed_calls_are_counted_per_hour_not_listed_one_by_one(env: Env) -> None:
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    env.events([event(env.agent, hour + timedelta(seconds=n)) for n in range(25)])
    items = env.timeline().json()["items"]
    activity = [i for i in items if i["kind"] == "activity"]
    assert len(activity) == 1 and activity[0]["calls"] == 25 and activity[0]["refused"] == 0
    assert not [i for i in items if i["kind"] == "refusal"]


def test_a_finding_shows_rule_kind_confidence_and_review_status_with_its_id(env: Env) -> None:
    env.report([finding("RAD-INJ-001", "high")])
    (item,) = [i for i in env.timeline().json()["items"] if i["kind"] == "finding"]
    assert item["rule_id"] == "RAD-INJ-001" and item["finding_kind"] == "injection" and item["confidence"] == "high"
    assert item["review_status"] == "open" and item["finding_id"]


def test_a_trip_shows_its_kind_and_where_it_was_seen_never_the_value(env: Env) -> None:
    env.trip(env.honeytoken())
    (item,) = [i for i in env.timeline().json()["items"] if i["kind"] == "trip"]
    assert item["trip_kind"] == "honeytoken" and item["seen_in"] == "arguments" and item["tool_name"] == "send_email"


def test_control_actions_name_whether_a_person_or_redhand_acted(env: Env) -> None:
    env.client.post(f"/v1/passports/{env.agent}/freeze", json={"reason": "Checking"}, headers=env.h("operator"))
    env.client.post(f"/v1/passports/{env.agent}/unfreeze", json={"reason": "Fine", "confirm": True}, headers=env.h("operator"))
    actions = [i for i in env.timeline().json()["items"] if i["kind"] == "action"]
    names = [a["action"] for a in actions]
    assert "passport.frozen" in names and "passport.unfrozen" in names
    frozen = next(a for a in actions if a["action"] == "passport.frozen")
    assert frozen["automatic"] is False and frozen["reason"] == "Checking"


# --- paging ----------------------------------------------------------------------------------------------------------------------------

def test_paging_has_no_gaps_and_no_repeats(env: Env) -> None:
    start = datetime.now(timezone.utc) - timedelta(hours=2)
    env.events([event(env.agent, start + timedelta(minutes=n), "BLOCK", f"tool_{n}", ["refused"]) for n in range(30)])
    seen: list[int] = []
    before: str | None = None
    for _ in range(10):
        params: dict[str, Any] = {"limit": 7}
        if before:
            params["before"] = before
        body = env.timeline(**params).json()
        seen.extend(i["seq"] for i in body["items"] if i["kind"] == "refusal")
        before = body["next_before"]
        if before is None:
            break
    assert sorted(seen) == sorted(set(seen)) and len(seen) == 30


def test_the_page_size_is_bounded(env: Env) -> None:
    assert env.timeline(limit=201).status_code == 422
    assert env.timeline(limit=0).status_code == 422


# --- who may read it, and whose data it holds ------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 200), ("admin", 200), ("owner", 200)])
def test_roles(env: Env, user: str, expected: int) -> None:
    assert env.timeline(user=user).status_code == expected


def test_another_organizations_agent_is_not_found(env: Env) -> None:
    from uuid import UUID

    other = operator_headers(settings=env.settings, user_id=UUID(OTHER_OWNER))
    assert env.timeline(headers=other).status_code == 404


def test_an_unknown_agent_is_not_found(env: Env) -> None:
    assert env.timeline(agent=str(uuid4())).status_code == 404


def test_another_agents_records_never_appear(env: Env) -> None:
    other = env.register("Other bot")["id"]
    now = datetime.now(timezone.utc)
    env.events([event(other, now, "BLOCK", "secret_tool", ["refused"])])
    env.report([finding()], agent=other)
    env.trip(env.honeytoken(), agent=other)
    env.client.post(f"/v1/passports/{other}/freeze", json={"reason": "other"}, headers=env.h("operator"))
    text = json.dumps(env.timeline().json())
    assert "secret_tool" not in text and other not in text


def test_no_payload_argument_value_secret_or_full_address_leaks(env: Env) -> None:
    """Planted where RedHand really keeps such text: a captured payload on the event, and the details of an audit row (a destination
    change stores the full host there). The timeline shows neither."""
    now = datetime.now(timezone.utc)
    env.events([event(env.agent, now, "BLOCK", "send_report", ["An address in this call is not on this agent's allowed list: example.net"])])
    for row in env.store.tables["agent_events"]:
        row["arguments_redacted"] = {"text": f'{{"note": "{SECRET} {SUBDOMAIN}"}}', "truncated": False, "original_bytes": 80}
        row["result_excerpt"] = {"text": SECRET, "truncated": False, "original_bytes": 40}
    env.store.tables["control_audit_log"].append({
        "id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "actor_user_id": "00000000-0000-0000-0000-0000000000a2",
        "action": "passport.destination_added", "target_type": "agent", "target_id": env.agent, "reason": None,
        "details": {"host": SUBDOMAIN, "note": SECRET}, "created_at": now.isoformat(),
    })
    body = env.timeline().json()
    text = json.dumps(body)
    assert "passport.destination_added" in text, "the action itself is shown"
    assert SECRET not in text and SUBDOMAIN not in text
    for field in ("argument_keys", "arguments_sha256", "credential_jti", "arguments_redacted", "result_excerpt", "details"):
        assert field not in text, field


def test_a_revoked_agent_can_still_be_investigated(env: Env) -> None:
    assert env.client.post(f"/v1/passports/{env.agent}/revoke", json={"reason": "done", "confirm": True}, headers=env.h("admin")).status_code == 200
    body = env.timeline().json()
    assert body["agent"]["status"] == "revoked" and "passport.revoked" in [i.get("action") for i in body["items"]]


def test_an_agent_with_no_history_has_an_empty_timeline(env: Env) -> None:
    fresh = env.register("Quiet bot")["id"]
    body = env.timeline(agent=fresh).json()
    assert [i["action"] for i in body["items"]] == ["passport.created"] and body["next_before"] is None


def test_a_source_that_cannot_be_read_fails_the_whole_answer(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    """A timeline with a missing part would read as 'nothing happened'. It is refused instead."""
    from postgrest.exceptions import APIError

    from redhand_core.timeline import service

    async def broken(*_: Any, **__: Any) -> Any:
        raise APIError({"message": "boom", "code": "XX000", "details": "", "hint": ""})

    monkeypatch.setattr(service, "_trips", broken)
    resp = env.timeline()
    assert resp.status_code == 503 and resp.json() == {"detail": "The timeline could not be read. Try again shortly."}


def test_every_read_is_scoped_by_organization_not_only_by_agent(env: Env) -> None:
    """Agent ids are unique, so the agent filter alone would usually be enough; the organization filter is the second wall. A row that
    names this agent but belongs to another organization (corruption, a bug elsewhere) must still not appear."""
    from test_risk_engine import OTHER_ORG  # noqa: PLC0415

    now = datetime.now(timezone.utc).isoformat()
    env.store.tables.setdefault("agent_events", []).append({
        "organization_id": OTHER_ORG, "agent_id": env.agent, "seq": 999, "occurred_at": now, "server": "x", "tool_name": "foreign_tool",
        "decision": "BLOCK", "reasons": ["foreign"],
    })
    env.store.tables.setdefault("honeytrips", []).append({
        "id": str(uuid4()), "organization_id": OTHER_ORG, "agent_id": env.agent, "kind": "honeytoken", "ref_id": str(uuid4()),
        "seen_in": "result", "tool_name": "foreign_tool", "server_slug": "x", "occurred_at": now,
    })
    env.store.tables["control_audit_log"].append({
        "id": str(uuid4()), "organization_id": OTHER_ORG, "actor_user_id": OTHER_OWNER, "action": "passport.frozen",
        "target_type": "agent", "target_id": env.agent, "reason": "foreign", "details": {}, "created_at": now,
    })
    text = json.dumps(env.timeline().json())
    assert "foreign" not in text


def test_items_that_share_a_moment_are_never_split_across_pages(env: Env) -> None:
    moment = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5)
    env.events([event(env.agent, moment, "BLOCK", f"tool_{n}", ["refused"]) for n in range(10)])
    seen: list[int] = []
    before: str | None = None
    for _ in range(10):
        params: dict[str, Any] = {"limit": 3}
        if before:
            params["before"] = before
        body = env.timeline(**params).json()
        seen.extend(i["seq"] for i in body["items"] if i["kind"] == "refusal")
        before = body["next_before"]
        if before is None:
            break
    assert len(seen) == 10 and len(set(seen)) == 10


def test_an_action_redhand_took_by_itself_is_marked_automatic(env: Env) -> None:
    """A honeytoken's own default action freezes the agent, written by the fixed system actor."""
    resp = env.client.post("/v1/honeytokens", json={"label": "Freezing decoy", "kind": "api_key"}, headers=env.h("admin"))
    assert resp.status_code == 201, resp.text
    env.trip(str(resp.json()["id"]))
    frozen = [i for i in env.timeline().json()["items"] if i["kind"] == "action" and i["action"] == "passport.frozen"]
    assert frozen and frozen[0]["automatic"] is True


def test_a_trip_appears_once_not_again_as_an_audit_action(env: Env) -> None:
    env.trip(env.honeytoken())
    items = env.timeline().json()["items"]
    assert len([i for i in items if i["kind"] == "trip"]) == 1
    assert not [i for i in items if i["kind"] == "action" and i["action"] in ("honeytoken.tripped", "honey_tool.tripped")]


def test_freeze_all_and_organization_safe_mode_appear_in_every_agents_timeline(env: Env) -> None:
    """They are recorded against the organization, not the agent, but they change what the agent may do: the timeline must show them."""
    resp = env.client.post("/v1/passports/freeze-all", json={"reason": "Incident drill", "confirm": True}, headers=env.h("owner"))
    assert resp.status_code == 200, resp.text
    resp = env.client.post("/v1/organization/safe-mode", json={"enabled": True, "reason": "Drill"}, headers=env.h("admin"))
    assert resp.status_code == 200, resp.text
    items = env.timeline().json()["items"]
    safe = [i for i in items if i["kind"] == "action" and i["action"] == "organization.safe_mode_enabled"]
    assert safe and safe[0]["organization_wide"] is True and safe[0]["reason"] == "Drill"
    frozen_all = [i for i in items if i["kind"] == "action" and i["action"] == "organization.frozen_all"]
    assert frozen_all and frozen_all[0]["organization_wide"] is True and frozen_all[0]["reason"] == "Incident drill"
    per_agent = [i for i in items if i["kind"] == "action" and i["action"] == "passport.created"]
    assert per_agent and per_agent[0]["organization_wide"] is False


def test_another_organizations_freeze_all_never_appears(env: Env) -> None:
    from uuid import UUID

    other = operator_headers(settings=env.settings, user_id=UUID(OTHER_OWNER))
    assert env.client.post("/v1/passports/freeze-all", json={"reason": "Other org drill", "confirm": True}, headers=other).status_code == 200
    assert "Other org drill" not in json.dumps(env.timeline().json())


# --- the incident summary export -------------------------------------------------------------------------------------------------------

def export(env: Env, fmt: str = "json", user: str = "operator", agent: str | None = None, headers: dict[str, str] | None = None) -> Any:
    return env.client.get(f"/v1/agents/{agent or env.agent}/timeline/export", params={"format": fmt}, headers=headers or env.h(user))


@pytest.fixture(autouse=True)
def _fresh_export_limit() -> None:
    from redhand_core.routers import timeline as timeline_router

    timeline_router._export_limiter._events.clear()  # noqa: SLF001


def test_the_json_export_is_the_whole_timeline_as_a_download(env: Env) -> None:
    env.events([event(env.agent, datetime.now(timezone.utc), "BLOCK", "delete_invoice", ["refused"])])
    env.report([finding()])
    resp = export(env, "json")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-disposition"].startswith('attachment; filename="redhand-timeline-')
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["agent"]["name"] == "Risky bot" and body["truncated"] is False and body["exported_at"]
    assert {"refusal", "finding", "action"} <= {i["kind"] for i in body["items"]}


def test_the_csv_export_has_a_header_and_defuses_spreadsheet_formulas(env: Env) -> None:
    formula = '=HYPERLINK("http://evil.example/x","click")'
    env.client.post(f"/v1/passports/{env.agent}/freeze", json={"reason": formula}, headers=env.h("operator"))
    resp = export(env, "csv")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.splitlines()
    assert lines[0].startswith("at,kind,tool_name,server,reasons")  # the night brief promises this header
    assert formula not in resp.text.replace("'" + formula, ""), "a formula cell is prefixed so a spreadsheet shows it as text"
    assert ("'" + formula).replace('"', '""') in resp.text


def test_an_export_is_audited_before_anything_is_read(env: Env) -> None:
    export(env, "json")
    rows = [r for r in env.store.tables["control_audit_log"] if r["action"] == "passport.timeline_exported"]
    assert len(rows) == 1 and rows[0]["target_id"] == env.agent and rows[0]["details"]["format"] == "json"
    shown = [i for i in env.timeline().json()["items"] if i.get("action") == "passport.timeline_exported"]
    assert shown, "the export itself appears in the timeline"


def test_when_the_audit_cannot_be_written_nothing_is_exported(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from postgrest.exceptions import APIError

    from redhand_core.timeline import service

    async def broken(*_: Any, **__: Any) -> None:
        raise APIError({"message": "boom", "code": "XX000", "details": "", "hint": ""})

    monkeypatch.setattr(service, "audit_export", broken)
    resp = export(env, "json")
    assert resp.status_code == 503 and resp.json() == {"detail": "The export could not be started."}


@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 200)])
def test_export_roles(env: Env, user: str, expected: int) -> None:
    assert export(env, user=user).status_code == expected


def test_another_organization_cannot_export_and_leaves_no_audit_row(env: Env) -> None:
    from uuid import UUID

    other = operator_headers(settings=env.settings, user_id=UUID(OTHER_OWNER))
    assert export(env, headers=other).status_code == 404
    assert not [r for r in env.store.tables["control_audit_log"] if r["action"] == "passport.timeline_exported"]


def test_exports_are_rate_limited_per_operator(env: Env) -> None:
    statuses = [export(env).status_code for _ in range(11)]
    assert statuses[:10] == [200] * 10 and statuses[10] == 429


def test_a_long_history_is_cut_and_says_so(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.timeline import service

    monkeypatch.setattr(service, "MAX_EXPORT_ITEMS", 5)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    env.events([event(env.agent, start + timedelta(minutes=n), "BLOCK", f"t{n}", ["refused"]) for n in range(12)])
    body = export(env).json()
    assert body["truncated"] is True and len(body["items"]) == 5


def test_the_export_holds_no_payload_or_secret(env: Env) -> None:
    env.events([event(env.agent, datetime.now(timezone.utc), "BLOCK", "send_report", ["refused"])])
    for row in env.store.tables["agent_events"]:
        row["arguments_redacted"] = {"text": SECRET, "truncated": False, "original_bytes": 40}
    for fmt in ("json", "csv"):
        assert SECRET not in export(env, fmt).text
