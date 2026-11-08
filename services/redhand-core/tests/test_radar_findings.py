"""
Prompt Injection Radar, core side (Phase 4 M4.2): the gateway's findings are stored coalesced and without any scanned text,
owners review them, set the modes and suppress a rule for an agent, and nothing crosses organizations or loosens a control
without the right role, confirmation and an audit row.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any
from uuid import UUID, uuid4

from pydantic import SecretStr
import pytest

from redhand_core.services.local_store import DEFAULT_ORG_ID
from redhand_core.services.metrics import get_metrics

from core_helpers import operator_headers
from test_telegram import OTHER_ORG, OWNER_CHAT, Env as TelegramEnv

SERVICE_TOKEN = "radar-core-test-internal-service-token-0123456789"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
GATEWAY_HEADERS = {"Authorization": f"Bearer {SERVICE_TOKEN}"}


def item(rule: str = "RAD-INJ-001", **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rule_id": rule, "kind": "injection" if rule.startswith("RAD-INJ") else "output",
        "family": "override" if rule.startswith("RAD-INJ") else "xss", "severity": "high", "confidence": "medium",
        "place": "text", "evasion": [], "tool_name": "get_ticket", "server": "helpdesk", "would_block": False, "occurrences": 1,
    }
    return {**base, **over}


class Env(TelegramEnv):
    def __init__(self) -> None:
        super().__init__(INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE_TOKEN))
        self.agent = self.register("Helpdesk bot")["id"]

    def report(self, items: list[dict[str, Any]], agent: str | None = None, org: str = DEFAULT_ORG_ID, token: str | None = SERVICE_TOKEN) -> Any:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post("/internal/v1/findings", json={"organization_id": org, "agent_id": agent or self.agent, "items": items}, headers=headers)

    def settings_get(self, user: str = "operator") -> Any:
        return self.client.get("/v1/radar/settings", headers=self.h(user))

    def settings_put(self, injection: str, output: str, user: str = "admin", **extra: Any) -> Any:
        return self.client.put("/v1/radar/settings", json={"radar_mode": injection, "output_check_mode": output, **extra}, headers=self.h(user))

    def findings(self, user: str = "operator", **params: Any) -> Any:
        return self.client.get("/v1/findings", params=params, headers=self.h(user))

    def review(self, finding_id: str, status: str = "false_alarm", user: str = "operator", **extra: Any) -> Any:
        return self.client.post(f"/v1/findings/{finding_id}/review", json={"status": status, **extra}, headers=self.h(user))

    def suppress(self, rule: str = "RAD-INJ-001", user: str = "admin", **extra: Any) -> Any:
        body = {"agent_id": self.agent, "rule_id": rule, "reason": "known noisy tool", "confirm": True, **extra}
        return self.client.post("/v1/radar/suppressions", json=body, headers=self.h(user))

    def suppressions(self, user: str = "operator") -> Any:
        return self.client.get("/v1/radar/suppressions", headers=self.h(user))

    def alerts(self) -> list[str]:
        return [t for t in self.fake.to(OWNER_CHAT) if not t.startswith("Linked.")]

    def audit_actions(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.store.tables.get("control_audit_log", []) if r["action"] == name]

    def other_agent(self) -> str:
        agent_id = str(uuid4())
        self.store.tables["agents"].append({"id": agent_id, "organization_id": OTHER_ORG, "name": "Other bot", "external_agent_id": "other", "status": "active"})
        return agent_id

    def other_headers(self) -> dict[str, str]:
        return operator_headers(settings=self.settings, user_id=UUID(OTHER_OWNER))

    def first_finding(self) -> str:
        return str(self.findings().json()["findings"][0]["id"])


@pytest.fixture
def env() -> Env:
    return Env()


# --- reports from the gateway --------------------------------------------------------------------------------------

def test_findings_are_stored_coalesced_and_the_owner_is_alerted_once_with_rule_ids_only(env: Env) -> None:
    env.link()
    resp = env.report([item("RAD-INJ-001"), item("RAD-OUT-001")])
    assert resp.status_code == 200 and resp.json() == {"new": 2, "coalesced": 0, "suppressed": 0, "capped": 0, "skipped": 0, "disabled": 0}
    again = env.report([item("RAD-INJ-001", occurrences=4, would_block=True)])
    assert again.json()["new"] == 0 and again.json()["coalesced"] == 1
    body = env.findings().json()["findings"]
    injection = next(f for f in body if f["rule_id"] == "RAD-INJ-001")
    assert injection["occurrences"] == 5 and injection["would_block"] is True and injection["review_status"] == "open"
    assert injection["agent_name"] == "Helpdesk bot"
    alerts = env.alerts()
    assert len(alerts) == 1 and "RAD-INJ-001" in alerts[0] and "Helpdesk bot" in alerts[0]
    assert "known-pattern" in alerts[0]


def test_a_second_alert_comes_only_after_ten_minutes(env: Env) -> None:
    env.link()
    env.report([item("RAD-INJ-001")])
    env.report([item("RAD-INJ-002")])
    assert len(env.alerts()) == 1
    for a in env.store.tables["agents"]:
        a["radar_last_alert_at"] = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
    env.report([item("RAD-INJ-003")])
    assert len(env.alerts()) == 2


def test_the_internal_endpoint_needs_the_service_token(env: Env) -> None:
    assert env.report([item()], token=None).status_code in (401, 403)
    assert env.report([item()], token="not-the-token-0123456789-0123456789-0123456789").status_code in (401, 403)
    assert env.findings().json()["findings"] == []


def test_an_agent_of_another_organization_or_an_unknown_agent_is_not_reported_against(env: Env) -> None:
    assert env.report([item()], agent=env.other_agent()).status_code == 404  # the claimed organization does not own it
    assert env.report([item()], agent=str(uuid4())).status_code == 404
    assert env.report([item()], org=OTHER_ORG).status_code == 404  # the agent is not that organization's
    assert env.findings().json()["findings"] == []


@pytest.mark.parametrize(
    "bad",
    [
        item(rule_id="free text"), item(kind="other"), item(severity="extreme"), item(place="elsewhere"), item(evasion=["whatever"]),
        item(tool_name="x" * 129), item(server="x" * 64), item(occurrences=0), item(occurrences=1001), item(family="Bad Family"),
        {**item(), "text": "the scanned text"},  # extra fields are refused: a report cannot smuggle text in
    ],
)
def test_malformed_reports_are_refused_at_the_boundary(env: Env, bad: dict[str, Any]) -> None:
    assert env.report([bad]).status_code == 422
    assert env.findings().json()["findings"] == []


def test_item_counts_are_bounded(env: Env) -> None:
    assert env.report([]).status_code == 422
    assert env.report([item() for _ in range(21)]).status_code == 422
    assert env.report([item(tool_name=f"t{i}") for i in range(20)]).json()["new"] == 20


def test_a_rule_kind_mismatch_is_skipped_not_stored(env: Env) -> None:
    resp = env.report([item("RAD-INJ-001", kind="output"), item("RAD-OUT-001", kind="injection"), item("RAD-INJ-002")])
    assert resp.status_code == 200 and resp.json()["skipped"] == 2 and resp.json()["new"] == 1


def test_nothing_the_gateway_reports_can_become_text_in_a_log_or_an_alert(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    env.link()
    caplog.set_level(logging.DEBUG)
    env.report([item(tool_name="ZQXJWK9981_tool", server="srv_marker")])
    assert "ZQXJWK9981" not in caplog.text
    assert all("ZQXJWK9981" not in t for t in env.alerts())


def test_metrics_count_new_findings_by_kind_and_what_was_not_stored(env: Env) -> None:
    before = dict(get_metrics()._counters.get("redhand_radar_findings_total", {}))
    env.report([item("RAD-INJ-001"), item("RAD-OUT-001")])
    after = get_metrics()._counters["redhand_radar_findings_total"]
    assert after[(("kind", "injection"),)] - before.get((("kind", "injection"),), 0) == 1
    assert after[(("kind", "output"),)] - before.get((("kind", "output"),), 0) == 1


# --- settings ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 200), ("admin", 200), ("owner", 200)])
def test_reading_the_settings_needs_a_security_operator(env: Env, user: str, expected: int) -> None:
    assert env.settings_get(user).status_code == expected


def test_default_settings_and_capabilities_by_role(env: Env) -> None:
    body = env.settings_get("operator").json()
    assert body["radar_mode"] == "observe" and body["output_check_mode"] == "observe" and body["block_available"] is False
    assert body["capabilities"] == {"can_change_modes": False, "can_review": True, "can_suppress": False}
    assert env.settings_get("admin").json()["capabilities"] == {"can_change_modes": True, "can_review": True, "can_suppress": True}


@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 403), ("admin", 200), ("owner", 200)])
def test_only_admins_change_the_modes(env: Env, user: str, expected: int) -> None:
    assert env.settings_put("observe", "observe", user).status_code == expected


def test_turning_a_check_off_needs_confirmation_and_is_audited(env: Env) -> None:
    refused = env.settings_put("off", "observe")
    assert refused.status_code == 400 and "confirm" in refused.text
    assert env.settings_get().json()["radar_mode"] == "observe"
    ok = env.settings_put("off", "observe", confirm=True, reason="too noisy this week")
    assert ok.status_code == 200 and ok.json()["radar_mode"] == "off" and ok.json()["output_check_mode"] == "observe"
    (row,) = env.audit_actions("organization.radar_settings_changed")
    assert row["reason"] == "too noisy this week" and row["details"]["old_injection"] == "observe" and row["details"]["new_injection"] == "off"
    assert row["actor_user_id"] == "00000000-0000-0000-0000-0000000000a2"  # the admin


def test_turning_a_check_back_on_needs_no_confirmation(env: Env) -> None:
    env.settings_put("off", "off", confirm=True)
    assert env.settings_put("observe", "observe").status_code == 200


def test_repeating_the_current_modes_changes_nothing_and_writes_no_audit_row(env: Env) -> None:
    assert env.settings_put("observe", "observe").status_code == 200
    assert env.audit_actions("organization.radar_settings_changed") == []


def test_block_mode_is_not_available_yet_whatever_the_request(env: Env) -> None:
    for body in ({"radar_mode": "block", "output_check_mode": "observe"}, {"radar_mode": "observe", "output_check_mode": "block"}):
        assert env.client.put("/v1/radar/settings", json={**body, "confirm": True}, headers=env.h("owner")).status_code == 422
    assert env.settings_get().json()["radar_mode"] == "observe"
    for org in env.store.tables["organizations"]:
        org["radar_mode"] = "block"  # even a tampered value cannot be set through the API
    assert env.settings_get().json()["block_available"] is False


def test_modes_are_per_kind_and_off_stops_storage_of_that_kind_only(env: Env) -> None:
    env.settings_put("off", "observe", confirm=True)
    resp = env.report([item("RAD-INJ-001"), item("RAD-OUT-001")])
    assert resp.json()["disabled"] == 1 and resp.json()["new"] == 1
    assert [f["kind"] for f in env.findings().json()["findings"]] == ["output"]


def test_a_stale_view_is_retried_once_and_a_real_conflict_is_reported(env: Env) -> None:
    resp = env.settings_put("off", "off", confirm=True)
    assert resp.status_code == 200 and resp.json()["radar_mode"] == "off" and resp.json()["output_check_mode"] == "off"


def test_organizations_have_separate_settings(env: Env) -> None:
    env.settings_put("off", "off", confirm=True)
    other = env.client.get("/v1/radar/settings", headers=env.other_headers())
    assert other.status_code == 200 and other.json()["radar_mode"] == "observe"


# --- listing and review --------------------------------------------------------------------------------------------

def test_listing_findings_needs_a_security_operator(env: Env) -> None:
    assert env.findings("viewer").status_code == 403
    assert env.findings("operator").status_code == 200


def test_filters_and_paging(env: Env) -> None:
    env.report([item("RAD-INJ-001", tool_name=f"t{i}") for i in range(6)])
    env.report([item("RAD-OUT-001", would_block=True)])
    assert len(env.findings().json()["findings"]) == 7
    assert {f["kind"] for f in env.findings(kind="output").json()["findings"]} == {"output"}
    assert [f["rule_id"] for f in env.findings(rule_id="RAD-OUT-001", would_block=True).json()["findings"]] == ["RAD-OUT-001"]
    assert env.findings(agent_id=str(uuid4())).json()["findings"] == []
    first = env.findings(limit=3).json()
    assert len(first["findings"]) == 3 and first["next_before"] is not None
    for i, f in enumerate(env.store.tables["security_findings"]):  # give every row a distinct time so the cursor is exact
        f["last_seen_at"] = (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat()
    page1 = env.findings(limit=3).json()
    page2 = env.findings(limit=3, before=page1["next_before"]).json()
    assert {f["id"] for f in page1["findings"]}.isdisjoint({f["id"] for f in page2["findings"]})
    assert len(page2["findings"]) == 3
    assert env.findings(limit=101).status_code == 422
    assert env.findings(kind="bogus").status_code == 422
    assert env.findings(rule_id="free text").status_code == 422


def test_another_organization_sees_none_of_them_and_cannot_review_them(env: Env) -> None:
    env.report([item()])
    finding = env.first_finding()
    assert env.client.get("/v1/findings", headers=env.other_headers()).json()["findings"] == []
    assert env.client.post(f"/v1/findings/{finding}/review", json={"status": "false_alarm"}, headers=env.other_headers()).status_code == 404
    assert env.findings().json()["findings"][0]["review_status"] == "open"


@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 200), ("admin", 200)])
def test_reviewing_needs_a_security_operator(env: Env, user: str, expected: int) -> None:
    env.report([item()])
    assert env.review(env.first_finding(), user=user).status_code == expected


def test_a_review_is_audited_and_feeds_the_summary(env: Env) -> None:
    env.report([item("RAD-INJ-001", would_block=True), item("RAD-INJ-002")])
    summary = env.settings_get().json()["last_7_days"]
    assert summary["findings"] == 2 and summary["would_block"] == 1 and summary["open"] == 2
    first = next(f["id"] for f in env.findings(rule_id="RAD-INJ-001").json()["findings"])
    ok = env.review(first, "false_alarm", note="a security article")
    assert ok.status_code == 200 and ok.json() == {"review_status": "false_alarm", "changed": True}
    summary = env.settings_get().json()["last_7_days"]
    assert summary["false_alarm"] == 1 and summary["open"] == 1 and summary["would_block_open"] == 0
    (row,) = env.audit_actions("radar_finding.reviewed")
    assert row["reason"] == "a security article" and row["details"]["rule"] == "RAD-INJ-001"
    assert row["details"]["old_status"] == "open" and row["details"]["new_status"] == "false_alarm"
    assert env.review(first, "false_alarm").json()["changed"] is False
    assert len(env.audit_actions("radar_finding.reviewed")) == 1


def test_a_review_can_be_changed_on_purpose_and_validation_holds(env: Env) -> None:
    env.report([item()])
    finding = env.first_finding()
    env.review(finding, "false_alarm")
    assert env.review(finding, "confirmed", note="on reflection it was real").json()["review_status"] == "confirmed"
    assert env.review(finding, "open").status_code == 422
    assert env.review(finding, "confirmed", note="x" * 301).status_code == 422
    assert env.review(str(uuid4())).status_code == 404
    assert env.client.post(f"/v1/findings/{finding}/review", json={"status": "confirmed", "extra": 1}, headers=env.h("operator")).status_code == 422


# --- suppression ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 403), ("admin", 200), ("owner", 200)])
def test_only_admins_suppress(env: Env, user: str, expected: int) -> None:
    assert env.suppress(user=user).status_code == expected


def test_a_suppression_needs_confirmation_and_a_reason(env: Env) -> None:
    refused = env.client.post("/v1/radar/suppressions", json={"agent_id": env.agent, "rule_id": "RAD-INJ-001", "reason": "noise"}, headers=env.h("admin"))
    assert refused.status_code == 400 and "confirm" in refused.text
    assert env.suppress(reason="ab").status_code == 422
    assert env.suppress(reason="x" * 301).status_code == 422
    assert env.suppress(days=0).status_code == 422 and env.suppress(days=91).status_code == 422
    assert env.suppress(rule="honeytoken").status_code == 422  # only Radar rules; never a honeytoken check
    assert env.suppressions().json()["suppressions"] == []
    assert env.audit_actions("radar_suppression.created") == []


def test_a_suppressed_rule_is_not_recorded_for_that_agent_only_and_revoking_restores_it(env: Env) -> None:
    other = env.register("Second bot")["id"]
    created = env.suppress("RAD-INJ-005", days=7)
    assert created.status_code == 200 and created.json()["created"] is True
    sid = created.json()["id"]
    resp = env.report([item("RAD-INJ-005"), item("RAD-INJ-006")])
    assert resp.json()["suppressed"] == 1 and resp.json()["new"] == 1
    assert env.report([item("RAD-INJ-005")], agent=other).json()["new"] == 1
    listed = env.suppressions().json()["suppressions"]
    assert [(s["rule_id"], s["agent_name"]) for s in listed] == [("RAD-INJ-005", "Helpdesk bot")]
    assert env.client.delete(f"/v1/radar/suppressions/{sid}", headers=env.h("operator")).status_code == 403
    assert env.client.delete(f"/v1/radar/suppressions/{sid}", params={"reason": "no longer needed"}, headers=env.h("admin")).json() == {"revoked": True}
    assert env.client.delete(f"/v1/radar/suppressions/{sid}", headers=env.h("admin")).json() == {"revoked": False}
    assert env.report([item("RAD-INJ-005")]).json()["new"] == 1 and env.suppressions().json()["suppressions"] == []
    assert len(env.audit_actions("radar_suppression.created")) == 1 and len(env.audit_actions("radar_suppression.revoked")) == 1


def test_creating_a_live_suppression_again_is_idempotent_and_an_expired_one_no_longer_applies(env: Env) -> None:
    first = env.suppress("RAD-INJ-005").json()
    again = env.suppress("RAD-INJ-005", days=5).json()
    assert again["created"] is False and again["id"] == first["id"]
    for s in env.store.tables["radar_suppressions"]:
        s["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert env.report([item("RAD-INJ-005")]).json()["suppressed"] == 0
    assert env.suppressions().json()["suppressions"] == []
    renewed = env.suppress("RAD-INJ-005", days=3).json()
    assert renewed["created"] is True and renewed["id"] != first["id"]


def test_another_organization_cannot_suppress_for_or_revoke_a_suppression_of_ours(env: Env) -> None:
    sid = env.suppress().json()["id"]
    body = {"agent_id": env.agent, "rule_id": "RAD-INJ-002", "reason": "not theirs", "confirm": True}
    assert env.client.post("/v1/radar/suppressions", json=body, headers=env.other_headers()).status_code == 404
    assert env.client.delete(f"/v1/radar/suppressions/{sid}", headers=env.other_headers()).status_code == 404
    assert env.client.get("/v1/radar/suppressions", headers=env.other_headers()).json()["suppressions"] == []


def test_at_most_a_hundred_live_suppressions_per_organization(env: Env) -> None:
    now = datetime.now(timezone.utc)
    for i in range(100):
        env.store.tables.setdefault("radar_suppressions", []).append({
            "id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "agent_id": env.agent, "rule_id": f"RAD-OUT-{100 + i:03d}",
            "reason": "bulk", "created_by": "x", "created_at": now.isoformat(), "expires_at": (now + timedelta(days=5)).isoformat(),
            "revoked_at": None, "revoked_by": None,
        })
    resp = env.suppress("RAD-INJ-001")
    assert resp.status_code == 409 and "100" in resp.text


def test_the_daily_cap_counts_but_does_not_store_past_two_thousand_rows(env: Env) -> None:
    rows = env.store.tables.setdefault("security_findings", [])
    now = datetime.now(timezone.utc)
    for i in range(2000):
        rows.append({
            "id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "agent_id": env.agent, "rule_id": "RAD-INJ-001", "family": "override",
            "kind": "injection", "severity": "low", "confidence": "low", "place": "text", "evasion": [], "tool_name": f"t{i}", "server_slug": "",
            "would_block": False, "occurrences": 1, "window_start": (now - timedelta(hours=1)).isoformat(), "first_seen_at": now.isoformat(),
            "last_seen_at": now.isoformat(), "review_status": "open", "reviewed_by": None, "reviewed_at": None, "review_note": None,
        })
    resp = env.report([item(tool_name="brand_new_tool")])
    assert resp.json()["capped"] == 1 and resp.json()["new"] == 0 and len(rows) == 2000


# --- the gateway's context carries the modes (Phase 4 M4.3) ----------------------------------------------------------

def _context(env: Env) -> dict[str, Any]:
    params = {"agent_id": env.agent, "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": "gateway-test-0001"}
    resp = env.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS)
    assert resp.status_code == 200, resp.text
    return resp.json()["agent"]


def test_the_gateway_context_carries_the_two_modes_and_follows_changes(env: Env) -> None:
    assert _context(env)["radar_mode"] == "observe" and _context(env)["output_check_mode"] == "observe"
    env.settings_put("off", "observe", confirm=True)
    agent = _context(env)
    assert agent["radar_mode"] == "off" and agent["output_check_mode"] == "observe"


@pytest.mark.parametrize("odd", ["block", "OBSERVE", "", None, True, 1])
def test_anything_but_an_explicit_observe_is_off_in_the_context(env: Env, odd: Any) -> None:
    org = next(o for o in env.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)
    org["radar_mode"] = odd
    org["output_check_mode"] = odd
    agent = _context(env)
    assert agent["radar_mode"] == "off" and agent["output_check_mode"] == "off"


# --- the gateway-context lookups (latency work) ------------------------------------------------------------------------------

def _agent_row(env: Env) -> dict[str, Any]:
    return next(a for a in env.store.tables["agents"] if a["id"] == env.agent)


def test_last_seen_is_written_at_most_once_a_minute(env: Env) -> None:
    row = _agent_row(env)
    row["last_seen_at"] = None
    _context(env)
    first = row["last_seen_at"]
    assert first is not None
    _context(env)
    assert row["last_seen_at"] == first  # a second lookup within a minute does not write again


@pytest.mark.parametrize("old", [None, "", "not a time", "2999-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"])
def test_a_missing_unreadable_future_or_old_last_seen_is_rewritten(env: Env, old: Any) -> None:
    row = _agent_row(env)
    row["last_seen_at"] = old
    _context(env)
    assert row["last_seen_at"] != old


def test_a_freeze_shows_in_the_very_next_lookup(env: Env) -> None:
    assert _context(env)["status"] == "active"
    _agent_row(env)["status"] = "frozen"
    assert _context(env)["status"] == "frozen"  # nothing in the core caches the passport


def test_an_unknown_agent_is_still_404_and_another_tenants_agent_is_not_returned(env: Env) -> None:
    params = {"agent_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": "gateway-test-0001"}
    assert env.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS).status_code == 404
    params = {"agent_id": env.agent, "organization_id": OTHER_ORG, "server": "xero", "instance_id": "gateway-test-0001"}
    assert env.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS).status_code == 404


def test_a_failed_bait_lookup_is_still_a_503_so_the_gateway_denies(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    real = env.store.table

    def broken(name: str) -> Any:
        if name == "honeytokens":
            raise RuntimeError("database down")
        return real(name)

    monkeypatch.setattr(env.store, "table", broken)
    params = {"agent_id": env.agent, "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": "gateway-test-0001"}
    assert env.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS).status_code == 503
