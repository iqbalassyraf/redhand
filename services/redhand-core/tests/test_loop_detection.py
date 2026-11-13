"""
Loop detection, core side (Phase 4 M6, docs/plans/phase4-m6-loop-detection.md): loop findings reuse the Radar's storage, review and
suppression, the settings need the right role and a confirmation, the gateway's context carries the settings and the exemption, and
a loop never enters the arithmetic of the injection and output checks.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest

from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_radar_findings import GATEWAY_HEADERS, Env, _context, item

LOOP_RULE = "RAD-LOOP-001"


def loop_item(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rule_id": LOOP_RULE, "kind": "loop", "family": "loop", "severity": "medium", "confidence": "high", "place": "call",
        "evasion": [], "tool_name": "get_status", "server": "helpdesk", "would_block": False, "occurrences": 1,
    }
    return {**base, **over}


@pytest.fixture
def env() -> Env:
    return Env()


def get_loop(env: Env, user: str = "operator") -> Any:
    return env.client.get("/v1/radar/loop-settings", headers=env.h(user))


def put_loop(env: Env, mode: str = "observe", limit: int = 20, window: int = 60, user: str = "admin", **extra: Any) -> Any:
    body = {"loop_mode": mode, "loop_limit": limit, "loop_window_seconds": window, **extra}
    return env.client.put("/v1/radar/loop-settings", json=body, headers=env.h(user))


# --- findings and alerts ---------------------------------------------------------------------------------------------

def test_a_loop_finding_is_stored_coalesced_and_alerted_once_without_call_details(env: Env) -> None:
    env.link()
    first = env.report([loop_item()])
    assert first.status_code == 200 and first.json()["new"] == 1
    again = env.report([loop_item(occurrences=5)])
    assert again.json()["new"] == 0 and again.json()["coalesced"] == 1
    stored = env.findings(kind="loop").json()["findings"]
    assert len(stored) == 1 and stored[0]["occurrences"] == 6 and stored[0]["place"] == "call" and stored[0]["rule_id"] == LOOP_RULE
    alerts = env.alerts()
    assert len(alerts) == 1 and "Loop" in alerts[0] and "Helpdesk bot" in alerts[0] and "get_status" in alerts[0]
    assert "no call details" in alerts[0]


def test_the_tool_name_in_an_alert_is_reduced_to_plain_characters(env: Env) -> None:
    env.link()
    env.report([loop_item(tool_name="get_status\n<b>click</b> https://evil.example/x")])
    alert = env.alerts()[0]
    assert "<" not in alert and "\n<" not in alert and "https://" not in alert and " evil" not in alert


def test_a_loop_alert_and_an_injection_alert_do_not_hide_each_other(env: Env) -> None:
    env.link()
    env.report([loop_item()])
    env.report([item("RAD-INJ-001")])
    alerts = env.alerts()
    assert len(alerts) == 2 and sum("Loop" in a for a in alerts) == 1 and sum("RAD-INJ-001" in a for a in alerts) == 1
    env.report([loop_item(tool_name="other_tool")])
    env.report([item("RAD-INJ-002")])
    assert len(env.alerts()) == 2  # both are inside their own ten minutes


def test_an_injection_alert_does_not_hide_a_loop_alert_that_follows_it(env: Env) -> None:
    env.link()
    env.report([item("RAD-INJ-001")])
    env.report([loop_item()])
    alerts = env.alerts()
    assert len(alerts) == 2 and sum("Loop" in a for a in alerts) == 1


def test_a_second_loop_alert_comes_after_ten_minutes(env: Env) -> None:
    env.link()
    env.report([loop_item()])
    for a in env.store.tables["agents"]:
        a["loop_last_alert_at"] = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
    env.report([loop_item(tool_name="third_tool")])
    assert len([a for a in env.alerts() if "Loop" in a]) == 2


@pytest.mark.parametrize(
    "over",
    [{"kind": "injection"}, {"kind": "output"}, {"place": "text"}, {"rule_id": "RAD-INJ-001"}],
    ids=["injection kind", "output kind", "text place", "injection rule"],
)
def test_inconsistent_loop_items_are_skipped_not_stored(env: Env, over: dict[str, Any]) -> None:
    resp = env.report([loop_item(**over)])
    assert resp.status_code == 200 and resp.json()["skipped"] == 1 and resp.json()["new"] == 0
    assert env.findings().json()["findings"] == []


@pytest.mark.parametrize("over", [{"rule_id": "RAD-LOOP-1"}, {"rule_id": "RAD-LOP-001"}, {"kind": "telepathy"}, {"place": "elsewhere"}])
def test_malformed_loop_items_are_refused_at_the_boundary(env: Env, over: dict[str, Any]) -> None:
    assert env.report([loop_item(**over)]).status_code == 422


def test_a_loop_report_for_another_organizations_agent_is_refused(env: Env) -> None:
    foreign = env.other_agent()
    assert env.report([loop_item()], agent=foreign).status_code == 404
    assert env.findings(kind="loop").json()["findings"] == []


def test_nothing_is_stored_while_loop_detection_is_off(env: Env) -> None:
    assert put_loop(env, "off", confirm=True).status_code == 200
    resp = env.report([loop_item()])
    assert resp.json()["disabled"] == 1 and resp.json()["new"] == 0
    assert env.report([item("RAD-INJ-001")]).json()["new"] == 1  # the Radar's own checks are unaffected


def test_a_loop_never_enters_the_radar_summary_or_the_readiness_kinds(env: Env) -> None:
    env.report([loop_item(), loop_item(tool_name="t2")])
    env.report([item("RAD-INJ-001")])
    summary = env.settings_get().json()["last_7_days"]
    assert summary["findings"] == 1  # the injection finding only
    readiness = env.client.get("/v1/radar/readiness", headers=env.h("operator"))
    assert readiness.status_code == 200 and {c["kind"] for c in readiness.json()["checks"]} == {"injection", "output"}
    assert get_loop(env).json()["last_7_days"]["findings"] == 2


# --- settings ----------------------------------------------------------------------------------------------------------

def test_the_defaults_are_observe_twenty_calls_in_sixty_seconds(env: Env) -> None:
    body = get_loop(env).json()
    assert body["loop_mode"] == "observe" and body["loop_limit"] == 20 and body["loop_window_seconds"] == 60
    assert body["capabilities"] == {"can_change_modes": False, "can_review": True, "can_suppress": False}
    assert get_loop(env, "admin").json()["capabilities"]["can_change_modes"] is True


def test_a_viewer_cannot_read_or_change_the_settings(env: Env) -> None:
    assert get_loop(env, "viewer").status_code == 403
    assert put_loop(env, "observe", 30, user="viewer").status_code == 403


def test_a_security_operator_can_read_but_not_change(env: Env) -> None:
    assert get_loop(env, "operator").status_code == 200
    assert put_loop(env, "observe", 30, user="operator").status_code == 403
    assert get_loop(env).json()["loop_limit"] == 20
    assert env.audit_actions("organization.loop_settings_changed") == []


def test_throttle_needs_confirmation_and_is_audited_with_the_actor(env: Env) -> None:
    refused = put_loop(env, "throttle", 30, 120)
    assert refused.status_code == 400 and "confirm" in refused.json()["detail"]
    assert get_loop(env).json()["loop_mode"] == "observe"
    ok = put_loop(env, "throttle", 30, 120, confirm=True, reason="night test")
    assert ok.status_code == 200 and ok.json()["loop_mode"] == "throttle" and ok.json()["loop_limit"] == 30
    rows = env.audit_actions("organization.loop_settings_changed")
    assert len(rows) == 1 and rows[0]["details"]["new_mode"] == "throttle" and rows[0]["details"]["old_mode"] == "observe"
    assert rows[0]["reason"] == "night test" and rows[0]["actor_user_id"]


def test_turning_detection_off_needs_confirmation_too(env: Env) -> None:
    assert put_loop(env, "off").status_code == 400
    assert put_loop(env, "off", confirm=True).status_code == 200


def test_changing_only_the_limit_in_observe_needs_no_confirmation(env: Env) -> None:
    assert put_loop(env, "observe", 40, 90).status_code == 200
    assert get_loop(env).json()["loop_limit"] == 40


def test_leaving_throttle_for_observe_needs_no_confirmation(env: Env) -> None:
    put_loop(env, "throttle", confirm=True)
    assert put_loop(env, "observe").status_code == 200


def test_repeating_the_current_settings_is_a_no_op_with_no_new_audit_row(env: Env) -> None:
    put_loop(env, "throttle", 30, 120, confirm=True)
    assert put_loop(env, "throttle", 30, 120).status_code == 200  # already throttling: no confirmation needed, nothing changes
    assert len(env.audit_actions("organization.loop_settings_changed")) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"loop_mode": "block", "loop_limit": 20, "loop_window_seconds": 60},
        {"loop_mode": "observe", "loop_limit": 2, "loop_window_seconds": 60},
        {"loop_mode": "observe", "loop_limit": 1001, "loop_window_seconds": 60},
        {"loop_mode": "observe", "loop_limit": 20, "loop_window_seconds": 9},
        {"loop_mode": "observe", "loop_limit": 20, "loop_window_seconds": 601},
        {"loop_mode": "observe", "loop_limit": "20", "loop_window_seconds": 60},
        {"loop_mode": "observe", "loop_limit": 20, "loop_window_seconds": 60, "extra": 1},
        {"loop_mode": "observe", "loop_limit": 20},
        {"loop_mode": "observe", "loop_limit": 20, "loop_window_seconds": 60, "confirm": "yes"},
    ],
    ids=["block", "limit 2", "limit 1001", "window 9", "window 601", "string limit", "extra field", "missing window", "string confirm"],
)
def test_nonsense_settings_are_refused_and_change_nothing(env: Env, body: dict[str, Any]) -> None:
    assert env.client.put("/v1/radar/loop-settings", json=body, headers=env.h("admin")).status_code == 422
    assert get_loop(env).json()["loop_limit"] == 20 and get_loop(env).json()["loop_mode"] == "observe"


def test_a_caller_who_saw_another_mode_gets_a_conflict(env: Env) -> None:
    put_loop(env, "observe", 25)
    resp = put_loop(env, "throttle", 30, 60, confirm=True, expected_mode="off")
    assert resp.status_code == 409
    assert get_loop(env).json()["loop_mode"] == "observe"


def test_one_organizations_settings_never_touch_another(env: Env) -> None:
    put_loop(env, "throttle", 50, 300, confirm=True)
    other = env.client.get("/v1/radar/loop-settings", headers=env.other_headers())
    assert other.status_code == 200 and other.json()["loop_mode"] == "observe" and other.json()["loop_limit"] == 20
    changed = env.client.put(
        "/v1/radar/loop-settings", json={"loop_mode": "observe", "loop_limit": 7, "loop_window_seconds": 15}, headers=env.other_headers()
    )
    assert changed.status_code == 200
    assert get_loop(env).json()["loop_limit"] == 50 and get_loop(env).json()["loop_mode"] == "throttle"


def test_the_endpoints_need_a_sign_in(env: Env) -> None:
    assert env.client.get("/v1/radar/loop-settings").status_code in (401, 403)
    assert env.client.put("/v1/radar/loop-settings", json={"loop_mode": "off", "loop_limit": 20, "loop_window_seconds": 60}).status_code in (401, 403)


# --- the gateway's context ---------------------------------------------------------------------------------------------

def test_the_context_carries_the_loop_settings_and_follows_changes(env: Env) -> None:
    agent = _context(env)
    assert (agent["loop_mode"], agent["loop_limit"], agent["loop_window_seconds"], agent["loop_exempt"]) == ("observe", 20, 60, False)
    put_loop(env, "throttle", 30, 120, confirm=True)
    agent = _context(env)
    assert (agent["loop_mode"], agent["loop_limit"], agent["loop_window_seconds"]) == ("throttle", 30, 120)


@pytest.mark.parametrize("odd", ["block", "OBSERVE", "Throttle", "", None, True, 1, ["throttle"]])
def test_anything_but_an_explicit_mode_is_off_in_the_context(env: Env, odd: Any) -> None:
    org = next(o for o in env.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)
    org["loop_mode"] = odd
    assert _context(env)["loop_mode"] == "off"


@pytest.mark.parametrize("odd", [0, 2, 1001, True, "20", None, 10**9, 20.5, -5])
def test_a_limit_or_window_that_is_not_a_plain_in_range_integer_falls_back_to_the_defaults(env: Env, odd: Any) -> None:
    org = next(o for o in env.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)
    org["loop_limit"] = odd
    org["loop_window_seconds"] = odd
    agent = _context(env)
    assert agent["loop_limit"] == 20 and agent["loop_window_seconds"] == 60


def test_a_live_loop_suppression_exempts_the_agent_and_revoking_it_ends_the_exemption(env: Env) -> None:
    assert _context(env)["loop_exempt"] is False
    created = env.suppress(LOOP_RULE)
    assert created.status_code in (200, 201) and created.json()["created"] is True
    assert _context(env)["loop_exempt"] is True
    assert env.client.delete(f"/v1/radar/suppressions/{created.json()['id']}", headers=env.h("admin")).json() == {"revoked": True}
    assert _context(env)["loop_exempt"] is False


def test_only_the_loop_rule_for_this_agent_and_organization_exempts(env: Env) -> None:
    env.suppress("RAD-INJ-001")
    assert _context(env)["loop_exempt"] is False  # another rule
    rows = env.store.tables.setdefault("radar_suppressions", [])
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    rows.append({"id": "00000000-0000-0000-0000-00000000aa01", "organization_id": DEFAULT_ORG_ID, "agent_id": "00000000-0000-0000-0000-00000000aaaa",
                 "rule_id": LOOP_RULE, "reason": "other agent", "created_by": "x", "created_at": future, "expires_at": future, "revoked_at": None, "revoked_by": None})
    rows.append({"id": "00000000-0000-0000-0000-00000000aa02", "organization_id": "00000000-0000-0000-0000-0000000000ff", "agent_id": env.agent,
                 "rule_id": LOOP_RULE, "reason": "other organization", "created_by": "x", "created_at": future, "expires_at": future, "revoked_at": None, "revoked_by": None})
    assert _context(env)["loop_exempt"] is False


def test_an_expired_or_revoked_suppression_does_not_exempt(env: Env) -> None:
    rows = env.store.tables.setdefault("radar_suppressions", [])
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    base = {"organization_id": DEFAULT_ORG_ID, "agent_id": env.agent, "rule_id": LOOP_RULE, "reason": "r", "created_by": "x", "created_at": past}
    rows.append({**base, "id": "00000000-0000-0000-0000-00000000bb01", "expires_at": past, "revoked_at": None, "revoked_by": None})
    rows.append({**base, "id": "00000000-0000-0000-0000-00000000bb02", "expires_at": future, "revoked_at": past, "revoked_by": "x"})
    assert _context(env)["loop_exempt"] is False


def test_a_failed_exemption_lookup_means_not_exempt_and_does_not_fail_the_context(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    assert env.suppress(LOOP_RULE).status_code in (200, 201)
    assert _context(env)["loop_exempt"] is True
    real_table = env.store.table

    def broken(name: str) -> Any:
        if name == "radar_suppressions":
            raise RuntimeError("database unavailable")
        return real_table(name)

    monkeypatch.setattr(env.store, "table", broken)
    agent = _context(env)  # the lookup still answers 200: the exemption is a side question
    assert agent["loop_exempt"] is False and agent["status"] == "active"


def test_the_suppression_endpoint_accepts_the_loop_rule_and_refuses_a_mistyped_one(env: Env) -> None:
    assert env.suppress(LOOP_RULE).status_code in (200, 201)
    assert env.suppress("RAD-LOP-001").status_code == 422
    assert env.suppress(LOOP_RULE, user="operator").status_code == 403


def test_the_internal_context_endpoint_still_needs_the_service_token(env: Env) -> None:
    params = {"agent_id": env.agent, "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": "gateway-test-0001"}
    assert env.client.get("/internal/v1/gateway-context", params=params).status_code in (401, 403)
    assert env.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS).status_code == 200
    assert UUID(env.agent)
