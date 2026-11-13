"""
The per-agent destination allowlist, core side (Phase 4 M7, docs/plans/phase4-m7-destination-allowlist.md): who may change a list or its mode,
what needs a confirmation, that hosts are stored in the gateway's own canonical spelling, that nothing crosses organizations, what the gateway's
context carries (and how it fails), and that destination findings reuse the Radar's storage without entering the arithmetic of its checks.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_radar_findings import GATEWAY_HEADERS, Env, _context, item

TOOL_PAGE_SIZE = 100


def dst_item(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rule_id": "RAD-DST-001", "kind": "destination", "family": "destination", "severity": "high", "confidence": "high", "place": "call",
        "evasion": [], "tool_name": "send_report", "server": "mail", "would_block": False, "occurrences": 1, "detail": "evil.com",
    }
    return {**base, **over}


@pytest.fixture
def env() -> Env:
    return Env()


def url(env: Env, agent: str | None = None, suffix: str = "destinations") -> str:
    return f"/v1/passports/{agent or env.agent}/{suffix}"


def get_dest(env: Env, user: str = "operator", agent: str | None = None) -> Any:
    return env.client.get(url(env, agent), headers=env.h(user))


def add(env: Env, host: str, user: str = "admin", agent: str | None = None, confirm: bool = True, **extra: Any) -> Any:
    return env.client.post(url(env, agent), json={"host": host, "confirm": confirm, **extra}, headers=env.h(user))


def set_mode(env: Env, mode: str, expected: str, user: str = "admin", agent: str | None = None, confirm: bool = False, **extra: Any) -> Any:
    body = {"destination_mode": mode, "expected_mode": expected, "confirm": confirm, **extra}
    return env.client.put(url(env, agent, "destination-mode"), json=body, headers=env.h(user))


def remove(env: Env, entry_id: str, user: str = "admin", agent: str | None = None, **params: Any) -> Any:
    return env.client.delete(url(env, agent, f"destinations/{entry_id}"), params=params, headers=env.h(user))


def hosts(env: Env, agent: str | None = None) -> list[str]:
    return [e["host"] for e in get_dest(env, agent=agent).json()["entries"]]


def audit(env: Env, action: str) -> list[dict[str, Any]]:
    return env.audit_actions(action)


# --- who may do what --------------------------------------------------------------------------------------------------

def test_a_viewer_cannot_read_or_change_anything(env: Env) -> None:
    assert get_dest(env, "viewer").status_code == 403
    assert add(env, "good.com", "viewer").status_code == 403
    assert set_mode(env, "observe", "off", "viewer").status_code == 403
    assert remove(env, str(uuid4()), "viewer").status_code == 403


def test_a_security_operator_can_read_but_not_change(env: Env) -> None:
    assert add(env, "good.com").status_code == 200
    entry = get_dest(env, "operator").json()["entries"][0]["id"]
    assert get_dest(env, "operator").status_code == 200
    assert add(env, "other.com", "operator").status_code == 403
    assert remove(env, entry, "operator").status_code == 403
    assert set_mode(env, "observe", "off", "operator").status_code == 403
    assert hosts(env) == ["good.com"]
    assert get_dest(env, "operator").json()["capabilities"] == {"can_change": False}


@pytest.mark.parametrize("user", ["admin", "owner"])
def test_an_admin_or_owner_can_change(env: Env, user: str) -> None:
    assert add(env, "good.com", user).status_code == 200
    assert get_dest(env, user).json()["capabilities"] == {"can_change": True}


def test_every_endpoint_needs_a_sign_in(env: Env) -> None:
    assert env.client.get(url(env)).status_code in (401, 403)
    assert env.client.post(url(env), json={"host": "a.com", "confirm": True}).status_code in (401, 403)
    assert env.client.put(url(env, suffix="destination-mode"), json={"destination_mode": "off", "expected_mode": "off"}).status_code in (401, 403)
    assert env.client.delete(url(env, suffix=f"destinations/{uuid4()}")).status_code in (401, 403)


# --- adding hosts -----------------------------------------------------------------------------------------------------

def test_adding_needs_the_confirmation(env: Env) -> None:
    refused = add(env, "good.com", confirm=False)
    assert refused.status_code == 400 and "confirm" in refused.json()["detail"]
    assert hosts(env) == [] and audit(env, "passport.destination_added") == []


@pytest.mark.parametrize(
    "typed,stored",
    [("good.com", "good.com"), ("Good.COM.", "good.com"), ("BÜCHER.de", "xn--bcher-kva.de"), ("0x7f.1", "127.0.0.1"),
     ("2130706433", "127.0.0.1"), ("[::1]", "::1"), ("  files.good.com  ", "files.good.com"), ("аpple.com", "xn--pple-43d.com")],
)
def test_a_host_is_stored_in_the_gateways_canonical_spelling(env: Env, typed: str, stored: str) -> None:
    resp = add(env, typed)
    assert resp.status_code == 200 and resp.json()["host"] == stored and resp.json()["added"] is True
    assert hosts(env) == [stored]


@pytest.mark.parametrize(
    "typed",
    ["https://good.com", "good.com/path", "good.com:8080", "*.good.com", "good com", "a@b.com", "%2e", "good.com%2f", "-bad.com", "a..b.com", "[::1", "256.1.1.1", "x" * 64 + ".com"],
)
def test_anything_that_is_not_a_plain_host_is_refused_with_a_plain_message(env: Env, typed: str) -> None:
    resp = add(env, typed)
    assert resp.status_code == 422, typed
    assert "host name or address only" in resp.json()["detail"]
    assert hosts(env) == [] and audit(env, "passport.destination_added") == []


@pytest.mark.parametrize("body", [{"host": ""}, {"host": "x" * 301}, {"host": "a.com", "confirm": "yes"}, {"host": "a.com", "extra": 1}, {}])
def test_malformed_requests_are_refused_at_the_boundary(env: Env, body: dict[str, Any]) -> None:
    assert env.client.post(url(env), json={"confirm": True, **body} if "confirm" not in body else body, headers=env.h("admin")).status_code == 422


def test_adding_the_same_host_again_changes_nothing_and_is_audited_once_with_the_actor(env: Env) -> None:
    first = add(env, "good.com", reason="the reporting service")
    again = add(env, "GOOD.com.")
    assert again.status_code == 200 and again.json()["added"] is False and again.json()["id"] == first.json()["id"]
    rows = audit(env, "passport.destination_added")
    assert len(rows) == 1 and rows[0]["details"]["host"] == "good.com" and rows[0]["reason"] == "the reporting service" and rows[0]["actor_user_id"]


def test_the_list_holds_at_most_one_hundred_hosts(env: Env) -> None:
    for i in range(100):
        assert add(env, f"h{i}.example.com").status_code == 200
    full = add(env, "one-too-many.example.com")
    assert full.status_code == 409 and "100" in full.json()["detail"]
    assert add(env, "h0.example.com").status_code == 200  # already on the list: an idempotent no-op even when full
    assert len(hosts(env)) == 100


def test_each_agent_has_its_own_list(env: Env) -> None:
    second = env.register("Second bot")["id"]
    add(env, "good.com")
    assert hosts(env, second) == [] and add(env, "good.com", agent=second).json()["added"] is True


# --- removing hosts ---------------------------------------------------------------------------------------------------

def test_removing_a_host_is_audited_with_the_host(env: Env) -> None:
    entry = add(env, "good.com").json()["id"]
    resp = remove(env, entry, reason="no longer used")
    assert resp.status_code == 200 and resp.json() == {"removed": True} and hosts(env) == []
    rows = audit(env, "passport.destination_removed")
    assert len(rows) == 1 and rows[0]["details"]["host"] == "good.com" and rows[0]["reason"] == "no longer used"


def test_an_unknown_entry_and_another_agents_entry_are_not_found(env: Env) -> None:
    second = env.register("Second bot")["id"]
    entry = add(env, "good.com").json()["id"]
    assert remove(env, str(uuid4())).status_code == 404
    assert remove(env, entry, agent=second).status_code == 404  # the entry belongs to the first agent
    assert hosts(env) == ["good.com"]


def test_the_last_host_cannot_be_removed_while_the_agent_is_enforcing(env: Env) -> None:
    first = add(env, "good.com").json()["id"]
    second = add(env, "files.good.com").json()["id"]
    assert set_mode(env, "enforce", "off", confirm=True).status_code == 200
    assert remove(env, first).status_code == 200  # two entries: one can go
    stuck = remove(env, second)
    assert stuck.status_code == 409 and "last allowed destination" in stuck.json()["detail"]
    assert hosts(env) == ["files.good.com"]
    assert set_mode(env, "observe", "enforce").status_code == 200
    assert remove(env, second).status_code == 200


# --- the mode ---------------------------------------------------------------------------------------------------------

def test_an_agent_starts_with_the_check_off_and_an_empty_list(env: Env) -> None:
    body = get_dest(env).json()
    assert body["destination_mode"] == "off" and body["entries"] == [] and body["max_entries"] == 100


def test_observe_needs_no_confirmation_and_is_audited_with_the_actor(env: Env) -> None:
    resp = set_mode(env, "observe", "off", reason="learn what it talks to")
    assert resp.status_code == 200 and resp.json()["destination_mode"] == "observe"
    rows = audit(env, "passport.destination_mode_changed")
    assert len(rows) == 1 and rows[0]["details"] == {"old_mode": "off", "new_mode": "observe"} and rows[0]["actor_user_id"]


def test_enforce_needs_the_confirmation_and_a_non_empty_list(env: Env) -> None:
    refused = set_mode(env, "enforce", "off")
    assert refused.status_code == 400 and "confirm" in refused.json()["detail"]
    empty = set_mode(env, "enforce", "off", confirm=True)
    assert empty.status_code == 409 and "at least one allowed destination" in empty.json()["detail"]
    assert get_dest(env).json()["destination_mode"] == "off" and audit(env, "passport.destination_mode_changed") == []
    add(env, "good.com")
    assert set_mode(env, "enforce", "off", confirm=True).json()["destination_mode"] == "enforce"


def test_turning_the_check_off_needs_the_confirmation(env: Env) -> None:
    set_mode(env, "observe", "off")
    assert set_mode(env, "off", "observe").status_code == 400
    assert set_mode(env, "off", "observe", confirm=True).status_code == 200


def test_leaving_enforce_for_observe_needs_no_confirmation(env: Env) -> None:
    add(env, "good.com")
    set_mode(env, "enforce", "off", confirm=True)
    assert set_mode(env, "observe", "enforce").status_code == 200


def test_a_caller_who_saw_another_mode_gets_a_conflict(env: Env) -> None:
    set_mode(env, "observe", "off")
    resp = set_mode(env, "off", "enforce", confirm=True)
    assert resp.status_code == 409 and "someone else" in resp.json()["detail"]
    assert get_dest(env).json()["destination_mode"] == "observe"


def test_repeating_the_current_mode_changes_nothing(env: Env) -> None:
    set_mode(env, "observe", "off")
    assert set_mode(env, "observe", "observe").status_code == 200
    assert len(audit(env, "passport.destination_mode_changed")) == 1


@pytest.mark.parametrize(
    "body",
    [{"destination_mode": "block", "expected_mode": "off"}, {"destination_mode": "observe", "expected_mode": "maybe"}, {"destination_mode": "observe"},
     {"destination_mode": "observe", "expected_mode": "off", "confirm": 1}, {"destination_mode": "observe", "expected_mode": "off", "extra": True}],
    ids=["block", "bad expected", "no expected", "int confirm", "extra field"],
)
def test_nonsense_mode_requests_are_refused(env: Env, body: dict[str, Any]) -> None:
    assert env.client.put(url(env, suffix="destination-mode"), json=body, headers=env.h("admin")).status_code == 422
    assert get_dest(env).json()["destination_mode"] == "off"


# --- tenant isolation -------------------------------------------------------------------------------------------------

def test_another_organization_cannot_touch_this_agent_and_this_organization_cannot_touch_theirs(env: Env) -> None:
    add(env, "good.com")
    set_mode(env, "observe", "off")
    other = env.other_headers()
    mine = env.agent
    assert env.client.get(url(env), headers=other).status_code == 404
    assert env.client.post(url(env), json={"host": "evil.com", "confirm": True}, headers=other).status_code == 404
    assert env.client.put(url(env, suffix="destination-mode"), json={"destination_mode": "off", "expected_mode": "observe", "confirm": True}, headers=other).status_code == 404
    entry = get_dest(env).json()["entries"][0]["id"]
    assert env.client.delete(url(env, suffix=f"destinations/{entry}"), headers=other).status_code == 404
    assert hosts(env) == ["good.com"] and get_dest(env).json()["destination_mode"] == "observe"
    foreign = env.other_agent()
    assert get_dest(env, agent=foreign).status_code == 404
    assert add(env, "evil.com", agent=foreign).status_code == 404
    assert set_mode(env, "observe", "off", agent=foreign).status_code == 404
    assert mine != foreign


# --- what the gateway is told -----------------------------------------------------------------------------------------

def test_the_context_defaults_to_off_with_no_list(env: Env) -> None:
    agent = _context(env)
    assert agent["destination_mode"] == "off" and agent["allowed_destinations"] == []


def test_the_list_is_sent_only_while_the_check_is_on(env: Env) -> None:
    add(env, "good.com")
    add(env, "files.good.com")
    assert _context(env)["allowed_destinations"] == []  # off: nothing is sent
    set_mode(env, "observe", "off")
    agent = _context(env)
    assert agent["destination_mode"] == "observe" and agent["allowed_destinations"] == ["files.good.com", "good.com"]
    set_mode(env, "enforce", "observe", confirm=True)
    assert _context(env)["destination_mode"] == "enforce"
    set_mode(env, "off", "enforce", confirm=True)
    assert _context(env)["allowed_destinations"] == []


def _agent_row(env: Env) -> dict[str, Any]:
    return next(a for a in env.store.tables["agents"] if a["id"] == env.agent)


def test_a_missing_or_null_mode_is_off(env: Env) -> None:
    row = _agent_row(env)
    row.pop("destination_mode", None)
    assert _context(env)["destination_mode"] == "off"
    row["destination_mode"] = None
    assert _context(env)["destination_mode"] == "off"


@pytest.mark.parametrize("odd", ["block", "ENFORCE", "Observe", "", True, 1, ["off"]])
def test_a_mode_that_is_present_but_unrecognised_is_read_as_enforce(env: Env, odd: Any) -> None:
    """The restrictive reading: a corrupted value must never quietly mean "no checks" (the database also refuses such a value)."""
    add(env, "good.com")
    _agent_row(env)["destination_mode"] = odd
    agent = _context(env)
    assert agent["destination_mode"] == "enforce" and agent["allowed_destinations"] == ["good.com"]


def test_a_stored_entry_that_is_not_in_canonical_form_is_dropped_never_widened(env: Env) -> None:
    add(env, "good.com")
    set_mode(env, "observe", "off")
    rows = env.store.tables.setdefault("agent_destinations", [])
    for host in ("UPPER.com", "good.com:80", "a/b.com", "0x7f.1", "*.good.com", "", "good.com."):
        rows.append({"id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "agent_id": env.agent, "host": host, "created_by": "x", "created_at": "2026-11-13T00:00:00+00:00"})
    assert _context(env)["allowed_destinations"] == ["good.com"]


def test_only_this_agents_entries_are_sent(env: Env) -> None:
    second = env.register("Second bot")["id"]
    add(env, "good.com")
    add(env, "other.com", agent=second)
    set_mode(env, "observe", "off")
    set_mode(env, "observe", "off", agent=second)
    assert _context(env)["allowed_destinations"] == ["good.com"]
    rows = env.store.tables["agent_destinations"]
    rows.append({"id": str(uuid4()), "organization_id": "00000000-0000-0000-0000-0000000000ff", "agent_id": env.agent, "host": "foreign.com", "created_by": "x", "created_at": "2026-11-13T00:00:00+00:00"})
    assert _context(env)["allowed_destinations"] == ["good.com"]  # an entry of another organization is never sent


def test_a_failed_list_lookup_denies_the_whole_lookup(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    add(env, "good.com")
    set_mode(env, "observe", "off")
    real = env.store.table

    def broken(name: str) -> Any:
        if name == "agent_destinations":
            raise RuntimeError("database unavailable")
        return real(name)

    monkeypatch.setattr(env.store, "table", broken)
    params = {"agent_id": env.agent, "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": "gateway-test-0001"}
    resp = env.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS)
    assert resp.status_code == 503 and "RuntimeError" not in resp.text and "database" not in resp.text


def test_with_the_check_off_a_failed_list_lookup_is_not_even_attempted(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    real = env.store.table

    def broken(name: str) -> Any:
        if name == "agent_destinations":
            raise RuntimeError("must not be called")
        return real(name)

    monkeypatch.setattr(env.store, "table", broken)
    assert _context(env)["destination_mode"] == "off"


# --- findings, alerts and summaries -----------------------------------------------------------------------------------

def test_a_destination_finding_is_stored_with_the_coarse_host_and_alerted_once(env: Env) -> None:
    env.link()
    set_mode(env, "observe", "off")
    resp = env.report([dst_item()])
    assert resp.status_code == 200 and resp.json()["new"] == 1
    found = env.findings(kind="destination").json()["findings"]
    assert len(found) == 1 and found[0]["detail"] == "evil.com" and found[0]["place"] == "call" and found[0]["rule_id"] == "RAD-DST-001"
    alerts = env.alerts()
    assert len(alerts) == 1 and "Destination" in alerts[0] and "evil.com" in alerts[0] and "send_report" in alerts[0] and "Helpdesk bot" in alerts[0]
    assert "Recorded only" in alerts[0] and "no call details" in alerts[0]
    env.report([dst_item(tool_name="other_tool")])
    assert len(env.alerts()) == 1  # inside the ten minutes


def test_the_alert_says_the_call_was_refused_in_enforce(env: Env) -> None:
    env.link()
    add(env, "good.com")
    set_mode(env, "enforce", "off", confirm=True)
    env.report([dst_item()])
    assert "The call was refused" in env.alerts()[0]


def test_the_tool_name_and_host_in_an_alert_are_reduced_to_plain_characters(env: Env) -> None:
    env.link()
    set_mode(env, "observe", "off")
    env.report([dst_item(tool_name="send\n<b>click</b> https://evil.example/x")])
    alert = env.alerts()[0]
    assert "<" not in alert and "https://" not in alert and "\n<" not in alert


def test_a_destination_alert_does_not_hide_an_injection_or_loop_alert_and_the_other_way_round(env: Env) -> None:
    env.link()
    set_mode(env, "observe", "off")
    env.report([dst_item()])
    env.report([item("RAD-INJ-001")])
    env.report([{"rule_id": "RAD-LOOP-001", "kind": "loop", "family": "loop", "severity": "medium", "confidence": "high", "place": "call", "tool_name": "t",
                 "server": "s", "would_block": False, "occurrences": 1}])
    alerts = env.alerts()
    assert len(alerts) == 3 and sum("Destination" in a for a in alerts) == 1 and sum("Loop" in a for a in alerts) == 1


def test_nothing_is_stored_while_the_agents_check_is_off(env: Env) -> None:
    resp = env.report([dst_item()])
    assert resp.json()["disabled"] == 1 and resp.json()["new"] == 0
    assert env.findings().json()["findings"] == []


def test_each_agents_own_mode_decides(env: Env) -> None:
    second = env.register("Second bot")["id"]
    set_mode(env, "observe", "off", agent=second)
    assert env.report([dst_item()]).json()["disabled"] == 1  # the first agent is off
    assert env.report([dst_item()], agent=second).json()["new"] == 1


@pytest.mark.parametrize("over", [{"place": "text"}, {"kind": "loop"}, {"kind": "injection"}, {"rule_id": "RAD-LOOP-001"}])
def test_inconsistent_destination_items_are_skipped(env: Env, over: dict[str, Any]) -> None:
    set_mode(env, "observe", "off")
    resp = env.report([dst_item(**over)])
    assert resp.status_code == 200 and resp.json()["skipped"] == 1 and resp.json()["new"] == 0


@pytest.mark.parametrize("over", [{"detail": "Evil.COM"}, {"detail": "a/b"}, {"detail": "x" * 65}, {"rule_id": "RAD-DST-1"}, {"rule_id": "RAD-DSX-001"}, {"kind": "telepathy"}])
def test_malformed_destination_items_are_refused_at_the_boundary(env: Env, over: dict[str, Any]) -> None:
    assert env.report([dst_item(**over)]).status_code == 422


def test_another_kind_never_keeps_a_detail(env: Env) -> None:
    resp = env.report([{**item("RAD-INJ-001"), "detail": "evil.com"}])
    assert resp.status_code == 200
    assert env.findings().json()["findings"][0]["detail"] is None


def test_the_first_host_seen_in_a_window_is_kept(env: Env) -> None:
    set_mode(env, "observe", "off")
    env.report([dst_item(detail="evil.com")])
    env.report([dst_item(detail="other.org", occurrences=4)])
    found = env.findings(kind="destination").json()["findings"]
    assert len(found) == 1 and found[0]["detail"] == "evil.com" and found[0]["occurrences"] == 5


def test_a_destination_report_for_another_organizations_agent_is_refused(env: Env) -> None:
    assert env.report([dst_item()], agent=env.other_agent()).status_code == 404


def test_a_destination_never_enters_the_radar_loop_or_readiness_numbers(env: Env) -> None:
    set_mode(env, "observe", "off")
    env.report([dst_item(), dst_item(tool_name="t2")])
    env.report([item("RAD-INJ-001")])
    assert env.settings_get().json()["last_7_days"]["findings"] == 1
    assert env.client.get("/v1/radar/loop-settings", headers=env.h("operator")).json()["last_7_days"].get("findings", 0) == 0
    readiness = env.client.get("/v1/radar/readiness", headers=env.h("operator"))
    assert readiness.status_code == 200 and {c["kind"] for c in readiness.json()["checks"]} == {"injection", "output"}
    assert get_dest(env).json()["last_7_days"]["findings"] == 2


def test_a_destination_rule_can_be_suppressed_and_a_mistyped_one_cannot(env: Env) -> None:
    set_mode(env, "observe", "off")
    assert env.suppress("RAD-DST-001").status_code in (200, 201)
    assert env.suppress("RAD-DSX-001").status_code == 422
    assert env.report([dst_item()]).json()["suppressed"] == 1
