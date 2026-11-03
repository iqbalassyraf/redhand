"""
Safe Mode control actions in redhand-core (Phase 2, M2): who may turn it on and off, the audit
trail, idempotency, tenancy, and what the gateway is told. The gateway's own enforcement is
tested in agentwall/tests/test_gateway.py.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_passports import OTHER_ORG, Env


@pytest.fixture
def env() -> Env:
    return Env()


def _safe_mode_actions(env: Env) -> list[dict[str, Any]]:
    return [e for e in env.audit() if "safe_mode" in e["action"]]


def _context_flag(env: Env, agent_id: str) -> bool:
    resp = env.context(agent_id)
    assert resp.status_code == 200, resp.text
    flag = resp.json()["agent"]["safe_mode"]
    assert isinstance(flag, bool)
    return flag


# ---------------------------------------------------------------------------
# Per-agent flag
# ---------------------------------------------------------------------------


def test_security_operator_can_turn_an_agent_on_and_it_is_audited(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    resp = env.client.post(
        f"/v1/passports/{agent_id}/safe-mode", json={"enabled": True, "reason": "odd traffic"}, headers=env.h("operator")
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["changed"] is True and resp.json()["passport"]["safe_mode"] is True

    entry = _safe_mode_actions(env)[0]
    assert entry["action"] == "passport.safe_mode_enabled"
    assert entry["target_type"] == "agent" and entry["target_id"] == agent_id
    assert entry["reason"] == "odd traffic"
    listed = {p["id"]: p for p in env.client.get("/v1/passports", headers=env.h("viewer")).json()}
    assert listed[agent_id]["safe_mode"] is True


def test_turning_on_twice_changes_nothing_and_audits_once(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    url = f"/v1/passports/{agent_id}/safe-mode"
    env.client.post(url, json={"enabled": True}, headers=env.h("operator"))
    again = env.client.post(url, json={"enabled": True}, headers=env.h("operator"))
    assert again.status_code == 200 and again.json()["changed"] is False
    assert len(_safe_mode_actions(env)) == 1


def test_turning_off_needs_an_admin_and_explicit_confirmation(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    url = f"/v1/passports/{agent_id}/safe-mode"
    env.client.post(url, json={"enabled": True}, headers=env.h("operator"))

    assert env.client.post(url, json={"enabled": False, "confirm": True}, headers=env.h("operator")).status_code == 403
    assert env.client.post(url, json={"enabled": False}, headers=env.h("admin")).status_code == 400
    assert env.client.post(url, json={"enabled": False, "confirm": False}, headers=env.h("admin")).status_code == 400
    assert _context_flag(env, agent_id) is True  # nothing changed so far

    ok = env.client.post(url, json={"enabled": False, "confirm": True, "reason": "fixed"}, headers=env.h("admin"))
    assert ok.status_code == 200 and ok.json()["passport"]["safe_mode"] is False
    assert [e["action"] for e in _safe_mode_actions(env)] == ["passport.safe_mode_disabled", "passport.safe_mode_enabled"]


def test_viewers_and_anonymous_callers_cannot_change_safe_mode(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    url = f"/v1/passports/{agent_id}/safe-mode"
    assert env.client.post(url, json={"enabled": True}, headers=env.h("viewer")).status_code == 403
    assert env.client.post(url, json={"enabled": True}).status_code == 401
    assert env.client.post("/v1/organization/safe-mode", json={"enabled": True}, headers=env.h("viewer")).status_code == 403
    assert env.client.post("/v1/organization/safe-mode", json={"enabled": True}).status_code == 401
    assert _safe_mode_actions(env) == []


@pytest.mark.parametrize("body", [{}, {"enabled": "yes"}, {"enabled": True, "extra": 1}, {"enabled": True, "reason": "x" * 501}])
def test_invalid_safe_mode_requests_are_rejected(env: Env, body: dict[str, Any]) -> None:
    agent_id = env.register()["passport"]["id"]
    assert env.client.post(f"/v1/passports/{agent_id}/safe-mode", json=body, headers=env.h("operator")).status_code == 422
    assert env.client.post("/v1/organization/safe-mode", json=body, headers=env.h("operator")).status_code == 422


def test_unknown_agent_and_other_tenants_agents_are_not_found(env: Env) -> None:
    foreign_id = str(uuid4())
    env.store.tables["agents"].append(
        {"id": foreign_id, "organization_id": OTHER_ORG, "external_agent_id": "f", "name": "F", "status": "active",
         "scopes": [], "version": 1, "safe_mode": False, "expires_at": "2099-01-01T00:00:00+00:00"}
    )
    for target in (foreign_id, str(uuid4())):
        resp = env.client.post(f"/v1/passports/{target}/safe-mode", json={"enabled": True}, headers=env.h("owner"))
        assert resp.status_code == 404
    assert next(a for a in env.store.tables["agents"] if a["id"] == foreign_id)["safe_mode"] is False


# ---------------------------------------------------------------------------
# Organization flag
# ---------------------------------------------------------------------------


def test_organization_safe_mode_covers_every_agent_of_the_tenant_only(env: Env) -> None:
    first = env.register(name="bot-1")["passport"]["id"]
    second = env.register(name="bot-2")["passport"]["id"]
    foreign_id = str(uuid4())
    env.store.tables["agents"].append(
        {"id": foreign_id, "organization_id": OTHER_ORG, "external_agent_id": "f", "name": "F", "status": "active",
         "scopes": [], "version": 1, "safe_mode": False, "expires_at": "2099-01-01T00:00:00+00:00"}
    )
    assert env.client.get("/v1/organization/safe-mode", headers=env.h("viewer")).json()["enabled"] is False

    resp = env.client.post("/v1/organization/safe-mode", json={"enabled": True, "reason": "incident 7"}, headers=env.h("operator"))
    assert resp.status_code == 200 and resp.json() == {"enabled": True, "changed": True}
    assert env.client.get("/v1/organization/safe-mode", headers=env.h("viewer")).json()["enabled"] is True

    assert _context_flag(env, first) is True and _context_flag(env, second) is True
    foreign = env.context(foreign_id, org=OTHER_ORG)
    assert foreign.json()["agent"]["safe_mode"] is False  # the other tenant is untouched
    entry = _safe_mode_actions(env)[0]
    assert entry["action"] == "organization.safe_mode_enabled" and entry["target_type"] == "organization"
    assert entry["target_id"] == DEFAULT_ORG_ID and entry["reason"] == "incident 7"


def test_organization_safe_mode_is_idempotent_and_off_needs_admin_and_confirmation(env: Env) -> None:
    url = "/v1/organization/safe-mode"
    env.client.post(url, json={"enabled": True}, headers=env.h("operator"))
    assert env.client.post(url, json={"enabled": True}, headers=env.h("operator")).json()["changed"] is False
    assert len(_safe_mode_actions(env)) == 1

    assert env.client.post(url, json={"enabled": False, "confirm": True}, headers=env.h("operator")).status_code == 403
    assert env.client.post(url, json={"enabled": False}, headers=env.h("admin")).status_code == 400
    assert env.client.get(url, headers=env.h("viewer")).json()["enabled"] is True
    assert env.client.post(url, json={"enabled": False, "confirm": True}, headers=env.h("admin")).json() == {
        "enabled": False, "changed": True,
    }


# ---------------------------------------------------------------------------
# What the gateway is told
# ---------------------------------------------------------------------------


def test_gateway_context_reports_the_effective_flag(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    assert _context_flag(env, agent_id) is False

    env.client.post(f"/v1/passports/{agent_id}/safe-mode", json={"enabled": True}, headers=env.h("operator"))
    assert _context_flag(env, agent_id) is True  # agent flag alone
    env.client.post(f"/v1/passports/{agent_id}/safe-mode", json={"enabled": False, "confirm": True}, headers=env.h("admin"))
    assert _context_flag(env, agent_id) is False

    env.client.post("/v1/organization/safe-mode", json={"enabled": True}, headers=env.h("operator"))
    assert _context_flag(env, agent_id) is True  # organization flag alone


@pytest.mark.parametrize("stored", [None, "false", 0, "yes"])
def test_anything_but_a_stored_false_means_safe_mode_is_on(env: Env, stored: Any) -> None:
    """Fail closed: malformed flag data is read as the restrictive value."""
    agent_id = env.register()["passport"]["id"]
    next(a for a in env.store.tables["agents"] if a["id"] == agent_id)["safe_mode"] = stored
    assert _context_flag(env, agent_id) is True

    next(a for a in env.store.tables["agents"] if a["id"] == agent_id)["safe_mode"] = False
    next(o for o in env.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)["safe_mode"] = stored
    assert _context_flag(env, agent_id) is True


def test_a_failed_audit_write_leaves_safe_mode_unchanged(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    agent_id = env.register()["passport"]["id"]

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("audit table unwritable")

    monkeypatch.setattr("redhand_core.services.local_rpc._append_audit", boom)
    with pytest.raises(RuntimeError):  # the test client re-raises the simulated crash
        env.client.post(f"/v1/passports/{agent_id}/safe-mode", json={"enabled": True}, headers=env.h("operator"))
    monkeypatch.undo()
    assert _context_flag(env, agent_id) is False  # the change was rolled back with the failed audit write
