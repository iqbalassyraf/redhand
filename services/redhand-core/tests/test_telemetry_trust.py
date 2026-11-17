"""
Telemetry trust (Phase 4.5 C1b, docs/plans/phase45-c1-sdk-keys.md). An SDK key can report for its organization's agents, but it must not change a passport an
admin made (name, framework, environment), and an agent id it reports for the first time becomes a "reported only" passport that cannot use the gateway until an
admin promotes it (audited, confirmed).
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from redhand_core.risk import service as risk_service
from redhand_core.sdkkeys import service as keys_service
from redhand_core.services.local_store import DEFAULT_DEV_API_KEY

from test_budget_guard import Env as BudgetEnv
from test_telegram import OTHER_ORG


def span() -> dict[str, Any]:
    return {"session_id": str(uuid4()), "trace_id": uuid4().hex, "span_id": uuid4().hex[:16], "step_type": "observation"}


class Env(BudgetEnv):
    def ingest(self, external: str, name: str = "from-sdk", framework: str = "sdk-fw", environment: str = "production") -> Any:
        body = {"sdk_version": "0.1.0", "external_agent_id": external, "agent_name": name, "framework": framework, "environment": environment, "spans": [span()]}
        return self.client.post("/v1/telemetry/ingest", json=body, headers={"X-RedHand-API-Key": DEFAULT_DEV_API_KEY})

    def agent(self, agent_id: str) -> dict[str, Any]:
        return next(a for a in self.store.tables["agents"] if str(a["id"]) == agent_id)

    def passport(self, agent_id: str) -> dict[str, Any]:
        return next(p for p in self.client.get("/v1/passports", headers=self.h("viewer")).json() if p["id"] == agent_id)

    def promote(self, agent_id: str, user: str = "admin", confirm: bool = True) -> Any:
        return self.client.post(f"/v1/passports/{agent_id}/promote", json={"confirm": confirm, "reason": "reviewed"}, headers=self.h(user))

    def exchange(self, agent_key: str) -> Any:
        return self.client.post("/v1/agent-auth/token", headers={"Authorization": f"Bearer {agent_key}"})


@pytest.fixture
def env() -> Env:
    keys_service.reset_limits_for_tests()
    return Env()


# --- an existing passport is never changed by telemetry ---------------------------------------------------------------------------

def test_telemetry_never_renames_or_changes_a_registered_passport(env: Env) -> None:
    passport = env.register("Payroll bot")
    response = env.ingest(passport["external_agent_id"], name="Evil Name", framework="evil-fw", environment="production")
    assert response.status_code == 202, response.text
    assert response.json()["agent_id"] == passport["id"]
    row = env.agent(passport["id"])
    assert row["name"] == "Payroll bot" and row["framework"] == "n8n"
    assert row.get("reported_only") is not True, "a registered passport is never marked reported only"


def test_telemetry_still_records_that_a_registered_agent_was_seen(env: Env) -> None:
    passport = env.register("Seen bot")
    env.ingest(passport["external_agent_id"])
    assert env.agent(passport["id"]).get("last_heartbeat_at")


# --- a new agent id becomes "reported only" ---------------------------------------------------------------------------------------

def test_a_new_agent_id_becomes_a_reported_only_passport(env: Env) -> None:
    response = env.ingest("brand-new-bot", name="Brand new")
    assert response.status_code == 202
    agent_id = response.json()["agent_id"]
    assert env.agent(agent_id)["reported_only"] is True
    view = env.passport(agent_id)
    assert view["reported_only"] is True and view["name"] == "Brand new"


def test_the_same_new_agent_reporting_again_keeps_its_first_name(env: Env) -> None:
    first = env.ingest("drift-bot", name="First").json()["agent_id"]
    second = env.ingest("drift-bot", name="Second").json()["agent_id"]
    assert first == second and env.agent(first)["name"] == "First"


def test_a_reported_only_agent_cannot_get_a_gateway_token(env: Env) -> None:
    agent_id = env.ingest("no-gateway-bot").json()["agent_id"]
    rotated = env.client.post(f"/v1/passports/{agent_id}/rotate-key", json={}, headers=env.h("admin"))
    assert rotated.status_code == 200, rotated.text
    refused = env.exchange(rotated.json()["agent_key"])
    assert refused.status_code == 403 and "reported only" in refused.json()["detail"].lower()


def test_the_gateway_context_treats_a_reported_only_agent_as_not_active(env: Env) -> None:
    agent_id = env.ingest("context-bot").json()["agent_id"]
    context = env.context(agent_id)
    assert context.status_code == 200 and context.json()["agent"]["status"] == "frozen"


def test_the_risk_ladder_never_acts_on_a_reported_only_agent() -> None:
    rows = [{"id": "a", "reported_only": True}, {"id": "b", "reported_only": False}, {"id": "c"}]
    assert [r["id"] for r in risk_service.ladder_eligible(rows)] == ["b", "c"]


# --- promote ---------------------------------------------------------------------------------------------------------------------

def test_an_admin_promotes_a_reported_only_passport_with_confirmation_and_it_is_audited(env: Env) -> None:
    agent_id = env.ingest("promote-bot").json()["agent_id"]
    assert env.promote(agent_id, confirm=False).status_code == 400
    assert env.agent(agent_id)["reported_only"] is True
    response = env.promote(agent_id)
    assert response.status_code == 200 and response.json()["changed"] is True
    assert env.agent(agent_id)["reported_only"] is False
    assert "passport.promoted" in [e["action"] for e in env.audit()]


def test_after_promotion_the_agent_can_get_a_token(env: Env) -> None:
    agent_id = env.ingest("promoted-token-bot").json()["agent_id"]
    env.promote(agent_id)
    key = env.client.post(f"/v1/passports/{agent_id}/rotate-key", json={}, headers=env.h("admin")).json()["agent_key"]
    assert env.exchange(key).status_code == 200


@pytest.mark.parametrize("user", ["operator", "viewer"])
def test_only_an_admin_can_promote(env: Env, user: str) -> None:
    agent_id = env.ingest(f"role-{user}-bot").json()["agent_id"]
    assert env.promote(agent_id, user=user).status_code == 403
    assert env.agent(agent_id)["reported_only"] is True


def test_promoting_an_ordinary_passport_changes_nothing(env: Env) -> None:
    passport = env.register("Ordinary")
    response = env.promote(passport["id"])
    assert response.status_code == 200 and response.json()["changed"] is False
    assert "passport.promoted" not in [e["action"] for e in env.audit()]


def test_another_organizations_agent_cannot_be_promoted(env: Env) -> None:
    foreign = str(uuid4())
    env.store.tables["agents"].append({"id": foreign, "organization_id": OTHER_ORG, "external_agent_id": "t", "name": "T", "status": "active",
                                       "reported_only": True, "expires_at": "2099-01-01T00:00:00+00:00", "scopes": []})
    assert env.promote(foreign).status_code == 404
    assert env.agent(foreign)["reported_only"] is True


def test_a_revoked_passport_cannot_be_promoted(env: Env) -> None:
    agent_id = env.ingest("revoked-promote-bot").json()["agent_id"]
    env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h("admin"))
    assert env.promote(agent_id).status_code == 409
