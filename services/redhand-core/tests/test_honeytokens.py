"""
Honeytokens and honey tools (Phase 3 M3/M4), core side: creation (the value is shown once), tenant isolation,
roles and limits, what the gateway is told, and trip handling (idempotent, alert, freeze, no value anywhere).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from uuid import uuid4

from pydantic import SecretStr
import pytest

from redhand_core.honeytokens import generator
from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_telegram import OTHER_ORG, OWNER_CHAT, Env as TelegramEnv

SERVICE_TOKEN = "honey-test-internal-service-token-0123456789"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
GATEWAY_HEADERS = {"Authorization": f"Bearer {SERVICE_TOKEN}"}


class Env(TelegramEnv):
    def __init__(self, **settings: Any) -> None:
        settings.setdefault("INTERNAL_SERVICE_TOKEN", SecretStr(SERVICE_TOKEN))
        super().__init__(**settings)

    def create(self, user: str = "admin", **body: Any) -> Any:
        body = {"label": "Decoy key", "kind": "api_key", **body}
        return self.client.post("/v1/honeytokens", json=body, headers=self.h(user))

    def create_ok(self, **body: Any) -> dict[str, Any]:
        resp = self.create(**body)
        assert resp.status_code == 201, resp.text
        return dict(resp.json())

    def other_org_headers(self) -> dict[str, str]:
        from uuid import UUID
        from core_helpers import operator_headers

        return operator_headers(settings=self.settings, user_id=UUID(OTHER_OWNER))

    def context(self, agent_id: str, server: str = "xero") -> Any:
        return self.client.get(
            "/internal/v1/gateway-context",
            params={"agent_id": agent_id, "organization_id": DEFAULT_ORG_ID, "server": server},
            headers=GATEWAY_HEADERS,
        )

    def trip(self, agent_id: str, ref_id: str, kind: str = "honeytoken", seen_in: str = "arguments",
             trip_id: str | None = None, org: str = DEFAULT_ORG_ID, token: str | None = SERVICE_TOKEN) -> Any:
        body = {
            "organization_id": org, "trip_id": trip_id or str(uuid4()), "agent_id": agent_id, "kind": kind,
            "ref_id": ref_id, "seen_in": seen_in, "tool_name": "send_email", "server": "mail",
        }
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post("/internal/v1/trips", json=body, headers=headers)

    def alerts(self) -> list[str]:
        """What the owner's phone received about trips (the link confirmation is not an alert)."""
        return [t for t in self.fake.to(OWNER_CHAT) if not t.startswith("Linked.")]

    def audit_actions(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.store.tables.get("control_audit_log", []) if r["action"] == name]


@pytest.fixture
def env() -> Env:
    return Env()


def _agent(env: Env, name: str = "Alpha") -> str:
    return str(env.register(name)["id"])


# --- generator ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("kind", "pattern"), [
    ("api_key", r"^sk_live_[A-Za-z0-9]{32}$"), ("aws_key", r"^AKIA[A-Z0-9]{16}$"), ("password", r"^[A-Za-z0-9]{24}$"),
    ("canary", r"^[A-Za-z0-9]{24}$"),
])
def test_generated_values_have_the_documented_shape_and_are_unique(kind: str, pattern: str) -> None:
    values = {generator.generate_value(kind) for _ in range(200)}  # type: ignore[arg-type]
    assert len(values) == 200 and all(re.match(pattern, v) for v in values)
    assert all("redhand" not in v.lower() for v in values)  # no marker that would let an attacker skip it


def test_passwords_mix_letter_cases_and_digits() -> None:
    for _ in range(100):
        value = generator.generate_value("password")
        assert any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value)


# --- creating and listing ----------------------------------------------------------------------------------

def test_the_value_is_returned_once_and_only_its_digest_is_stored(env: Env) -> None:
    created = env.create_ok(label="Decoy prod key")
    value = created["value"]
    assert value.startswith("sk_live_") and created["hint"] == value[-4:]
    stored = env.store.tables["honeytokens"]
    assert stored[0]["digest"] == generator.digest_of(value) and value not in json.dumps(stored)
    listing = env.client.get("/v1/honeytokens", headers=env.h("operator"))
    assert listing.status_code == 200 and value not in listing.text and "digest" not in listing.text
    (created_audit,) = env.audit_actions("honeytoken.created")
    assert value not in json.dumps(created_audit) and created_audit["details"]["label"] == "Decoy prod key"


def test_creation_responses_are_not_cacheable(env: Env) -> None:
    assert env.create().headers["cache-control"] == "no-store"


def test_roles_for_honeytokens(env: Env) -> None:
    assert env.create("viewer").status_code == 403 and env.create("operator").status_code == 403
    assert env.create("admin").status_code == 201 and env.create("owner", label="Owner's").status_code == 201
    assert env.client.get("/v1/honeytokens", headers=env.h("viewer")).status_code == 403
    assert env.client.get("/v1/honeytokens", headers=env.h("operator")).status_code == 200


def test_input_is_validated(env: Env) -> None:
    assert env.create(label="").status_code == 422
    assert env.create(label="x" * 65).status_code == 422
    assert env.create(label="bad\x00label").status_code == 422
    assert env.create(kind="rsa").status_code == 422
    assert env.create(action_on_use="delete").status_code == 422
    assert env.create(extra="field").status_code == 422


def test_at_most_fifty_active_honeytokens(env: Env) -> None:
    first = env.create_ok(label="first")
    for i in range(49):
        env.create_ok(label=f"bulk {i}")
    assert env.create().status_code == 409
    assert env.client.post(f"/v1/honeytokens/{first['id']}/retire", headers=env.h("admin")).json() == {"changed": True}
    assert env.create().status_code == 201


def test_retiring_is_idempotent_and_tenant_scoped(env: Env) -> None:
    created = env.create_ok()
    other = env.client.post(f"/v1/honeytokens/{created['id']}/retire", headers=env.other_org_headers())
    assert other.status_code == 404 and env.store.tables["honeytokens"][0]["status"] == "active"
    assert env.client.post(f"/v1/honeytokens/{created['id']}/retire", headers=env.h("viewer")).status_code == 403
    assert env.client.post(f"/v1/honeytokens/{created['id']}/retire", headers=env.h("admin")).json() == {"changed": True}
    assert env.client.post(f"/v1/honeytokens/{created['id']}/retire", headers=env.h("admin")).json() == {"changed": False}
    assert len(env.audit_actions("honeytoken.retired")) == 1


def test_another_organization_sees_none_of_them(env: Env) -> None:
    env.create_ok()
    assert env.client.get("/v1/honeytokens", headers=env.other_org_headers()).json() == []


# --- honey tools -------------------------------------------------------------------------------------------

def _tool(env: Env, agent: str, user: str = "admin", **body: Any) -> Any:
    body = {"agent_id": agent, "server": "xero", "name": "export_all_customer_records",
            "description": "Exports every customer record", **body}
    return env.client.post("/v1/honey-tools", json=body, headers=env.h(user))


def test_honey_tool_lifecycle_roles_and_limits(env: Env) -> None:
    agent = _agent(env)
    assert _tool(env, agent, "operator").status_code == 403
    created = _tool(env, agent)
    assert created.status_code == 201 and created.json()["action"] == "alert" and created.json()["server"] == "xero"
    assert _tool(env, agent).status_code == 409  # same name again
    for i in range(4):
        assert _tool(env, agent, name=f"decoy_tool_{i}").status_code == 201
    assert _tool(env, agent, name="decoy_tool_9").status_code == 409  # five is the limit
    listing = env.client.get("/v1/honey-tools", params={"agent_id": agent}, headers=env.h("operator"))
    assert len(listing.json()) == 5
    assert env.client.get("/v1/honey-tools", headers=env.h("viewer")).status_code == 403
    tool_id = created.json()["id"]
    assert env.client.post(f"/v1/honey-tools/{tool_id}/retire", headers=env.h("admin")).json() == {"changed": True}
    assert _tool(env, agent, name="decoy_tool_9").status_code == 201


@pytest.mark.parametrize("name", ["x", "bad name", "1abc", "a" * 65, "tool-with-dash"])
def test_honey_tool_names_are_validated(env: Env, name: str) -> None:
    assert _tool(env, _agent(env), name=name).status_code == 422


def test_a_honey_tool_cannot_be_added_to_another_organizations_agent(env: Env) -> None:
    agent = _agent(env)
    body = {"agent_id": agent, "server": "xero", "name": "decoy_one", "description": "d"}
    resp = env.client.post("/v1/honey-tools", json=body, headers=env.other_org_headers())
    assert resp.status_code == 404 and env.store.tables.get("honey_tools", []) == []


# --- what the gateway is told ------------------------------------------------------------------------------

def test_the_gateway_context_carries_digests_and_decoys_but_never_values(env: Env) -> None:
    agent, other_agent = _agent(env), _agent(env, "Beta")
    token = env.create_ok(label="A")
    retired = env.create_ok(label="B")
    env.client.post(f"/v1/honeytokens/{retired['id']}/retire", headers=env.h("admin"))
    _tool(env, agent)
    _tool(env, agent, server="other", name="elsewhere_tool")
    body = env.context(agent).json()["agent"]
    assert body["honeytokens"] == [{"id": token["id"], "digest": generator.digest_of(token["value"])}]
    assert [t["name"] for t in body["honey_tools"]] == ["export_all_customer_records"]  # this server only
    assert env.context(other_agent).json()["agent"]["honey_tools"] == []  # decoys are per agent
    assert token["value"] not in json.dumps(body) and retired["value"] not in json.dumps(body)


def test_the_context_fails_closed_when_the_bait_lookup_fails(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _agent(env)
    original = env.store.table

    def broken(name: str) -> Any:
        if name == "honeytokens":
            raise RuntimeError("database down")
        return original(name)

    monkeypatch.setattr(env.store, "table", broken)
    assert env.context(agent).status_code == 503


# --- trips -------------------------------------------------------------------------------------------------

def test_a_trip_with_freeze_freezes_the_agent_audits_it_and_alerts_the_owner(env: Env) -> None:
    env.link()
    agent = _agent(env)
    token = env.create_ok(label="Decoy prod key", action_on_use="freeze")
    resp = env.trip(agent, token["id"])
    assert resp.status_code == 200 and resp.json() == {"recorded": True}
    assert env.statuses()["Alpha"] == "frozen"
    assert env.audit_actions("honeytoken.tripped")[0]["actor_user_id"] == "00000000-0000-0000-0000-000000000000"
    frozen = env.audit_actions("passport.frozen")[0]
    assert frozen["actor_user_id"] == "00000000-0000-0000-0000-000000000000" and "Decoy prod key" in frozen["reason"]
    alert = env.fake.last(OWNER_CHAT)
    assert "Decoy prod key" in alert and "Alpha" in alert and "frozen" in alert and token["value"] not in alert


def test_a_trip_with_alert_does_not_freeze(env: Env) -> None:
    env.link()
    agent = _agent(env)
    token = env.create_ok(action_on_use="alert")
    env.trip(agent, token["id"])
    assert env.statuses()["Alpha"] == "active" and len(env.alerts()) == 1


def test_a_result_trip_uses_the_read_action(env: Env) -> None:
    env.link()
    agent = _agent(env)
    token = env.create_ok(action_on_use="freeze", action_on_read="alert")
    env.trip(agent, token["id"], seen_in="result")
    assert env.statuses()["Alpha"] == "active" and "appeared in a result" in env.fake.last(OWNER_CHAT)


def test_a_retried_trip_is_counted_and_alerted_once(env: Env) -> None:
    env.link()
    agent = _agent(env)
    token = env.create_ok(action_on_use="alert")
    trip_id = str(uuid4())
    assert env.trip(agent, token["id"], trip_id=trip_id).json() == {"recorded": True}
    assert env.trip(agent, token["id"], trip_id=trip_id).json() == {"recorded": False}
    assert len(env.alerts()) == 1 and env.store.tables["honeytokens"][0]["trip_count"] == 1


def test_repeated_trips_within_five_minutes_are_recorded_but_alert_once(env: Env) -> None:
    env.link()
    agent = _agent(env)
    token = env.create_ok(action_on_use="alert")
    for _ in range(3):
        env.trip(agent, token["id"])
    # Counts the honeytoken's own alerts. Since the Risk Engine (Phase 4.5 B1) the repeated trips also raise the agent's risk score past the
    # default alert rung (50); the trip alert is rate-limited by then, so the engine's "Risk:" alert is its own message. It is tested in
    # test_risk_engine.py; here only the honeytoken's once-per-five-minutes rule is checked, as before.
    honeytoken_alerts = [a for a in env.alerts() if not a.startswith("Risk:")]
    assert len(honeytoken_alerts) == 1 and env.store.tables["honeytokens"][0]["trip_count"] == 3


def test_a_honey_tool_trip_alerts_and_is_never_a_freeze_by_default(env: Env) -> None:
    env.link()
    agent = _agent(env)
    tool = _tool(env, agent).json()
    assert env.trip(agent, tool["id"], kind="honey_tool", seen_in="call").json() == {"recorded": True}
    assert env.statuses()["Alpha"] == "active"
    assert "export_all_customer_records" in env.fake.last(OWNER_CHAT) and "not forwarded" in env.fake.last(OWNER_CHAT)
    assert env.audit_actions("honey_tool.tripped")


def test_a_trip_for_an_unknown_or_retired_reference_is_ignored(env: Env) -> None:
    env.link()
    agent = _agent(env)
    assert env.trip(agent, str(uuid4())).json() == {"recorded": False}
    token = env.create_ok()
    env.client.post(f"/v1/honeytokens/{token['id']}/retire", headers=env.h("admin"))
    assert env.trip(agent, token["id"]).json() == {"recorded": False}
    assert env.alerts() == [] and env.audit_actions("honeytoken.tripped") == []


def test_trips_cannot_cross_organizations(env: Env) -> None:
    agent = _agent(env)
    token = env.create_ok()
    # The organization claimed does not own the agent.
    assert env.trip(agent, token["id"], org=OTHER_ORG).status_code == 404
    assert env.statuses()["Alpha"] == "active"


def test_the_trip_endpoint_needs_the_service_token(env: Env) -> None:
    agent = _agent(env)
    token = env.create_ok()
    assert env.trip(agent, token["id"], token=None).status_code == 401
    assert env.trip(agent, token["id"], token="wrong").status_code == 401
    assert env.client.post("/internal/v1/trips", json={}, headers=env.h("owner")).status_code == 401


def test_malformed_trips_are_rejected_at_the_boundary(env: Env) -> None:
    agent = _agent(env)
    token = env.create_ok()
    body = {"organization_id": DEFAULT_ORG_ID, "trip_id": str(uuid4()), "agent_id": agent, "kind": "honeytoken",
            "ref_id": token["id"], "seen_in": "call"}
    # A honeytoken can only be tripped in arguments or a result: the database refuses "call", and core says 422.
    assert env.client.post("/internal/v1/trips", json=body, headers=GATEWAY_HEADERS).status_code == 422
    assert env.client.post("/internal/v1/trips", json={**body, "extra": 1}, headers=GATEWAY_HEADERS).status_code == 422
    assert env.client.post("/internal/v1/trips", json={**body, "kind": "other"}, headers=GATEWAY_HEADERS).status_code == 422
    assert env.client.post("/internal/v1/trips", json={**body, "tool_name": "x" * 200}, headers=GATEWAY_HEADERS).status_code == 422


def test_a_failed_alert_does_not_undo_the_freeze(env: Env) -> None:
    env.link()
    env.fake.fail = True
    agent = _agent(env)
    token = env.create_ok(action_on_use="freeze")
    assert env.trip(agent, token["id"]).json() == {"recorded": True}
    assert env.statuses()["Alpha"] == "frozen"


def test_the_honeytoken_value_is_never_logged(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    env.link()
    agent = _agent(env)
    with caplog.at_level(logging.DEBUG):
        token = env.create_ok(action_on_use="freeze")
        env.trip(agent, token["id"])
        env.context(agent)
    assert token["value"] not in caplog.text


# --- system-prompt canaries (Phase 4 M5a, docs/plans/phase4-m5a-canary.md) --------------------------------------

def test_an_unknown_kind_is_an_error_and_never_quietly_a_password() -> None:
    with pytest.raises(ValueError, match="unknown honeytoken kind"):
        generator.generate_value("rsa")  # type: ignore[arg-type]  # the point: a value outside the Literal must not produce a password


def test_canaries_mix_letter_cases_and_digits_and_never_repeat() -> None:
    values = {generator.generate_value("canary") for _ in range(200)}
    assert len(values) == 200
    assert all(any(c.islower() for c in v) and any(c.isupper() for c in v) and any(c.isdigit() for c in v) for v in values)


def test_a_canary_defaults_to_refuse_and_alert_but_never_freeze(env: Env) -> None:
    """Decision F-D3: a stolen prompt would let anyone freeze an agent on demand if freezing were the default."""
    canary = env.create_ok(label="System prompt canary", kind="canary")
    assert canary["kind"] == "canary" and canary["action_on_use"] == "alert" and canary["action_on_read"] == "alert"
    assert re.match(r"^[A-Za-z0-9]{24}$", canary["value"]) and canary["hint"] == canary["value"][-4:]
    other = env.create_ok(label="Decoy", kind="api_key")
    assert other["action_on_use"] == "freeze" and other["action_on_read"] == "alert"  # the other kinds keep their defaults


def test_a_canary_may_still_be_told_to_freeze_when_an_admin_asks(env: Env) -> None:
    canary = env.create_ok(kind="canary", action_on_use="freeze", action_on_read="freeze")
    assert canary["action_on_use"] == "freeze" and canary["action_on_read"] == "freeze"
    half = env.create_ok(label="Half", kind="canary", action_on_use="freeze")
    assert half["action_on_use"] == "freeze" and half["action_on_read"] == "alert"  # only what was asked is changed


def test_a_canary_is_stored_as_a_digest_listed_without_its_value_and_audited_with_its_kind(env: Env) -> None:
    canary = env.create_ok(label="System prompt canary", kind="canary")
    value = canary["value"]
    assert env.store.tables["honeytokens"][0]["digest"] == generator.digest_of(value) and value not in json.dumps(env.store.tables["honeytokens"])
    listing = env.client.get("/v1/honeytokens", headers=env.h("operator"))
    assert listing.json()[0]["kind"] == "canary" and value not in listing.text and "digest" not in listing.text
    (audit,) = env.audit_actions("honeytoken.created")
    assert audit["details"]["kind"] == "canary" and value not in json.dumps(audit)


def test_only_admins_create_or_retire_canaries(env: Env) -> None:
    assert env.create("viewer", kind="canary").status_code == 403 and env.create("operator", kind="canary").status_code == 403
    created = env.create_ok(kind="canary")
    assert env.client.post(f"/v1/honeytokens/{created['id']}/retire", headers=env.h("operator")).status_code == 403
    assert env.client.post(f"/v1/honeytokens/{created['id']}/retire", headers=env.h("admin")).json() == {"changed": True}


def test_canaries_count_toward_the_fifty_active_limit(env: Env) -> None:
    env.create_ok(label="canary", kind="canary")
    for i in range(49):
        env.create_ok(label=f"bulk {i}", kind="password")
    assert env.create(kind="canary").status_code == 409


def test_the_gateway_is_told_a_canary_digest_like_any_honeytoken_and_only_its_own_organizations(env: Env) -> None:
    agent = _agent(env)
    mine = env.create_ok(label="mine", kind="canary")
    theirs = env.client.post("/v1/honeytokens", json={"label": "theirs", "kind": "canary"}, headers=env.other_org_headers())
    assert theirs.status_code == 201
    body = env.context(agent).json()["agent"]
    assert body["honeytokens"] == [{"id": mine["id"], "digest": generator.digest_of(mine["value"])}]
    assert theirs.json()["value"] not in json.dumps(body) and mine["value"] not in json.dumps(body)


def test_a_canary_in_a_call_alerts_with_leak_wording_and_does_not_freeze(env: Env) -> None:
    env.link()
    agent = _agent(env)
    canary = env.create_ok(label="System prompt canary", kind="canary")
    assert env.trip(agent, canary["id"]).json() == {"recorded": True}
    assert env.statuses()["Alpha"] == "active"
    alert = env.fake.last(OWNER_CHAT)
    assert "canary" in alert.lower() and "leak" in alert and "Alpha" in alert and "System prompt canary" in alert and "refused" in alert
    assert "decoy" not in alert.lower() and canary["value"] not in alert
    assert env.audit_actions("honeytoken.tripped")[0]["details"]["kind"] == "canary"


def test_a_canary_in_a_result_alerts_with_leak_wording(env: Env) -> None:
    env.link()
    agent = _agent(env)
    canary = env.create_ok(label="System prompt canary", kind="canary")
    env.trip(agent, canary["id"], seen_in="result")
    alert = env.fake.last(OWNER_CHAT)
    assert "canary" in alert.lower() and "result" in alert and "leak" in alert and "decoy" not in alert.lower() and "refused" not in alert
    assert env.statuses()["Alpha"] == "active"


def test_a_canary_set_to_freeze_does_freeze_and_says_so(env: Env) -> None:
    env.link()
    agent = _agent(env)
    canary = env.create_ok(kind="canary", action_on_use="freeze")
    env.trip(agent, canary["id"])
    assert env.statuses()["Alpha"] == "frozen" and "frozen" in env.fake.last(OWNER_CHAT)


def test_other_honeytoken_alerts_keep_their_decoy_wording_and_audit_kind(env: Env) -> None:
    env.link()
    agent = _agent(env)
    bait = env.create_ok(label="Decoy prod key", kind="api_key", action_on_use="alert")
    env.trip(agent, bait["id"])
    assert "Honeytoken used" in env.fake.last(OWNER_CHAT) and "canary" not in env.fake.last(OWNER_CHAT).lower()
    assert env.audit_actions("honeytoken.tripped")[0]["details"]["kind"] == "api_key"


def test_a_retired_canary_no_longer_trips_and_another_organizations_cannot_be_tripped(env: Env) -> None:
    env.link()
    agent = _agent(env)
    canary = env.create_ok(kind="canary")
    env.client.post(f"/v1/honeytokens/{canary['id']}/retire", headers=env.h("admin"))
    assert env.trip(agent, canary["id"]).json() == {"recorded": False}
    assert env.trip(agent, canary["id"], org=OTHER_ORG).status_code == 404
    assert env.alerts() == []


def test_the_canary_value_is_never_logged(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    env.link()
    agent = _agent(env)
    with caplog.at_level(logging.DEBUG):
        canary = env.create_ok(kind="canary")
        env.trip(agent, canary["id"])
        env.context(agent)
    assert canary["value"] not in caplog.text
