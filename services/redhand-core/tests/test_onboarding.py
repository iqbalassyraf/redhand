"""
Onboarding (Phase 4.5 D1, ADR 0026): how a stranger becomes a customer. A signed-in person with no organization creates one with a single-use sign-up
code the platform owner issued, or joins one with an invite token an admin issued; admins manage members and roles. The rules (single use, expiry, one
organization per person, no owner by invite, the last owner stays, nobody above their own role) are tested through the real routes; the database functions
have their own SQL tests. Plus the two role tightenings of the same change: registering an agent and rotating its key are admin actions, and a viewer's
state snapshot carries no reasoning or tool-argument text.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from redhand_core.onboarding import service as onboarding
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter

from core_helpers import make_client, operator_headers

SERVICE = "onboarding-internal-service-token-0123456789abcdef"
SERVICE_HEADERS = {"Authorization": f"Bearer {SERVICE}"}


class Env:
    def __init__(self, **settings: Any) -> None:
        onboarding.reset_limits_for_tests()
        self.store = LocalSupabaseAdapter()
        self.client, self.settings = make_client(self.store, INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE), ENVIRONMENT="development", **settings)

    def user(self) -> UUID:
        return uuid4()

    def h(self, who: str | UUID, org: str | None = None) -> dict[str, str]:
        if isinstance(who, UUID):
            return operator_headers(settings=self.settings, user_id=who, org=org)
        return operator_headers(who, settings=self.settings, org=org)

    def code(self, days: int = 14) -> str:
        response = self.client.post("/internal/v1/signup-codes", json={"note": "test", "expires_in_days": days}, headers=SERVICE_HEADERS)
        assert response.status_code == 201, response.text
        return str(response.json()["code"])

    def create_org(self, user: UUID, name: str = "Acme Ltd", code: str | None = None, slug: str | None = None) -> Any:
        body: dict[str, Any] = {"name": name, "code": code or self.code()}
        if slug:
            body["slug"] = slug
        return self.client.post("/v1/organizations", json=body, headers=self.h(user))

    def invite(self, who: str | UUID, role: str = "viewer", org: str | None = None) -> Any:
        return self.client.post("/v1/organization/invites", json={"role": role}, headers=self.h(who, org))

    def accept(self, user: UUID, token: str) -> Any:
        return self.client.post("/v1/invites/accept", json={"token": token}, headers=self.h(user))

    def snapshot(self) -> Any:
        return copy.deepcopy(self.store.tables)


@pytest.fixture
def env() -> Env:
    return Env()


# --- creating an organization -----------------------------------------------------------------------------------------------------------

def test_a_signup_code_lets_a_new_person_create_an_organization_and_become_its_owner(env: Env) -> None:
    founder = env.user()
    response = env.create_org(founder, "Acme Ltd")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["role"] == "owner" and body["slug"].startswith("acme-ltd-")
    assert env.client.get("/v1/passports", headers=env.h(founder)).status_code == 200, "the new owner can use the dashboard API at once"
    me = env.client.get("/v1/organization/members", headers=env.h(founder)).json()["members"]
    assert [m["role"] for m in me] == ["owner"]


def test_a_person_with_no_organization_is_told_so_not_given_someone_elses(env: Env) -> None:
    stranger = env.user()
    response = env.client.get("/v1/passports", headers=env.h(stranger))
    assert response.status_code == 403 and "member" in response.json()["detail"].lower()


def test_a_code_works_once(env: Env) -> None:
    code = env.code()
    assert env.create_org(env.user(), code=code).status_code == 201
    second = env.create_org(env.user(), "Rival", code=code)
    assert second.status_code == 403 and second.json()["detail"] == onboarding.NO_CODE


def test_unknown_used_and_expired_codes_all_get_the_same_answer(env: Env) -> None:
    expired = env.code()
    for row in env.store.tables["signup_codes"]:
        row["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    answers = {
        env.create_org(env.user(), code="rh_inv_" + "z" * 32).json()["detail"],
        env.create_org(env.user(), code=expired).json()["detail"],
    }
    assert answers == {onboarding.NO_CODE}


def test_a_code_is_never_stored_or_logged_in_the_clear(env: Env) -> None:
    code = env.code()
    env.create_org(env.user(), code=code)
    assert code not in json.dumps(env.store.tables, default=str)
    assert all(len(row["code_hash"]) == 64 for row in env.store.tables["signup_codes"])


def test_a_malformed_code_or_slug_is_rejected_before_anything_happens(env: Env) -> None:
    before = env.snapshot()
    user = env.user()
    assert env.client.post("/v1/organizations", json={"name": "X", "code": "short"}, headers=env.h(user)).status_code == 422
    assert env.client.post("/v1/organizations", json={"name": "X", "code": "rh_inv_" + "a" * 30, "slug": "Bad Slug"}, headers=env.h(user)).status_code == 422
    assert env.client.post("/v1/organizations", json={"name": "", "code": "rh_inv_" + "a" * 30}, headers=env.h(user)).status_code == 422
    assert env.client.post("/v1/organizations", json={"name": "X", "code": "rh_inv_" + "a" * 30, "extra": 1}, headers=env.h(user)).status_code == 422
    assert env.snapshot() == before


def test_a_person_who_already_belongs_to_an_organization_cannot_create_another(env: Env) -> None:
    founder = env.user()
    env.create_org(founder)
    code = env.code()
    assert env.create_org(founder, "Second", code=code).status_code == 409
    assert env.create_org(env.user(), "Fine", code=code).status_code == 201, "and the refusal did not burn the code"
    assert env.client.post("/v1/organizations", json={"name": "Dev", "code": env.code()}, headers=env.h("owner")).status_code == 409


def test_a_taken_slug_is_a_conflict_and_does_not_burn_the_code(env: Env) -> None:
    assert env.create_org(env.user(), slug="acme-ltd").status_code == 201
    code = env.code()
    assert env.create_org(env.user(), slug="acme-ltd", code=code).status_code == 409
    assert env.create_org(env.user(), slug="acme-two", code=code).status_code == 201


def test_creating_an_organization_is_audited_without_the_code(env: Env) -> None:
    founder = env.user()
    code = env.code()
    org = env.create_org(founder, code=code).json()["organization_id"]
    rows = [r for r in env.store.tables["control_audit_log"] if r["action"] == "organization.created"]
    assert len(rows) == 1 and str(rows[0]["organization_id"]) == org and str(rows[0]["actor_user_id"]) == str(founder)
    assert code not in json.dumps(rows, default=str)


def test_signing_up_can_be_closed(env: Env) -> None:
    closed = Env(SIGNUP_MODE="closed")
    code = closed.code()
    response = closed.create_org(closed.user(), code=code)
    assert response.status_code == 403 and closed.snapshot()["signup_codes"][0].get("used_at") is None


def test_guessing_codes_is_rate_limited_per_person_before_any_lookup() -> None:
    env = Env(SIGNUPS_PER_HOUR_PER_USER=3)
    user = env.user()
    statuses = [env.create_org(user, code="rh_inv_" + str(n).zfill(32)).status_code for n in range(5)]
    assert statuses[:3] == [403, 403, 403] and statuses[3:] == [429, 429]


def test_guessing_codes_is_rate_limited_per_source_across_people() -> None:
    env = Env(SIGNUPS_PER_HOUR_PER_SOURCE=4)
    statuses = [env.create_org(env.user(), code="rh_inv_" + str(n).zfill(32)).status_code for n in range(6)]
    assert statuses[:4] == [403] * 4 and statuses[4:] == [429, 429]


def test_the_routes_need_a_valid_token_and_issuing_codes_needs_the_service_token(env: Env) -> None:
    assert env.client.post("/v1/organizations", json={"name": "X", "code": "rh_inv_" + "a" * 30}).status_code == 401
    assert env.client.post("/v1/invites/accept", json={"token": "rh_join_" + "a" * 30}).status_code == 401
    assert env.client.post("/internal/v1/signup-codes", json={}).status_code == 401
    assert env.client.post("/internal/v1/signup-codes", json={}, headers=env.h("owner")).status_code == 401, "an operator token is not the service token"
    assert env.snapshot().get("signup_codes", []) == []


# --- invites ----------------------------------------------------------------------------------------------------------------------------

def test_an_admin_invites_a_person_who_joins_at_that_role(env: Env) -> None:
    created = env.invite("admin", "security_operator")
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    assert created.json()["join_path"] == f"/join?token={token}" and created.json()["invite"]["state"] == "pending"
    newcomer = env.user()
    joined = env.accept(newcomer, token)
    assert joined.status_code == 200 and joined.json() == {"organization_id": DEFAULT_ORG_ID, "role": "security_operator"}
    assert env.client.get("/v1/passports", headers=env.h(newcomer)).status_code == 200
    assert env.client.post("/v1/organization/sdk-keys", json={"name": "x"}, headers=env.h(newcomer)).status_code == 403, "at their role, no higher"


def test_an_invite_works_once_and_expires_and_can_be_revoked(env: Env) -> None:
    token = env.invite("admin").json()["token"]
    assert env.accept(env.user(), token).status_code == 200
    again = env.accept(env.user(), token)
    assert again.status_code == 403 and again.json()["detail"] == onboarding.NO_INVITE
    # revoked
    revoked = env.invite("admin").json()
    assert env.client.delete(f"/v1/organization/invites/{revoked['invite']['id']}", headers=env.h("admin")).json()["changed"] is True
    assert env.accept(env.user(), revoked["token"]).json()["detail"] == onboarding.NO_INVITE
    # expired
    late = env.invite("admin").json()["token"]
    for row in env.store.tables["member_invites"]:
        row["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert env.accept(env.user(), late).json()["detail"] == onboarding.NO_INVITE


def test_an_invite_never_makes_an_owner_or_exceeds_the_inviter(env: Env) -> None:
    assert env.client.post("/v1/organization/invites", json={"role": "owner"}, headers=env.h("owner")).status_code == 422
    assert env.invite("operator").status_code == 403, "a security operator cannot invite"
    assert env.invite("viewer").status_code == 403
    assert env.invite("admin", "admin").status_code == 201, "an admin may invite up to admin"


def test_a_person_in_an_organization_cannot_join_a_second_one(env: Env) -> None:
    token = env.invite("admin").json()["token"]
    assert env.accept(env.user(), env.invite("admin").json()["token"]).status_code == 200
    member = UUID(DEV_OPERATORS["viewer"]["id"])
    assert env.accept(member, token).status_code == 409


def test_an_invite_from_someone_who_was_demoted_stops_working(env: Env) -> None:
    token = env.invite("admin", "viewer").json()["token"]
    admin = UUID(DEV_OPERATORS["admin"]["id"])
    assert env.client.put(f"/v1/organization/members/{admin}", json={"role": "viewer"}, headers=env.h("owner")).status_code == 200
    assert env.accept(env.user(), token).json()["detail"] == onboarding.NO_INVITE


def test_the_invite_list_never_shows_a_token_or_hash_and_is_admin_only(env: Env) -> None:
    created = env.invite("admin").json()
    listing = env.client.get("/v1/organization/invites", headers=env.h("admin"))
    text = listing.text
    assert created["token"] not in text and "token_hash" not in text and "token" not in json.dumps(listing.json()["invites"][0])
    assert listing.json()["invites"][0]["state"] == "pending"
    assert env.client.get("/v1/organization/invites", headers=env.h("operator")).status_code == 403
    assert created["token"] not in json.dumps(env.store.tables, default=str)


def test_inviting_is_audited_without_the_token(env: Env) -> None:
    token = env.invite("admin").json()["token"]
    env.accept(env.user(), token)
    actions = [r["action"] for r in env.store.tables["control_audit_log"]]
    assert "member.invited" in actions and "member.joined" in actions
    assert token not in json.dumps(env.store.tables["control_audit_log"], default=str)


def test_at_most_twenty_pending_invites(env: Env) -> None:
    for _ in range(20):
        assert env.invite("admin").status_code == 201
    assert env.invite("admin").status_code == 409


def test_a_bad_invite_token_is_rejected_by_shape_and_by_lookup(env: Env) -> None:
    user = env.user()
    assert env.client.post("/v1/invites/accept", json={"token": "nope"}, headers=env.h(user)).status_code == 422
    assert env.accept(user, "rh_join_" + "q" * 32).status_code == 403


# --- members ----------------------------------------------------------------------------------------------------------------------------

def test_an_admin_sees_members_with_e_mail_and_nobody_below_admin_does(env: Env) -> None:
    members = env.client.get("/v1/organization/members", headers=env.h("admin")).json()["members"]
    assert {m["email"] for m in members} >= {"owner@dev.local", "viewer@dev.local"}
    assert members[0]["role"] == "owner"
    assert env.client.get("/v1/organization/members", headers=env.h("operator")).status_code == 403
    assert env.client.get("/v1/organization/members", headers=env.h("viewer")).status_code == 403


def test_an_admin_changes_a_role_and_it_is_audited_and_effective(env: Env) -> None:
    viewer = UUID(DEV_OPERATORS["viewer"]["id"])
    response = env.client.put(f"/v1/organization/members/{viewer}", json={"role": "security_operator"}, headers=env.h("admin"))
    assert response.status_code == 200 and response.json()["changed"] is True
    assert env.client.get("/v1/findings", headers=env.h(viewer)).status_code == 200, "the new role applies on the next call"
    assert [r for r in env.store.tables["control_audit_log"] if r["action"] == "member.role_changed"][0]["details"] == {"from": "viewer", "to": "security_operator"}
    assert env.client.put(f"/v1/organization/members/{viewer}", json={"role": "security_operator"}, headers=env.h("admin")).json()["changed"] is False


def test_nobody_can_give_a_role_above_their_own_or_touch_someone_above_them(env: Env) -> None:
    viewer, owner = UUID(DEV_OPERATORS["viewer"]["id"]), UUID(DEV_OPERATORS["owner"]["id"])
    assert env.client.put(f"/v1/organization/members/{viewer}", json={"role": "owner", "confirm": True}, headers=env.h("admin")).status_code == 403
    assert env.client.put(f"/v1/organization/members/{owner}", json={"role": "viewer"}, headers=env.h("admin")).status_code == 403
    assert env.client.delete(f"/v1/organization/members/{owner}", headers=env.h("admin")).status_code == 403
    assert env.client.put(f"/v1/organization/members/{viewer}", json={"role": "admin"}, headers=env.h("operator")).status_code == 403
    assert env.client.put(f"/v1/organization/members/{viewer}", json={"role": "admin"}, headers=env.h("viewer")).status_code == 403


def test_making_an_owner_needs_confirmation(env: Env) -> None:
    viewer = UUID(DEV_OPERATORS["viewer"]["id"])
    assert env.client.put(f"/v1/organization/members/{viewer}", json={"role": "owner"}, headers=env.h("owner")).status_code == 400
    assert env.client.put(f"/v1/organization/members/{viewer}", json={"role": "owner", "confirm": True}, headers=env.h("owner")).status_code == 200


def test_the_last_owner_cannot_be_demoted_or_removed(env: Env) -> None:
    owner = UUID(DEV_OPERATORS["owner"]["id"])
    assert env.client.put(f"/v1/organization/members/{owner}", json={"role": "admin"}, headers=env.h("owner")).status_code == 409
    assert env.client.delete(f"/v1/organization/members/{owner}", headers=env.h("owner")).status_code == 409
    assert [m["role"] for m in env.client.get("/v1/organization/members", headers=env.h("owner")).json()["members"]].count("owner") == 1


def test_a_removed_member_loses_access_at_once(env: Env) -> None:
    viewer = UUID(DEV_OPERATORS["viewer"]["id"])
    assert env.client.get("/v1/passports", headers=env.h(viewer)).status_code == 200
    assert env.client.delete(f"/v1/organization/members/{viewer}", headers=env.h("admin")).json()["removed"] is True
    assert env.client.get("/v1/passports", headers=env.h(viewer)).status_code == 403
    assert env.client.delete(f"/v1/organization/members/{viewer}", headers=env.h("admin")).status_code == 404


def test_one_organizations_admin_cannot_reach_anothers_members(env: Env) -> None:
    founder = env.user()
    env.create_org(founder, "Other Co")
    mine = UUID(DEV_OPERATORS["viewer"]["id"])
    before = env.snapshot()
    assert env.client.put(f"/v1/organization/members/{mine}", json={"role": "admin"}, headers=env.h(founder)).status_code == 404
    assert env.client.delete(f"/v1/organization/members/{mine}", headers=env.h(founder)).status_code == 404
    assert [m["email"] for m in env.client.get("/v1/organization/members", headers=env.h(founder)).json()["members"]] == [None]
    assert {k: v for k, v in env.snapshot().items() if k != "control_audit_log"} == {k: v for k, v in before.items() if k != "control_audit_log"}


# --- the two role tightenings of the same change ----------------------------------------------------------------------------------------

def test_registering_an_agent_and_rotating_its_key_need_an_admin(env: Env) -> None:
    body = {"name": "New bot", "framework": "custom", "scopes": []}
    assert env.client.post("/v1/passports", json=body, headers=env.h("operator")).status_code == 403
    assert env.client.post("/v1/passports", json=body, headers=env.h("viewer")).status_code == 403
    created = env.client.post("/v1/passports", json=body, headers=env.h("admin"))
    assert created.status_code == 201
    agent = created.json()["passport"]["id"]
    assert env.client.post(f"/v1/passports/{agent}/rotate-key", json={}, headers=env.h("operator")).status_code == 403
    assert env.client.post(f"/v1/passports/{agent}/rotate-key", json={}, headers=env.h("admin")).status_code == 200


def test_an_operator_can_still_freeze_and_unfreeze(env: Env) -> None:
    agent = env.client.post("/v1/passports", json={"name": "Bot", "framework": "custom", "scopes": []}, headers=env.h("admin")).json()["passport"]["id"]
    assert env.client.post(f"/v1/passports/{agent}/freeze", json={"reason": "x"}, headers=env.h("operator")).status_code == 200
    assert env.client.post(f"/v1/passports/{agent}/unfreeze", json={"confirm": True}, headers=env.h("operator")).status_code == 200


SECRET_TEXT = "chain-of-thought-and-arguments-the-viewer-must-not-read"


def seed_trace(env: Env) -> None:
    env.store.tables.setdefault("execution_traces", []).append({
        "id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "agent_id": str(uuid4()), "trace_id": "t", "span_id": "s", "step_type": "thought",
        "thought_content": SECRET_TEXT, "observation_payload": {"x": SECRET_TEXT}, "tool_arguments": {"q": SECRET_TEXT}, "tool_name": "list_invoices"})
    env.store.tables.setdefault("hitl_interventions", []).append({
        "id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "status": "pending", "proposed_tool_arguments": {"q": SECRET_TEXT}, "tool_name": "t"})


def test_a_viewers_snapshot_has_the_shape_of_the_activity_but_not_what_the_agent_thought_or_was_given(env: Env) -> None:
    seed_trace(env)
    viewer = env.client.get("/v1/state/snapshot", headers=env.h("viewer"))
    assert viewer.status_code == 200 and SECRET_TEXT not in viewer.text
    trace = viewer.json()["execution_traces"][0]
    assert trace["tool_name"] == "list_invoices" and "thought_content" not in trace and "tool_arguments" not in trace
    assert viewer.json()["hitl_interventions"][0]["status"] == "pending"


@pytest.mark.parametrize("who", ["operator", "admin", "owner"])
def test_security_operators_and_above_still_see_it(env: Env, who: str) -> None:
    seed_trace(env)
    assert SECRET_TEXT in env.client.get("/v1/state/snapshot", headers=env.h(who)).text


def test_guessing_invite_tokens_is_rate_limited_too() -> None:
    env = Env(SIGNUPS_PER_HOUR_PER_USER=3)
    user = env.user()
    statuses = [env.accept(user, "rh_join_" + str(n).zfill(32)).status_code for n in range(5)]
    assert statuses[:3] == [403, 403, 403] and statuses[3:] == [429, 429]


def test_me_tells_the_dashboard_who_and_which_role(env: Env) -> None:
    mine = env.client.get("/v1/me", headers=env.h("operator")).json()
    assert mine["role"] == "security_operator"
    assert mine["organization_id"] == DEFAULT_ORG_ID and mine["organization_name"]
    assert env.client.get("/v1/me", headers=env.h("viewer")).json()["role"] == "viewer"
    assert env.client.get("/v1/me", headers=env.h("owner")).json()["role"] == "owner"
    assert env.client.get("/v1/me", headers=env.h(env.user())).status_code == 403, "a person with no organization is told they are not a member"
    assert env.client.get("/v1/me").status_code == 401
