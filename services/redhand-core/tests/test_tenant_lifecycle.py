"""
Tenant data lifecycle (Phase 4.5 D1, ADR 0027): an owner can take their organization's data out, and can ask for it to be deleted with a 7-day grace period.
Tested through the real routes against the in-memory twin; the database functions have their own SQL tests (supabase/tests/tenant_lifecycle_test.sql).
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from redhand_core.lifecycle.manifest import MANIFEST
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter

from core_helpers import make_client, operator_headers

MIGRATIONS = Path(__file__).resolve().parents[3] / "supabase" / "migrations"
# The manifest is redefined whenever a table with tenant data is added: the newest migration that defines it is the real one.
MIGRATION = [m for m in sorted(MIGRATIONS.glob("*.sql")) if "FUNCTION public.tenant_data_manifest() RETURNS jsonb" in m.read_text(encoding="utf-8")][-1]


class Env:
    def __init__(self) -> None:
        self.store = LocalSupabaseAdapter()
        self.client, self.settings = make_client(self.store, ENVIRONMENT="development")

    def h(self, who: str) -> dict[str, str]:
        return operator_headers(who, settings=self.settings)

    @property
    def org(self) -> dict[str, Any]:
        return next(o for o in self.store.tables["organizations"] if str(o["id"]) == DEFAULT_ORG_ID)

    def snapshot(self) -> Any:
        return copy.deepcopy(self.store.tables)

    def audit(self, action: str) -> list[dict[str, Any]]:
        return [a for a in self.store.tables.get("control_audit_log", []) if a["action"] == action]

    def request_deletion(self, who: str = "owner", slug: str | None = None) -> Any:
        return self.client.post("/v1/organization/delete-request", json={"confirm_slug": slug or self.org["slug"]}, headers=self.h(who))


@pytest.fixture
def env() -> Env:
    return Env()


# --- the manifest ---------------------------------------------------------------------------------------------------------------------

def test_the_twin_manifest_matches_the_database_manifest() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    entries = re.findall(r"jsonb_build_object\('table', '(\w+)', 'scope', '(\w+)', 'exclude', jsonb_build_array\(([^)]*)\)\)", sql)
    database = [(t, s, tuple(re.findall(r"'(\w+)'", cols))) for t, s, cols in entries]
    assert database, "the manifest was not found in the migration"
    assert list(MANIFEST) == database


# --- export ---------------------------------------------------------------------------------------------------------------------------

def test_an_owner_gets_every_table_as_a_download_and_it_is_audited(env: Env) -> None:
    response = env.client.get("/v1/organization/export", headers=env.h("owner"))
    assert response.status_code == 200, response.text
    assert response.headers["content-disposition"].startswith("attachment;") and response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["exported"] is True and body["organization_id"] == DEFAULT_ORG_ID
    assert set(body["tables"]) == {t for t, _, _ in MANIFEST}
    assert body["tables"]["agents"]["count"] == len(body["tables"]["agents"]["rows"]) > 0
    audit = env.audit("organization.exported")
    assert len(audit) == 1 and set(audit[0]["details"]) == {"row_counts"}, "the audit row holds counts only"


def test_the_export_holds_no_secret_and_nothing_of_another_organization(env: Env) -> None:
    other = "00000000-0000-0000-0000-00000000ffff"
    env.store.tables["organizations"].append({"id": other, "name": "Rival Ltd", "slug": "rival-ltd"})
    env.store.tables["agents"].append({"id": "00000000-0000-0000-0000-00000000fff1", "organization_id": other, "external_agent_id": "x", "name": "Rival Agent", "status": "active"})
    env.store.tables["sdk_api_keys"].append({"id": "k", "organization_id": other, "name": "Rival key", "key_prefix": "rh_live_zzzz", "key_hash": "f" * 64, "is_active": True})
    text = env.client.get("/v1/organization/export", headers=env.h("owner")).text
    assert "Rival" not in text and other not in text and "rh_live_zzzz" not in text
    forbidden = {c for _, _, cols in MANIFEST for c in cols}
    assert forbidden >= {"key_hash", "token_hash", "code_hash", "ephemeral_token_jti", "siem_webhook_url", "notification_webhook_url", "resume_webhook_url"}
    for name in forbidden:
        assert f'"{name}"' not in text, name
    dev_key_hash = next(k["key_hash"] for k in env.store.tables["sdk_api_keys"] if k["organization_id"] == DEFAULT_ORG_ID)
    assert dev_key_hash not in text


def test_the_export_carries_members_with_their_e_mail(env: Env) -> None:
    body = env.client.get("/v1/organization/export", headers=env.h("owner")).json()
    emails = {m["email"] for m in body["tables"]["organization_members"]["rows"]}
    assert emails == {op["email"] for op in DEV_OPERATORS.values()}


@pytest.mark.parametrize("who", ["admin", "operator", "viewer"])
def test_only_an_owner_can_export(env: Env, who: str) -> None:
    before = env.snapshot()
    assert env.client.get("/v1/organization/export", headers=env.h(who)).status_code == 403
    assert env.snapshot() == before


def test_export_needs_a_token(env: Env) -> None:
    assert env.client.get("/v1/organization/export").status_code == 401


def test_a_second_export_within_the_hour_is_throttled_and_leaves_no_audit_row(env: Env) -> None:
    assert env.client.get("/v1/organization/export", headers=env.h("owner")).status_code == 200
    again = env.client.get("/v1/organization/export", headers=env.h("owner"))
    assert again.status_code == 429 and 1 <= int(again.headers["retry-after"]) <= 3600
    assert len(env.audit("organization.exported")) == 1


# --- deletion request -----------------------------------------------------------------------------------------------------------------

def test_a_wrong_or_missing_slug_changes_nothing(env: Env) -> None:
    before = env.snapshot()
    assert env.request_deletion(slug="not-this-one").status_code == 400
    assert env.client.post("/v1/organization/delete-request", json={}, headers=env.h("owner")).status_code == 422
    assert env.client.post("/v1/organization/delete-request", json={"confirm_slug": env.org["slug"], "extra": 1}, headers=env.h("owner")).status_code == 422
    assert env.snapshot() == before


@pytest.mark.parametrize("who", ["admin", "operator", "viewer"])
def test_only_an_owner_can_request_or_cancel(env: Env, who: str) -> None:
    before = env.snapshot()
    assert env.request_deletion(who).status_code == 403
    assert env.client.post("/v1/organization/delete-request/cancel", headers=env.h(who)).status_code == 403
    assert env.snapshot() == before


def test_the_request_starts_a_seven_day_grace_period_and_stops_what_can_act(env: Env) -> None:
    active = [a["id"] for a in env.store.tables["agents"] if a["organization_id"] == DEFAULT_ORG_ID and a["status"] == "active"]
    assert active and any(k["is_active"] for k in env.store.tables["sdk_api_keys"] if k["organization_id"] == DEFAULT_ORG_ID)
    response = env.request_deletion()
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["requested"] is True and body["already"] is False
    assert env.org["deletion_requested_by"] == DEV_OPERATORS["owner"]["id"]
    assert all(a["status"] == "frozen" for a in env.store.tables["agents"] if a["organization_id"] == DEFAULT_ORG_ID and a["id"] in active)
    assert not any(k["is_active"] for k in env.store.tables["sdk_api_keys"] if k["organization_id"] == DEFAULT_ORG_ID)
    audit = env.audit("organization.deletion_requested")
    assert len(audit) == 1 and audit[0]["details"]["agents_frozen"] == len(active)


def test_asking_twice_is_idempotent(env: Env) -> None:
    first = env.request_deletion().json()
    second = env.request_deletion().json()
    assert second["already"] is True and second["purge_after"] == first["purge_after"]
    assert len(env.audit("organization.deletion_requested")) == 1


def test_while_deletion_is_pending_only_status_export_and_cancel_work(env: Env) -> None:
    env.request_deletion()
    for who in ("owner", "admin", "operator", "viewer"):
        refused = env.client.get("/v1/passports", headers=env.h(who))
        assert refused.status_code == 403 and "scheduled for deletion" in refused.json()["detail"], who
    owner = env.h("owner")
    assert env.client.post("/v1/passports/freeze-all", json={"reason": "x", "confirm": True}, headers=owner).status_code == 403
    assert env.client.get("/v1/organization/invites", headers=owner).status_code == 403
    assert env.client.get("/v1/organization/deletion", headers=owner).json()["requested"] is True
    assert env.client.get("/v1/organization/export", headers=owner).status_code == 200


def test_cancelling_reopens_the_organization_but_agents_stay_frozen(env: Env) -> None:
    env.request_deletion()
    assert env.client.post("/v1/organization/delete-request/cancel", headers=env.h("owner")).json() == {"requested": False, "requested_at": None, "purge_after": None}
    assert env.client.get("/v1/passports", headers=env.h("viewer")).status_code == 200
    assert env.client.get("/v1/organization/deletion", headers=env.h("owner")).json()["requested"] is False
    assert any(a["status"] == "frozen" for a in env.store.tables["agents"] if a["organization_id"] == DEFAULT_ORG_ID)
    assert len(env.audit("organization.deletion_cancelled")) == 1
    assert env.client.post("/v1/organization/delete-request/cancel", headers=env.h("owner")).status_code == 409


def test_a_pending_deletion_is_only_for_its_own_organization(env: Env) -> None:
    other = "00000000-0000-0000-0000-00000000ffff"
    env.store.tables["organizations"].append({"id": other, "name": "Rival Ltd", "slug": "rival-ltd"})
    env.store.tables["organization_members"].append({"id": "m", "organization_id": other, "user_id": "00000000-0000-0000-0000-0000000000f1", "role": "owner"})
    env.request_deletion()
    headers = operator_headers(settings=env.settings, user_id="00000000-0000-0000-0000-0000000000f1", org=other)  # type: ignore[arg-type]
    assert env.client.get("/v1/passports", headers=headers).status_code == 200


def test_a_membership_without_an_organization_row_is_denied(env: Env) -> None:
    env.store.tables["organizations"] = [o for o in env.store.tables["organizations"] if str(o["id"]) != DEFAULT_ORG_ID]
    assert env.client.get("/v1/passports", headers=env.h("owner")).status_code == 403


def test_the_purge_is_not_an_api_route(env: Env) -> None:
    paths = {getattr(r, "path", "") for r in env.client.app.routes}  # type: ignore[attr-defined]
    assert not any("purge" in p for p in paths)
    assert "control_org_purge" not in json.dumps(sorted(paths))


def test_me_tells_the_dashboard_the_slug_and_when_a_pending_deletion_ends(env: Env) -> None:
    before = env.client.get("/v1/me", headers=env.h("viewer")).json()
    assert before["organization_slug"] == env.org["slug"] and before["deletion_purge_after"] is None
    purge_after = env.request_deletion().json()["purge_after"]
    during = env.client.get("/v1/me", headers=env.h("viewer"))
    assert during.status_code == 200, "every member can still see who they are while deletion is pending"
    assert during.json()["deletion_purge_after"] == purge_after
