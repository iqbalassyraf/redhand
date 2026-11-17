"""
SDK keys an admin issues and revokes (Phase 4.5 C1a, docs/plans/phase45-c1-sdk-keys.md). The plaintext is shown once and never stored or logged;
revoked, expired, tampered and other-organization keys are refused; each key has its own ingest rate limit; every change is audited.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest

from redhand_core.routers import telemetry as telemetry_router
from redhand_core.sdkkeys import service as keys_service

from test_telegram import OTHER_ORG, Env as TelegramEnv


def span() -> dict[str, Any]:
    return {"session_id": str(uuid4()), "trace_id": uuid4().hex, "span_id": uuid4().hex[:16], "step_type": "observation"}


class Env(TelegramEnv):
    def create(self, name: str = "ci", days: int | None = 90, user: str = "admin", **extra: Any) -> Any:
        body: dict[str, Any] = {"name": name, **extra}
        if days is not None:
            body["expires_in_days"] = days
        return self.client.post("/v1/organization/sdk-keys", json=body, headers=self.h(user))

    def listing(self, user: str = "viewer") -> Any:
        return self.client.get("/v1/organization/sdk-keys", headers=self.h(user))

    def revoke(self, key_id: str, user: str = "admin") -> Any:
        return self.client.request("DELETE", f"/v1/organization/sdk-keys/{key_id}", json={"reason": "rotated"}, headers=self.h(user))

    def ingest(self, key: str | None, external: str = "keyed-bot") -> Any:
        headers = {"X-RedHand-API-Key": key} if key is not None else {}
        body = {"sdk_version": "0.1.0", "external_agent_id": external, "agent_name": external, "framework": "pytest", "environment": "development", "spans": [span()]}
        return self.client.post("/v1/telemetry/ingest", json=body, headers=headers)

    def row(self, key_id: str) -> dict[str, Any]:
        return next(r for r in self.store.tables["sdk_api_keys"] if str(r["id"]) == key_id)


@pytest.fixture
def env() -> Env:
    keys_service.reset_limits_for_tests()
    return Env()


# --- creating -----------------------------------------------------------------------------------------------------------------------

def test_an_admin_creates_a_key_that_is_shown_once_and_stored_only_as_a_hash(env: Env) -> None:
    response = env.create(name="ci pipeline")
    assert response.status_code == 201, response.text
    body = response.json()
    secret = body["secret"]
    assert secret.startswith("rh_live_") and len(secret) >= 8 + 43  # 32 random bytes, URL-safe
    key = body["key"]
    assert key["key_prefix"] == secret[:12] and key["name"] == "ci pipeline" and key["state"] == "active"
    stored = env.row(key["id"])
    assert stored["key_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in str(stored) and "secret" not in stored


def test_the_default_expiry_is_ninety_days_and_can_be_chosen(env: Env) -> None:
    now = datetime.now(timezone.utc)
    default = env.create(days=None).json()["key"]
    assert timedelta(days=89) < datetime.fromisoformat(default["expires_at"]) - now <= timedelta(days=90, minutes=1)
    one = env.create(name="short", days=1).json()["key"]
    assert datetime.fromisoformat(one["expires_at"]) - now <= timedelta(days=1, minutes=1)


def test_the_plaintext_never_appears_again(env: Env) -> None:
    secret = env.create().json()["secret"]
    listing = env.listing().text
    assert secret not in listing and secret[12:] not in listing and "key_hash" not in listing


@pytest.mark.parametrize("user", ["operator", "viewer"])
def test_only_an_admin_can_create_or_revoke(env: Env, user: str) -> None:
    assert env.create(user=user).status_code == 403
    key_id = env.create().json()["key"]["id"]
    assert env.revoke(key_id, user=user).status_code == 403
    assert env.row(key_id)["is_active"] is True


def test_every_signed_in_role_can_list_without_secrets(env: Env) -> None:
    env.create()
    for user in ("viewer", "operator", "admin"):
        body = env.listing(user).json()
        assert len(body["keys"]) >= 1 and body["max_active"] == 10
        assert all(set(k) >= {"id", "name", "key_prefix", "created_at", "expires_at", "last_used_at", "state"} for k in body["keys"])


@pytest.mark.parametrize(
    "body",
    [
        {"name": "", "expires_in_days": 90},
        {"name": "x" * 101, "expires_in_days": 90},
        {"name": "ok", "expires_in_days": 0},
        {"name": "ok", "expires_in_days": 366},
        {"name": "ok", "expires_in_days": 1.5},
        {"name": "ok", "expires_in_days": "30"},
        {"name": "ok", "expires_in_days": True},
        {"name": "ok", "tenant": "x"},
    ],
)
def test_bad_input_is_refused(env: Env, body: dict[str, Any]) -> None:
    assert env.client.post("/v1/organization/sdk-keys", json=body, headers=env.h("admin")).status_code == 422


def test_an_organization_keeps_at_most_ten_usable_keys(env: Env) -> None:
    usable = sum(1 for r in env.store.tables["sdk_api_keys"] if r["is_active"])  # the seeded development key counts
    for n in range(10 - usable):
        assert env.create(name=f"k{n}").status_code == 201
    over = env.create(name="eleventh")
    assert over.status_code == 409 and "10" in over.json()["detail"]


def test_creating_and_revoking_are_audited_without_the_key(env: Env) -> None:
    created = env.create().json()
    env.revoke(created["key"]["id"])
    actions = [e["action"] for e in env.audit()]
    assert "sdk_key.created" in actions and "sdk_key.revoked" in actions
    assert created["secret"] not in str(env.store.tables["control_audit_log"])


def test_the_secret_never_reaches_a_log(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    secret = env.create().json()["secret"]
    env.ingest(secret)
    assert secret not in caplog.text


# --- using --------------------------------------------------------------------------------------------------------------------------

def test_a_new_key_works_for_ingest_and_its_last_use_is_recorded(env: Env) -> None:
    created = env.create().json()
    assert env.ingest(created["secret"]).status_code == 202
    assert env.row(created["key"]["id"])["last_used_at"] is not None
    listed = next(k for k in env.listing().json()["keys"] if k["id"] == created["key"]["id"])
    assert listed["last_used_at"] is not None


def test_a_revoked_key_is_refused(env: Env) -> None:
    created = env.create().json()
    assert env.revoke(created["key"]["id"]).status_code == 200
    assert env.ingest(created["secret"]).status_code == 401
    assert next(k for k in env.listing().json()["keys"] if k["id"] == created["key"]["id"])["state"] == "revoked"


def test_revoking_twice_changes_nothing(env: Env) -> None:
    key_id = env.create().json()["key"]["id"]
    assert env.revoke(key_id).json()["changed"] is True
    assert env.revoke(key_id).json()["changed"] is False


def test_an_expired_key_is_refused_and_shown_as_expired(env: Env) -> None:
    created = env.create().json()
    env.row(created["key"]["id"])["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert env.ingest(created["secret"]).status_code == 401
    assert next(k for k in env.listing().json()["keys"] if k["id"] == created["key"]["id"])["state"] == "expired"


@pytest.mark.parametrize("mangle", [lambda s: s[:-1] + ("A" if s[-1] != "A" else "B"), lambda s: s.replace("rh_live_", "xx_live_"), lambda s: s + "x", lambda s: ""])
def test_a_tampered_or_malformed_key_is_refused(env: Env, mangle) -> None:  # type: ignore[no-untyped-def]
    secret = env.create().json()["secret"]
    assert env.ingest(mangle(secret)).status_code in (401, 422)


def test_a_missing_key_is_refused(env: Env) -> None:
    assert env.ingest(None).status_code in (401, 422)


def test_another_organizations_key_cannot_be_listed_or_revoked(env: Env) -> None:
    foreign = str(uuid4())
    env.store.tables["sdk_api_keys"].append({"id": foreign, "organization_id": OTHER_ORG, "name": "theirs", "key_prefix": "rh_live_zzzz",
                                             "key_hash": "0" * 64, "is_active": True, "expires_at": None, "created_at": datetime.now(timezone.utc).isoformat()})
    assert foreign not in {k["id"] for k in env.listing().json()["keys"]}
    assert env.revoke(foreign).status_code == 404
    assert env.row(foreign)["is_active"] is True


def test_a_key_sends_data_only_to_its_own_organization(env: Env) -> None:
    secret = env.create().json()["secret"]
    response = env.ingest(secret, external="org-check-bot")
    agent = next(a for a in env.store.tables["agents"] if a["id"] == response.json()["agent_id"])
    assert str(agent["organization_id"]) != OTHER_ORG


def test_each_key_has_its_own_rate_limit(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keys_service, "INGEST_BATCHES_PER_MINUTE", 2)
    first = env.create(name="a").json()["secret"]
    second = env.create(name="b").json()["secret"]
    assert [env.ingest(first).status_code for _ in range(3)] == [202, 202, 429]
    assert env.ingest(second).status_code == 202, "another key is not slowed by the first one"


def test_the_rate_limit_reply_says_when_to_retry(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keys_service, "INGEST_BATCHES_PER_MINUTE", 1)
    secret = env.create().json()["secret"]
    env.ingest(secret)
    limited = env.ingest(secret)
    assert limited.status_code == 429 and limited.headers.get("retry-after") == "60"


def test_a_failing_last_use_write_never_fails_the_ingest(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = env.create().json()["secret"]
    original = env.store.rpc

    def broken(function: str, params: dict[str, Any] | None = None) -> Any:
        if function == "sdk_key_touch":
            raise RuntimeError("database down")
        return original(function, params)

    monkeypatch.setattr(env.store, "rpc", broken)
    assert env.ingest(secret).status_code == 202


def test_key_generation_has_enough_randomness() -> None:
    a, b = keys_service.generate_key(), keys_service.generate_key()
    assert a != b and a.startswith("rh_live_") and len(a) - len("rh_live_") >= 43
    assert keys_service.key_prefix(a) == a[:12]
    assert keys_service.hash_key(a) == hashlib.sha256(a.encode()).hexdigest()


def test_the_telemetry_router_still_imports_the_key_check() -> None:
    assert hasattr(telemetry_router, "verify_sdk_api_key")


def test_a_busy_key_does_not_write_its_last_use_on_every_batch(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = env.create().json()["secret"]
    calls: list[str] = []
    original = env.store.rpc

    def counting(function: str, params: dict[str, Any] | None = None) -> Any:
        if function == "sdk_key_touch":
            calls.append(function)
        return original(function, params)

    monkeypatch.setattr(env.store, "rpc", counting)
    for _ in range(5):
        env.ingest(secret)
    assert calls == ["sdk_key_touch"], "one database write a minute per key, not one per batch"
