"""
Agent Passports, agent credentials, control actions and the gateway context endpoint
(Phase 1, M3). Covers "done" tests 1, 3 and 4 at the core API level.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from pydantic import SecretStr
import pytest

from redhand_core.passports.credentials import AGENT_TOKEN_AUDIENCE, AGENT_TOKEN_ISSUER, hash_agent_key
from redhand_core.passports.models import (
    Scope,
    effective_status,
    is_scope_expansion,
    scopes_allow,
)
from redhand_core.routers import agent_auth
from redhand_core.services.local_store import (
    DEFAULT_ORG_ID,
    DEV_OPERATORS,
    LocalStoreConstraintError,
    LocalSupabaseAdapter,
)

from core_helpers import make_client, operator_headers

SERVICE_TOKEN = "test-internal-service-token-0123456789"
OTHER_ORG = "00000000-0000-0000-0000-0000000000f0"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"


class Env:
    """A core instance on a fresh local store with helpers for each role."""

    def __init__(self, **settings: Any) -> None:
        self.store = LocalSupabaseAdapter()
        self.store.tables["organizations"].append({"id": OTHER_ORG, "name": "Other", "slug": "other", "safe_mode": False})
        self.store.tables["organization_members"].append(
            {"id": str(uuid4()), "organization_id": OTHER_ORG, "user_id": OTHER_OWNER, "role": "owner"}
        )
        settings.setdefault("INTERNAL_SERVICE_TOKEN", SecretStr(SERVICE_TOKEN))
        # The development-only flag is refused outside development and test (H2.5), so a harness that runs as staging cannot default it on.
        settings.setdefault("ALLOW_INSECURE_MCP_URLS", settings.get("ENVIRONMENT", "development") in ("development", "test"))
        self.client, self.settings = make_client(self.store, **settings)
        agent_auth._exchange_limiter._events.clear()

    def h(self, user: str = "owner") -> dict[str, str]:
        return operator_headers(user, self.settings)

    def other_tenant(self) -> dict[str, str]:
        from uuid import UUID

        return operator_headers(settings=self.settings, user_id=UUID(OTHER_OWNER))

    def register(self, user: str = "admin", **body: Any) -> dict[str, Any]:
        payload = {"name": "Invoice Bot", "framework": "n8n", "scopes": [{"server": "xero", "tool": "list_invoices"}]}
        payload.update(body)
        resp = self.client.post("/v1/passports", json=payload, headers=self.h(user))
        assert resp.status_code == 201, resp.text
        return resp.json()

    def exchange(self, key: str) -> Any:
        return self.client.post("/v1/agent-auth/token", headers={"Authorization": f"Bearer {key}"})

    def context(self, agent_id: str, org: str = DEFAULT_ORG_ID, server: str = "xero") -> Any:
        return self.client.get(
            "/internal/v1/gateway-context",
            params={"agent_id": agent_id, "organization_id": org, "server": server},
            headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        )

    def audit(self) -> list[dict[str, Any]]:
        return self.client.get("/v1/audit/control", headers=self.h("viewer")).json()


@pytest.fixture
def env() -> Env:
    return Env()


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------


def test_effective_status_rules() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    future, past = (now + timedelta(days=1)).isoformat(), (now - timedelta(seconds=1)).isoformat()
    assert effective_status("active", future, now) == "active"
    assert effective_status("active", past, now) == "expired"
    assert effective_status("frozen", past, now) == "frozen"
    assert effective_status("revoked", future, now) == "revoked"
    assert effective_status("quarantined", future, now) == "revoked"  # unknown -> fail closed
    assert effective_status("active", "garbage", now) == "expired"
    assert effective_status("active", None, now) == "expired"


def test_scope_matching_and_expansion() -> None:
    read_one = Scope(server="xero", tool="list_invoices", access="read")
    write_one = Scope(server="xero", tool="list_invoices", access="write")
    read_all = Scope(server="xero", tool="*", access="read")
    assert scopes_allow([read_one], "xero", "list_invoices")
    assert not scopes_allow([read_one], "xero", "delete_invoice")
    assert not scopes_allow([read_one], "github", "list_invoices")
    assert scopes_allow([read_all], "xero", "anything")
    assert is_scope_expansion([read_one], [write_one])
    assert is_scope_expansion([read_one], [read_all])
    assert not is_scope_expansion([read_all], [read_one])
    assert not is_scope_expansion([write_one], [read_one])
    assert not is_scope_expansion([read_one, write_one], [])


# ---------------------------------------------------------------------------
# Done test 1: register an agent and get a passport
# ---------------------------------------------------------------------------


def test_register_agent_returns_passport_and_one_time_key(env: Env) -> None:
    created = env.register(expires_in_days=30)
    passport, key = created["passport"], created["agent_key"]
    assert key.startswith("rh_agent_")
    assert passport["status"] == "active"
    assert passport["owner_id"] == DEV_OPERATORS["admin"]["id"]
    assert passport["scopes"] == [{"server": "xero", "tool": "list_invoices", "access": "read"}]
    expiry = datetime.fromisoformat(passport["expires_at"])
    assert timedelta(days=29) < expiry - datetime.now(timezone.utc) <= timedelta(days=30)

    listed = env.client.get("/v1/passports", headers=env.h("viewer")).json()
    assert passport["id"] in [p["id"] for p in listed]
    one = env.client.get(f"/v1/passports/{passport['id']}", headers=env.h("viewer")).json()
    assert one["name"] == "Invoice Bot" and "agent_key" not in one

    key_rows = env.store.tables["agent_keys"]
    assert key_rows[0]["key_hash"] == hash_agent_key(key)
    assert key not in str(key_rows) and key not in str(env.store.tables["control_audit_log"])
    assert env.audit()[0]["action"] == "passport.created"


def test_register_requires_operator_role_and_valid_input(env: Env) -> None:
    body = {"name": "x"}
    assert env.client.post("/v1/passports", json=body, headers=env.h("viewer")).status_code == 403
    assert env.client.post("/v1/passports", json=body).status_code == 401
    bad = [
        {"name": "x", "scopes": [{"server": "Bad Slug", "tool": "t"}]},
        {"name": "x", "scopes": [{"server": "ok", "tool": "t", "access": "admin"}]},
        {"name": "x", "expires_in_days": 0},
        {"name": "x", "expires_in_days": 366},
        {"name": "x", "unexpected": True},
        {"name": ""},
    ]
    for payload in bad:
        assert env.client.post("/v1/passports", json=payload, headers=env.h()).status_code == 422, payload


def test_owners_must_belong_to_the_tenant(env: Env) -> None:
    resp = env.client.post(
        "/v1/passports", json={"name": "x", "backup_owner_id": OTHER_OWNER}, headers=env.h()
    )
    assert resp.status_code == 400


def test_duplicate_external_id_conflicts(env: Env) -> None:
    env.register(external_agent_id="bot-1")
    resp = env.client.post(
        "/v1/passports", json={"name": "y", "external_agent_id": "bot-1"}, headers=env.h()
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Agent key -> short-lived access token
# ---------------------------------------------------------------------------


def test_token_exchange_issues_verifiable_short_lived_token(env: Env) -> None:
    created = env.register()
    resp = env.exchange(created["agent_key"])
    assert resp.status_code == 200
    body = resp.json()
    jwks = env.client.get("/v1/agent-auth/jwks").json()
    public = jwt.PyJWK(jwks["keys"][0])
    claims = jwt.decode(
        body["access_token"], public.key, algorithms=["EdDSA"],
        audience=AGENT_TOKEN_AUDIENCE, issuer=AGENT_TOKEN_ISSUER,
    )
    assert claims["sub"] == created["passport"]["id"]
    assert claims["org"] == DEFAULT_ORG_ID
    assert claims["ver"] == 1
    assert claims["exp"] - claims["iat"] == env.settings.AGENT_TOKEN_TTL_SECONDS == 600


@pytest.mark.parametrize(
    "key", ["", "not-a-key", "rh_agent_" + "A" * 43, "rh_agent_short", "rh_agent_" + "x" * 30 + "!" * 13]
)
def test_token_exchange_rejects_unknown_or_malformed_keys(env: Env, key: str) -> None:
    assert env.exchange(key).status_code == 401


def test_token_exchange_refused_for_frozen_revoked_and_expired(env: Env) -> None:
    frozen, revoked, expired = env.register(name="a"), env.register(name="b"), env.register(name="c")
    env.client.post(f"/v1/passports/{frozen['passport']['id']}/freeze", json={}, headers=env.h())
    env.client.post(
        f"/v1/passports/{revoked['passport']['id']}/revoke", json={"confirm": True}, headers=env.h("admin")
    )
    for row in env.store.tables["agents"]:
        if row["id"] == expired["passport"]["id"]:
            row["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()

    assert env.exchange(frozen["agent_key"]).status_code == 403
    assert env.exchange(expired["agent_key"]).status_code == 403
    # Revocation also deactivates the key, so it is no longer recognised at all.
    assert env.exchange(revoked["agent_key"]).status_code == 401


def test_token_exchange_is_rate_limited_per_key() -> None:
    env = Env(AGENT_TOKEN_EXCHANGES_PER_MINUTE=3)
    key = env.register()["agent_key"]
    assert [env.exchange(key).status_code for _ in range(4)] == [200, 200, 200, 429]


# ---------------------------------------------------------------------------
# Done test 3: revoke / freeze one agent
# ---------------------------------------------------------------------------


def test_freeze_is_idempotent_and_audited_once(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    first = env.client.post(f"/v1/passports/{agent_id}/freeze", json={"reason": "odd spend"}, headers=env.h())
    second = env.client.post(f"/v1/passports/{agent_id}/freeze", json={}, headers=env.h())
    assert first.json()["changed"] is True and first.json()["passport"]["status"] == "frozen"
    assert second.json()["changed"] is False
    actions = [e["action"] for e in env.audit()]
    assert actions.count("passport.frozen") == 1
    entry = next(e for e in env.audit() if e["action"] == "passport.frozen")
    assert entry["actor_user_id"] == DEV_OPERATORS["owner"]["id"] and entry["reason"] == "odd spend"


def test_unfreeze_requires_confirmation(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    env.client.post(f"/v1/passports/{agent_id}/freeze", json={}, headers=env.h())
    url = f"/v1/passports/{agent_id}/unfreeze"
    assert env.client.post(url, json={}, headers=env.h("operator")).status_code == 400
    assert env.client.post(url, json={"confirm": False}, headers=env.h("operator")).status_code == 400
    ok = env.client.post(url, json={"confirm": True}, headers=env.h("operator"))
    assert ok.status_code == 200 and ok.json()["passport"]["status"] == "active"


def test_expired_passport_must_be_renewed_before_unfreeze(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    env.client.post(f"/v1/passports/{agent_id}/freeze", json={}, headers=env.h())
    row = next(r for r in env.store.tables["agents"] if r["id"] == agent_id)
    row["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    url = f"/v1/passports/{agent_id}/unfreeze"
    assert env.client.post(url, json={"confirm": True}, headers=env.h()).status_code == 409
    renew = env.client.post(f"/v1/passports/{agent_id}/renew", json={"expires_in_days": 10}, headers=env.h("admin"))
    assert renew.status_code == 200
    assert env.client.post(url, json={"confirm": True}, headers=env.h()).json()["passport"]["status"] == "active"


def test_revoke_is_admin_only_confirmed_and_permanent(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    url = f"/v1/passports/{agent_id}/revoke"
    assert env.client.post(url, json={"confirm": True}, headers=env.h("operator")).status_code == 403
    assert env.client.post(url, json={}, headers=env.h("admin")).status_code == 400
    assert env.client.post(url, json={"confirm": True}, headers=env.h("admin")).json()["passport"]["status"] == "revoked"
    again = env.client.post(url, json={"confirm": True}, headers=env.h("admin"))
    assert again.status_code == 200 and again.json()["changed"] is False

    for path, body, role in [
        ("unfreeze", {"confirm": True}, "owner"),
        ("freeze", {}, "owner"),
        ("renew", {}, "owner"),
        ("rotate-key", {}, "owner"),
    ]:
        assert env.client.post(f"/v1/passports/{agent_id}/{path}", json=body, headers=env.h(role)).status_code == 409, path
    scopes = env.client.put(f"/v1/passports/{agent_id}/scopes", json={"scopes": []}, headers=env.h())
    assert scopes.status_code == 409


def test_store_rejects_reactivating_revoked_agent_directly(env: Env) -> None:
    import asyncio

    agent_id = env.register()["passport"]["id"]
    env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h())
    with pytest.raises(LocalStoreConstraintError):
        asyncio.run(env.store.table("agents").update({"status": "active"}).eq("id", agent_id).execute())


def test_control_actions_on_unknown_or_foreign_agents_are_404(env: Env) -> None:
    mine = env.register()["passport"]["id"]
    for agent_id, headers in [(str(uuid4()), env.h()), (mine, env.other_tenant())]:
        for path, body in [("freeze", {}), ("unfreeze", {"confirm": True}), ("revoke", {"confirm": True})]:
            resp = env.client.post(f"/v1/passports/{agent_id}/{path}", json=body, headers=headers)
            assert resp.status_code == 404, (path, resp.text)
        assert env.client.get(f"/v1/passports/{agent_id}", headers=headers).status_code == 404
    status_after = next(r for r in env.store.tables["agents"] if r["id"] == mine)["status"]
    assert status_after == "active"


# ---------------------------------------------------------------------------
# Done test 4: freeze everything
# ---------------------------------------------------------------------------


def test_freeze_all_freezes_every_agent_in_tenant_only(env: Env) -> None:
    created = [env.register(name=f"bot-{i}") for i in range(3)]
    foreign_id = str(uuid4())
    env.store.tables["agents"].append(
        {"id": foreign_id, "organization_id": OTHER_ORG, "external_agent_id": "f", "name": "F",
         "status": "active", "scopes": [], "version": 1,
         "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}
    )

    assert env.client.post("/v1/passports/freeze-all", json={"confirm": True}, headers=env.h("operator")).status_code == 403
    assert env.client.post("/v1/passports/freeze-all", json={}, headers=env.h("admin")).status_code == 400

    resp = env.client.post(
        "/v1/passports/freeze-all", json={"confirm": True, "reason": "incident 42"}, headers=env.h("admin")
    )
    assert resp.status_code == 200
    body = resp.json()
    seeded_active = 3  # demo agents in the local store
    assert body["frozen_count"] == len(created) + seeded_active

    statuses = {r["id"]: r["status"] for r in env.store.tables["agents"]}
    assert all(statuses[c["passport"]["id"]] == "frozen" for c in created)
    assert statuses[foreign_id] == "active"
    assert all(env.exchange(c["agent_key"]).status_code == 403 for c in created)

    entry = env.audit()[0]
    assert entry["action"] == "organization.frozen_all"
    assert entry["actor_user_id"] == DEV_OPERATORS["admin"]["id"]
    assert entry["reason"] == "incident 42" and entry["details"]["frozen_count"] == body["frozen_count"]

    # Unfreeze stays per agent.
    one = created[0]["passport"]["id"]
    env.client.post(f"/v1/passports/{one}/unfreeze", json={"confirm": True}, headers=env.h())
    statuses = {r["id"]: r["status"] for r in env.store.tables["agents"]}
    assert statuses[one] == "active" and statuses[created[1]["passport"]["id"]] == "frozen"


# ---------------------------------------------------------------------------
# Scopes, renewal, key rotation
# ---------------------------------------------------------------------------


def test_scope_expansion_requires_confirmation_and_bumps_version(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    url = f"/v1/passports/{agent_id}/scopes"
    wider = {"scopes": [{"server": "xero", "tool": "*", "access": "write"}]}
    assert env.client.put(url, json=wider, headers=env.h("operator")).status_code == 403
    assert env.client.put(url, json=wider, headers=env.h("admin")).status_code == 400
    ok = env.client.put(url, json={**wider, "confirm": True}, headers=env.h("admin")).json()
    assert ok["changed"] is True and ok["passport"]["version"] == 2

    narrower = env.client.put(url, json={"scopes": []}, headers=env.h("admin")).json()
    assert narrower["changed"] is True and narrower["passport"]["version"] == 3
    entry = env.audit()[0]
    assert entry["action"] == "passport.scopes_changed" and entry["details"]["expansion"] is False


def test_rotate_key_invalidates_previous_key(env: Env) -> None:
    created = env.register()
    rotated = env.client.post(
        f"/v1/passports/{created['passport']['id']}/rotate-key", json={}, headers=env.h("admin")
    ).json()
    assert env.exchange(created["agent_key"]).status_code == 401
    assert env.exchange(rotated["agent_key"]).status_code == 200


# ---------------------------------------------------------------------------
# Gateway context (internal)
# ---------------------------------------------------------------------------


def test_gateway_context_requires_service_token() -> None:
    disabled = Env(INTERNAL_SERVICE_TOKEN=None)
    agent_id = disabled.register()["passport"]["id"]
    assert disabled.context(agent_id).status_code == 503

    env = Env()
    agent_id = env.register()["passport"]["id"]
    for header in [{}, {"Authorization": "Bearer wrong"}, {"Authorization": SERVICE_TOKEN}]:
        resp = env.client.get(
            "/internal/v1/gateway-context",
            params={"agent_id": agent_id, "organization_id": DEFAULT_ORG_ID, "server": "xero"},
            headers=header,
        )
        assert resp.status_code == 401, header


def test_gateway_context_reflects_status_scopes_and_server(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    ctx = env.context(agent_id).json()
    assert ctx["agent"]["status"] == "active" and ctx["server"] is None
    assert ctx["agent"]["scopes"][0]["tool"] == "list_invoices"

    env.client.post(
        "/v1/mcp-servers", json={"slug": "xero", "name": "Xero", "url": "http://localhost:9100/mcp"},
        headers=env.h("admin"),
    )
    assert env.context(agent_id).json()["server"] == {
        "slug": "xero", "url": "http://localhost:9100/mcp", "pin_mode": "alert", "approved_tools": [],
    }

    env.client.post(f"/v1/passports/{agent_id}/freeze", json={}, headers=env.h())
    frozen = env.context(agent_id).json()["agent"]
    assert frozen["status"] == "frozen" and frozen["version"] == 2

    row = next(r for r in env.store.tables["agents"] if r["id"] == agent_id)
    assert row["last_seen_at"] is not None


def test_gateway_context_is_tenant_bound(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    assert env.context(agent_id, org=OTHER_ORG).status_code == 404
    assert env.context(str(uuid4())).status_code == 404


def test_gateway_context_malformed_passport_fails_closed(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    row = next(r for r in env.store.tables["agents"] if r["id"] == agent_id)
    row["scopes"] = [{"server": "xero", "tool": "x", "access": "root"}]
    assert env.context(agent_id).json()["agent"]["status"] == "revoked"


# ---------------------------------------------------------------------------
# MCP servers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/mcp",
        "https://localhost/mcp",
        "https://10.0.0.5/mcp",
        "https://169.254.169.254/latest",
        "https://[::1]/mcp",
        "https://user:pass@example.com/mcp",
        "ftp://example.com",
        "example.com/mcp",
        "https://db.internal/mcp",
    ],
)
def test_mcp_server_url_must_be_public_https(url: str) -> None:
    env = Env(ALLOW_INSECURE_MCP_URLS=False)
    resp = env.client.post(
        "/v1/mcp-servers", json={"slug": "s", "name": "S", "url": url}, headers=env.h("admin")
    )
    assert resp.status_code in (400, 422), url


def test_mcp_server_registration_rules(env: Env) -> None:
    body = {"slug": "github", "name": "GitHub", "url": "https://mcp.example.com/github"}
    strict = Env(ALLOW_INSECURE_MCP_URLS=False)
    assert strict.client.post("/v1/mcp-servers", json=body, headers=strict.h("admin")).status_code == 201
    assert env.client.post("/v1/mcp-servers", json=body, headers=env.h("operator")).status_code == 403
    created = env.client.post("/v1/mcp-servers", json=body, headers=env.h("admin"))
    assert created.status_code == 201
    assert env.client.post("/v1/mcp-servers", json=body, headers=env.h("admin")).status_code == 409
    server_id = created.json()["id"]
    assert env.client.post(f"/v1/mcp-servers/{server_id}/deactivate", headers=env.other_tenant()).status_code == 404
    off = env.client.post(f"/v1/mcp-servers/{server_id}/deactivate", headers=env.h("admin"))
    assert off.json()["is_active"] is False


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_control_audit_is_tenant_scoped_and_append_only(env: Env) -> None:
    import asyncio

    env.register()
    assert env.audit()
    assert env.client.get("/v1/audit/control", headers=env.other_tenant()).json() == []
    assert env.client.get("/v1/audit/control").status_code == 401
    with pytest.raises(LocalStoreConstraintError):
        asyncio.run(env.store.table("control_audit_log").update({"reason": "x"}).execute())


class _FailingAuditLog(list):  # type: ignore[type-arg]  # test double for an unwritable audit table
    def insert(self, *_: Any) -> None:
        from postgrest.exceptions import APIError

        # The database reports a failed statement as an APIError with a SQLSTATE code.
        raise APIError({"code": "P0001", "message": "simulated audit failure", "hint": None, "details": None})


def _break_audit_log(env: Env) -> dict[str, Any]:
    """Makes the audit insert fail and returns a copy of every other table for comparison."""
    state = copy.deepcopy({k: v for k, v in env.store.tables.items() if k != "control_audit_log"})
    env.store.tables["control_audit_log"] = _FailingAuditLog()
    return state


def _state_without_audit(env: Env) -> dict[str, Any]:
    return {k: v for k, v in env.store.tables.items() if k != "control_audit_log"}


def test_failed_audit_write_rolls_back_every_control_action(env: Env) -> None:
    """Atomicity: if the audit row cannot be written, the action is not applied at all."""
    created = env.register()
    agent_id, key = created["passport"]["id"], created["agent_key"]
    env.client.post(
        "/v1/mcp-servers", json={"slug": "xero", "name": "Xero", "url": "http://localhost:9100/mcp"},
        headers=env.h("admin"),
    )
    server_id = env.client.get("/v1/mcp-servers", headers=env.h("viewer")).json()[0]["id"]
    before = _break_audit_log(env)

    attempts: list[tuple[str, str, dict[str, Any], str]] = [
        ("post", f"/v1/passports/{agent_id}/freeze", {"reason": "x"}, "operator"),
        ("post", f"/v1/passports/{agent_id}/revoke", {"confirm": True}, "admin"),
        ("post", f"/v1/passports/{agent_id}/rotate-key", {}, "admin"),
        ("post", f"/v1/passports/{agent_id}/renew", {"expires_in_days": 5}, "admin"),
        ("put", f"/v1/passports/{agent_id}/scopes", {"scopes": [], "confirm": True}, "admin"),
        ("post", "/v1/passports/freeze-all", {"confirm": True, "reason": "x"}, "admin"),
        ("post", "/v1/passports", {"name": "Second bot"}, "admin"),
        ("post", "/v1/mcp-servers", {"slug": "github", "name": "GH", "url": "http://localhost:9101/mcp"}, "admin"),
        ("post", f"/v1/mcp-servers/{server_id}/deactivate", {}, "admin"),
    ]
    for method, url, body, role in attempts:
        resp = env.client.request(method, url, json=body, headers=env.h(role))
        assert resp.status_code == 500, (url, resp.text)
        assert "could not be completed" in resp.json()["detail"], url
        assert _state_without_audit(env) == before, f"{url} left partial changes behind"

    # The agent was never affected: its key still works.
    env.store.tables["control_audit_log"] = []
    assert env.exchange(key).status_code == 200


def test_unexpected_database_error_is_generic_and_does_not_leak(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from postgrest.exceptions import APIError

    agent_id = env.register()["passport"]["id"]

    def exploding_rpc(function: str, params: Any = None) -> Any:
        raise APIError({"code": "XX000", "message": "internal detail: relation secret_table", "hint": None, "details": None})

    monkeypatch.setattr(env.store, "rpc", exploding_rpc)
    resp = env.client.post(f"/v1/passports/{agent_id}/freeze", json={}, headers=env.h())
    assert resp.status_code == 500
    assert "secret_table" not in resp.text and "internal detail" not in resp.text


def _interfere_before_rpc(env: Env, agent_id: str, statuses: list[str]) -> list[int]:
    """Simulates another operator changing the passport between our read and our write."""
    calls: list[int] = []
    original = env.store.rpc

    def rpc(function: str, params: Any = None) -> Any:
        if function == "control_agent_change":
            index = len(calls)
            calls.append(index)
            if index < len(statuses):
                row = next(r for r in env.store.tables["agents"] if r["id"] == agent_id)
                row["status"] = statuses[index]
        return original(function, params)

    env.store.rpc = rpc  # type: ignore[method-assign]  # test double
    return calls


def test_concurrent_change_is_retried_once_from_fresh_state(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    # Another operator freezes the agent after our revoke read "active" but before it applies.
    calls = _interfere_before_rpc(env, agent_id, ["frozen"])
    resp = env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h("admin"))
    assert resp.status_code == 200 and resp.json()["passport"]["status"] == "revoked"
    assert len(calls) == 2  # first attempt conflicted, second succeeded
    actions = [e["action"] for e in env.audit()]
    assert actions.count("passport.revoked") == 1


def test_persistent_concurrent_changes_end_in_409_without_partial_state(env: Env) -> None:
    agent_id = env.register()["passport"]["id"]
    audit_before = len(env.audit())
    _interfere_before_rpc(env, agent_id, ["frozen", "active"])
    resp = env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h("admin"))
    assert resp.status_code == 409
    assert "changed by someone else" in resp.json()["detail"]
    assert len(env.audit()) == audit_before  # nothing was recorded because nothing was applied
    row = next(r for r in env.store.tables["agents"] if r["id"] == agent_id)
    assert row["status"] != "revoked"


def test_signing_key_required_outside_development() -> None:
    env = Env(ENVIRONMENT="staging", AGENT_TOKEN_SIGNING_KEY=None)
    key = env.register()["agent_key"]
    assert env.exchange(key).status_code == 503


def test_configured_signing_key_is_used() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    env = Env(ENVIRONMENT="staging", AGENT_TOKEN_SIGNING_KEY=SecretStr(pem))
    token = env.exchange(env.register()["agent_key"]).json()["access_token"]
    claims = jwt.decode(token, private.public_key(), algorithms=["EdDSA"], audience=AGENT_TOKEN_AUDIENCE)
    assert claims["iss"] == AGENT_TOKEN_ISSUER

