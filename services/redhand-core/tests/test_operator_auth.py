"""
Operator authentication, role checks and tenant isolation for redhand-core (Phase 1, M2).

Each rule is tested for the allowed case and the denied cases: missing, malformed,
expired, wrongly signed and wrongly typed tokens; non-members; insufficient roles;
and cross-tenant access.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import jwt
import pytest

from redhand_core.auth.operator import OPERATOR_JWT_AUDIENCE, issue_operator_token
from redhand_core.main import create_app
from redhand_core.routers.state import filter_event_for_org
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter

from core_helpers import TEST_OPERATOR_SECRET, make_client, make_settings, operator_headers

OTHER_ORG_ID = "00000000-0000-0000-0000-0000000000f0"
OTHER_AGENT_ID = "00000000-0000-0000-0000-0000000000f1"
OTHER_INTERVENTION_ID = "00000000-0000-0000-0000-0000000000f2"
OTHER_OWNER_ID = "00000000-0000-0000-0000-0000000000f3"


def _store_with_second_tenant() -> LocalSupabaseAdapter:
    """Local store holding the default dev tenant plus a second, unrelated tenant."""
    store = LocalSupabaseAdapter()
    state = {"step": 1}
    checksum = hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    store.tables["organizations"].append({"id": OTHER_ORG_ID, "name": "Other Co", "slug": "other"})
    store.tables["organization_members"].append(
        {"id": str(uuid4()), "organization_id": OTHER_ORG_ID, "user_id": OTHER_OWNER_ID, "role": "owner"}
    )
    store.tables["agents"].append(
        {
            "id": OTHER_AGENT_ID,
            "organization_id": OTHER_ORG_ID,
            "external_agent_id": "other-agent",
            "name": "Other Agent",
            "status": "active",
            "allowed_tools": [],
        }
    )
    store.tables["hitl_interventions"].append(
        {
            "id": OTHER_INTERVENTION_ID,
            "organization_id": OTHER_ORG_ID,
            "agent_id": OTHER_AGENT_ID,
            "trace_id": "t",
            "span_id": "s",
            "status": "pending",
            "required_approvals": 1,
            "approvals": [],
            "serialized_agent_state": state,
            "state_checksum": checksum,
            "proposed_tool_arguments": {},
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }
    )
    return store


def _token(claims: dict[str, Any], key: str = TEST_OPERATOR_SECRET, algorithm: str = "HS256") -> str:
    return jwt.encode(claims, key, algorithm=algorithm)


def _valid_claims(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "sub": DEV_OPERATORS["owner"]["id"],
        "aud": OPERATOR_JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(overrides)
    return claims


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_valid_operator_token_is_accepted() -> None:
    client, settings = make_client()
    resp = client.get("/v1/state/snapshot", headers=operator_headers("viewer", settings))
    assert resp.status_code == 200
    assert resp.json()["organization_id"] == DEFAULT_ORG_ID


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": f"Bearer {_token(_valid_claims(), key='wrong-secret-0123456789abcdef0123456789')}"},
        {"Authorization": f"Bearer {_token(_valid_claims(exp=1_000_000_000))}"},
        {"Authorization": f"Bearer {_token(_valid_claims(aud='anon'))}"},
        {"Authorization": f"Bearer {_token({k: v for k, v in _valid_claims().items() if k != 'exp'})}"},
        {"Authorization": f"Bearer {_token(_valid_claims(), algorithm='HS384')}"},
        {"Authorization": f"Bearer {_token(_valid_claims(sub='not-a-uuid'))}"},
    ],
    ids=[
        "missing",
        "wrong-scheme",
        "malformed",
        "wrong-signature",
        "expired",
        "wrong-audience",
        "no-expiry",
        "disallowed-algorithm",
        "non-uuid-subject",
    ],
)
def test_invalid_operator_tokens_are_rejected(headers: dict[str, str]) -> None:
    client, _ = make_client()
    assert client.get("/v1/state/snapshot", headers=headers).status_code == 401


def test_unsigned_alg_none_token_is_rejected() -> None:
    client, _ = make_client()
    unsigned = jwt.encode(_valid_claims(), key="", algorithm="none")
    resp = client.get("/v1/state/snapshot", headers={"Authorization": f"Bearer {unsigned}"})
    assert resp.status_code == 401


def test_core_refuses_to_start_without_operator_auth_outside_development() -> None:
    """Missing operator auth is caught at startup, not as mysterious 401s later."""
    from pydantic import ValidationError

    from redhand_core.config import Settings

    for environment in ("staging", "production"):
        with pytest.raises(ValidationError, match="not configured"):
            Settings(ENVIRONMENT=environment)


def test_request_path_still_fails_closed_if_the_secret_is_missing() -> None:
    """Defense in depth: even if settings were mutated after startup, no token is accepted."""
    client, settings = make_client()
    settings.OPERATOR_JWT_SECRET = None
    headers = {"Authorization": f"Bearer {_token(_valid_claims())}"}
    assert client.get("/v1/state/snapshot", headers=headers).status_code == 401


def test_authenticated_non_member_is_forbidden() -> None:
    client, settings = make_client()
    headers = operator_headers(settings=settings, user_id=uuid4())
    assert client.get("/v1/state/snapshot", headers=headers).status_code == 403


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


def test_viewer_cannot_freeze_agent_but_operator_can() -> None:
    store = LocalSupabaseAdapter()
    client, settings = make_client(store)
    agent_id = store.tables["agents"][0]["id"]
    url = f"/v1/passports/{agent_id}/freeze"

    assert client.post(url, json={}, headers=operator_headers("viewer", settings)).status_code == 403
    assert client.post(url, json={}, headers=operator_headers("operator", settings)).status_code == 200


def test_viewer_cannot_resolve_hitl() -> None:
    store = LocalSupabaseAdapter()
    client, settings = make_client(store)
    intervention_id = store.tables["hitl_interventions"][0]["id"]
    resp = client.post(
        f"/v1/hitl/{intervention_id}/resolve",
        json={"action": "approve"},
        headers=operator_headers("viewer", settings),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_snapshot_only_returns_own_tenant_data() -> None:
    client, settings = make_client(_store_with_second_tenant())
    snapshot = client.get("/v1/state/snapshot", headers=operator_headers("owner", settings)).json()
    for key in ("agents", "hitl_interventions"):
        assert snapshot[key], key
        assert {row["organization_id"] for row in snapshot[key]} == {DEFAULT_ORG_ID}


def test_cannot_freeze_another_tenants_agent() -> None:
    store = _store_with_second_tenant()
    client, settings = make_client(store)
    resp = client.post(
        f"/v1/passports/{OTHER_AGENT_ID}/freeze", json={}, headers=operator_headers("owner", settings)
    )
    assert resp.status_code == 404
    other = next(a for a in store.tables["agents"] if a["id"] == OTHER_AGENT_ID)
    assert other["status"] == "active"


def test_cannot_resolve_another_tenants_intervention() -> None:
    store = _store_with_second_tenant()
    client, settings = make_client(store)
    resp = client.post(
        f"/v1/hitl/{OTHER_INTERVENTION_ID}/resolve",
        json={"action": "approve"},
        headers=operator_headers("owner", settings),
    )
    assert resp.status_code == 404
    other = next(i for i in store.tables["hitl_interventions"] if i["id"] == OTHER_INTERVENTION_ID)
    assert other["status"] == "pending"


def test_org_header_cannot_select_a_tenant_the_user_is_not_in() -> None:
    client, settings = make_client(_store_with_second_tenant())
    headers = operator_headers("owner", settings, org=OTHER_ORG_ID)
    assert client.get("/v1/state/snapshot", headers=headers).status_code == 403


def test_multi_org_user_must_choose_org() -> None:
    store = _store_with_second_tenant()
    store.tables["organization_members"].append(
        {"id": str(uuid4()), "organization_id": OTHER_ORG_ID, "user_id": DEV_OPERATORS["owner"]["id"], "role": "viewer"}
    )
    client, settings = make_client(store)
    assert client.get("/v1/state/snapshot", headers=operator_headers("owner", settings)).status_code == 400
    chosen = client.get(
        "/v1/state/snapshot", headers=operator_headers("owner", settings, org=OTHER_ORG_ID)
    )
    assert chosen.status_code == 200
    assert chosen.json()["organization_id"] == OTHER_ORG_ID


# ---------------------------------------------------------------------------
# HITL reviewer identity (four-eyes)
# ---------------------------------------------------------------------------


def test_reviewer_identity_cannot_be_supplied_in_body() -> None:
    store = LocalSupabaseAdapter()
    client, settings = make_client(store)
    intervention_id = store.tables["hitl_interventions"][0]["id"]
    resp = client.post(
        f"/v1/hitl/{intervention_id}/resolve",
        json={"action": "approve", "reviewer_user_id": str(uuid4())},
        headers=operator_headers("operator", settings),
    )
    assert resp.status_code == 422


def test_four_eyes_requires_two_distinct_authenticated_operators(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_webhook(**_: Any) -> None:
        return None

    monkeypatch.setattr("redhand_core.routers.hitl.trigger_agent_resume_webhook", _no_webhook)
    store = LocalSupabaseAdapter()
    client, settings = make_client(store)
    intervention = store.tables["hitl_interventions"][0]
    url = f"/v1/hitl/{intervention['id']}/resolve"

    first = client.post(url, json={"action": "approve"}, headers=operator_headers("operator", settings))
    assert first.json()["status"] == "partially_approved"

    # The same operator presenting a fresh token is still the same person.
    again = client.post(url, json={"action": "approve"}, headers=operator_headers("operator", settings))
    assert again.status_code == 400

    second = client.post(url, json={"action": "approve"}, headers=operator_headers("operator2", settings))
    assert second.json()["status"] == "approved"
    reviewers = [a["reviewer_user_id"] for a in intervention["approvals"]]
    assert reviewers == [DEV_OPERATORS["operator"]["id"], DEV_OPERATORS["operator2"]["id"]]


# ---------------------------------------------------------------------------
# Development login
# ---------------------------------------------------------------------------


def _dev_login_status(settings: Any) -> int:
    return TestClient(create_app(settings)).post("/v1/dev/login", json={"user": "owner"}).status_code


def test_dev_login_only_exists_in_development_with_local_store() -> None:
    assert _dev_login_status(make_settings(ENVIRONMENT="development")) == 200
    for env in ("test", "staging", "production"):
        assert _dev_login_status(make_settings(ENVIRONMENT=env)) == 404, env
    real_supabase = make_settings(
        ENVIRONMENT="development", SUPABASE_URL="https://real-project.supabase.co"
    )
    assert _dev_login_status(real_supabase) == 404


def test_dev_login_token_authenticates() -> None:
    settings = make_settings(ENVIRONMENT="development")
    app = create_app(settings)
    from redhand_core.config import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    client = TestClient(app)
    login = client.post("/v1/dev/login", json={"user": "viewer"}).json()
    resp = client.get("/v1/state/snapshot", headers={"Authorization": f"Bearer {login['access_token']}"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Real-time stream
# ---------------------------------------------------------------------------


def test_stream_requires_valid_single_use_ticket() -> None:
    client, settings = make_client()
    assert client.get("/v1/state/stream").status_code == 422
    assert client.get("/v1/state/stream", params={"ticket": "forged"}).status_code == 401
    assert client.post("/v1/state/stream-ticket").status_code == 401

    from redhand_core.routers.state import _redeem_stream_ticket, _stream_tickets

    ticket = client.post(
        "/v1/state/stream-ticket", headers=operator_headers("viewer", settings)
    ).json()["ticket"]
    assert _redeem_stream_ticket(ticket) == DEFAULT_ORG_ID
    assert ticket not in _stream_tickets  # single use


def test_stream_events_are_filtered_by_tenant() -> None:
    message = {
        "event": "agents.updated",
        "data": [
            {"id": "a", "organization_id": DEFAULT_ORG_ID},
            {"id": "b", "organization_id": OTHER_ORG_ID},
        ],
    }
    scoped = filter_event_for_org(message, DEFAULT_ORG_ID)
    assert scoped is not None and [r["id"] for r in scoped["data"]] == ["a"]
    assert filter_event_for_org({"event": "x", "data": [{"organization_id": OTHER_ORG_ID}]}, DEFAULT_ORG_ID) is None
    assert filter_event_for_org({"event": "x", "data": {"no_org": True}}, DEFAULT_ORG_ID) is None


def test_issued_operator_token_round_trips() -> None:
    settings = make_settings()
    uid = UUID(DEV_OPERATORS["admin"]["id"])
    token = issue_operator_token(user_id=uid, email="a@b.c", settings=settings)
    claims = jwt.decode(token, TEST_OPERATOR_SECRET, algorithms=["HS256"], audience=OPERATOR_JWT_AUDIENCE)
    assert claims["sub"] == str(uid)
