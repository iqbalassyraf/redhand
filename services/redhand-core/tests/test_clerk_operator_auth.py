"""
Operator sign-in through Clerk (ADR 0032, slice C2). A fake Clerk JWKS (httpx MockTransport) and a generated RSA key stand in for the Clerk
instance. Covers the allowed path, every refusal of the token contract (algorithm, issuer, audience, expiry, verified e-mail), the mapping to
RedHand's own operator id (created on first use, never matched by e-mail), tenant isolation, the switch back to Supabase, and fail-closed paths.
"""

from __future__ import annotations

import json
import time
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt
from pydantic import ValidationError
import pytest

from redhand_core.auth import operator as operator_module
from redhand_core.config import Settings
from redhand_core.services import local_rpc
from redhand_core.services.local_store import DEFAULT_ORG_ID

from core_helpers import make_client, make_settings

ISSUER = "https://clean-heron-12.clerk.accounts.dev"
JWKS = f"{ISSUER}/.well-known/jwks.json"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def jwk(private: Any, kid: str, alg: str = "RS256") -> dict[str, Any]:
    if alg == "ES256":
        data = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
    else:
        data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    data.update({"kid": kid, "alg": alg, "use": "sig"})
    return data


class FakeClerk:
    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json={"keys": self.keys})


def token(key: Any = KEY, *, kid: str = "ins_1", alg: str = "RS256", **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {"sub": "user_2alice", "iss": ISSUER, "aud": "redhand-core", "iat": now, "nbf": now - 5, "exp": now + 300,
                              "email": "alice@example.com", "email_verified": True}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


@pytest.fixture(autouse=True)
def _clear() -> Any:
    operator_module._clerk_verifiers.clear()
    yield
    operator_module._clerk_verifiers.clear()


class Env:
    def __init__(self, keys: list[dict[str, Any]] | None = None) -> None:
        self.client, self.settings = make_client(OPERATOR_AUTH_PROVIDER="clerk", CLERK_ISSUER=ISSUER, OPERATOR_JWT_SECRET=None)
        self.fake = FakeClerk(keys if keys is not None else [jwk(KEY, "ins_1")])
        # The verifier is built by the code under test (so its algorithm and audience settings are the real ones); only its network is faked.
        verifier = operator_module._clerk_verifier(self.settings)
        verifier._http = httpx.AsyncClient(transport=httpx.MockTransport(self.fake.handler))

    def me(self, tok: str) -> httpx.Response:
        return self.client.get("/v1/me", headers={"Authorization": f"Bearer {tok}"})

    def create_org(self, tok: str) -> httpx.Response:
        return self.client.post("/v1/organizations", json={"name": "Clerk Org", "code": "rh_inv_" + "z" * 30}, headers={"Authorization": f"Bearer {tok}"})


def test_settings_require_an_issuer_and_https_and_drop_the_supabase_modes() -> None:
    with pytest.raises(ValidationError, match="CLERK_ISSUER"):
        Settings(ENVIRONMENT="staging", SUPABASE_URL="https://x.supabase.co", SUPABASE_SERVICE_ROLE_KEY="k", OPERATOR_AUTH_PROVIDER="clerk")
    with pytest.raises(ValidationError, match="https"):
        Settings(ENVIRONMENT="staging", SUPABASE_URL="https://x.supabase.co", SUPABASE_SERVICE_ROLE_KEY="k", OPERATOR_AUTH_PROVIDER="clerk", CLERK_ISSUER="http://clerk.example.com")
    s = make_settings(OPERATOR_AUTH_PROVIDER="clerk", CLERK_ISSUER=ISSUER + "/")
    assert s.CLERK_JWKS_URL == JWKS and s.OPERATOR_JWT_SECRET is None and s.OPERATOR_JWKS_URL is None


def test_a_valid_clerk_token_without_a_membership_reaches_the_onboarding_routes_only() -> None:
    env = Env()
    tok = token()
    assert env.me(tok).status_code == 403  # signed in, but in no organization yet
    resp = env.create_org(tok)
    assert resp.status_code != 401, resp.text  # the sign-up route accepted the identity (the code itself is checked there)


def test_the_same_clerk_user_maps_to_one_operator_and_another_claiming_the_same_email_does_not() -> None:
    env = Env()
    first = local_rpc._operator_resolve(_store(env), {"p_provider": "clerk", "p_subject": "user_2alice", "p_email": "alice@example.com"})
    again = local_rpc._operator_resolve(_store(env), {"p_provider": "clerk", "p_subject": "user_2alice", "p_email": "alice@example.com"})
    other = local_rpc._operator_resolve(_store(env), {"p_provider": "clerk", "p_subject": "user_2mallory", "p_email": "alice@example.com"})
    assert first == again and other != first


def _store(env: Env) -> Any:
    from redhand_core.routers.telemetry import get_supabase_service_client

    return env.client.app.dependency_overrides[get_supabase_service_client]()


def test_a_member_signed_in_through_clerk_acts_in_their_own_organization_only() -> None:
    env = Env()
    store = _store(env)
    operator_id = local_rpc._operator_resolve(store, {"p_provider": "clerk", "p_subject": "user_2alice", "p_email": "alice@example.com"})
    store.tables["organization_members"].append({"id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "user_id": operator_id, "role": "viewer"})
    resp = env.me(token())
    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == operator_id and resp.json()["organization_id"] == DEFAULT_ORG_ID and resp.json()["role"] == "viewer"
    forged = env.client.get("/v1/me", headers={"Authorization": f"Bearer {token()}", "X-RedHand-Org": str(uuid4())})
    assert forged.status_code == 403
    # A different Clerk user with the same e-mail is a different person: no membership.
    assert env.me(token(sub="user_2mallory")).status_code == 403


@pytest.mark.parametrize(
    ("label", "make"),
    [
        ("wrong audience", lambda: token(aud="authenticated")),
        ("no audience", lambda: token(aud=None)),
        ("wrong issuer", lambda: token(iss="https://evil.clerk.accounts.dev")),
        ("expired", lambda: token(exp=int(time.time()) - 120, iat=int(time.time()) - 900)),
        ("not yet valid", lambda: token(nbf=int(time.time()) + 600)),
        ("signed by another key", lambda: token(OTHER_KEY)),
        ("unknown key id", lambda: token(kid="ins_unknown")),
        ("e-mail not verified", lambda: token(email_verified=False)),
        ("e-mail verified as a string", lambda: token(email_verified="true")),
        ("no e-mail", lambda: token(email=None)),
        ("no subject", lambda: token(sub=None)),
        ("subject too long", lambda: token(sub="u" * 256)),
        ("HS256 with the issuer's name", lambda: jwt.encode({"sub": "user_2alice", "iss": ISSUER, "aud": "redhand-core", "exp": int(time.time()) + 300, "iat": int(time.time()),
                                                            "email": "a@example.com", "email_verified": True}, "secret-of-32-bytes-or-more-padding!!", algorithm="HS256", headers={"kid": "ins_1"})),
        ("alg none", lambda: jwt.encode({"sub": "user_2alice", "iss": ISSUER, "aud": "redhand-core"}, None, algorithm="none", headers={"kid": "ins_1"})),
    ],
)
def test_every_broken_token_is_refused_with_401(label: str, make: Any) -> None:
    env = Env()
    resp = env.me(make())
    assert resp.status_code == 401, f"{label}: {resp.status_code} {resp.text}"
    assert not _store(env).tables.get("operators"), f"{label}: an operator was created for a refused token"


def test_es256_is_refused_in_clerk_mode_even_with_a_published_key() -> None:
    env = Env(keys=[jwk(EC_KEY, "ins_ec", "ES256")])
    assert env.me(token(EC_KEY, kid="ins_ec", alg="ES256")).status_code == 401


def test_a_supabase_token_is_refused_in_clerk_mode() -> None:
    from redhand_core.auth.operator import issue_operator_token

    env = Env()
    supabase_style = issue_operator_token(user_id=uuid4(), email="x@example.com", settings=make_settings())
    assert env.me(supabase_style).status_code == 401


def test_clerk_keys_unreachable_means_refused() -> None:
    env = Env()
    env.fake.down = True
    assert env.me(token()).status_code == 401


def test_a_database_failure_while_resolving_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Env()

    def broken(*_: Any) -> Any:
        raise local_rpc._error("XX000", "internal")

    monkeypatch.setitem(local_rpc.HANDLERS, "operator_resolve", broken)
    resp = env.me(token())
    assert resp.status_code == 503 and "internal" not in resp.text


def test_supabase_mode_is_unchanged_and_ignores_clerk_tokens() -> None:
    from uuid import UUID

    from redhand_core.auth.operator import issue_operator_token
    from redhand_core.services.local_store import DEV_OPERATORS

    client, settings = make_client()
    ok = issue_operator_token(user_id=UUID(DEV_OPERATORS["owner"]["id"]), email="o@example.com", settings=settings)
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {ok}"}).status_code == 200
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {token()}"}).status_code == 401
