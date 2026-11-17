"""
The route sweep (release-readiness 3.2 and 3.3, CLAUDE.md 5.3): every core route is authenticated unless it is on a short, reasoned allowlist, checks the
caller's role, and never lets one organization reach another's data. It is generated from the live route table, so a route added tomorrow is covered
(or the test fails and says what to add).

Four sweeps, each over every route:
  1. classification: each route has exactly one recognised kind of authentication, or an entry in PUBLIC with the reason it needs none;
  2. no or bad credentials: refused with 401/403 (and 503 where a feature is not configured), nothing executed, nothing changed;
  3. wrong role: every dev operator below a route's minimum role is refused with 403, nothing changed; the minimum itself gets past authorization;
  4. other tenant: an organization A owner calls every route that takes an id with organization B's ids: never a 2xx, nothing of B in the answer,
     nothing in the store changed.
Refusals are asserted on the response and on a deep copy of the whole store taken before the call.
"""

from __future__ import annotations

import copy
import inspect
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.routing import APIRoute
from pydantic import SecretStr

from redhand_core.auth.operator import OPERATOR_JWT_AUDIENCE, Role, get_authenticated_user, get_operator, issue_operator_token
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.scim import require_scim_token
from redhand_core.routers.telemetry import verify_sdk_api_key
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter, apply_insert_defaults

from core_helpers import TEST_OPERATOR_SECRET, make_client

INTERNAL = "sweep-internal-service-token-0123456789abcdef"
SCIM = "sweep-scim-bearer-token-0123456789abcdef"
OTHER_ORG = "00000000-0000-0000-0000-0000000000b0"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000b1"
OTHER_MARK = "ZZ-OTHER-TENANT-MARK"  # appears in every row of organization B: it must never be in an answer to organization A

Method = str


@dataclass(frozen=True)
class Route:
    method: Method
    path: str
    dependant: Any

    @property
    def key(self) -> tuple[Method, str]:
        return (self.method, self.path)


# --- the route table -------------------------------------------------------------------------------------------------------------------

def iter_routes(routes: Any) -> Iterator[Route]:
    """Every route, including those FastAPI keeps inside lazily included routers."""
    for route in routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield Route(method, route.path, route.dependant)
        elif hasattr(route, "effective_route_contexts"):
            for ctx in route.effective_route_contexts():
                for method in sorted(set(ctx.methods) - {"HEAD", "OPTIONS"}):
                    yield Route(method, ctx.path, ctx.dependant)


def calls_in(dependant: Any) -> list[Callable[..., Any]]:
    found: list[Callable[..., Any]] = []
    for sub in dependant.dependencies:
        if sub.call is not None:
            found.append(sub.call)
        found.extend(calls_in(sub))
    return found


def minimum_role(call: Callable[..., Any]) -> Role | None:
    """The `minimum` that `require_role` closed over, for the dependency it returned."""
    if call.__qualname__.endswith("require_role.<locals>._check"):
        value = inspect.getclosurevars(call).nonlocals.get("minimum")
        return value if isinstance(value, Role) else None
    return None


@dataclass(frozen=True)
class Auth:
    kind: str  # operator | user (a verified token, no organization yet) | internal | scim | sdk_key | public
    role: Role | None = None


def classify(route: Route) -> Auth:
    calls = calls_in(route.dependant)
    roles = [r for r in (minimum_role(c) for c in calls) if r is not None]
    kinds = {
        "operator": get_operator in calls,
        "user": get_authenticated_user in calls,
        "internal": require_internal_service in calls,
        "scim": require_scim_token in calls,
        "sdk_key": verify_sdk_api_key in calls,
    }
    present = [k for k, on in kinds.items() if on]
    if len(present) > 1:
        raise AssertionError(f"{route.key} mixes authentication kinds: {present}")
    if not present:
        return Auth("public")
    return Auth(present[0], max(roles) if roles else None)


# Routes that need no operator, service or SDK credential, and why. Each has its own check in `test_public_routes_still_refuse_what_they_must`.
PUBLIC: dict[tuple[Method, str], str] = {
    ("GET", "/health"): "liveness probe, returns no data",
    ("GET", "/healthz"): "liveness probe, returns no data",
    ("POST", "/v1/dev/login"): "development sign-in; not mounted outside development and test (test_dev_login_is_not_mounted_in_shared_environments)",
    ("POST", "/v1/hitl/slack/interactivity"): "Slack calls it; the request signature is verified in the handler",
    ("GET", "/v1/state/stream"): "browser EventSource cannot send headers; needs a single-use 60 s ticket issued to an authenticated viewer",
    ("POST", "/v1/telegram/webhook"): "Telegram calls it; the secret header is verified in the handler",
    ("GET", "/v1/agent-auth/jwks"): "public keys for verifying agent tokens, by design",
    ("POST", "/v1/agent-auth/token"): "agent key exchange: the key itself is the credential, checked in the handler",
}

# Operator routes with no role dependency because the role depends on the request body (checked in the handler).
BODY_DEPENDENT_ROLE: dict[tuple[Method, str], str] = {
    ("POST", "/v1/organization/safe-mode"): "on: security operator, off: admin",
    ("POST", "/v1/passports/{agent_id}/safe-mode"): "on: security operator, off: admin",
}

# The reviewed role matrix: the lowest role allowed on each operator route. It is written out here, not read from the code, so that loosening a role
# (or adding a route with the wrong one) is a visible change in review and fails this test until the matrix is edited on purpose.
EXPECTED_MINIMUM_ROLE: dict[str, list[tuple[Method, str]]] = {
    "VIEWER": [
        ("GET", "/v1/audit/control"),
        ("GET", "/v1/blackbox/events"),
        ("GET", "/v1/blackbox/settings"),
        ("GET", "/v1/blackbox/verify"),
        ("GET", "/v1/mcp-servers"),
        ("GET", "/v1/organization/approved-models"),
        ("GET", "/v1/organization/budget-default"),
        ("GET", "/v1/organization/safe-mode"),
        ("GET", "/v1/organization/sdk-keys"),
        ("GET", "/v1/passports"),
        ("GET", "/v1/passports/{agent_id}"),
        ("GET", "/v1/spend/agents"),
        ("GET", "/v1/spend/agents/{agent_id}"),
        ("GET", "/v1/state/snapshot"),
        ("GET", "/v1/usage"),
        ("POST", "/v1/state/stream-ticket"),
    ],
    "SECURITY_OPERATOR": [
        ("GET", "/v1/agents/{agent_id}/timeline"),
        ("GET", "/v1/agents/{agent_id}/timeline/export"),
        ("GET", "/v1/blackbox/export"),
        ("GET", "/v1/findings"),
        ("GET", "/v1/honey-tools"),
        ("GET", "/v1/honeytokens"),
        ("GET", "/v1/mcp-servers/{server_id}/tool-pins"),
        ("GET", "/v1/passports/{agent_id}/destinations"),
        ("GET", "/v1/radar/loop-settings"),
        ("GET", "/v1/radar/readiness"),
        ("GET", "/v1/radar/settings"),
        ("GET", "/v1/radar/suppressions"),
        ("GET", "/v1/risk/agents"),
        ("GET", "/v1/risk/agents/{agent_id}"),
        ("GET", "/v1/risk/behaviour/summary"),
        ("GET", "/v1/risk/ladder"),
        ("POST", "/v1/findings/{finding_id}/review"),
        ("POST", "/v1/hitl/{intervention_id}/resolve"),
        ("POST", "/v1/passports/{agent_id}/freeze"),
        ("POST", "/v1/passports/{agent_id}/unfreeze"),
        ("POST", "/v1/radar/self-test"),
        ("PUT", "/v1/blackbox/payload-capture"),
        ("PUT", "/v1/passports/{agent_id}/budget"),
    ],
    "OWNER": [
        ("GET", "/v1/organization/export"),
        ("GET", "/v1/organization/deletion"),
        ("POST", "/v1/organization/delete-request"),
        ("POST", "/v1/organization/delete-request/cancel"),
    ],
    "ADMIN": [
        ("POST", "/v1/passports"),
        ("POST", "/v1/passports/{agent_id}/rotate-key"),
        ("GET", "/v1/organization/invites"),
        ("POST", "/v1/organization/invites"),
        ("DELETE", "/v1/organization/invites/{invite_id}"),
        ("GET", "/v1/organization/members"),
        ("PUT", "/v1/organization/members/{user_id}"),
        ("DELETE", "/v1/organization/members/{user_id}"),
        ("DELETE", "/v1/organization/sdk-keys/{key_id}"),
        ("DELETE", "/v1/passports/{agent_id}/destinations/{entry_id}"),
        ("DELETE", "/v1/radar/suppressions/{suppression_id}"),
        ("GET", "/v1/blackbox/events/{seq}/payload"),
        ("GET", "/v1/telegram/links"),
        ("POST", "/v1/blackbox/payloads/clear"),
        ("POST", "/v1/honey-tools"),
        ("POST", "/v1/honey-tools/{honey_tool_id}/retire"),
        ("POST", "/v1/honeytokens"),
        ("POST", "/v1/honeytokens/{honeytoken_id}/retire"),
        ("POST", "/v1/mcp-servers"),
        ("POST", "/v1/mcp-servers/{server_id}/deactivate"),
        ("POST", "/v1/mcp-servers/{server_id}/scan"),
        ("POST", "/v1/mcp-servers/{server_id}/tool-pins/approve-all"),
        ("POST", "/v1/organization/sdk-keys"),
        ("POST", "/v1/passports/freeze-all"),
        ("POST", "/v1/passports/{agent_id}/destinations"),
        ("POST", "/v1/passports/{agent_id}/promote"),
        ("POST", "/v1/passports/{agent_id}/renew"),
        ("POST", "/v1/passports/{agent_id}/revoke"),
        ("POST", "/v1/radar/suppressions"),
        ("POST", "/v1/telegram/link-code"),
        ("POST", "/v1/telegram/links/{link_id}/unlink"),
        ("POST", "/v1/tool-pins/{pin_id}/decision"),
        ("PUT", "/v1/blackbox/retention"),
        ("PUT", "/v1/mcp-servers/{server_id}/pin-mode"),
        ("PUT", "/v1/organization/approved-models"),
        ("PUT", "/v1/organization/budget-default"),
        ("PUT", "/v1/passports/{agent_id}/destination-mode"),
        ("PUT", "/v1/passports/{agent_id}/scopes"),
        ("PUT", "/v1/passports/{agent_id}/spend-limit"),
        ("PUT", "/v1/radar/loop-settings"),
        ("PUT", "/v1/radar/settings"),
        ("PUT", "/v1/risk/ladder"),
    ],
}

# SCIM is deployment-level and in-memory (documented in scim.py): not tenant-scoped, off unless a bearer token is configured.
DEPLOYMENT_LEVEL = {"scim"}


SWEEP_SETTINGS: dict[str, Any] = {"ENVIRONMENT": "development", "INTERNAL_SERVICE_TOKEN": SecretStr(INTERNAL), "SCIM_BEARER_TOKEN": SecretStr(SCIM)}
# "development" is the one environment that also mounts the dev sign-in route, so the sweep sees the largest route table.
app = make_client(LocalSupabaseAdapter(), **SWEEP_SETTINGS)[0].app
ROUTES = sorted(iter_routes(app.routes), key=lambda r: r.key)
AUTH = {r.key: classify(r) for r in ROUTES}


def ids(routes: list[Route]) -> list[str]:
    return [f"{r.method} {r.path}" for r in routes]


# --- a fresh world per test ------------------------------------------------------------------------------------------------------------

class World:
    def __init__(self) -> None:
        self.store = LocalSupabaseAdapter()
        self.client, self.settings = make_client(self.store, **SWEEP_SETTINGS)
        other_org: dict[str, Any] = {"id": OTHER_ORG, "name": OTHER_MARK, "slug": "other-org", "safe_mode": False}
        apply_insert_defaults("organizations", other_org)
        self.store.tables["organizations"].append(other_org)
        self.store.tables["organization_members"].append({"id": str(uuid4()), "organization_id": OTHER_ORG, "user_id": OTHER_OWNER, "role": "owner"})
        self.theirs = self._seed_other_tenant()

    def _seed_other_tenant(self) -> dict[str, str]:
        t = self.store.tables
        now = datetime.now(timezone.utc).isoformat()
        ident = {name: str(uuid4()) for name in (
            "agent_id", "entry_id", "finding_id", "honey_tool_id", "honeytoken_id", "intervention_id", "key_id", "link_id", "pin_id",
            "server_id", "suppression_id", "invite_id")}
        ident["user_id"] = OTHER_OWNER  # organization B's member: the members routes take a user id
        ident["seq"] = "987654"
        org = {"organization_id": OTHER_ORG}
        agent: dict[str, Any] = {
            **org, "id": ident["agent_id"], "external_agent_id": OTHER_MARK, "name": OTHER_MARK, "framework": "n8n", "environment": "production",
            "scopes": [], "status": "active", "owner_id": OTHER_OWNER, "expires_at": "2099-01-01T00:00:00+00:00", "version": 1, "created_at": now,
            "safe_mode": False, "reported_only": False}
        apply_insert_defaults("agents", agent)
        t.setdefault("agents", []).append(agent)
        t.setdefault("agent_destinations", []).append({**org, "id": ident["entry_id"], "agent_id": ident["agent_id"], "host": f"{OTHER_MARK}.example.com"})
        t.setdefault("security_findings", []).append({
            **org, "id": ident["finding_id"], "agent_id": ident["agent_id"], "rule_id": "RAD-INJ-001", "kind": "injection", "family": "override",
            "severity": "high", "confidence": "high", "place": "text", "tool_name": OTHER_MARK, "server_slug": OTHER_MARK, "status": "open",
            "evasion": [], "would_block": False, "review_status": "open", "occurrences": 1, "window_start": now, "detail": None, "first_seen_at": now, "last_seen_at": now})
        t.setdefault("honey_tools", []).append({**org, "id": ident["honey_tool_id"], "name": OTHER_MARK, "description": OTHER_MARK, "server_slug": "x", "server": "x", "status": "active",
            "agent_id": ident["agent_id"], "action": "alert", "created_at": now, "last_tripped_at": None, "trip_count": 0})
        t.setdefault("honeytokens", []).append({**org, "id": ident["honeytoken_id"], "label": OTHER_MARK, "kind": "api_key", "status": "active", "digest": "d" * 64,
            "hint": "zz", "action_on_use": "alert", "action_on_read": "alert", "created_at": now, "last_tripped_at": None, "trip_count": 0})
        t.setdefault("hitl_interventions", []).append({
            **org, "id": ident["intervention_id"], "agent_id": ident["agent_id"], "status": "pending", "tool_name": OTHER_MARK, "created_at": now})
        t.setdefault("sdk_api_keys", []).append({
            **org, "id": ident["key_id"], "name": OTHER_MARK, "key_prefix": "rh_live_zzzz", "key_hash": "e" * 64, "is_active": True,
            "expires_at": "2099-01-01T00:00:00+00:00", "created_at": now, "organizations": {"siem_webhook_url": None}})
        t.setdefault("telegram_links", []).append({**org, "id": ident["link_id"], "user_id": OTHER_OWNER, "chat_id": 777001, "revoked_at": None, "created_at": now})
        t.setdefault("mcp_tool_pins", []).append({**org, "id": ident["pin_id"], "server_id": ident["server_id"], "tool_name": OTHER_MARK, "digest": "f" * 64, "status": "approved"})
        t.setdefault("mcp_servers", []).append({**org, "id": ident["server_id"], "slug": "other-server", "name": OTHER_MARK, "url": "https://other.example.com/mcp", "is_active": True, "pin_mode": "off"})
        t.setdefault("radar_suppressions", []).append({**org, "id": ident["suppression_id"], "agent_id": ident["agent_id"], "rule_id": "RAD-INJ-001", "revoked_at": None, "created_at": now,
            "expires_at": "2099-01-01T00:00:00+00:00", "reason": OTHER_MARK, "created_by": OTHER_OWNER})
        t.setdefault("member_invites", []).append({
            **org, "id": ident["invite_id"], "role": "viewer", "token_hash": "a" * 64, "created_by": OTHER_OWNER, "created_at": now,
            "expires_at": "2099-01-01T00:00:00+00:00", "used_at": None, "used_by": None, "revoked_at": None})
        t.setdefault("agent_events", []).append({
            **org, "agent_id": ident["agent_id"], "seq": int(ident["seq"]), "occurred_at": now, "server": OTHER_MARK, "tool_name": OTHER_MARK, "decision": "BLOCK", "method": "tools/call", "reasons": [OTHER_MARK]})
        return ident

    def token(self, user: str | None = None, *, user_id: str | None = None, org: str | None = None) -> dict[str, str]:
        uid = UUID(user_id) if user_id else UUID(DEV_OPERATORS[user or "owner"]["id"])
        headers = {"Authorization": f"Bearer {issue_operator_token(user_id=uid, email=None, settings=self.settings)}"}
        if org:
            headers["X-RedHand-Org"] = org
        return headers

    def snapshot(self) -> Any:
        return copy.deepcopy(self.store.tables)

    def send(self, route: Route, headers: dict[str, str] | None = None, params: dict[str, str] | None = None, body: Any = None) -> Any:
        path = route.path
        for name in _path_names(route.path):
            path = path.replace("{" + name + "}", (params or {}).get(name, "1" if name == "seq" else str(uuid4())))
        return self.client.request(route.method, path, headers=headers or {}, json=body if body is not None else ({} if route.method != "GET" else None))


def _path_names(path: str) -> list[str]:
    return [seg[1:-1] for seg in path.split("/") if seg.startswith("{") and seg.endswith("}")]


@pytest.fixture
def world() -> World:
    return World()


def refused(status_code: int) -> bool:
    return status_code in (401, 403, 503)


# --- 1. classification ----------------------------------------------------------------------------------------------------------------

def test_the_sweep_sees_every_route() -> None:
    declared = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops if m in {"get", "post", "put", "patch", "delete"}}
    swept = {r.key for r in ROUTES}
    assert declared <= swept, f"routes the sweep cannot see: {sorted(declared - swept)}"
    assert len(swept) >= 90, "the route table looks truncated"


def test_every_route_has_a_known_authentication_or_a_reasoned_public_entry() -> None:
    public_found = {key for key, auth in AUTH.items() if auth.kind == "public"}
    assert public_found == set(PUBLIC), f"unauthenticated routes not on the allowlist: {sorted(public_found - set(PUBLIC))}; stale entries: {sorted(set(PUBLIC) - public_found)}"
    assert all(reason.strip() for reason in PUBLIC.values())


def test_every_operator_route_has_exactly_the_reviewed_minimum_role() -> None:
    expected = {tuple(route): Role[name] for name, routes in EXPECTED_MINIMUM_ROLE.items() for route in routes}
    actual = {key: auth.role for key, auth in AUTH.items() if auth.kind == "operator" and auth.role is not None}
    assert actual == expected, (
        f"changed or new role requirements: {sorted((k, actual.get(k), expected.get(k)) for k in set(actual) | set(expected) if actual.get(k) != expected.get(k))}"
    )


def test_every_operator_route_names_its_role_or_says_why_not() -> None:
    no_role = {key for key, auth in AUTH.items() if auth.kind == "operator" and auth.role is None}
    assert no_role == set(BODY_DEPENDENT_ROLE), f"operator routes with no role check: {sorted(no_role - set(BODY_DEPENDENT_ROLE))}; stale: {sorted(set(BODY_DEPENDENT_ROLE) - no_role)}"


def test_the_sweep_is_not_vacuous() -> None:
    kinds = {auth.kind for auth in AUTH.values()}
    assert {"operator", "user", "internal", "scim", "sdk_key", "public"} <= kinds
    assert {auth.role for auth in AUTH.values() if auth.kind == "operator"} >= {Role.VIEWER, Role.SECURITY_OPERATOR, Role.ADMIN}


def test_dev_login_is_not_mounted_in_shared_environments() -> None:
    for environment in ("staging", "production"):
        paths = {r.path for r in iter_routes(make_client(LocalSupabaseAdapter(), ENVIRONMENT=environment)[0].app.routes)}
        assert "/v1/dev/login" not in paths, environment


# --- 2. no or bad credentials ---------------------------------------------------------------------------------------------------------

def bad_operator_headers(world: World) -> dict[str, dict[str, str]]:
    now = datetime.now(timezone.utc)
    uid = DEV_OPERATORS["owner"]["id"]
    good = {"sub": uid, "aud": OPERATOR_JWT_AUDIENCE, "role": "authenticated", "iat": int(now.timestamp()), "exp": int((now + timedelta(hours=1)).timestamp())}
    expired = {**good, "iat": int((now - timedelta(hours=3)).timestamp()), "exp": int((now - timedelta(hours=2)).timestamp())}
    return {
        "no header": {},
        "not a bearer": {"Authorization": "Basic abc"},
        "garbage": {"Authorization": "Bearer not.a.jwt"},
        "expired": {"Authorization": "Bearer " + jwt.encode(expired, TEST_OPERATOR_SECRET, algorithm="HS256")},
        "wrong secret": {"Authorization": "Bearer " + jwt.encode(good, "x" * 48, algorithm="HS256")},
        "alg none": {"Authorization": "Bearer " + jwt.encode(good, None, algorithm="none")},
        "wrong audience": {"Authorization": "Bearer " + jwt.encode({**good, "aud": "someone-else"}, TEST_OPERATOR_SECRET, algorithm="HS256")},
        "no subject": {"Authorization": "Bearer " + jwt.encode({k: v for k, v in good.items() if k != "sub"}, TEST_OPERATOR_SECRET, algorithm="HS256")},
        "unknown user": world.token(user_id="00000000-0000-0000-0000-00000000dead"),
        "other org's header": world.token("owner", org=OTHER_ORG),
        "delegated headers only": {"X-User-ID": uid, "X-User-Roles": "owner", "X-RedHand-Org": DEFAULT_ORG_ID},
    }


OPERATOR_ROUTES = [r for r in ROUTES if AUTH[r.key].kind == "operator"]
USER_ROUTES = [r for r in ROUTES if AUTH[r.key].kind == "user"]
INTERNAL_ROUTES = [r for r in ROUTES if AUTH[r.key].kind == "internal"]
SCIM_ROUTES = [r for r in ROUTES if AUTH[r.key].kind == "scim"]
SDK_ROUTES = [r for r in ROUTES if AUTH[r.key].kind == "sdk_key"]


@pytest.mark.parametrize("route", OPERATOR_ROUTES, ids=ids(OPERATOR_ROUTES))
def test_operator_routes_refuse_missing_and_bad_credentials(world: World, route: Route) -> None:
    before = world.snapshot()
    for label, headers in bad_operator_headers(world).items():
        response = world.send(route, headers=headers)
        assert refused(response.status_code), f"{route.key} answered {response.status_code} to: {label}"
        assert response.status_code != 503 or label == "never", label
        assert OTHER_MARK not in response.text
    assert world.snapshot() == before, f"{route.key} changed the store for a caller with no valid credentials"


@pytest.mark.parametrize("route", USER_ROUTES, ids=ids(USER_ROUTES))
def test_routes_for_people_without_an_organization_still_need_a_valid_token(world: World, route: Route) -> None:
    before = world.snapshot()
    for label, headers in bad_operator_headers(world).items():
        if label in ("other org's header", "unknown user"):  # a verified token of a user with no organization is exactly who these routes are for
            continue
        response = world.send(route, headers=headers)
        assert refused(response.status_code) and response.status_code != 503, f"{route.key} answered {response.status_code} to: {label}"
    assert world.snapshot() == before


@pytest.mark.parametrize("route", INTERNAL_ROUTES, ids=ids(INTERNAL_ROUTES))
def test_internal_routes_refuse_missing_and_wrong_service_tokens(world: World, route: Route) -> None:
    before = world.snapshot()
    for label, headers in {"none": {}, "wrong": {"Authorization": "Bearer wrong-service-token"}, "operator token": world.token("owner"),
                           "prefix only": {"Authorization": f"Bearer {INTERNAL[:-1]}"}}.items():
        response = world.send(route, headers=headers)
        assert response.status_code == 401, f"{route.key} answered {response.status_code} to: {label}"
    assert world.snapshot() == before


@pytest.mark.parametrize("route", INTERNAL_ROUTES[:1], ids=ids(INTERNAL_ROUTES[:1]))
def test_internal_routes_are_off_when_no_service_token_is_configured(route: Route) -> None:
    client, _ = make_client(LocalSupabaseAdapter(), ENVIRONMENT="development")
    assert client.request(route.method, route.path, headers={"Authorization": f"Bearer {INTERNAL}"}, json={}).status_code == 503


@pytest.mark.parametrize("route", SCIM_ROUTES, ids=ids(SCIM_ROUTES))
def test_scim_routes_refuse_missing_wrong_and_unconfigured(world: World, route: Route) -> None:
    for label, headers in {"none": {}, "wrong": {"Authorization": "Bearer nope"}, "operator token": world.token("owner")}.items():
        assert world.send(route, headers=headers).status_code == 401, label
    off, _ = make_client(LocalSupabaseAdapter(), ENVIRONMENT="development")
    assert off.request(route.method, route.path.replace("{user_id}", str(uuid4())), headers={"Authorization": f"Bearer {SCIM}"}, json={}).status_code == 503


@pytest.mark.parametrize("route", SDK_ROUTES, ids=ids(SDK_ROUTES))
def test_sdk_key_routes_refuse_missing_malformed_and_unknown_keys(world: World, route: Route) -> None:
    before = world.snapshot()
    for label, headers in {"none": {}, "malformed": {"X-RedHand-API-Key": "nope"}, "unknown": {"X-RedHand-API-Key": "rh_live_" + "z" * 43},
                           "operator token as key": {"X-RedHand-API-Key": world.token("owner")["Authorization"][7:]},
                           "service token as key": {"X-RedHand-API-Key": INTERNAL}}.items():
        response = world.send(route, headers=headers)
        assert response.status_code in (401, 422), f"{route.key} answered {response.status_code} to: {label}"
    assert world.snapshot() == before


def test_public_routes_still_refuse_what_they_must(world: World) -> None:
    before = world.snapshot()
    assert world.client.get("/v1/state/stream", params={"ticket": "made-up"}).status_code == 401
    assert world.client.get("/v1/state/stream").status_code == 422
    assert world.client.post("/v1/hitl/slack/interactivity", content=b"payload=%7B%7D").status_code in (400, 401, 403, 503)
    assert world.client.post("/v1/telegram/webhook", json={"update_id": 1}).status_code in (401, 403, 503)
    assert world.client.post("/v1/telegram/webhook", json={"update_id": 1}, headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"}).status_code in (401, 403, 503)
    assert world.client.post("/v1/agent-auth/token").status_code == 401
    assert world.client.post("/v1/agent-auth/token", headers={"Authorization": "Bearer rh_agent_" + "z" * 43}).status_code == 401
    assert world.client.post("/v1/dev/login", json={"user": "nobody"}).status_code in (400, 401, 404, 422)
    assert world.snapshot() == before


def test_a_ticket_is_single_use_and_bound_to_one_organization(world: World) -> None:
    ticket = world.client.post("/v1/state/stream-ticket", headers=world.token("viewer")).json()["ticket"]
    from redhand_core.routers import state

    assert state._stream_tickets[ticket][0] == DEFAULT_ORG_ID  # noqa: SLF001
    assert state._redeem_stream_ticket(ticket) == DEFAULT_ORG_ID  # noqa: SLF001
    with pytest.raises(Exception):
        state._redeem_stream_ticket(ticket)  # noqa: SLF001


# --- 3. wrong role --------------------------------------------------------------------------------------------------------------------

ROLE_OF = {name: Role.from_db(op["role"]) for name, op in DEV_OPERATORS.items()}
ROLE_ROUTES = [r for r in OPERATOR_ROUTES if AUTH[r.key].role is not None]


@pytest.mark.parametrize("route", ROLE_ROUTES, ids=ids(ROLE_ROUTES))
def test_a_role_below_the_minimum_is_refused_and_changes_nothing(world: World, route: Route) -> None:
    need = AUTH[route.key].role
    assert need is not None
    before = world.snapshot()
    below = [name for name, role in ROLE_OF.items() if role < need]
    for name in below:
        response = world.send(route, headers=world.token(name))
        assert response.status_code == 403, f"{route.key} answered {response.status_code} to {name} ({ROLE_OF[name].name}); needs {need.name}"
        assert need.name.lower() in response.text.lower() or "role" in response.text.lower()
    assert world.snapshot() == before
    # the minimum role itself is past authorization (the answer may be 400, 404, 409 or 422 for the made-up ids, never 401 or 403)
    at_minimum = next(name for name, role in ROLE_OF.items() if role == need)
    got = world.send(route, headers=world.token(at_minimum))
    assert got.status_code not in (401, 403), f"{route.key}: {at_minimum} ({need.name}) was refused with {got.status_code}: {got.text[:120]}"


@pytest.mark.parametrize("path", ["/v1/organization/safe-mode", "/v1/passports/{agent_id}/safe-mode"])
def test_safe_mode_on_needs_security_operator_and_off_needs_admin(world: World, path: str) -> None:
    agent = next(a["id"] for a in world.store.tables["agents"] if a["organization_id"] == DEFAULT_ORG_ID)
    url = path.replace("{agent_id}", agent)
    before = world.snapshot()
    assert world.client.post(url, json={"enabled": True, "reason": "x", "confirm": True}, headers=world.token("viewer")).status_code == 403
    assert world.client.post(url, json={"enabled": False, "reason": "x", "confirm": True}, headers=world.token("operator")).status_code == 403
    assert world.snapshot() == before
    assert world.client.post(url, json={"enabled": True, "reason": "x", "confirm": True}, headers=world.token("operator")).status_code == 200
    assert world.client.post(url, json={"enabled": False, "reason": "x", "confirm": True}, headers=world.token("admin")).status_code == 200


def test_claiming_a_role_in_a_header_changes_nothing(world: World) -> None:
    viewer = {**world.token("viewer"), "X-User-Roles": "owner", "X-User-ID": DEV_OPERATORS["owner"]["id"], "X-Role": "owner"}
    freeze_all = next(r for r in ROUTES if r.key == ("POST", "/v1/passports/freeze-all"))
    before = world.snapshot()
    assert world.send(freeze_all, headers=viewer, body={"confirm": True, "reason": "x"}).status_code == 403
    assert world.snapshot() == before


# --- 4. the other tenant --------------------------------------------------------------------------------------------------------------

def example(schema: dict[str, Any], spec: dict[str, Any]) -> Any:
    """A small valid value for a JSON schema, so a request gets past validation and reaches the handler's own tenant checks."""
    if "$ref" in schema:
        return example(spec["components"]["schemas"][schema["$ref"].split("/")[-1]], spec)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [s for s in schema[key] if s.get("type") != "null"]
            return example(options[0], spec) if options else None
    if "allOf" in schema:
        merged: dict[str, Any] = {}
        for part in schema["allOf"]:
            value = example(part, spec)
            if isinstance(value, dict):
                merged.update(value)
        return merged
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "object":
        props = schema.get("properties", {})
        out: dict[str, Any] = {}
        for name, sub in props.items():
            if name in schema.get("required", []):
                out[name] = example(sub, spec)
            elif name == "confirm":
                out[name] = True  # confirmation gates sit in front of the lookup we are exercising
        return out
    if kind == "array":
        return [example(schema["items"], spec)] * max(1, schema.get("minItems", 0)) if schema.get("minItems") else []
    if kind == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return str(uuid4())
        if fmt == "date-time":
            return datetime.now(timezone.utc).isoformat()
        if fmt in ("uri", "url") or schema.get("maxLength") == 2083:
            return "https://example.com/x"
        return "x" * max(1, schema.get("minLength", 0))
    if kind == "integer":
        return schema.get("minimum", 1)
    if kind == "number":
        return schema.get("minimum", 1.0)
    if kind == "boolean":
        return True
    return None


# Hand-written bodies where the generated one cannot satisfy a pattern or a cross-field rule.
BODY_OVERRIDES: dict[tuple[Method, str], Any] = {}

SPEC = app.openapi()


def body_for(route: Route) -> Any:
    if route.key in BODY_OVERRIDES:
        return BODY_OVERRIDES[route.key]
    op = SPEC["paths"].get(route.path, {}).get(route.method.lower(), {})
    schema = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
    return example(schema, SPEC) if schema else None


TENANT_ROUTES = [r for r in OPERATOR_ROUTES if _path_names(r.path)]


@pytest.mark.parametrize("route", TENANT_ROUTES, ids=ids(TENANT_ROUTES))
def test_another_organizations_ids_are_never_reachable(world: World, route: Route) -> None:
    # An organization A owner (the highest role, so no refusal for lack of role can hide a missing tenant check) names organization B's ids.
    names = _path_names(route.path)
    unknown = [n for n in names if n not in world.theirs]
    assert not unknown, f"{route.key}: no organization B resource for path id(s) {unknown}; add one to World._seed_other_tenant"
    before = world.snapshot()
    response = world.send(route, headers=world.token("owner"), params={n: world.theirs[n] for n in names}, body=body_for(route))
    assert response.status_code != 422, f"{route.key}: the body did not reach the handler ({response.text[:160]}); add a BODY_OVERRIDES entry"
    assert response.status_code in (403, 404), f"{route.key} answered {response.status_code} for another organization's id: {response.text[:160]}"
    assert OTHER_MARK not in response.text and OTHER_ORG not in response.text, f"{route.key} leaked organization B's data"
    assert world.snapshot() == before, f"{route.key} changed the store while refusing"


LIST_ROUTES = [r for r in OPERATOR_ROUTES if r.method == "GET" and not _path_names(r.path)]


@pytest.mark.parametrize("route", LIST_ROUTES, ids=ids(LIST_ROUTES))
def test_list_routes_never_include_another_organizations_rows(world: World, route: Route) -> None:
    response = world.send(route, headers=world.token("owner"))
    assert response.status_code not in (401, 403) or response.status_code == 403
    assert OTHER_MARK not in response.text and OTHER_ORG not in response.text, f"{route.key} listed organization B's data"
    # and organization B's owner sees only B (the same call as B must not show A's default-organization seed data)
    mine = world.send(route, headers=world.token(user_id=OTHER_OWNER))
    if mine.status_code == 200:
        assert DEFAULT_ORG_ID not in mine.text, f"{route.key} listed the default organization's data to organization B"


def test_a_user_of_one_organization_cannot_borrow_anothers_with_a_header(world: World) -> None:
    assert world.client.get("/v1/passports", headers=world.token("owner", org=OTHER_ORG)).status_code == 403
    assert world.client.get("/v1/passports", headers=world.token(user_id=OTHER_OWNER, org=DEFAULT_ORG_ID)).status_code == 403
    assert world.client.get("/v1/passports", headers=world.token(user_id=OTHER_OWNER, org="not-a-uuid")).status_code in (401, 403, 422)


def test_the_other_tenant_seed_is_real_not_decoration(world: World) -> None:
    """A control: organization B's owner can read B's own passport, so the refusals above are about tenancy, not a broken seed."""
    mine = world.client.get(f"/v1/passports/{world.theirs['agent_id']}", headers=world.token(user_id=OTHER_OWNER))
    assert mine.status_code == 200, mine.text
    assert OTHER_MARK in json.dumps(mine.json())
