"""
Operator (human) authentication and tenant resolution for redhand-core.

Operators authenticate with a Supabase Auth access token (a JWT). We verify it locally, in
one of two mutually exclusive modes chosen by configuration (ADR 0007):

- JWKS mode (`OPERATOR_JWKS_URL`): Supabase projects using asymmetric signing keys; ES256 or
  RS256 against the project's public keys (see operator_jwks.py).
- HS256 mode (`OPERATOR_JWT_SECRET`): a shared secret; local development and tests.

Either way the algorithm allowlist, audience and expiry are enforced. We then resolve which tenant
(organization) and role the operator acts as from `organization_members`. The tenant is
never taken from the request on trust: a requested organization is only honoured if the
verified user is a member of it.

Every failure is a 401/403. There is no anonymous or default identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import IntEnum
import logging
from typing import Annotated, Any, Protocol
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
import jwt
from postgrest.exceptions import APIError

from redhand_core.auth import bearer_token
from redhand_core.auth.operator_jwks import OperatorJwksVerifier, OperatorTokenError
from redhand_core.config import Settings, get_settings
from redhand_core.routers.telemetry import get_supabase_service_client

logger = logging.getLogger("redhand.core.auth")

# HS256 mode accepts only HS256; "none" and every other algorithm are rejected so a token
# can't pick its own verification method.
OPERATOR_JWT_ALGORITHMS = ["HS256"]
OPERATOR_JWT_AUDIENCE = "authenticated"
OPERATOR_JWT_LEEWAY_SECONDS = 30


class Role(IntEnum):
    """Operator roles, ordered by privilege. Matches organization_members.role."""

    VIEWER = 1
    SECURITY_OPERATOR = 2
    ADMIN = 3
    OWNER = 4

    @classmethod
    def from_db(cls, value: str) -> Role:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown operator role '{value}'") from exc


@dataclass(frozen=True, slots=True)
class OperatorContext:
    """The authenticated operator and the single tenant this request acts on."""

    user_id: UUID
    organization_id: UUID
    role: Role
    email: str | None = None


class _SupabaseLike(Protocol):
    def table(self, name: str) -> Any: ...


def _unauthorized(detail: str = "Authentication required.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _signing_secret(settings: Settings) -> str | None:
    secret = settings.OPERATOR_JWT_SECRET
    return secret.get_secret_value() if secret else None


def decode_operator_token(token: str, settings: Settings) -> dict[str, Any]:
    """HS256 mode: verifies signature, algorithm, audience and expiry. Raises 401 on failure."""
    secret = _signing_secret(settings)
    if not secret:
        # Fail closed: without a configured secret no operator can authenticate.
        logger.error("OPERATOR_JWT_SECRET is not configured; rejecting operator request")
        raise _unauthorized()
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            secret,
            algorithms=OPERATOR_JWT_ALGORITHMS,
            audience=OPERATOR_JWT_AUDIENCE,
            leeway=OPERATOR_JWT_LEEWAY_SECONDS,
            options={"require": ["exp", "sub", "aud"]},
        )
    except jwt.PyJWTError as exc:
        # Log the failure class only; never the token.
        logger.info("Operator token rejected: %s", type(exc).__name__)
        raise _unauthorized("Invalid or expired operator token.") from exc
    return claims


_jwks_verifiers: dict[tuple[str, str], OperatorJwksVerifier] = {}


def _jwks_verifier(settings: Settings) -> OperatorJwksVerifier:
    """One verifier (and key cache) per configured JWKS URL and issuer."""
    url, issuer = settings.OPERATOR_JWKS_URL, settings.OPERATOR_JWT_ISSUER
    if not url or not issuer:
        raise _unauthorized()  # unreachable: Settings validation enforces both together
    cache_key = (url, issuer)
    if cache_key not in _jwks_verifiers:
        _jwks_verifiers[cache_key] = OperatorJwksVerifier(jwks_url=url, issuer=issuer)
    return _jwks_verifiers[cache_key]


CLERK_ALGORITHMS = ("RS256",)
CLERK_SUBJECT_MAX = 255
_clerk_verifiers: dict[tuple[str, str, str], OperatorJwksVerifier] = {}


def _clerk_verifier(settings: Settings) -> OperatorJwksVerifier:
    """Clerk mode (ADR 0032): RS256 only, the Clerk instance as issuer, our own audience. One key cache per configuration."""
    url, issuer, audience = settings.CLERK_JWKS_URL, settings.CLERK_ISSUER, settings.CLERK_AUDIENCE
    if not url or not issuer:
        raise _unauthorized()  # unreachable: Settings validation requires them in Clerk mode
    cache_key = (url, issuer, audience)
    if cache_key not in _clerk_verifiers:
        _clerk_verifiers[cache_key] = OperatorJwksVerifier(jwks_url=url, issuer=issuer, audience=audience, algorithms=CLERK_ALGORITHMS)
    return _clerk_verifiers[cache_key]


async def verify_operator_token(token: str, settings: Settings) -> dict[str, Any]:
    """Verifies an operator token in whichever mode is configured. Raises 401 on any failure."""
    if settings.OPERATOR_AUTH_PROVIDER == "clerk":
        try:
            return await _clerk_verifier(settings).verify(token)
        except OperatorTokenError as exc:
            logger.info("Operator token rejected: %s", exc)
            raise _unauthorized("Invalid or expired operator token.") from exc
    if settings.OPERATOR_JWKS_URL:
        try:
            return await _jwks_verifier(settings).verify(token)
        except OperatorTokenError as exc:
            # Log the failure class only; never the token.
            logger.info("Operator token rejected: %s", exc)
            raise _unauthorized("Invalid or expired operator token.") from exc
    return decode_operator_token(token, settings)


async def operator_identity(claims: dict[str, Any], settings: Settings, supabase: Any) -> tuple[UUID, str | None]:
    """RedHand's operator id and display e-mail for verified claims.

    Supabase mode: the subject IS the operator id (same UUID). Clerk mode: the subject is Clerk's user id; the database maps it to RedHand's own
    operator id, creating it on first use, and never matches an existing account by e-mail (ADR 0032). A Clerk token without a verified e-mail is
    refused. A database failure denies (503), never lets the request through."""
    if settings.OPERATOR_AUTH_PROVIDER != "clerk":
        try:
            user_id = UUID(str(claims["sub"]))
        except (KeyError, ValueError) as exc:
            raise _unauthorized("Invalid operator identity.") from exc
        email = claims.get("email")
        return user_id, str(email) if email else None

    subject = claims.get("sub")
    email = claims.get("email")
    if not isinstance(subject, str) or not 1 <= len(subject) <= CLERK_SUBJECT_MAX:
        raise _unauthorized("Invalid operator identity.")
    if claims.get("email_verified") is not True or not isinstance(email, str) or not email or len(email) > 320:
        raise _unauthorized("A verified e-mail address is required.")
    try:
        res = await supabase.rpc("operator_resolve", {"p_provider": "clerk", "p_subject": subject, "p_email": email}).execute()
        return UUID(str(res.data)), email
    except APIError as exc:
        logger.error("Operator identity could not be resolved: sqlstate=%s", exc.code)
    except (TypeError, ValueError):
        logger.error("Operator identity could not be resolved: unexpected answer")
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Sign-in could not be completed. Try again.")


async def resolve_membership(
    supabase: _SupabaseLike,
    user_id: UUID,
    requested_org: UUID | None,
) -> tuple[UUID, Role]:
    """Returns (organization_id, role) for the user, or raises 403."""
    res = await (
        supabase.table("organization_members")
        .select("organization_id, role")
        .eq("user_id", str(user_id))
        .execute()
    )
    memberships: list[dict[str, Any]] = list(res.data or [])
    if requested_org is not None:
        memberships = [m for m in memberships if str(m.get("organization_id")) == str(requested_org)]

    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator is not a member of the requested organization.",
        )
    if len(memberships) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator belongs to several organizations; set the X-RedHand-Org header.",
        )
    try:
        return UUID(str(memberships[0]["organization_id"])), Role.from_db(str(memberships[0]["role"]))
    except (KeyError, ValueError) as exc:
        logger.error("Malformed organization membership row for user %s", user_id)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.") from exc


# While an organization's deletion is pending (the 7-day grace period) its operators may only look at the status, export their data and cancel. Everything else
# is refused here, in the one dependency every operator route passes through, so a new route is closed by default. Matched on the route's path template.
PENDING_DELETION_ALLOWED: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/v1/me"),
    ("GET", "/v1/organization/deletion"),
    ("GET", "/v1/organization/export"),
    ("POST", "/v1/organization/delete-request"),
    ("POST", "/v1/organization/delete-request/cancel"),
})


async def _refuse_if_deletion_pending(supabase: _SupabaseLike, request: Request, organization_id: UUID) -> None:
    res = await supabase.table("organizations").select("deletion_requested_at").eq("id", str(organization_id)).execute()
    rows = list(res.data or [])
    if len(rows) != 1:
        # A membership with no organization row, or a read that returned nothing: deny rather than guess.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    if rows[0].get("deletion_requested_at") is None:
        return
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if (request.method, path) not in PENDING_DELETION_ALLOWED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This organization is scheduled for deletion. You can export your data or cancel the deletion.",
        )


async def get_operator(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_redhand_org: Annotated[str | None, Header(alias="X-RedHand-Org")] = None,
    settings: Settings = Depends(get_settings),
    supabase: Any = Depends(get_supabase_service_client),
) -> OperatorContext:
    """FastAPI dependency: authenticated operator scoped to exactly one tenant."""
    token = bearer_token(authorization)
    if token is None:
        raise _unauthorized()
    claims = await verify_operator_token(token, settings)
    try:
        requested_org = UUID(x_redhand_org) if x_redhand_org else None
    except ValueError as exc:
        raise _unauthorized("Invalid operator identity.") from exc
    user_id, email = await operator_identity(claims, settings, supabase)

    org_id, role = await resolve_membership(supabase, user_id, requested_org)
    await _refuse_if_deletion_pending(supabase, request, org_id)
    return OperatorContext(user_id=user_id, organization_id=org_id, role=role, email=email)


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """A verified operator token and nothing else: no organization, no role. Only for the routes a person uses BEFORE they belong to an organization
    (creating one with a sign-up code, joining one with an invite). Everything else needs `get_operator`."""

    user_id: UUID
    email: str | None = None


async def get_authenticated_user(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    settings: Settings = Depends(get_settings),
    supabase: Any = Depends(get_supabase_service_client),
) -> AuthenticatedUser:
    token = bearer_token(authorization)
    if token is None:
        raise _unauthorized()
    claims = await verify_operator_token(token, settings)
    user_id, email = await operator_identity(claims, settings, supabase)
    return AuthenticatedUser(user_id=user_id, email=email)


def require_role(minimum: Role) -> Any:
    """Dependency factory: the operator must hold at least `minimum`."""

    async def _check(operator: Annotated[OperatorContext, Depends(get_operator)]) -> OperatorContext:
        if operator.role < minimum:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{minimum.name.lower()}' role or higher.",
            )
        return operator

    return _check


def issue_operator_token(
    *,
    user_id: UUID,
    email: str | None,
    settings: Settings,
    now: datetime | None = None,
    ttl: timedelta = timedelta(hours=1),
) -> str:
    """
    Mints a Supabase-compatible operator token. Used only by the development login
    endpoint and tests; production tokens are issued by Supabase Auth.
    """
    secret = _signing_secret(settings)
    if not secret:
        raise RuntimeError("OPERATOR_JWT_SECRET is not configured.")
    issued = now or datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "sub": str(user_id),
        "aud": OPERATOR_JWT_AUDIENCE,
        "role": "authenticated",
        "iat": int(issued.timestamp()),
        "exp": int((issued + ttl).timestamp()),
    }
    if email:
        claims["email"] = email
    return jwt.encode(claims, secret, algorithm="HS256")


UserDep = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
OperatorDep = Annotated[OperatorContext, Depends(get_operator)]
ViewerDep = Annotated[OperatorContext, Depends(require_role(Role.VIEWER))]
SecurityOperatorDep = Annotated[OperatorContext, Depends(require_role(Role.SECURITY_OPERATOR))]
AdminDep = Annotated[OperatorContext, Depends(require_role(Role.ADMIN))]
OwnerDep = Annotated[OperatorContext, Depends(require_role(Role.OWNER))]
