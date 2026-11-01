"""
Operator (human) authentication and tenant resolution for redhand-core.

Operators authenticate with a Supabase Auth access token (a JWT). We verify it locally
with an explicit algorithm allowlist, audience and expiry, then resolve which tenant
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

from fastapi import Depends, Header, HTTPException, status
import jwt

from redhand_core.config import Settings, get_settings
from redhand_core.routers.telemetry import get_supabase_service_client

logger = logging.getLogger("redhand.core.auth")

# Supabase signs user access tokens with HS256 (project JWT secret) and the
# "authenticated" audience. Only this algorithm is accepted; "none" and asymmetric
# algorithms are rejected so a token can't pick its own verification method.
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
    """Verifies signature, algorithm, audience and expiry. Raises 401 on any failure."""
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


async def get_operator(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_redhand_org: Annotated[str | None, Header(alias="X-RedHand-Org")] = None,
    settings: Settings = Depends(get_settings),
    supabase: Any = Depends(get_supabase_service_client),
) -> OperatorContext:
    """FastAPI dependency: authenticated operator scoped to exactly one tenant."""
    if not authorization or not authorization.startswith("Bearer "):
        raise _unauthorized()
    claims = decode_operator_token(authorization.removeprefix("Bearer ").strip(), settings)

    try:
        user_id = UUID(str(claims["sub"]))
        requested_org = UUID(x_redhand_org) if x_redhand_org else None
    except ValueError as exc:
        raise _unauthorized("Invalid operator identity.") from exc

    org_id, role = await resolve_membership(supabase, user_id, requested_org)
    email = claims.get("email")
    return OperatorContext(
        user_id=user_id,
        organization_id=org_id,
        role=role,
        email=str(email) if email else None,
    )


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


OperatorDep = Annotated[OperatorContext, Depends(get_operator)]
ViewerDep = Annotated[OperatorContext, Depends(require_role(Role.VIEWER))]
SecurityOperatorDep = Annotated[OperatorContext, Depends(require_role(Role.SECURITY_OPERATOR))]
AdminDep = Annotated[OperatorContext, Depends(require_role(Role.ADMIN))]
