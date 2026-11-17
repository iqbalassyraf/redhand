"""
Agent Passport domain model and pure rules (no I/O).

A passport is RedHand's identity and permission record for one agent: who owns it,
which MCP servers and tools it may use, until when, and whether it is currently
allowed to act at all.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

PassportStatus = Literal["active", "frozen", "revoked", "expired"]
StoredStatus = Literal["active", "frozen", "revoked"]
Access = Literal["read", "write"]

SERVER_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"
TOOL_NAME_PATTERN = r"^(\*|[A-Za-z0-9_.:/-]{1,128})$"
MAX_SCOPES = 200
MAX_REASON_LENGTH = 500


class Scope(BaseModel):
    """
    One allowlisted permission. `tool="*"` allows every tool on the server.
    `access` is declared by the operator, never inferred: MCP servers' own read/write hints are
    self-declared by the server and untrusted. It is enforced only while Safe Mode is on (ADR 0009):
    then the gateway allows a tool only if a scope with access "read" covers it. RedHand cannot verify
    that a tool really is read-only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    server: str = Field(pattern=SERVER_SLUG_PATTERN)
    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    access: Access = "read"


def scopes_allow(scopes: list[Scope], server: str, tool: str) -> bool:
    """True when some scope covers (server, tool). Exact match or server wildcard only."""
    return any(s.server == server and (s.tool == "*" or s.tool == tool) for s in scopes)


def scope_covers(granted: Scope, requested: Scope) -> bool:
    """True when `granted` already permits everything `requested` would."""
    if granted.server != requested.server:
        return False
    if granted.tool != "*" and granted.tool != requested.tool:
        return False
    return granted.access == "write" or requested.access == "read"


def is_scope_expansion(old: list[Scope], new: list[Scope]) -> bool:
    """True when `new` grants anything `old` did not. Expansions need confirmation."""
    return any(not any(scope_covers(g, r) for g in old) for r in new)


def parse_scopes(raw: Any) -> list[Scope]:
    """Parses stored scopes. Malformed data raises, so callers fail closed."""
    if not isinstance(raw, list):
        raise ValueError("Passport scopes must be a list.")
    return [Scope.model_validate(item) for item in raw]


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamps must be timezone-aware.")
    return parsed


def effective_status(stored_status: str, expires_at: Any, now: datetime) -> PassportStatus:
    """
    The status the gateway must act on. An active passport past its expiry is
    `expired`. Anything unrecognised is treated as `revoked` (fail closed).
    """
    if stored_status == "revoked":
        return "revoked"
    if stored_status == "frozen":
        return "frozen"
    if stored_status != "active":
        return "revoked"
    try:
        expiry = parse_timestamp(expires_at)
    except (TypeError, ValueError):
        return "expired"
    return "expired" if expiry <= now else "active"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# -----------------------------------------------------------------------------
# API contracts
# -----------------------------------------------------------------------------


class PassportCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    framework: str = Field(default="custom", min_length=1, max_length=40)
    external_agent_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
    )
    environment: Literal["development", "staging", "production"] = "production"
    owner_id: UUID | None = None
    backup_owner_id: UUID | None = None
    scopes: list[Scope] = Field(default_factory=list, max_length=MAX_SCOPES)
    expires_in_days: int = Field(default=90, ge=1, le=365)


def _stored_limit(raw: Any) -> int | None:
    """A stored daily call limit for display; anything that is not a positive integer shows as none."""
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 1 else None


class PassportView(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    external_agent_id: str
    framework: str
    environment: str
    owner_id: UUID | None
    backup_owner_id: UUID | None
    scopes: list[Scope]
    status: PassportStatus
    stored_status: str
    status_reason: str | None
    expires_at: datetime
    version: int
    created_at: datetime | None
    last_seen_at: datetime | None
    safe_mode: bool
    daily_call_limit: int | None
    budget_action: str
    reported_only: bool = Field(
        default=False, description="Created by an SDK key's telemetry, not by a person: no gateway access until an admin promotes it."
    )

    @classmethod
    def from_row(cls, row: dict[str, Any], now: datetime) -> PassportView:
        def _opt_ts(key: str) -> datetime | None:
            return parse_timestamp(row[key]) if row.get(key) else None

        return cls(
            id=UUID(str(row["id"])),
            organization_id=UUID(str(row["organization_id"])),
            name=str(row["name"]),
            external_agent_id=str(row["external_agent_id"]),
            framework=str(row.get("framework") or "custom"),
            environment=str(row.get("environment") or "production"),
            owner_id=UUID(str(row["owner_id"])) if row.get("owner_id") else None,
            backup_owner_id=UUID(str(row["backup_owner_id"])) if row.get("backup_owner_id") else None,
            scopes=parse_scopes(row.get("scopes", [])),
            status=effective_status(str(row.get("status")), row.get("expires_at"), now),
            stored_status=str(row.get("status")),
            status_reason=row.get("status_reason"),
            expires_at=parse_timestamp(row["expires_at"]),
            version=int(row.get("version") or 1),
            created_at=_opt_ts("created_at"),
            last_seen_at=_opt_ts("last_seen_at"),
            safe_mode=row.get("safe_mode") is True,
            daily_call_limit=_stored_limit(row.get("daily_call_limit")),
            budget_action=str(row.get("budget_action") or "deny"),
            reported_only=row.get("reported_only") is True,
        )


class PassportCreateResponse(BaseModel):
    passport: PassportView
    agent_key: str = Field(description="Shown once. Store it in the agent's secret store.")


class ControlActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)


class ConfirmedControlActionRequest(ControlActionRequest):
    confirm: bool = Field(
        default=False, description="Must be true. Guards against accidental unfreeze/revoke."
    )


class BudgetUpdateRequest(BaseModel):
    """Set an agent's daily limit on tool calls through the gateway (null removes the limit)."""

    model_config = ConfigDict(extra="forbid")

    daily_call_limit: StrictInt | None = Field(default=None, ge=1, le=10_000_000)
    action: Literal["deny", "freeze"] = "deny"
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to raise or remove a limit.")


class OrgBudgetDefaultRequest(BaseModel):
    """The daily limit new agents of the organization start with (null: no default)."""

    model_config = ConfigDict(extra="forbid")

    default_daily_call_limit: StrictInt | None = Field(default=None, ge=1, le=10_000_000)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to raise or remove the default.")


class OrgBudgetDefaultResponse(BaseModel):
    default_daily_call_limit: int | None
    changed: bool


class AgentBudgetResponse(BaseModel):
    passport: PassportView
    changed: bool


class SafeModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to turn Safe Mode off.")


class AgentSafeModeResponse(BaseModel):
    passport: PassportView
    changed: bool


class OrganizationSafeModeResponse(BaseModel):
    enabled: bool
    changed: bool


class ScopesUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopes: list[Scope] = Field(max_length=MAX_SCOPES)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: bool = Field(default=False, description="Required when the change grants new access.")


class RenewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_in_days: int = Field(default=90, ge=1, le=365)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)


class ControlActionResponse(BaseModel):
    passport: PassportView
    changed: bool


class FreezeAllResponse(BaseModel):
    organization_id: UUID
    frozen_count: int
    frozen_agent_ids: list[UUID]


class KeyRotationResponse(BaseModel):
    passport: PassportView
    agent_key: str = Field(description="Shown once. The previous key stops working immediately.")


class ControlAuditEntry(BaseModel):
    id: UUID
    organization_id: UUID
    actor_user_id: UUID
    action: str
    target_type: str
    target_id: UUID
    reason: str | None
    details: dict[str, Any]
    created_at: datetime


class McpServerCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str = Field(pattern=SERVER_SLUG_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class McpServerView(BaseModel):
    id: UUID
    organization_id: UUID
    slug: str
    name: str
    url: str
    is_active: bool
