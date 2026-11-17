"""
Organization SDK keys (Phase 4.5 C1a, ADR 0024): generated here, stored as a SHA-256 hash with a 12-character display prefix through audited database
functions, shown once. Also the per-key ingest rate limit and the "last used" stamp that `routers/telemetry.py` uses.

The plaintext key exists only in the create response: it is never stored, logged or returned again. This module avoids importing the passports
service at load time, because the telemetry router (which auth.operator imports) imports this module.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import HTTPException, status

from redhand_core.sdkkeys.models import (
    MAX_ACTIVE_KEYS,
    KeyState,
    SdkKeyCreated,
    SdkKeyCreateRequest,
    SdkKeyList,
    SdkKeyRevokeResponse,
    SdkKeyView,
)
from redhand_core.services.metrics import get_metrics
from redhand_core.services.rate_limit import SlidingWindowLimiter

if TYPE_CHECKING:
    from redhand_core.auth.operator import OperatorContext

logger = logging.getLogger("redhand.core.sdkkeys")

KEY_PREFIX = "rh_live_"
DISPLAY_PREFIX_LENGTH = 12
INGEST_BATCHES_PER_MINUTE = 120  # per key, per core instance (see services/rate_limit.py for what "per instance" means)
TOUCH_EVERY_SECONDS = 60.0
_MAX_TOUCH_ENTRIES = 10_000
LIST_COLUMNS = "id,name,key_prefix,is_active,expires_at,last_used_at,created_at,revoked_at"

_limiter = SlidingWindowLimiter(window_seconds=60.0)
_last_touch: dict[str, float] = {}


def reset_limits_for_tests() -> None:
    global _limiter
    _limiter = SlidingWindowLimiter(window_seconds=60.0)
    _last_touch.clear()


def generate_key() -> str:
    """`rh_live_` plus 32 random bytes, URL-safe (256 bits)."""
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def key_prefix(key: str) -> str:
    return key[:DISPLAY_PREFIX_LENGTH]


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def state_of(row: dict[str, Any], now: datetime) -> KeyState:
    if not row.get("is_active"):
        return "revoked"
    expires = _parse(row.get("expires_at"))
    return "expired" if expires is not None and expires <= now else "active"


def view_of(row: dict[str, Any], now: datetime) -> SdkKeyView:
    return SdkKeyView(
        id=UUID(str(row["id"])), name=str(row["name"]), key_prefix=str(row["key_prefix"]), state=state_of(row, now),
        created_at=_parse(row.get("created_at")), expires_at=_parse(row.get("expires_at")), last_used_at=_parse(row.get("last_used_at")),
        revoked_at=_parse(row.get("revoked_at")),
    )


# --- managing (admin) -------------------------------------------------------------------------------------------------------------

async def list_keys(supabase: Any, organization_id: UUID, now: datetime) -> SdkKeyList:
    res = await (
        supabase.table("sdk_api_keys").select(LIST_COLUMNS).eq("organization_id", str(organization_id)).order("created_at", desc=True).execute()
    )
    return SdkKeyList(keys=[view_of(dict(r), now) for r in res.data or []])


async def create_key(supabase: Any, operator: OperatorContext, payload: SdkKeyCreateRequest, now: datetime) -> SdkKeyCreated:
    from redhand_core.passports.service import _conflict, _rpc  # late: see the module docstring

    name = payload.name.strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A name is required.")
    secret = generate_key()
    expires_at = now + timedelta(days=payload.expires_in_days)
    data = await _rpc(
        supabase,
        "control_sdk_key_create",
        {
            "p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_name": name, "p_key_hash": hash_key(secret),
            "p_key_prefix": key_prefix(secret), "p_expires_at": expires_at.isoformat(),
        },
        not_found_detail="Organization not found.",
        conflict_detail="The key could not be created. Try again.",
    )
    if isinstance(data, dict) and data.get("limit"):
        raise _conflict(f"An organization can have at most {MAX_ACTIVE_KEYS} active SDK keys. Revoke one first.")
    res = await supabase.table("sdk_api_keys").select(LIST_COLUMNS).eq("organization_id", str(operator.organization_id)).eq("id", str(data["id"])).execute()
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "The key was created but could not be read back. Revoke it and try again.")
    get_metrics().increment_counter("sdk_keys_total", labels={"event": "created"})
    return SdkKeyCreated(secret=secret, key=view_of(dict(rows[0]), now))


async def revoke_key(supabase: Any, operator: OperatorContext, key_id: UUID, reason: str | None) -> SdkKeyRevokeResponse:
    from redhand_core.passports.service import _rpc  # late: see the module docstring

    data = await _rpc(
        supabase,
        "control_sdk_key_revoke",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_key_id": str(key_id), "p_reason": reason},
        not_found_detail="SDK key not found.",
        conflict_detail="The key could not be revoked. Try again.",
    )
    changed = bool(data["changed"])
    if changed:
        get_metrics().increment_counter("sdk_keys_total", labels={"event": "revoked"})
    return SdkKeyRevokeResponse(id=key_id, changed=changed)


# --- using (ingest) --------------------------------------------------------------------------------------------------------------

def allow_ingest(key_id: str, now: float | None = None) -> bool:
    """False when this key has sent more than INGEST_BATCHES_PER_MINUTE batches in the last minute (on this instance)."""
    allowed = _limiter.allow(key_id, INGEST_BATCHES_PER_MINUTE, time.monotonic() if now is None else now)
    if not allowed:
        get_metrics().increment_counter("sdk_ingest_rate_limited_total")
    return allowed


async def touch(supabase: Any, key_id: UUID) -> None:
    """Records that the key was used, at most once a minute per key and instance (the database also throttles). Never raises: it runs after the
    SDK has its reply, and a failure only means "last used" is a little stale."""
    key = str(key_id)
    now = time.monotonic()
    last = _last_touch.get(key)
    if last is not None and now - last < TOUCH_EVERY_SECONDS:
        return
    if len(_last_touch) >= _MAX_TOUCH_ENTRIES:
        _last_touch.clear()
    _last_touch[key] = now
    try:
        await supabase.rpc("sdk_key_touch", {"p_key_id": key}).execute()
    except Exception as exc:  # noqa: BLE001  best effort, after the reply; logged by type only
        logger.warning("SDK key last-use could not be recorded: %s", type(exc).__name__)
