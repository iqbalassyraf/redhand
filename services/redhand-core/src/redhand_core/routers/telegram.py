"""
Telegram panic command endpoints.

- POST /v1/telegram/webhook          called by Telegram only; authenticated by the webhook secret
- POST /v1/telegram/link-code        admin/owner: one-time code to link their Telegram chat
- GET  /v1/telegram/links            admin/owner: linked chats of the organization
- POST /v1/telegram/links/{id}/unlink  admin/owner: remove a linked chat (lost phone)

The webhook always answers 200 once the secret has been verified, so Telegram does not redeliver;
the sender is told the outcome in chat instead.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from postgrest.exceptions import APIError
from pydantic import BaseModel, ValidationError

from redhand_core.auth.operator import AdminDep
from redhand_core.config import Settings, get_settings
from redhand_core.passports.models import utcnow
from redhand_core.services.rate_limit import SlidingWindowLimiter
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.telegram.bot import (
    CODE_TTL_SECONDS,
    generate_link_code,
    handle_update,
    hash_link_code,
)
from redhand_core.telegram.client import TelegramClient, get_telegram_client_for
from redhand_core.telegram.deps import OptionalClientDep as OptionalClientDep  # re-exported: routers and tests import it from here
from redhand_core.telegram.deps import get_optional_telegram_client as get_optional_telegram_client
from redhand_core.telegram.models import TelegramUpdate

logger = logging.getLogger("redhand.core.telegram")

router = APIRouter(prefix="/v1/telegram", tags=["Telegram panic command"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]
SettingsDep = Annotated[Settings, Depends(get_settings)]

MAX_WEBHOOK_BYTES = 64 * 1024
LINK_CODES_PER_HOUR = 5
_code_limiter = SlidingWindowLimiter(window_seconds=3600.0)


def _require_configured(settings: Settings) -> TelegramClient:
    client = get_telegram_client_for(settings)
    if client is None or settings.TELEGRAM_WEBHOOK_SECRET is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Telegram is not configured.")
    return client


def get_required_telegram_client(settings: SettingsDep) -> TelegramClient:
    return _require_configured(settings)


ClientDep = Annotated[TelegramClient, Depends(get_required_telegram_client)]


@router.post(
    "/webhook",
    summary="Telegram webhook (public; authenticated by the webhook secret header)",
    responses={401: {"description": "Missing or wrong X-Telegram-Bot-Api-Secret-Token"}},
)
async def telegram_webhook(
    request: Request,
    settings: SettingsDep,
    supabase: SupabaseDep,
    client: ClientDep,
    secret_token: Annotated[str | None, Header(alias="X-Telegram-Bot-Api-Secret-Token")] = None,
) -> dict[str, bool]:
    expected = settings.TELEGRAM_WEBHOOK_SECRET
    if expected is None:  # unreachable: ClientDep refuses first; kept so the check cannot be skipped
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Telegram is not configured.")
    presented = secret_token or ""
    if not hmac.compare_digest(presented.encode(), expected.get_secret_value().encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid webhook credentials.")

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_WEBHOOK_BYTES:
        raise HTTPException(413, "Request too large.")
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BYTES:
        raise HTTPException(413, "Request too large.")
    try:
        update = TelegramUpdate.model_validate(json.loads(raw))
    except (ValueError, ValidationError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed update.") from None

    await handle_update(supabase, settings, client, update)
    return {"ok": True}


class LinkCodeResponse(BaseModel):
    code: str
    expires_at: datetime
    bot_username: str | None
    deep_link: str | None


@router.post("/link-code", response_model=LinkCodeResponse, status_code=status.HTTP_201_CREATED)
async def create_link_code(operator: AdminDep, settings: SettingsDep, supabase: SupabaseDep) -> LinkCodeResponse:
    _require_configured(settings)
    if not _code_limiter.allow(str(operator.user_id), LINK_CODES_PER_HOUR, time.monotonic()):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many link codes. Try again later.", headers={"Retry-After": "3600"}
        )
    code = generate_link_code()
    expires_at = utcnow() + timedelta(seconds=CODE_TTL_SECONDS)
    await (
        supabase.table("telegram_link_codes")
        .insert(
            {
                "code_hash": hash_link_code(code),
                "organization_id": str(operator.organization_id),
                "user_id": str(operator.user_id),
                "expires_at": expires_at.isoformat(),
            }
        )
        .execute()
    )
    bot = settings.TELEGRAM_BOT_USERNAME
    return LinkCodeResponse(
        code=code, expires_at=expires_at, bot_username=bot, deep_link=f"https://t.me/{bot}?start={code}" if bot else None
    )


class TelegramLinkView(BaseModel):
    id: UUID
    user_id: UUID
    created_at: datetime


@router.get("/links", response_model=list[TelegramLinkView])
async def list_links(operator: AdminDep, supabase: SupabaseDep) -> list[TelegramLinkView]:
    # The chat id is deliberately not returned: it identifies a person's Telegram account.
    res = await (
        supabase.table("telegram_links")
        .select("id, user_id, created_at, revoked_at")
        .eq("organization_id", str(operator.organization_id))
        .execute()
    )
    rows = [r for r in (res.data or []) if not r.get("revoked_at")]
    return [TelegramLinkView.model_validate(r) for r in rows]


class UnlinkResponse(BaseModel):
    link_id: UUID
    changed: bool


@router.post("/links/{link_id}/unlink", response_model=UnlinkResponse)
async def unlink(link_id: UUID, operator: AdminDep, supabase: SupabaseDep) -> UnlinkResponse:
    try:
        res = await supabase.rpc(
            "telegram_unlink",
            {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_link_id": str(link_id)},
        ).execute()
    except APIError as exc:
        if exc.code == "P0002":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Telegram link not found.") from exc
        logger.error("Telegram unlink failed: sqlstate=%s", exc.code)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "The action could not be completed.") from exc
    return UnlinkResponse(link_id=link_id, changed=bool(res.data["changed"]))
