"""
The Telegram panic command: link a chat to an operator, then freeze agents from a phone.

Trust model (docs/adr/0008-telegram-panic-command.md):
- The webhook secret proves the request came from Telegram; it says nothing about the sender.
- A chat can act only when it is linked to an operator with a one-time code the operator created
  while signed in to the dashboard. The operator's role is re-read from the database on every
  command, so removing someone from the organization stops their phone at once.
- Only stopping commands exist here (freeze one agent, freeze all). Unfreeze, revoke and scope
  changes stay in the dashboard because they need explicit confirmation, so a stolen phone can
  stop agents but never start them.
- Every outcome is reported to the sender. A failure says plainly that nothing was done.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from postgrest.exceptions import APIError

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.config import Settings, get_settings
from redhand_core.passports import budget as budget_rules
from redhand_core.passports import service
from redhand_core.passports.models import PassportView, utcnow
from redhand_core.services.rate_limit import SlidingWindowLimiter
from redhand_core.services.metrics import get_metrics
from redhand_core.telegram.client import TelegramClient
from redhand_core.telegram.models import TelegramUpdate

logger = logging.getLogger("redhand.core.telegram")

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"  # no 0/O/1/I/L: easy to read out and type
CODE_LENGTH = 10  # 30**10 is about 49 bits; codes live 10 minutes and attempts are rate-limited
CODE_TTL_SECONDS = 600
LINK_ATTEMPTS_PER_MINUTE = 5
REASON_PREFIX = "via Telegram"
MAX_REASON_CHARS = 300
ALERT_TIMEOUT_SECONDS = 3.0
SQLSTATE_NOT_FOUND = "P0002"
SQLSTATE_FORBIDDEN = "42501"

_command_limiter = SlidingWindowLimiter()
_link_limiter = SlidingWindowLimiter()

HELP_TEXT = (
    "RedHand panic commands:\n"
    "/status - how many agents are active, frozen or revoked\n"
    "/freeze_all [reason] - stop every active agent now\n"
    "/freeze <agent name> - stop one agent\n"
    "/safemode on [agent name] - read-only mode for all agents, or one\n"
    "/usage - today's tool calls against each agent's daily limit\n"
    "Unfreezing, revoking and turning Safe Mode off are done in the dashboard."
)
NOT_LINKED_TEXT = (
    "This chat is not linked to a RedHand account. In the dashboard open Passports, choose "
    "'Link Telegram', and send the code here as: /link CODE"
)
FAILED_TEXT = (
    "Something went wrong and the command was NOT carried out. Freeze your agents from the "
    "dashboard instead."
)


def generate_link_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def hash_link_code(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    args: str


def parse_command(text: str, bot_username: str | None) -> Command | None:
    """Parses '/name@bot args'. None when it is not a command or is addressed to another bot."""
    stripped = text.strip()
    if not stripped.startswith("/"):
        return None
    parts = re.split(r"\s+", stripped, maxsplit=1)
    head = parts[0][1:]
    args = parts[1].strip() if len(parts) > 1 else ""
    name, _, target = head.partition("@")
    if target and bot_username and target.lower() != bot_username.lower():
        return None
    return Command(name.lower(), args)


def _reason(args: str) -> str:
    cleaned = " ".join(args.split())[:MAX_REASON_CHARS]
    return f"{REASON_PREFIX}: {cleaned}" if cleaned else REASON_PREFIX


async def _linked_operator(supabase: Any, chat_id: int) -> OperatorContext | None:
    """The operator this chat is linked to, with their role as it is right now; else None."""
    links = await supabase.table("telegram_links").select("*").eq("chat_id", chat_id).execute()
    active = [row for row in (links.data or []) if not row.get("revoked_at")]
    if len(active) != 1:
        return None
    link = active[0]
    members = await (
        supabase.table("organization_members")
        .select("role")
        .eq("organization_id", str(link["organization_id"]))
        .eq("user_id", str(link["user_id"]))
        .execute()
    )
    rows = list(members.data or [])
    if len(rows) != 1:
        return None
    try:
        role = Role.from_db(str(rows[0]["role"]))
        return OperatorContext(
            user_id=UUID(str(link["user_id"])), organization_id=UUID(str(link["organization_id"])), role=role
        )
    except (KeyError, ValueError):
        return None


async def _cmd_link(supabase: Any, chat_id: int, code: str, mono: float) -> str:
    candidate = code.strip().upper()
    if not _link_limiter.allow(str(chat_id), LINK_ATTEMPTS_PER_MINUTE, mono):
        return "Too many attempts. Wait a minute and try again."
    if not re.fullmatch(f"[{CODE_ALPHABET}]{{{CODE_LENGTH}}}", candidate):
        return "That is not a valid code. Generate a new one in the dashboard."
    try:
        await supabase.rpc(
            "telegram_link_chat", {"p_code_hash": hash_link_code(candidate), "p_chat_id": chat_id}
        ).execute()
    except APIError as exc:
        if exc.code == SQLSTATE_NOT_FOUND:
            return "That code is invalid, already used or expired. Generate a new one in the dashboard."
        if exc.code == SQLSTATE_FORBIDDEN:
            return "Your role does not allow panic commands. Ask an owner or admin."
        raise
    return "Linked. You can now use /status, /freeze_all and /freeze. Send /help for the list."


async def _cmd_status(supabase: Any, operator: OperatorContext, now: datetime) -> str:
    views = [PassportView.from_row(r, now) for r in await service.list_passport_rows(supabase, operator)]
    counts: dict[str, int] = {}
    for view in views:
        counts[view.status] = counts.get(view.status, 0) + 1
    summary = ", ".join(f"{counts.get(s, 0)} {s}" for s in ("active", "frozen", "revoked", "expired"))
    org_safe = await service.get_org_safe_mode(supabase, operator.organization_id)
    safe = f" Safe Mode for all agents: {'on' if org_safe else 'off'}."
    return f"Agents: {summary}.{safe}"


async def _cmd_freeze_all(supabase: Any, operator: OperatorContext, args: str) -> tuple[str, str | None]:
    frozen = await service.freeze_all(supabase, operator, _reason(args))
    noun = "agent" if len(frozen) == 1 else "agents"
    reply = f"Froze {len(frozen)} {noun}. Unfreeze them from the dashboard when it is safe."
    return reply, f"All agents were frozen from Telegram ({len(frozen)} {noun})."


async def _cmd_freeze(
    supabase: Any, operator: OperatorContext, name: str, now: datetime
) -> tuple[str, str | None]:
    if not name:
        return "Say which agent: /freeze <agent name>. Use /status to see counts.", None
    views = [PassportView.from_row(r, now) for r in await service.list_passport_rows(supabase, operator)]
    active = [v for v in views if v.status == "active"]
    matches = [v for v in active if v.name.casefold() == name.casefold()]
    if len(matches) != 1:
        names = ", ".join(sorted(v.name for v in active)[:15]) or "none"
        problem = "More than one active agent has" if len(matches) > 1 else "No active agent has"
        return f"{problem} that name. Active agents: {names}.", None
    target = matches[0]
    await service.freeze(supabase, operator, target.id, _reason(""), now)
    return f"Froze {target.name}.", f"{target.name} was frozen from Telegram."


async def _cmd_usage(supabase: Any, operator: OperatorContext, now: datetime) -> str:
    """Today's tool calls through the gateway against each agent's daily limit (calls, never money)."""
    offset = await service.get_org_utc_offset(supabase, operator.organization_id)
    day = budget_rules.local_day(now, offset)
    calls = await service.get_org_usage(supabase, operator.organization_id, day)
    views = [PassportView.from_row(r, now) for r in await service.list_passport_rows(supabase, operator)]
    lines = []
    for view in views:
        if view.status == "revoked":
            continue
        used = calls.get(view.id, 0)
        if view.daily_call_limit is not None:
            lines.append(f"{view.name}: {used} of {view.daily_call_limit} calls ({used * 100 // view.daily_call_limit}%)")
        elif used:
            lines.append(f"{view.name}: {used} calls (no limit)")
    shown = lines[:15]
    extra = f"\n...and {len(lines) - 15} more." if len(lines) > 15 else ""
    header = f"Tool calls today ({day.isoformat()}, {budget_rules.format_offset(offset)}):"
    return header + ("\n" + "\n".join(shown) if shown else "\nNo calls yet.") + extra


async def _cmd_safemode(
    supabase: Any, operator: OperatorContext, args: str, now: datetime
) -> tuple[str, str | None]:
    """/safemode on [agent name]. Turning it off is dashboard-only, like unfreeze."""
    parts = args.split(maxsplit=1)
    action = parts[0].lower() if parts else ""
    name = parts[1].strip() if len(parts) > 1 else ""
    if action == "off":
        return "Turning Safe Mode off is only available in the dashboard.", None
    if action != "on":
        return "Use /safemode on (all agents) or /safemode on <agent name>.", None
    if not name:
        changed = await service.set_org_safe_mode(supabase, operator, True, _reason(""), confirm=False)
        reply = "Safe Mode is on for all agents: only tools declared read-only will work."
        return (reply if changed else "Safe Mode was already on for all agents."), (
            "Safe Mode was turned on for all agents from Telegram." if changed else None
        )
    views = [PassportView.from_row(r, now) for r in await service.list_passport_rows(supabase, operator)]
    matches = [v for v in views if v.status != "revoked" and v.name.casefold() == name.casefold()]
    if len(matches) != 1:
        problem = "More than one agent has" if len(matches) > 1 else "No agent has"
        return f"{problem} that name.", None
    target = matches[0]
    _, changed = await service.set_agent_safe_mode(supabase, operator, target.id, True, _reason(""), False, now)
    return (
        f"Safe Mode is on for {target.name}." if changed else f"Safe Mode was already on for {target.name}.",
        f"Safe Mode was turned on for {target.name} from Telegram." if changed else None,
    )


async def notify_organization(
    supabase: Any,
    client: TelegramClient | None,
    organization_id: UUID,
    text: str,
    *,
    exclude_chat_id: int | None = None,
) -> None:
    """Tells every linked chat of the organization. Best effort: never raises, never blocks long."""
    if client is None:
        return
    try:
        links = await (
            supabase.table("telegram_links")
            .select("chat_id, revoked_at")
            .eq("organization_id", str(organization_id))
            .execute()
        )
        targets = [
            int(r["chat_id"])
            for r in (links.data or [])
            if not r.get("revoked_at") and int(r["chat_id"]) != exclude_chat_id
        ]
        if targets:
            await asyncio.wait_for(
                asyncio.gather(*(client.send_message(chat, text) for chat in targets)),
                timeout=ALERT_TIMEOUT_SECONDS,
            )
    except Exception as exc:  # noqa: BLE001  alerts must never break the action that triggered them
        logger.warning("Telegram alert not delivered: %s", type(exc).__name__)


MAX_ALERT_CHARS = 4000  # Telegram refuses a message over 4096 characters


def _dashboard_url() -> str | None:
    return get_settings().DASHBOARD_URL


def _with_timeline_link(body: str, agent_id: UUID | None) -> str:
    """Cuts the message to Telegram's limit and, for an alert about one agent, ends it with a link to that agent's incident view (Phase 4.5
    B3) when the dashboard's address is configured. The link is kept whole: the text is cut to make room for it."""
    dashboard = _dashboard_url() if agent_id is not None else None
    tail = f"\n\nTimeline: {dashboard}/passports/{agent_id}/timeline" if dashboard else ""
    room = MAX_ALERT_CHARS - len(tail)
    if len(body) > room:
        body = body[: room - 1] + "…"
    return body + tail


class AlertBatch:
    """The alerts one request raises, sent as ONE message per organization and agent (paragraphs joined) when the request ends, so a single
    event (a trip that also moves that agent's risk score) does not buzz the owner's phone twice, while alerts about different agents stay
    separate messages. Belongs to one request only."""

    def __init__(self) -> None:
        self._texts: dict[tuple[UUID, UUID | None], list[str]] = {}

    def add(self, organization_id: UUID, text: str, agent_id: UUID | None = None) -> None:
        texts = self._texts.setdefault((organization_id, agent_id), [])
        if text not in texts:
            texts.append(text)

    async def flush(self, supabase: Any, client: TelegramClient | None) -> None:
        """Sends and empties. Never raises (notify_organization is best effort)."""
        pending, self._texts = self._texts, {}
        for (organization_id, agent_id), texts in pending.items():
            await notify_organization(supabase, client, organization_id, _with_timeline_link("\n\n".join(texts), agent_id))


async def send_alert(
    batch: AlertBatch | None, supabase: Any, client: TelegramClient | None, organization_id: UUID, text: str,
    agent_id: UUID | None = None,
) -> None:
    """Adds to the request's batch when there is one, otherwise sends at once (the behaviour before batches existed)."""
    if batch is None:
        await notify_organization(supabase, client, organization_id, _with_timeline_link(text, agent_id))
    else:
        batch.add(organization_id, text, agent_id)


def _count(command: str, outcome: str) -> None:
    get_metrics().increment_counter(
        "redhand_telegram_commands_total", labels={"command": command, "outcome": outcome}
    )


async def handle_update(
    supabase: Any,
    settings: Settings,
    client: TelegramClient,
    update: TelegramUpdate,
    *,
    now: Callable[[], datetime] = utcnow,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Handles one Telegram update. Always replies to the sender; never raises."""
    message = update.message
    if message is None or message.text is None or message.chat.type != "private":
        return
    chat_id = message.chat.id
    command = parse_command(message.text, settings.TELEGRAM_BOT_USERNAME)
    if command is None:
        command = Command("help", "")
    name = command.name if command.name in {"start", "help", "link", "status", "freeze_all", "freeze", "safemode", "usage"} else "other"

    try:
        # The limit comes first: it costs no database write, so a flood from one chat is dropped before it becomes a flood of claims.
        if not _command_limiter.allow(str(chat_id), settings.TELEGRAM_COMMANDS_PER_MINUTE, monotonic()):
            _count(name, "rate_limited")
            return
        claim = await supabase.rpc("telegram_claim_update", {"p_update_id": update.update_id}).execute()
        if claim.data is not True:
            _count(name, "duplicate")
            return

        reply, alert, operator = await _dispatch(supabase, chat_id, command, now(), monotonic())
        outcome = "ok"
    except HTTPException as exc:
        reply, alert, operator, outcome = f"Not carried out: {exc.detail}", None, None, "refused"
    except Exception as exc:  # noqa: BLE001  report the failure to the sender instead of staying silent
        logger.error("Telegram command failed: command=%s error=%s", name, type(exc).__name__)
        reply, alert, operator, outcome = FAILED_TEXT, None, None, "error"

    _count(name, outcome)
    if operator is not None:
        logger.info(
            "telegram command command=%s outcome=%s org=%s user=%s", name, outcome,
            operator.organization_id, operator.user_id,
        )
    await client.send_message(chat_id, reply)
    if alert is not None and operator is not None:
        await notify_organization(supabase, client, operator.organization_id, alert, exclude_chat_id=chat_id)


async def _dispatch(
    supabase: Any, chat_id: int, command: Command, now: datetime, mono: float
) -> tuple[str, str | None, OperatorContext | None]:
    """Returns (reply, alert for other linked chats, the operator who acted)."""
    if command.name in {"link", "start"}:
        if command.args:
            return await _cmd_link(supabase, chat_id, command.args, mono), None, None
        return NOT_LINKED_TEXT if await _linked_operator(supabase, chat_id) is None else HELP_TEXT, None, None
    if command.name == "help":
        return HELP_TEXT, None, None

    operator = await _linked_operator(supabase, chat_id)
    if operator is None:
        return NOT_LINKED_TEXT, None, None
    if operator.role < Role.ADMIN:
        return "Your role no longer allows panic commands. Ask an owner or admin.", None, None

    if command.name == "status":
        return await _cmd_status(supabase, operator, now), None, operator
    if command.name == "freeze_all":
        reply, alert = await _cmd_freeze_all(supabase, operator, command.args)
        return reply, alert, operator
    if command.name == "freeze":
        reply, alert = await _cmd_freeze(supabase, operator, command.args, now)
        return reply, alert, operator
    if command.name == "usage":
        return await _cmd_usage(supabase, operator, now), None, operator
    if command.name == "safemode":
        reply, alert = await _cmd_safemode(supabase, operator, command.args, now)
        return reply, alert, operator
    if command.name in {"unfreeze", "revoke"}:
        return f"/{command.name} is only available in the dashboard.", None, operator
    return HELP_TEXT, None, operator
