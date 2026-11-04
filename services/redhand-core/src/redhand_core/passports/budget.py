"""
Budget Guard rules that need no I/O: the local day boundary, the system actor, and which limit changes
count as relaxing a restriction. See docs/adr/0010-budget-guard.md.

A "call" is a tool call the gateway forwards upstream. RedHand counts calls through the gateway only: it
does not see LLM tokens or money, and no text built from these helpers should say "spend".
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

BudgetAction = Literal["deny", "freeze"]

# Auto-freezes are recorded under this fixed actor. It is not a user, cannot log in, and only ever
# freezes (never unfreezes or widens anything).
SYSTEM_ACTOR_ID = UUID("00000000-0000-0000-0000-000000000000")
DEFAULT_UTC_OFFSET_MINUTES = 480  # UTC+8: Malaysia and Singapore, no daylight saving
MIN_UTC_OFFSET_MINUTES = -720
MAX_UTC_OFFSET_MINUTES = 840
MAX_DAILY_CALL_LIMIT = 10_000_000


def normalize_offset(raw: object) -> int:
    """A stored offset in minutes, or the default when it is missing or not a sane integer."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        return DEFAULT_UTC_OFFSET_MINUTES
    if not MIN_UTC_OFFSET_MINUTES <= raw <= MAX_UTC_OFFSET_MINUTES:
        return DEFAULT_UTC_OFFSET_MINUTES
    return raw


def local_day(now: datetime, offset_minutes: int) -> date:
    """The organization's current local date. `now` must be timezone-aware."""
    return (now.astimezone(timezone.utc) + timedelta(minutes=offset_minutes)).date()


def next_reset_utc(now: datetime, offset_minutes: int) -> datetime:
    """The UTC instant at which the organization's next local day begins."""
    next_local_midnight = datetime.combine(
        local_day(now, offset_minutes) + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc
    )
    return next_local_midnight - timedelta(minutes=offset_minutes)


def format_offset(offset_minutes: int) -> str:
    sign = "+" if offset_minutes >= 0 else "-"
    hours, minutes = divmod(abs(offset_minutes), 60)
    return f"UTC{sign}{hours}" + (f":{minutes:02d}" if minutes else "")


def is_relaxation(
    old_limit: int | None, new_limit: int | None, old_action: str, new_action: str
) -> bool:
    """
    True when a change makes the budget LESS restrictive: removing a limit, raising it, or turning
    auto-freeze off. Those need an admin and explicit confirmation. Setting a limit where there was
    none, lowering it, or turning auto-freeze on only restricts, so a security operator may do it.
    """
    if old_limit is not None and (new_limit is None or new_limit > old_limit):
        return True
    return old_action == "freeze" and new_action != "freeze"
