"""
The optional Telegram client as a FastAPI dependency, in a module that imports no router, so the telemetry ingest route can alert without
a circular import (routers/telegram.py imports routers/telemetry.py). routers/telegram.py re-exports both names: they are the same objects, so
`app.dependency_overrides[telegram_router.get_optional_telegram_client]` still replaces this dependency everywhere.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from redhand_core.config import Settings, get_settings
from redhand_core.telegram.client import TelegramClient, get_telegram_client_for

SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_optional_telegram_client(settings: SettingsDep) -> TelegramClient | None:
    """None when Telegram is not configured; alerts then silently do nothing."""
    return get_telegram_client_for(settings)


OptionalClientDep = Annotated[TelegramClient | None, Depends(get_optional_telegram_client)]
