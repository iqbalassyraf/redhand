"""
Outbound Telegram Bot API client.

Telegram carries the bot token in the request URL, so this module takes care that the token never
reaches a log line: httpx's INFO request log (which prints the URL) is silenced, and errors are
reported by class name only.
"""

from __future__ import annotations

import logging
from typing import Protocol

import httpx

from redhand_core.config import Settings

logger = logging.getLogger("redhand.core.telegram")

# httpx logs "HTTP Request: POST <url>" at INFO, and the URL contains the bot token.
for _noisy in ("httpx", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

API_BASE = "https://api.telegram.org"
SEND_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
MAX_MESSAGE_LENGTH = 3500


class TelegramClient(Protocol):
    async def send_message(self, chat_id: int, text: str) -> bool:
        """Sends plain text (no formatting, so agent names cannot inject markup). True on success."""
        ...


class HttpTelegramClient:
    def __init__(self, token: str, http: httpx.AsyncClient | None = None) -> None:
        self._url = f"{API_BASE}/bot{token}/sendMessage"
        self._http = http or httpx.AsyncClient(timeout=SEND_TIMEOUT)

    async def send_message(self, chat_id: int, text: str) -> bool:
        payload = {
            "chat_id": chat_id,
            "text": text[:MAX_MESSAGE_LENGTH],
            "disable_web_page_preview": True,
        }
        try:
            response = await self._http.post(self._url, json=payload)
        except httpx.HTTPError as exc:
            logger.warning("Telegram send failed: %s", type(exc).__name__)
            return False
        if response.status_code != 200:
            logger.warning("Telegram send refused: HTTP %s", response.status_code)
            return False
        return True


_client: HttpTelegramClient | None = None


def get_telegram_client_for(settings: Settings) -> TelegramClient | None:
    """The shared client, or None when the bot token is not configured."""
    global _client
    token = settings.TELEGRAM_BOT_TOKEN
    if token is None:
        return None
    if _client is None:
        _client = HttpTelegramClient(token.get_secret_value())
    return _client
