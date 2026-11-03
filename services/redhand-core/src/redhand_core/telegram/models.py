"""
The slice of a Telegram update that the panic command reads.

Telegram adds fields over time, so unknown fields are ignored here (the one deliberate exception
to `extra="forbid"`). Everything that is read is typed and length-limited, and the request is only
parsed after the webhook secret has been verified.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

MAX_TEXT_LENGTH = 1000


class TelegramChat(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    type: str = Field(max_length=32)


class TelegramMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    chat: TelegramChat
    text: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)


class TelegramUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    update_id: int = Field(ge=0)
    message: TelegramMessage | None = None
