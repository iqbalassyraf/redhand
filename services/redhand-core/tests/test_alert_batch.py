"""
One notification per event (Phase 4.5 B1): the alerts one request raises leave as one Telegram message per organization and agent, alerts
about different agents stay separate, a repeated text is sent once, and a message never exceeds Telegram's limit.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID, uuid4

from redhand_core.telegram.bot import MAX_ALERT_CHARS, AlertBatch, send_alert

ORG = UUID("00000000-0000-0000-0000-000000000010")


class Recorder:
    """Stands in for notify_organization's two collaborators: the chat lookup and the Telegram client."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send_message(self, chat: int, text: str) -> None:
        self.sent.append(text)


class Links:
    def table(self, _name: str) -> Any:
        return self

    def select(self, *_a: Any) -> Any:
        return self

    def eq(self, *_a: Any) -> Any:
        return self

    async def execute(self) -> Any:
        class R:
            data = [{"chat_id": 1, "revoked_at": None}]
        return R()


def run(batch: AlertBatch, client: Recorder) -> list[str]:
    asyncio.run(batch.flush(Links(), client))  # type: ignore[arg-type]  # the fakes implement only what notify_organization calls
    return client.sent


def test_alerts_about_one_agent_leave_as_one_message_in_order() -> None:
    agent, batch, client = uuid4(), AlertBatch(), Recorder()
    batch.add(ORG, "Honeytoken used: ...", agent)
    batch.add(ORG, "Risk: ...", agent)
    assert run(batch, client) == ["Honeytoken used: ...\n\nRisk: ..."]


def test_alerts_about_different_agents_stay_separate_messages() -> None:
    batch, client = AlertBatch(), Recorder()
    batch.add(ORG, "Budget Guard: A", uuid4())
    batch.add(ORG, "Budget Guard: B", uuid4())
    assert sorted(run(batch, client)) == ["Budget Guard: A", "Budget Guard: B"]


def test_the_same_text_twice_is_sent_once_and_flush_empties_the_batch() -> None:
    agent, batch, client = uuid4(), AlertBatch(), Recorder()
    batch.add(ORG, "Risk: same", agent)
    batch.add(ORG, "Risk: same", agent)
    assert run(batch, client) == ["Risk: same"]
    assert run(batch, client) == ["Risk: same"]  # a second flush sends nothing new


def test_a_long_message_is_cut_below_telegrams_limit() -> None:
    agent, batch, client = uuid4(), AlertBatch(), Recorder()
    batch.add(ORG, "x" * 3000, agent)
    batch.add(ORG, "y" * 3000, agent)
    (message,) = run(batch, client)
    assert len(message) == MAX_ALERT_CHARS and message.endswith("…") and MAX_ALERT_CHARS < 4096


def test_without_a_batch_an_alert_is_sent_at_once() -> None:
    client = Recorder()
    asyncio.run(send_alert(None, Links(), client, ORG, "now"))  # type: ignore[arg-type]
    assert client.sent == ["now"]
