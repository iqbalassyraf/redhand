"""
Telegram alerts about one agent end with a link to that agent's incident view (Phase 4.5 B3), when the dashboard's address is configured.
One link per message (alerts about one agent are batched), never on an alert that is not about one agent, never past the message limit.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from pydantic import SecretStr, ValidationError

from redhand_core.config import Settings
from redhand_core.services.local_store import DEFAULT_ORG_ID
from redhand_core.telegram import bot

from test_risk_engine import GATEWAY, SERVICE_TOKEN
from test_telegram import Env as TelegramEnv

DASHBOARD = "https://redhand.example.com"


class Env(TelegramEnv):
    """Alerts are sent outside a request, so they read the process settings (get_settings), as in production: set by environment."""

    def __init__(self) -> None:
        super().__init__(INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE_TOKEN))
        self.agent = self.register("Linked bot")["id"]
        self.link()

    def trip(self) -> None:
        resp = self.client.post("/v1/honeytokens", json={"label": "Decoy", "kind": "api_key", "action_on_use": "alert"}, headers=self.h("admin"))
        body = {"organization_id": DEFAULT_ORG_ID, "trip_id": str(uuid4()), "agent_id": self.agent, "kind": "honeytoken",
                "ref_id": resp.json()["id"], "seen_in": "arguments", "tool_name": "send_email", "server": "mail"}
        assert self.client.post("/internal/v1/trips", json=body, headers=GATEWAY).status_code == 200


@pytest.fixture
def dashboard(monkeypatch: pytest.MonkeyPatch) -> Any:
    from redhand_core.config import get_settings

    def set_to(value: str | None) -> None:
        if value is None:
            monkeypatch.delenv("DASHBOARD_URL", raising=False)
        else:
            monkeypatch.setenv("DASHBOARD_URL", value)
        get_settings.cache_clear()

    yield set_to
    get_settings.cache_clear()


def test_an_alert_about_an_agent_links_to_its_timeline_once(dashboard: Any) -> None:
    dashboard(DASHBOARD)
    env = Env()
    before = len(env.fake.sent)
    env.trip()
    texts = [text for _, text in env.fake.sent[before:]]
    assert texts, "the trip raised an alert"
    body = texts[-1]
    link = f"Timeline: {DASHBOARD}/passports/{env.agent}/timeline"
    assert body.endswith(link) and body.count("Timeline: ") == 1


def test_no_link_when_the_dashboard_address_is_not_configured(dashboard: Any) -> None:
    dashboard(None)
    env = Env()
    before = len(env.fake.sent)
    env.trip()
    texts = [text for _, text in env.fake.sent[before:]]
    assert texts and all("Timeline: " not in text for text in texts)


@pytest.mark.asyncio
async def test_an_alert_that_is_not_about_one_agent_has_no_link(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[str] = []

    async def capture(supabase: Any, client: Any, organization_id: Any, text: str) -> None:
        sent.append(text)

    monkeypatch.setattr(bot, "notify_organization", capture)
    monkeypatch.setattr(bot, "_dashboard_url", lambda: DASHBOARD)
    batch = bot.AlertBatch()
    batch.add(uuid4(), "Tool pinning: server 'deepwiki' has tool changes waiting for your review.")
    await batch.flush(None, None)
    assert sent and "Timeline: " not in sent[0]


@pytest.mark.asyncio
async def test_the_link_survives_a_message_cut_to_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[str] = []

    async def capture(supabase: Any, client: Any, organization_id: Any, text: str) -> None:
        sent.append(text)

    monkeypatch.setattr(bot, "notify_organization", capture)
    monkeypatch.setattr(bot, "_dashboard_url", lambda: DASHBOARD)
    agent = uuid4()
    batch = bot.AlertBatch()
    batch.add(uuid4(), "x" * (bot.MAX_ALERT_CHARS * 2), agent)
    await batch.flush(None, None)
    assert len(sent[0]) <= bot.MAX_ALERT_CHARS and sent[0].endswith(f"Timeline: {DASHBOARD}/passports/{agent}/timeline")


@pytest.mark.parametrize("url", ["http://redhand.example.com", "https://user:pw@redhand.example.com", "https://redhand.example.com/?q=1",
                                 "https://redhand.example.com/#x", "javascript:alert(1)", "redhand.example.com"])
def test_a_shared_environment_accepts_only_a_plain_https_address(url: str) -> None:
    with pytest.raises(ValidationError, match="DASHBOARD_URL"):
        Settings(ENVIRONMENT="staging", OPERATOR_JWKS_URL="https://x.supabase.co/auth/v1/.well-known/jwks.json",
                 OPERATOR_JWT_ISSUER="https://x.supabase.co/auth/v1", DASHBOARD_URL=url)  # type: ignore[arg-type]


def test_the_address_is_kept_without_a_trailing_slash() -> None:
    s = Settings(ENVIRONMENT="staging", OPERATOR_JWKS_URL="https://x.supabase.co/auth/v1/.well-known/jwks.json",
                 OPERATOR_JWT_ISSUER="https://x.supabase.co/auth/v1", DASHBOARD_URL="https://redhand.example.com/")  # type: ignore[arg-type]
    assert s.DASHBOARD_URL == "https://redhand.example.com"


def test_development_may_use_a_local_http_address() -> None:
    s = Settings(ENVIRONMENT="development", OPERATOR_JWT_SECRET=SecretStr("s" * 40), DASHBOARD_URL="http://localhost:3000")  # type: ignore[arg-type]
    assert s.DASHBOARD_URL == "http://localhost:3000"
