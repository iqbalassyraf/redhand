"""
Telegram panic command (Phase 2, M1): linking, commands, authorization, replay, failure modes,
alerts, and the rule that the bot token never reaches a log line. Telegram is replaced by a fake
client; nothing here touches the network.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from pydantic import SecretStr
import pytest

from redhand_core.config import Settings
from redhand_core.routers import telegram as telegram_router
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter
from redhand_core.telegram import bot
from redhand_core.telegram.bot import (
    CODE_ALPHABET,
    CODE_LENGTH,
    generate_link_code,
    hash_link_code,
    parse_command,
)
from redhand_core.telegram.client import HttpTelegramClient

from core_helpers import make_client, operator_headers

WEBHOOK_SECRET = "telegram-webhook-secret-0123456789abcdef"
BOT_TOKEN = "123456789:AAFakeTokenForTestsOnly_0123456789abc"
BOT_USERNAME = "redhand_test_bot"
OWNER_CHAT = 1001
SECOND_CHAT = 1002
OTHER_ORG = "00000000-0000-0000-0000-0000000000f0"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"


class FakeTelegram:
    """Records what the bot would send."""

    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []
        self.fail = False

    async def send_message(self, chat_id: int, text: str) -> bool:
        if self.fail:
            raise RuntimeError("telegram is down")
        self.sent.append((chat_id, text))
        return True

    def to(self, chat_id: int) -> list[str]:
        return [text for chat, text in self.sent if chat == chat_id]

    def last(self, chat_id: int) -> str:
        return self.to(chat_id)[-1]


class Env:
    def __init__(self, **settings: Any) -> None:
        self.store = LocalSupabaseAdapter()
        self.store.tables["organizations"].append({"id": OTHER_ORG, "name": "Other", "slug": "other", "safe_mode": False})
        self.store.tables["organization_members"].append(
            {"id": str(uuid4()), "organization_id": OTHER_ORG, "user_id": OTHER_OWNER, "role": "owner"}
        )
        settings.setdefault("TELEGRAM_BOT_TOKEN", SecretStr(BOT_TOKEN))
        settings.setdefault("TELEGRAM_WEBHOOK_SECRET", SecretStr(WEBHOOK_SECRET))
        settings.setdefault("TELEGRAM_BOT_USERNAME", BOT_USERNAME)
        self.client, self.settings = make_client(self.store, **settings)
        self.fake = FakeTelegram()
        overrides = self.client.app.dependency_overrides  # type: ignore[attr-defined]
        overrides[telegram_router.get_required_telegram_client] = lambda: self.fake
        overrides[telegram_router.get_optional_telegram_client] = lambda: self.fake
        self._update_id = 100
        bot._command_limiter._events.clear()
        bot._link_limiter._events.clear()
        telegram_router._code_limiter._events.clear()

    def h(self, user: str = "owner") -> dict[str, str]:
        return operator_headers(user, self.settings)

    def send(
        self,
        text: str,
        chat: int = OWNER_CHAT,
        *,
        update_id: int | None = None,
        chat_type: str = "private",
        secret: str | None = WEBHOOK_SECRET,
    ) -> Any:
        if update_id is None:
            self._update_id += 1
            update_id = self._update_id
        body = {
            "update_id": update_id,
            "message": {"message_id": 1, "chat": {"id": chat, "type": chat_type}, "from": {"id": chat}, "text": text},
        }
        headers = {"X-Telegram-Bot-Api-Secret-Token": secret} if secret is not None else {}
        return self.client.post("/v1/telegram/webhook", json=body, headers=headers)

    def link(self, user: str = "owner", chat: int = OWNER_CHAT) -> str:
        resp = self.client.post("/v1/telegram/link-code", headers=self.h(user))
        assert resp.status_code == 201, resp.text
        code: str = resp.json()["code"]
        assert self.send(f"/link {code}", chat).status_code == 200
        return code

    def register(self, name: str) -> dict[str, Any]:
        resp = self.client.post(
            "/v1/passports",
            json={"name": name, "framework": "n8n", "scopes": [{"server": "xero", "tool": "*"}]},
            headers=self.h("admin"),  # registering an agent issues its key: admin (D1, owner decision 2026-11-17)
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["passport"]

    def statuses(self) -> dict[str, str]:
        rows = self.client.get("/v1/passports", headers=self.h("viewer")).json()
        return {p["name"]: p["status"] for p in rows}

    def audit(self) -> list[dict[str, Any]]:
        return self.client.get("/v1/audit/control", headers=self.h("viewer")).json()

    def set_role(self, user: str, role: str) -> None:
        for member in self.store.tables["organization_members"]:
            if member["user_id"] == DEV_OPERATORS[user]["id"]:
                member["role"] = role


@pytest.fixture
def env() -> Env:
    return Env()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_parse_command() -> None:
    assert parse_command("/freeze_all", None) == bot.Command("freeze_all", "")
    assert parse_command("/FREEZE_ALL  too   late ", None) == bot.Command("freeze_all", "too   late")
    assert parse_command("/freeze Invoice Bot", None) == bot.Command("freeze", "Invoice Bot")
    assert parse_command(f"/status@{BOT_USERNAME}", BOT_USERNAME) == bot.Command("status", "")
    assert parse_command("/status@someone_elses_bot", BOT_USERNAME) is None
    assert parse_command("freeze everything please", None) is None
    assert parse_command("", None) is None


def test_link_codes_are_unambiguous_and_stored_hashed() -> None:
    codes = {generate_link_code() for _ in range(200)}
    assert len(codes) == 200
    assert all(len(c) == CODE_LENGTH and set(c) <= set(CODE_ALPHABET) for c in codes)
    code = next(iter(codes))
    assert hash_link_code(code) != code and len(hash_link_code(code)) == 64


def test_webhook_secret_must_be_long_enough() -> None:
    with pytest.raises(ValueError):
        Settings(ENVIRONMENT="test", TELEGRAM_WEBHOOK_SECRET=SecretStr("short"))  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Webhook authentication and input handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("secret", [None, "", "wrong-secret", WEBHOOK_SECRET[:-1]])
def test_webhook_rejects_wrong_or_missing_secret_and_does_nothing(env: Env, secret: str | None) -> None:
    env.link()
    before = env.statuses()
    resp = env.send("/freeze_all", secret=secret)
    assert resp.status_code == 401
    assert env.statuses() == before
    assert not any("Froze" in t for t in env.fake.to(OWNER_CHAT))


def test_webhook_is_closed_when_telegram_is_not_configured() -> None:
    unconfigured = Env(TELEGRAM_BOT_TOKEN=None, TELEGRAM_WEBHOOK_SECRET=None)
    # The fake client is injected by the Env, so remove that override to see the real behaviour.
    unconfigured.client.app.dependency_overrides.pop(telegram_router.get_required_telegram_client)  # type: ignore[attr-defined]
    assert unconfigured.send("/status").status_code == 503
    assert unconfigured.client.post("/v1/telegram/link-code", headers=unconfigured.h()).status_code == 503


def test_webhook_rejects_oversized_and_malformed_bodies(env: Env) -> None:
    headers = {"X-Telegram-Bot-Api-Secret-Token": WEBHOOK_SECRET}
    assert env.client.post("/v1/telegram/webhook", content=b"x" * 70_000, headers=headers).status_code == 413
    assert env.client.post("/v1/telegram/webhook", content=b"not json", headers=headers).status_code == 400
    assert env.client.post("/v1/telegram/webhook", json={"no": "update_id"}, headers=headers).status_code == 400


def test_webhook_ignores_group_chats_and_non_text_updates(env: Env) -> None:
    env.link()
    assert env.send("/freeze_all", chat_type="group").status_code == 200
    headers = {"X-Telegram-Bot-Api-Secret-Token": WEBHOOK_SECRET}
    assert env.client.post("/v1/telegram/webhook", json={"update_id": 7, "edited_message": {}}, headers=headers).status_code == 200
    assert set(env.statuses().values()) == {"active"}
    assert env.fake.sent == [(OWNER_CHAT, env.fake.sent[0][1])]  # only the "Linked" reply


# ---------------------------------------------------------------------------
# Linking
# ---------------------------------------------------------------------------


def test_owner_links_a_chat_with_a_one_time_code(env: Env) -> None:
    resp = env.client.post("/v1/telegram/link-code", headers=env.h("owner"))
    assert resp.status_code == 201
    body = resp.json()
    assert body["deep_link"] == f"https://t.me/{BOT_USERNAME}?start={body['code']}"
    stored = env.store.tables["telegram_link_codes"]
    assert body["code"] not in str(stored) and stored[0]["code_hash"] == hash_link_code(body["code"])

    env.send(f"/link {body['code']}")
    assert env.fake.last(OWNER_CHAT).startswith("Linked.")
    links = env.client.get("/v1/telegram/links", headers=env.h("owner")).json()
    assert len(links) == 1 and "chat_id" not in links[0]
    assert "telegram.linked" in [e["action"] for e in env.audit()]

    env.send(f"/link {body['code']}")  # a second use
    assert "invalid, already used or expired" in env.fake.last(OWNER_CHAT)


def test_start_with_a_code_links_too(env: Env) -> None:
    code = env.client.post("/v1/telegram/link-code", headers=env.h("owner")).json()["code"]
    env.send(f"/start {code}")
    assert env.fake.last(OWNER_CHAT).startswith("Linked.")


@pytest.mark.parametrize("text", ["/link", "/link nonsense", "/link AAAAAAAAAA", "/link ' OR 1=1 --"])
def test_bad_codes_link_nothing(env: Env, text: str) -> None:
    env.send(text)
    assert env.store.tables.get("telegram_links", []) == []
    assert "Linked" not in env.fake.last(OWNER_CHAT)


def test_only_admins_and_owners_can_create_codes(env: Env) -> None:
    for user in ("operator", "viewer"):
        assert env.client.post("/v1/telegram/link-code", headers=env.h(user)).status_code == 403
    assert env.client.post("/v1/telegram/link-code").status_code == 401
    assert env.client.post("/v1/telegram/link-code", headers=env.h("admin")).status_code == 201


def test_a_code_made_by_someone_since_demoted_cannot_link(env: Env) -> None:
    code = env.client.post("/v1/telegram/link-code", headers=env.h("admin")).json()["code"]
    env.set_role("admin", "viewer")
    env.send(f"/link {code}")
    assert "does not allow panic commands" in env.fake.last(OWNER_CHAT)
    assert env.store.tables.get("telegram_links", []) == []


def test_link_codes_are_rate_limited(env: Env) -> None:
    results = [env.client.post("/v1/telegram/link-code", headers=env.h()).status_code for _ in range(6)]
    assert results == [201] * 5 + [429]


def test_link_attempts_are_rate_limited_per_chat(env: Env) -> None:
    for _ in range(5):
        env.send("/link AAAAAAAAAA")
    env.send("/link AAAAAAAAAA")
    assert "Too many attempts" in env.fake.last(OWNER_CHAT)


def test_relinking_a_chat_to_another_operator_replaces_the_first(env: Env) -> None:
    env.link("owner")
    env.link("admin")  # same chat, different operator
    active = [link for link in env.store.tables["telegram_links"] if link["revoked_at"] is None]
    assert len(active) == 1 and active[0]["user_id"] == DEV_OPERATORS["admin"]["id"]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def test_unlinked_chat_cannot_do_anything(env: Env) -> None:
    env.register("Alpha")
    for command in ("/freeze_all", "/freeze Alpha", "/status"):
        env.send(command, chat=555)
        assert "not linked" in env.fake.last(555)
    assert env.statuses()["Alpha"] == "active"
    assert not [e for e in env.audit() if e["action"] == "organization.frozen_all"]


def test_freeze_all_from_telegram_stops_every_agent_and_is_audited(env: Env) -> None:
    env.register("Alpha")
    env.register("Beta")
    env.link()
    env.send("/freeze_all fraud suspected")
    assert env.fake.last(OWNER_CHAT).startswith("Froze ")
    assert set(env.statuses().values()) == {"frozen"}
    entry = next(e for e in env.audit() if e["action"] == "organization.frozen_all")
    assert entry["actor_user_id"] == DEV_OPERATORS["owner"]["id"]
    assert entry["reason"] == "via Telegram: fraud suspected"


def test_freeze_all_works_with_no_reason_and_repeats_safely(env: Env) -> None:
    env.link()
    env.send("/freeze_all")
    env.send("/freeze_all")
    assert env.fake.last(OWNER_CHAT).startswith("Froze 0 agents")
    assert set(env.statuses().values()) <= {"frozen", "revoked"}


def test_freeze_one_agent_by_name(env: Env) -> None:
    env.register("Alpha")
    env.register("Beta")
    env.link()
    env.send("/freeze alpha")  # case-insensitive
    assert env.fake.last(OWNER_CHAT) == "Froze Alpha."
    assert env.statuses()["Alpha"] == "frozen" and env.statuses()["Beta"] == "active"
    env.send("/freeze Nobody")
    assert "No active agent has that name" in env.fake.last(OWNER_CHAT)
    env.send("/freeze")
    assert "Say which agent" in env.fake.last(OWNER_CHAT)


def test_status_counts(env: Env) -> None:
    env.register("Alpha")
    env.link()
    env.send("/freeze Alpha")
    env.send("/status")
    assert "1 frozen" in env.fake.last(OWNER_CHAT)


def test_unfreeze_and_revoke_are_not_available_from_telegram(env: Env) -> None:
    alpha = env.register("Alpha")
    env.link()
    env.send("/freeze Alpha")
    for command in ("/unfreeze Alpha", "/revoke Alpha", f"/unfreeze {alpha['id']}"):
        env.send(command)
        assert "only available in the dashboard" in env.fake.last(OWNER_CHAT)
    assert env.statuses()["Alpha"] == "frozen"


def test_help_and_plain_text(env: Env) -> None:
    env.link()
    env.send("/help")
    assert "/freeze_all" in env.fake.last(OWNER_CHAT)
    env.send("please stop everything")
    assert "/freeze_all" in env.fake.last(OWNER_CHAT)
    assert set(env.statuses().values()) == {"active"}


def test_commands_for_another_bot_are_ignored(env: Env) -> None:
    env.link()
    sent = len(env.fake.sent)
    env.send("/freeze_all@someone_elses_bot")
    assert set(env.statuses().values()) == {"active"}
    assert "/freeze_all" in env.fake.sent[-1][1] and len(env.fake.sent) == sent + 1  # treated as plain text


# ---------------------------------------------------------------------------
# Authorization is re-checked on every command
# ---------------------------------------------------------------------------


def test_demoted_operator_loses_the_panic_command_at_once(env: Env) -> None:
    env.link("admin")
    env.set_role("admin", "viewer")
    env.send("/freeze_all")
    assert "no longer allows panic commands" in env.fake.last(OWNER_CHAT)
    assert set(env.statuses().values()) == {"active"}


def test_operator_removed_from_the_organization_loses_the_panic_command(env: Env) -> None:
    env.link("admin")
    env.store.tables["organization_members"] = [
        m for m in env.store.tables["organization_members"] if m["user_id"] != DEV_OPERATORS["admin"]["id"]
    ]
    env.send("/freeze_all")
    assert "not linked" in env.fake.last(OWNER_CHAT)
    assert set(env.statuses().values()) == {"active"}


def test_unlinking_stops_the_phone(env: Env) -> None:
    env.link()
    link_id = env.client.get("/v1/telegram/links", headers=env.h()).json()[0]["id"]
    assert env.client.post(f"/v1/telegram/links/{link_id}/unlink", headers=env.h()).json()["changed"] is True
    assert env.client.post(f"/v1/telegram/links/{link_id}/unlink", headers=env.h()).json()["changed"] is False
    env.send("/freeze_all")
    assert "not linked" in env.fake.last(OWNER_CHAT)
    assert set(env.statuses().values()) == {"active"}
    assert "telegram.unlinked" in [e["action"] for e in env.audit()]


def test_only_admins_can_list_or_unlink_and_not_across_tenants(env: Env) -> None:
    env.link()
    link_id = env.client.get("/v1/telegram/links", headers=env.h()).json()[0]["id"]
    assert env.client.get("/v1/telegram/links", headers=env.h("viewer")).status_code == 403
    assert env.client.post(f"/v1/telegram/links/{link_id}/unlink", headers=env.h("operator")).status_code == 403
    from uuid import UUID

    other = operator_headers(settings=env.settings, user_id=UUID(OTHER_OWNER))
    assert env.client.get("/v1/telegram/links", headers=other).json() == []
    assert env.client.post(f"/v1/telegram/links/{link_id}/unlink", headers=other).status_code == 404
    env.send("/freeze_all")
    assert env.fake.last(OWNER_CHAT).startswith("Froze ")


def test_a_chat_linked_to_one_tenant_cannot_touch_another(env: Env) -> None:
    other_agent = {
        "id": str(uuid4()), "organization_id": OTHER_ORG, "external_agent_id": "theirs", "name": "Theirs",
        "framework": "n8n", "environment": "production", "scopes": [], "status": "active",
        "expires_at": "2099-01-01T00:00:00+00:00", "version": 1,
    }
    env.store.tables["agents"].append(other_agent)
    env.link()
    env.send("/freeze_all")
    env.send("/freeze Theirs")
    assert other_agent["status"] == "active"
    assert "No active agent has that name" in env.fake.last(OWNER_CHAT)
    assert any(a["organization_id"] == DEFAULT_ORG_ID and a["status"] == "frozen" for a in env.store.tables["agents"])


# ---------------------------------------------------------------------------
# Replay, rate limits and failure modes
# ---------------------------------------------------------------------------


def test_a_replayed_update_is_not_processed_twice(env: Env) -> None:
    env.link()
    env.send("/freeze_all", update_id=9000)
    audits = len([e for e in env.audit() if e["action"] == "organization.frozen_all"])
    replies = len(env.fake.sent)
    assert env.send("/freeze_all", update_id=9000).status_code == 200
    assert len([e for e in env.audit() if e["action"] == "organization.frozen_all"]) == audits
    assert len(env.fake.sent) == replies


def test_commands_are_rate_limited_per_chat() -> None:
    limited = Env(TELEGRAM_COMMANDS_PER_MINUTE=3)
    limited.link()  # uses one
    for _ in range(5):
        limited.send("/status")
    assert len(limited.fake.to(OWNER_CHAT)) == 3


def test_a_rate_limited_chat_does_not_cost_a_database_write_per_message() -> None:
    """The limit is checked before the update is claimed: a flood of messages from one chat must not become a flood of writes (H3.3)."""
    limited = Env(TELEGRAM_COMMANDS_PER_MINUTE=3)
    calls: list[str] = []
    original = limited.store.rpc

    def spy(name: str, params: Any = None) -> Any:
        calls.append(name)
        return original(name, params)

    limited.store.rpc = spy  # type: ignore[method-assign]
    for _ in range(10):
        limited.send("/status")
    assert calls.count("telegram_claim_update") == 3, calls


def test_a_failure_is_reported_and_nothing_is_half_done(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.register("Alpha")
    env.link()

    async def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("database is down: password=hunter2")

    monkeypatch.setattr(bot.service, "freeze_all", boom)
    resp = env.send("/freeze_all")
    assert resp.status_code == 200  # Telegram must not redeliver; the sender is told instead
    reply = env.fake.last(OWNER_CHAT)
    assert "NOT carried out" in reply and "hunter2" not in reply
    assert env.statuses()["Alpha"] == "active"


def test_a_refused_action_says_why(env: Env) -> None:
    env.register("Alpha")
    env.link()
    env.send("/freeze Alpha")
    env.send("/freeze Alpha")  # already frozen: not an active agent any more
    assert "No active agent has that name" in env.fake.last(OWNER_CHAT)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_other_linked_chats_are_told_about_a_telegram_freeze(env: Env) -> None:
    env.link("owner", OWNER_CHAT)
    env.link("admin", SECOND_CHAT)
    env.send("/freeze_all", OWNER_CHAT)
    assert "frozen from Telegram" in env.fake.last(SECOND_CHAT)
    assert not any("frozen from Telegram" in t for t in env.fake.to(OWNER_CHAT))  # sender gets the reply only


def test_dashboard_actions_alert_linked_chats(env: Env) -> None:
    alpha = env.register("Alpha")
    env.link()
    assert env.client.post(f"/v1/passports/{alpha['id']}/freeze", json={"reason": "odd"}, headers=env.h()).status_code == 200
    assert "Alpha was frozen" in env.fake.last(OWNER_CHAT) and "Reason: odd" in env.fake.last(OWNER_CHAT)
    env.client.post(f"/v1/passports/{alpha['id']}/freeze", json={}, headers=env.h())  # no change: no alert
    count = len(env.fake.sent)
    env.client.post(f"/v1/passports/{alpha['id']}/unfreeze", json={"confirm": True}, headers=env.h())
    env.client.post("/v1/passports/freeze-all", json={"confirm": True}, headers=env.h())
    assert len(env.fake.sent) == count + 2
    assert "All agents were frozen" in env.fake.last(OWNER_CHAT)
    env.client.post(f"/v1/passports/{alpha['id']}/revoke", json={"confirm": True}, headers=env.h())
    assert "permanently revoked" in env.fake.last(OWNER_CHAT)


def test_alert_failure_never_breaks_the_control_action(env: Env) -> None:
    alpha = env.register("Alpha")
    env.link()
    env.fake.fail = True
    resp = env.client.post(f"/v1/passports/{alpha['id']}/freeze", json={}, headers=env.h())
    assert resp.status_code == 200 and env.statuses()["Alpha"] == "frozen"
    assert env.client.post("/v1/passports/freeze-all", json={"confirm": True}, headers=env.h()).status_code == 200


def test_dashboard_actions_work_when_telegram_is_not_configured() -> None:
    plain = Env(TELEGRAM_BOT_TOKEN=None, TELEGRAM_WEBHOOK_SECRET=None)
    for dep in (telegram_router.get_required_telegram_client, telegram_router.get_optional_telegram_client):
        plain.client.app.dependency_overrides.pop(dep, None)  # type: ignore[attr-defined]
    alpha = plain.register("Alpha")
    assert plain.client.post(f"/v1/passports/{alpha['id']}/freeze", json={}, headers=plain.h()).status_code == 200


# ---------------------------------------------------------------------------
# The bot token never reaches a log
# ---------------------------------------------------------------------------


def test_http_client_failures_never_log_the_token(caplog: pytest.LogCaptureFixture) -> None:
    import asyncio

    import httpx

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}")

    client = HttpTelegramClient(BOT_TOKEN, httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(client.send_message(1, "hello")) is False
    assert BOT_TOKEN not in caplog.text
    assert "ConnectError" in caplog.text


def test_http_client_reports_non_200_without_the_token(caplog: pytest.LogCaptureFixture) -> None:
    import asyncio

    import httpx

    client = HttpTelegramClient(
        BOT_TOKEN, httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403, json={})))
    )
    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(client.send_message(1, "hello")) is False
    assert BOT_TOKEN not in caplog.text and "403" in caplog.text


def test_httpx_request_logging_is_silenced_because_urls_carry_the_token() -> None:
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING


# ---------------------------------------------------------------------------
# Safe Mode commands (Phase 2, M2)
# ---------------------------------------------------------------------------


def _org_safe_mode(env: Env) -> bool:
    return bool(env.client.get("/v1/organization/safe-mode", headers=env.h("viewer")).json()["enabled"])


def test_safemode_on_for_everyone_from_telegram(env: Env) -> None:
    env.link()
    env.send("/safemode on")
    assert "Safe Mode is on for all agents" in env.fake.last(OWNER_CHAT)
    assert _org_safe_mode(env) is True
    entry = next(e for e in env.audit() if e["action"] == "organization.safe_mode_enabled")
    assert entry["reason"] == "via Telegram" and entry["actor_user_id"] == DEV_OPERATORS["owner"]["id"]
    env.send("/safemode on")
    assert "already on" in env.fake.last(OWNER_CHAT)
    env.send("/status")
    assert "Safe Mode for all agents: on" in env.fake.last(OWNER_CHAT)


def test_safemode_on_for_one_agent_by_name(env: Env) -> None:
    env.register("Alpha")
    env.link()
    env.send("/safemode on alpha")
    assert env.fake.last(OWNER_CHAT) == "Safe Mode is on for Alpha."
    rows = env.client.get("/v1/passports", headers=env.h("viewer")).json()
    assert {p["name"]: p["safe_mode"] for p in rows}["Alpha"] is True
    assert _org_safe_mode(env) is False
    env.send("/safemode on Nobody")
    assert "No agent has that name" in env.fake.last(OWNER_CHAT)


def test_safemode_off_is_not_available_from_telegram(env: Env) -> None:
    env.link()
    env.send("/safemode on")
    for text in ("/safemode off", "/safemode OFF Alpha"):
        env.send(text)
        assert "only available in the dashboard" in env.fake.last(OWNER_CHAT)
    assert _org_safe_mode(env) is True


@pytest.mark.parametrize("text", ["/safemode", "/safemode maybe", "/safemode toggle all"])
def test_safemode_needs_a_clear_on_or_off(env: Env, text: str) -> None:
    env.link()
    env.send(text)
    assert "Use /safemode on" in env.fake.last(OWNER_CHAT)
    assert _org_safe_mode(env) is False


def test_safemode_from_an_unlinked_or_demoted_chat_does_nothing(env: Env) -> None:
    env.send("/safemode on", chat=555)
    assert "not linked" in env.fake.last(555)
    env.link("admin")
    env.set_role("admin", "viewer")
    env.send("/safemode on")
    assert "no longer allows panic commands" in env.fake.last(OWNER_CHAT)
    assert _org_safe_mode(env) is False


def test_other_chats_are_told_when_safe_mode_changes(env: Env) -> None:
    env.link("owner", OWNER_CHAT)
    env.link("admin", SECOND_CHAT)
    env.send("/safemode on", OWNER_CHAT)
    assert "Safe Mode was turned on for all agents from Telegram" in env.fake.last(SECOND_CHAT)
    env.client.post(
        "/v1/organization/safe-mode", json={"enabled": False, "confirm": True, "reason": "all clear"}, headers=env.h("admin")
    )
    assert "Safe Mode was turned off for all agents" in env.fake.last(OWNER_CHAT)
    assert "Reason: all clear" in env.fake.last(OWNER_CHAT)


# ---------------------------------------------------------------------------
# /usage (Phase 2, M3c)
# ---------------------------------------------------------------------------


def test_usage_shows_todays_calls_against_each_limit(env: Env) -> None:
    from redhand_core.passports import budget as budget_rules
    from redhand_core.passports.models import utcnow

    alpha, beta = env.register("Alpha"), env.register("Beta")
    env.register("Gamma")
    day = budget_rules.local_day(utcnow(), 480).isoformat()
    env.client.put(f"/v1/passports/{alpha['id']}/budget", json={"daily_call_limit": 10}, headers=env.h("operator"))
    env.link()
    for agent, calls in ((alpha, 8), (beta, 3)):
        env.store.tables.setdefault("agent_usage_daily", []).append(
            {"agent_id": agent["id"], "organization_id": DEFAULT_ORG_ID, "day_key": day, "instance_id": "gateway-instance-aaaa", "calls": calls}
        )
    env.send("/usage")
    reply = env.fake.last(OWNER_CHAT)
    assert reply.startswith("Tool calls today (") and "UTC+8" in reply
    assert "Alpha: 8 of 10 calls (80%)" in reply and "Beta: 3 calls (no limit)" in reply
    assert "Gamma" not in reply  # no calls and no limit: nothing to say
    assert "spend" not in reply.lower() and "$" not in reply


def test_usage_with_no_calls_and_from_an_unlinked_chat(env: Env) -> None:
    env.send("/usage", chat=555)
    assert "not linked" in env.fake.last(555)
    env.link()
    env.send("/usage")
    assert "No calls yet." in env.fake.last(OWNER_CHAT)
