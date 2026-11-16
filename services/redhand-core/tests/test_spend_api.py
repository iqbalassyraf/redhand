"""
Model spend in redhand-core (Phase 4.5 B4a): what an agent's SDK reported, turned into an estimate, shown per agent, compared with an optional
dollar limit that raises ONE alert per agent per day and refuses nothing. The numbers are self-reported, so every response says so, and a model
with no known price is "price unknown", never $0.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from redhand_core.passports import budget as budget_rules
from redhand_core.passports.models import utcnow
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEFAULT_DEV_API_KEY
from redhand_core.services.metrics import get_metrics
from redhand_core.spend import service as spend_service
from redhand_core.spend.prices import PRICES_AS_OF_TEXT

from test_telegram import OTHER_ORG, OWNER_CHAT, Env as TelegramEnv

DEFAULT_ORG_ID_UUID = UUID(DEFAULT_ORG_ID)
SONNET = "claude-sonnet-5-5"  # $2 per million input tokens, $10 per million output tokens


class Env(TelegramEnv):
    def ingest(self, external_id: str, spans: list[dict[str, Any]], key: str = DEFAULT_DEV_API_KEY) -> Any:
        return self.client.post(
            "/v1/telemetry/ingest", headers={"X-RedHand-API-Key": key},
            json={"sdk_version": "0.1.0", "external_agent_id": external_id, "agent_name": external_id, "framework": "pytest",
                  "environment": "development", "spans": spans},
        )

    @staticmethod
    def span(model: str | None, prompt: int, completion: int, provider: str | None = "anthropic", at: Any = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "session_id": str(uuid4()), "trace_id": uuid4().hex, "span_id": uuid4().hex[:16], "step_type": "observation",
            "model_provider": provider, "model_name": model, "prompt_tokens": prompt, "completion_tokens": completion,
        }
        if at is not None:
            body["occurred_at"] = at.isoformat()
        return body

    def report(self, external_id: str, model: str | None, prompt: int, completion: int = 0, provider: str | None = "anthropic") -> str:
        response = self.ingest(external_id, [self.span(model, prompt, completion, provider)])
        assert response.status_code == 202, response.text
        return str(response.json()["agent_id"])

    def spend(self, user: str = "viewer") -> Any:
        return self.client.get("/v1/spend/agents", headers=self.h(user))

    def agent_view(self, agent_id: str, user: str = "viewer") -> dict[str, Any]:
        rows = self.spend(user).json()["agents"]
        return next(r for r in rows if r["agent_id"] == agent_id)

    def set_limit(self, agent_id: str, limit: int | None, user: str = "admin", **extra: Any) -> Any:
        return self.client.put(f"/v1/passports/{agent_id}/spend-limit", json={"spend_limit_micro_usd": limit, **extra}, headers=self.h(user))

    def alerts(self) -> list[str]:
        return [t for t in self.fake.to(OWNER_CHAT) if t.startswith("Spend alert")]


@pytest.fixture
def env() -> Env:
    return Env()


# --- reading ------------------------------------------------------------------------------------------------------------------------

def test_an_agents_reported_usage_is_shown_with_tokens_dollars_and_the_price_date(env: Env) -> None:
    agent = env.report("spend-bot", SONNET, 1_000_000, 100_000)
    body = env.spend().json()
    assert body["currency"] == "USD" and body["prices_as_of"] == PRICES_AS_OF_TEXT
    assert "estimated" in body["basis"].lower() and "sdk" in body["basis"].lower() and "invoice" in body["basis"].lower()
    view = env.agent_view(agent)
    assert (view["calls"], view["prompt_tokens"], view["completion_tokens"]) == (1, 1_000_000, 100_000)
    assert view["estimated_micro_usd"] == 3_000_000 and view["estimated_text"] == "$3.00"  # $2 input + $1 output
    assert view["usage_reported"] is True and view["unpriced_tokens"] == 0 and view["lower_bound"] is False
    assert view["models"][0]["model"] == SONNET and view["models"][0]["price_known"] is True and view["models"][0]["estimated_micro_usd"] == 3_000_000


def test_a_model_with_no_known_price_is_price_unknown_never_zero_dollars(env: Env) -> None:
    agent = env.report("unpriced-bot", "gpt-mystery", 5_000, 500, provider="openai")
    view = env.agent_view(agent)
    model = view["models"][0]
    assert model["price_known"] is False and model["estimated_micro_usd"] is None and model["estimated_text"] is None
    assert view["unpriced_tokens"] == 5_500 and view["unpriced_models"] == ["openai/gpt-mystery"]
    assert view["usage_reported"] is True


def test_unpriced_usage_is_reported_next_to_priced_usage_not_added_as_zero(env: Env) -> None:
    agent = env.report("mixed-bot", SONNET, 1_000_000)
    env.report("mixed-bot", "gpt-mystery", 7_000, 0, provider="openai")
    view = env.agent_view(agent)
    assert view["estimated_micro_usd"] == 2_000_000 and view["unpriced_tokens"] == 7_000 and view["calls"] == 2


def test_a_tiered_model_is_marked_as_a_lower_bound(env: Env) -> None:
    agent = env.report("tier-bot", "claude-haiku-5-5", 1_000_000)
    view = env.agent_view(agent)
    assert view["lower_bound"] is True and view["models"][0]["lower_bound"] is True


def test_an_agent_whose_sdk_reports_no_usage_says_so_instead_of_showing_zero_dollars(env: Env) -> None:
    agent = env.report("silent-bot", None, 0, 0, provider=None)
    view = env.agent_view(agent)
    assert view["usage_reported"] is False and view["models"] == [] and view["estimated_micro_usd"] == 0


def test_a_viewer_can_read_and_an_anonymous_caller_cannot(env: Env) -> None:
    env.report("read-bot", SONNET, 10)
    assert env.spend("viewer").status_code == 200
    assert env.client.get("/v1/spend/agents").status_code in (401, 403)


def test_an_organization_never_sees_another_organizations_spend(env: Env) -> None:
    env.report("mine", SONNET, 10)
    foreign = str(uuid4())
    env.store.tables["agents"].append({"id": foreign, "organization_id": OTHER_ORG, "external_agent_id": "theirs", "name": "Theirs", "status": "active"})
    env.store.tables["agent_model_daily"] = [{
        "organization_id": OTHER_ORG, "agent_id": foreign, "day": budget_rules.local_day(utcnow(), 480).isoformat(), "provider": "anthropic",
        "model": SONNET, "calls": 1, "prompt_tokens": 1, "completion_tokens": 1}]
    assert foreign not in {r["agent_id"] for r in env.spend().json()["agents"]}
    assert env.client.get(f"/v1/spend/agents/{foreign}", headers=env.h("viewer")).status_code == 404


def test_the_day_follows_the_organizations_offset(env: Env) -> None:
    now = utcnow()
    for offset in (480, -300):
        for org in env.store.tables["organizations"]:
            if org["id"] == DEFAULT_ORG_ID:
                org["utc_offset_minutes"] = offset
        assert env.spend().json()["day"] == budget_rules.local_day(now, offset).isoformat()


def test_the_detail_gives_seven_days_oldest_first_with_empty_days_kept(env: Env) -> None:
    agent = env.report("detail-bot", SONNET, 1_000_000)
    body = env.client.get(f"/v1/spend/agents/{agent}", headers=env.h("viewer")).json()
    days = body["days"]
    assert len(days) == 7 and [d["day"] for d in days] == sorted(d["day"] for d in days)
    assert days[-1]["estimated_micro_usd"] == 2_000_000 and all(d["usage_reported"] is False for d in days[:-1])
    assert body["agent"]["agent_id"] == agent and body["prices_as_of"] == PRICES_AS_OF_TEXT


def test_a_read_that_fails_is_an_error_never_a_clean_zero(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.report("fail-bot", SONNET, 10)
    original = env.store.rpc

    def broken(function: str, params: dict[str, Any] | None = None) -> Any:
        if function == "agent_model_usage":
            raise RuntimeError("database down")
        return original(function, params)

    monkeypatch.setattr(env.store, "rpc", broken)
    response = env.spend()
    assert response.status_code == 503 and "could not be read" in response.json()["detail"].lower()


# --- the limit ----------------------------------------------------------------------------------------------------------------------

def test_an_admin_sets_a_limit_and_it_is_audited_and_shown(env: Env) -> None:
    agent = env.report("limit-bot", SONNET, 10)
    response = env.set_limit(agent, 5_000_000, reason="keep it small")
    assert response.status_code == 200 and response.json() == {"agent_id": agent, "spend_limit_micro_usd": 5_000_000, "changed": True}
    view = env.agent_view(agent)
    assert view["spend_limit_micro_usd"] == 5_000_000 and view["spend_limit_text"] == "$5.00"
    entries = [e for e in env.audit() if e["action"] == "passport.spend_limit_changed"]
    assert len(entries) == 1 and entries[0]["details"] == {"old_limit": None, "new_limit": 5_000_000}


@pytest.mark.parametrize("user", ["operator", "viewer"])
def test_only_an_admin_can_change_a_limit(env: Env, user: str) -> None:
    agent = env.report("role-bot", SONNET, 10)
    assert env.set_limit(agent, 5_000_000, user=user).status_code == 403
    assert env.agent_view(agent)["spend_limit_micro_usd"] is None


def test_raising_or_removing_a_limit_needs_confirmation_and_lowering_does_not(env: Env) -> None:
    agent = env.report("confirm-bot", SONNET, 10)
    assert env.set_limit(agent, 5_000_000).status_code == 200  # first limit: tightens
    assert env.set_limit(agent, 4_000_000).status_code == 200  # lowering: tightens
    assert env.set_limit(agent, 9_000_000).status_code == 400  # raising: relaxes
    assert env.set_limit(agent, None).status_code == 400  # removing: relaxes
    assert env.agent_view(agent)["spend_limit_micro_usd"] == 4_000_000
    assert env.set_limit(agent, 9_000_000, confirm=True).status_code == 200
    assert env.set_limit(agent, None, confirm=True).status_code == 200
    assert env.agent_view(agent)["spend_limit_micro_usd"] is None


def test_setting_the_same_limit_changes_nothing_and_writes_no_audit_row(env: Env) -> None:
    agent = env.report("same-bot", SONNET, 10)
    env.set_limit(agent, 5_000_000)
    assert env.set_limit(agent, 5_000_000).json()["changed"] is False
    assert len([e for e in env.audit() if e["action"] == "passport.spend_limit_changed"]) == 1


@pytest.mark.parametrize("bad", [0, -1, 10**12 + 1, 1.5, "5", True])
def test_an_invalid_limit_is_refused(env: Env, bad: Any) -> None:
    agent = env.report("bad-bot", SONNET, 10)
    assert env.set_limit(agent, bad).status_code == 422


def test_an_unknown_field_is_refused(env: Env) -> None:
    agent = env.report("extra-bot", SONNET, 10)
    response = env.client.put(f"/v1/passports/{agent}/spend-limit", json={"spend_limit_micro_usd": 5, "tenant": "x"}, headers=env.h("admin"))
    assert response.status_code == 422


def test_another_organizations_agent_cannot_be_given_a_limit(env: Env) -> None:
    foreign = str(uuid4())
    env.store.tables["agents"].append({"id": foreign, "organization_id": OTHER_ORG, "external_agent_id": "t", "name": "T", "status": "active"})
    assert env.set_limit(foreign, 5_000_000).status_code == 404


def test_a_revoked_agents_limit_cannot_be_changed(env: Env) -> None:
    agent = env.report("revoked-bot", SONNET, 10)
    assert env.client.post(f"/v1/passports/{agent}/revoke", json={"confirm": True}, headers=env.h("admin")).status_code == 200
    assert env.set_limit(agent, 5_000_000).status_code == 409


# --- the alert ----------------------------------------------------------------------------------------------------------------------

def test_crossing_the_limit_raises_one_alert_exactly_at_the_number(env: Env) -> None:
    env.link()
    agent = env.report("cross-bot", SONNET, 400_000)  # $0.80
    env.set_limit(agent, 2_000_000)  # $2.00
    env.report("cross-bot", SONNET, 400_000)  # $1.60: below
    assert env.alerts() == []
    env.report("cross-bot", SONNET, 100_000)  # $1.80: below
    assert env.alerts() == []
    env.report("cross-bot", SONNET, 100_000)  # $2.00 in total: exactly the limit
    assert len(env.alerts()) == 1


def test_the_alert_says_what_it_is_and_what_it_is_not(env: Env) -> None:
    env.link()
    agent = env.report("words-bot", SONNET, 1_000_000)
    env.set_limit(agent, 1_000_000)
    env.report("words-bot", SONNET, 1)
    text = env.alerts()[0]
    assert "words-bot" in text and "$2.00" in text and "$1.00" in text
    assert "SDK reported" in text and PRICES_AS_OF_TEXT in text and "Nothing was refused" in text


def test_the_alert_leaves_once_per_agent_per_day_however_many_reports_follow(env: Env) -> None:
    env.link()
    agent = env.report("once-bot", SONNET, 1_000_000)
    env.set_limit(agent, 1_000_000)
    for _ in range(5):
        env.report("once-bot", SONNET, 1_000_000)
    assert len(env.alerts()) == 1


def test_a_new_limit_alerts_again_the_same_day(env: Env) -> None:
    env.link()
    agent = env.report("again-bot", SONNET, 1_000_000)
    env.set_limit(agent, 1_000_000)
    env.report("again-bot", SONNET, 1)
    env.set_limit(agent, 500_000)
    env.report("again-bot", SONNET, 1)
    assert len(env.alerts()) == 2


def test_a_new_day_alerts_again(env: Env) -> None:
    env.link()
    agent = env.report("tomorrow-bot", SONNET, 1_000_000)
    env.set_limit(agent, 1_000_000)
    env.report("tomorrow-bot", SONNET, 1)
    for row in env.store.tables["agents"]:
        if row["id"] == agent:
            row["spend_alerted_day"] = (budget_rules.local_day(utcnow(), 480) - timedelta(days=1)).isoformat()
    env.report("tomorrow-bot", SONNET, 1)
    assert len(env.alerts()) == 2


def test_no_limit_means_no_alert_however_much_is_reported(env: Env) -> None:
    env.link()
    env.report("free-bot", SONNET, 900_000_000)
    assert env.alerts() == []


def test_usage_on_unpriced_models_cannot_raise_an_alert_because_it_has_no_dollars_but_is_said_in_one(env: Env) -> None:
    env.link()
    agent = env.report("unp-bot", "gpt-mystery", 10_000_000, provider="openai")
    env.set_limit(agent, 1)
    assert env.alerts() == [], "an unknown price is not counted as a number, in either direction"
    env.report("unp-bot", SONNET, 1_000_000)
    text = env.alerts()[0]
    assert "no known price" in text and "not included" in text


def test_nothing_is_refused_when_the_limit_is_crossed(env: Env) -> None:
    agent = env.report("nobar-bot", SONNET, 1_000_000)
    env.set_limit(agent, 1)
    assert env.ingest("nobar-bot", [env.span(SONNET, 1_000_000, 0)]).status_code == 202
    assert env.statuses()["nobar-bot"] == "active"


def counter(name: str, **labels: str) -> float:
    return float(get_metrics()._counters.get(name, {}).get(tuple(sorted(labels.items())), 0.0))


def test_a_failing_check_never_fails_the_ingest_and_is_counted(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = env.report("boom-bot", SONNET, 10)
    env.set_limit(agent, 1)
    original = env.store.rpc

    def broken(function: str, params: dict[str, Any] | None = None) -> Any:
        if function == "spend_mark_alerted":
            raise RuntimeError("database down")
        return original(function, params)

    monkeypatch.setattr(env.store, "rpc", broken)
    before = counter("spend_checks_total", outcome="error")
    assert env.ingest("boom-bot", [env.span(SONNET, 1_000_000, 0)]).status_code == 202
    assert counter("spend_checks_total", outcome="error") == before + 1


def test_a_batch_with_no_reported_usage_does_not_run_the_check(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    async def spy(*args: Any, **kwargs: Any) -> None:
        calls.append(args)

    monkeypatch.setattr(spend_service, "check_spend", spy)
    env.report("quiet-bot", None, 0, 0, provider=None)
    assert calls == []
    env.report("loud-bot", SONNET, 10)
    assert len(calls) == 1


def test_models_with_no_price_are_counted_without_naming_them(env: Env) -> None:
    before = counter("spend_unpriced_models_total")
    env.ingest("count-bot", [env.span("gpt-a", 5, 5, "openai"), env.span("gpt-b", 5, 5, "openai"), env.span("gpt-a", 5, 5, "openai"), env.span(SONNET, 5, 5)])
    assert counter("spend_unpriced_models_total") == before + 2, "two distinct unpriced models in the batch (one repeated), the priced one not counted"
    assert "gpt-a" not in get_metrics().render_prometheus()


def test_too_many_checks_at_once_are_skipped_and_counted(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    monkeypatch.setattr(spend_service, "_in_flight", spend_service.MAX_CHECKS_IN_FLIGHT)
    before = counter("spend_checks_total", outcome="skipped")
    asyncio.run(spend_service.check_spend(env.store, None, DEFAULT_ORG_ID_UUID, uuid4(), utcnow()))
    assert counter("spend_checks_total", outcome="skipped") == before + 1



# --- gaps found by breaking the code on purpose -------------------------------------------------------------------------------------

def test_a_revoked_agent_is_not_listed_but_its_history_can_still_be_read(env: Env) -> None:
    agent = env.report("gone-bot", SONNET, 10)
    assert env.client.post(f"/v1/passports/{agent}/revoke", json={"confirm": True}, headers=env.h("admin")).status_code == 200
    assert agent not in {r["agent_id"] for r in env.spend().json()["agents"]}
    assert env.client.get(f"/v1/spend/agents/{agent}", headers=env.h("viewer")).status_code == 200


def test_the_percent_of_the_limit_is_exact_and_capped(env: Env) -> None:
    agent = env.report("pct-bot", SONNET, 1_000_000)  # $2.00
    env.set_limit(agent, 4_000_000)
    assert env.agent_view(agent)["percent_of_limit"] == 50
    env.set_limit(agent, 1)
    assert env.agent_view(agent)["percent_of_limit"] == 999


def test_a_distinct_unpriced_model_is_counted_once_however_many_spans_name_it() -> None:
    rows = [
        {"model_provider": "openai", "model_name": "GPT-A", "prompt_tokens": 1, "completion_tokens": 0},
        {"model_provider": "OpenAI", "model_name": "gpt-a ", "prompt_tokens": 99, "completion_tokens": 5},
    ]
    assert spend_service.summarize_batch(rows) == (True, 1)


@pytest.mark.parametrize(
    "row",
    [
        {"model_provider": "openai", "model_name": "gpt-a", "prompt_tokens": 0, "completion_tokens": 0},
        {"model_provider": "openai", "model_name": "   ", "prompt_tokens": 5, "completion_tokens": 5},
        {"model_provider": "openai", "model_name": None, "prompt_tokens": 5, "completion_tokens": 5},
        {"model_provider": "openai", "model_name": "gpt-a", "prompt_tokens": None, "completion_tokens": None},
    ],
)
def test_a_span_that_reports_no_model_use_is_not_counted_as_use(row: dict[str, Any]) -> None:
    assert spend_service.summarize_batch([row]) == (False, 0)


def test_a_stored_limit_that_is_not_a_real_number_never_alerts(env: Env) -> None:
    env.link()
    agent = env.report("odd-bot", SONNET, 1_000_000)
    for row in env.store.tables["agents"]:
        if row["id"] == agent:
            row["spend_limit_micro_usd"] = True
    env.report("odd-bot", SONNET, 1_000_000)
    assert env.alerts() == []


def test_the_check_only_looks_at_agents_of_the_organization_it_was_asked_about(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    env.link()
    foreign = str(uuid4())
    env.store.tables["agents"].append({"id": foreign, "organization_id": OTHER_ORG, "external_agent_id": "t", "name": "Theirs", "status": "active",
                                       "spend_limit_micro_usd": 1})
    env.store.tables["agent_model_daily"] = [{
        "organization_id": OTHER_ORG, "agent_id": foreign, "day": budget_rules.local_day(utcnow(), 480).isoformat(), "provider": "anthropic",
        "model": SONNET, "calls": 1, "prompt_tokens": 10**9, "completion_tokens": 0}]
    asyncio.run(spend_service.check_spend(env.store, env.fake, DEFAULT_ORG_ID_UUID, UUID(foreign), utcnow()))
    assert env.alerts() == []
    assert next(a for a in env.store.tables["agents"] if a["id"] == foreign).get("spend_alerted_day") is None
