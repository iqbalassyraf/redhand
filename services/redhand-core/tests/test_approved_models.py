"""
Approved models in redhand-core (Phase 4.5 B4b): an admin keeps a list; while it is not empty, a model an agent's SDK reports that is not on it becomes one
RAD-MDL-001 finding and one Telegram alert (10-minute cooldown). Detective only: nothing is refused, an empty list means no check, and a model finding
adds nothing to the Risk score. The SQL (supabase/tests/approved_models_test.sql) proves the database; these tests prove core and the local twin that core's
tests run against.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest

from redhand_core.passports.models import utcnow
from redhand_core.routers import telegram as telegram_router  # noqa: F401  (keeps the Telegram test environment importable)
from redhand_core.services.local_store import DEFAULT_ORG_ID
from redhand_core.services.metrics import get_metrics
from redhand_core.approved import service as approved_service

from test_telegram import OTHER_ORG, OWNER_CHAT
from test_spend_api import Env as SpendEnv

SONNET = {"provider": "anthropic", "model": "claude-sonnet-5-5"}
HAIKU = {"provider": "anthropic", "model": "claude-haiku-5-5"}


def counter(name: str, **labels: str) -> float:
    return float(get_metrics()._counters.get(name, {}).get(tuple(sorted(labels.items())), 0.0))


class Env(SpendEnv):
    def listing(self, user: str = "viewer") -> Any:
        return self.client.get("/v1/organization/approved-models", headers=self.h(user))

    def put_list(self, items: list[dict[str, str]], version: int | None = None, user: str = "admin", **extra: Any) -> Any:
        if version is None:
            version = self.listing().json()["version"]
        return self.client.put("/v1/organization/approved-models", json={"items": items, "version": version, **extra}, headers=self.h(user))

    def use(self, external: str, model: str, provider: str = "anthropic") -> Any:
        return self.ingest(external, [self.span(model, 100, 10, provider)])

    def findings(self) -> list[dict[str, Any]]:
        return [f for f in self.store.tables.get("security_findings", []) if f["kind"] == "model"]

    def model_alerts(self) -> list[str]:
        return [t for t in self.fake.to(OWNER_CHAT) if t.startswith("Model alert")]


@pytest.fixture
def env() -> Env:
    return Env()


# --- the list ----------------------------------------------------------------------------------------------------------------------

def test_a_new_organization_has_no_list_and_so_no_check(env: Env) -> None:
    body = env.listing().json()
    assert body["items"] == [] and body["check_active"] is False and body["max_items"] == 50 and body["version"] == 0


def test_an_admin_sets_the_list_and_everyone_signed_in_can_read_it(env: Env) -> None:
    response = env.put_list([SONNET, HAIKU], reason="pilot")
    assert response.status_code == 200 and response.json()["changed"] is True and response.json()["version"] == 1
    for user in ("viewer", "operator", "admin"):
        body = env.listing(user).json()
        assert body["check_active"] is True and [i["model"] for i in body["items"]] == ["claude-haiku-5-5", "claude-sonnet-5-5"]


@pytest.mark.parametrize("user", ["operator", "viewer"])
def test_only_an_admin_can_change_the_list(env: Env, user: str) -> None:
    assert env.put_list([SONNET], user=user).status_code == 403
    assert env.listing().json()["items"] == []


def test_entries_are_trimmed_lower_cased_and_de_duplicated(env: Env) -> None:
    env.put_list([{"provider": " Anthropic ", "model": "Claude-Sonnet-5-5"}, SONNET])
    assert env.listing().json()["items"] == [SONNET]


def test_the_same_list_again_changes_nothing_and_writes_no_audit_row(env: Env) -> None:
    env.put_list([SONNET])
    assert env.put_list([SONNET]).json()["changed"] is False
    assert len([e for e in env.audit() if e["action"] == "organization.approved_models_changed"]) == 1


def test_clearing_the_list_turns_the_check_off_so_it_needs_confirmation(env: Env) -> None:
    env.put_list([SONNET])
    assert env.put_list([]).status_code == 400
    assert env.listing().json()["check_active"] is True
    assert env.put_list([], confirm=True).status_code == 200
    assert env.listing().json()["check_active"] is False


def test_adding_and_removing_entries_need_no_confirmation(env: Env) -> None:
    assert env.put_list([SONNET]).status_code == 200
    assert env.put_list([SONNET, HAIKU]).status_code == 200
    assert env.put_list([HAIKU]).status_code == 200


def test_a_change_decided_on_an_old_version_is_a_conflict_and_changes_nothing(env: Env) -> None:
    env.put_list([SONNET])
    response = env.put_list([HAIKU], version=0)
    assert response.status_code == 409
    assert env.listing().json()["items"] == [SONNET]


@pytest.mark.parametrize(
    "items",
    [
        [{"provider": "a b", "model": "x"}],
        [{"provider": "", "model": "x"}],
        [{"provider": "a", "model": "<script>"}],
        [{"provider": "a", "model": "x", "extra": "y"}],
        [{"provider": "a"}],
        [{"provider": 5, "model": "x"}],
        [{"provider": "p", "model": f"m{n}"} for n in range(51)],
        "text",
    ],
)
def test_malformed_lists_are_refused(env: Env, items: Any) -> None:
    assert env.put_list(items).status_code == 422


def test_an_unknown_field_is_refused(env: Env) -> None:
    response = env.client.put("/v1/organization/approved-models", json={"items": [], "version": 0, "tenant": "x"}, headers=env.h("admin"))
    assert response.status_code == 422


def test_an_organization_never_sees_or_changes_anothers_list(env: Env) -> None:
    env.store.tables.setdefault("approved_models", []).append({"organization_id": OTHER_ORG, "provider": "x", "model": "y"})
    assert env.listing().json()["items"] == []
    env.put_list([SONNET])
    assert [r for r in env.store.tables["approved_models"] if r["organization_id"] == OTHER_ORG] == [{"organization_id": OTHER_ORG, "provider": "x", "model": "y"}]


# --- the check ---------------------------------------------------------------------------------------------------------------------

def test_without_a_list_nothing_is_flagged_however_odd_the_model(env: Env) -> None:
    env.link()
    assert env.use("free-bot", "weird-model-9", "nobody").status_code == 202
    assert env.findings() == [] and env.model_alerts() == []


def test_a_model_outside_the_list_is_one_finding_and_one_alert(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    env.use("model-bot", "gpt-mystery", "openai")
    found = env.findings()
    assert len(found) == 1 and found[0]["rule_id"] == "RAD-MDL-001" and found[0]["tool_name"] == "openai/gpt-mystery" and found[0]["place"] == "call"
    alerts = env.model_alerts()
    assert len(alerts) == 1 and "model-bot" in alerts[0] and "openai/gpt-mystery" in alerts[0]
    assert "Recorded only: nothing was refused." in alerts[0]


def test_an_approved_model_raises_nothing(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    env.use("ok-bot", "Claude-Sonnet-5-5", "Anthropic")
    env.use("ok-bot", "claude-sonnet-5-5-20260301")
    assert env.findings() == [] and env.model_alerts() == []


def test_the_same_model_again_is_not_a_second_finding_or_alert(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    for _ in range(4):
        env.use("repeat-bot", "gpt-mystery", "openai")
    assert len(env.findings()) == 1 and env.findings()[0]["occurrences"] == 4 and len(env.model_alerts()) == 1


def test_adding_the_model_to_the_list_stops_new_findings(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    env.use("grow-bot", "gpt-mystery", "openai")
    before = len(env.findings())
    env.put_list([SONNET, {"provider": "openai", "model": "gpt-mystery"}])
    env.store.tables["security_findings"].clear()
    env.use("grow-bot", "gpt-mystery", "openai")
    assert before == 1 and env.findings() == []


def test_nothing_is_refused(env: Env) -> None:
    env.put_list([SONNET])
    assert env.use("nobar-bot", "gpt-mystery", "openai").status_code == 202
    assert env.statuses()["nobar-bot"] == "active"


def test_a_hostile_model_name_is_plain_text_in_the_finding_and_the_alert(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    env.use("evil-bot", "<img src=x onerror=alert(1)>‮" + "x" * 60, "ev il")
    name = env.findings()[0]["tool_name"]
    import re

    assert re.fullmatch(r"[a-z0-9_.:/-]{1,128}", name)
    assert all("<" not in t and "‮" not in t for t in env.model_alerts())


def test_a_model_finding_adds_nothing_to_the_risk_score(env: Env) -> None:
    env.put_list([SONNET])
    agent = env.report("risk-bot", "gpt-mystery", 10, 1, "openai")
    assert env.findings()
    detail = env.client.get(f"/v1/risk/agents/{agent}", headers=env.h("operator")).json()
    assert detail["agent"]["score"] == 0


def test_a_silence_on_the_rule_stops_findings_for_that_agent(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    agent = env.report("quiet-bot", "gpt-first", 10, 1, "openai")
    silenced = env.client.post("/v1/radar/suppressions", json={"agent_id": agent, "rule_id": "RAD-MDL-001", "days": 7, "reason": "pilot model", "confirm": True}, headers=env.h("admin"))
    assert silenced.status_code in (200, 201), silenced.text
    env.store.tables["security_findings"].clear()
    env.use("quiet-bot", "gpt-second", "openai")
    assert env.findings() == []


def test_the_findings_list_can_be_filtered_to_unapproved_models(env: Env) -> None:
    env.put_list([SONNET])
    env.use("filter-bot", "gpt-mystery", "openai")
    body = env.client.get("/v1/findings?kind=model", headers=env.h("operator"))
    assert body.status_code == 200 and [f["rule_id"] for f in body.json()["findings"]] == ["RAD-MDL-001"]


def test_a_failing_check_never_fails_the_ingest_and_is_counted(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.put_list([SONNET])
    original = env.store.rpc

    def broken(function: str, params: dict[str, Any] | None = None) -> Any:
        if function == "record_model_findings":
            raise RuntimeError("database down")
        return original(function, params)

    monkeypatch.setattr(env.store, "rpc", broken)
    before = counter("model_checks_total", outcome="error")
    assert env.use("boom-bot", "gpt-mystery", "openai").status_code == 202
    assert counter("model_checks_total", outcome="error") == before + 1


def test_too_many_checks_at_once_are_skipped_and_counted(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    monkeypatch.setattr(approved_service, "_in_flight", approved_service.MAX_CHECKS_IN_FLIGHT)
    before = counter("model_checks_total", outcome="skipped")
    asyncio.run(approved_service.check_models(env.store, None, UUID(DEFAULT_ORG_ID), uuid4(), [("p", "m")], utcnow()))
    assert counter("model_checks_total", outcome="skipped") == before + 1


def test_a_batch_that_names_no_model_does_not_run_the_check(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    async def spy(*args: Any, **kwargs: Any) -> None:
        calls.append(args)

    monkeypatch.setattr(approved_service, "check_models", spy)
    env.ingest("nomodel-bot", [env.span(None, 0, 0, None)])
    assert calls == []
    env.use("model-bot2", "gpt-x", "openai")
    assert len(calls) == 1


def test_a_batch_names_each_model_once_and_at_most_twenty() -> None:
    rows = [{"model_provider": "OpenAI", "model_name": " GPT-X "}, {"model_provider": "openai", "model_name": "gpt-x"}, {"model_provider": None, "model_name": "m"},
            {"model_provider": "p", "model_name": ""}, {"model_provider": "p", "model_name": None}]
    assert approved_service.models_in_batch(rows) == [("openai", "gpt-x"), ("", "m")]
    many = [{"model_provider": "p", "model_name": f"m{n}"} for n in range(50)]
    assert len(approved_service.models_in_batch(many)) == 20


# --- gaps found by breaking the code on purpose -------------------------------------------------------------------------------------

def test_a_second_unapproved_model_inside_ten_minutes_is_a_finding_but_not_another_alert(env: Env) -> None:
    env.link()
    env.put_list([SONNET])
    env.use("two-bot", "gpt-first", "openai")
    env.use("two-bot", "gpt-second", "openai")
    assert len(env.findings()) == 2 and len(env.model_alerts()) == 1


def test_an_unreadable_list_is_an_error_never_an_empty_list(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    original = env.store.rpc

    def broken(function: str, params: dict[str, Any] | None = None) -> Any:
        if function == "approved_models_list":
            raise RuntimeError("database down")
        return original(function, params)

    monkeypatch.setattr(env.store, "rpc", broken)
    response = env.listing()
    assert response.status_code == 503 and "could not be read" in response.json()["detail"].lower()


def test_the_database_function_refuses_a_stale_version_on_its_own() -> None:
    import asyncio

    from redhand_core.services.local_store import LocalSupabaseAdapter

    store = LocalSupabaseAdapter()
    params = {"p_org": DEFAULT_ORG_ID, "p_actor": str(uuid4()), "p_items": [{"provider": "a", "model": "b"}], "p_reason": None, "p_expected_version": 0}
    assert asyncio.run(store.rpc("control_approved_models", params).execute()).data["changed"] is True
    assert asyncio.run(store.rpc("control_approved_models", params).execute()).data == {"conflict": True}
