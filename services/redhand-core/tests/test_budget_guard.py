"""
Budget Guard in redhand-core (Phase 2, M3a): daily call limits, who may change them, usage reports from
the gateway, alerts once per day, the optional auto-freeze under a system actor, and the budget the
gateway is told about. The gateway's own enforcement is tested in agentwall/tests.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from pydantic import SecretStr
import pytest

from redhand_core.passports import budget
from redhand_core.passports.models import utcnow
from redhand_core.services import local_rpc
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS

from test_telegram import OTHER_ORG, Env as TelegramEnv

SERVICE_TOKEN = "budget-test-internal-service-token-0123456789"
INSTANCE = "gateway-instance-aaaa"
OTHER_INSTANCE = "gateway-instance-bbbb"


class Env(TelegramEnv):
    """The Telegram test environment (fake bot, seeded tenants) with the internal service token set."""

    def __init__(self, **settings: Any) -> None:
        settings.setdefault("INTERNAL_SERVICE_TOKEN", SecretStr(SERVICE_TOKEN))
        super().__init__(**settings)

    def today(self) -> date:
        return budget.local_day(utcnow(), 480)

    def set_budget(self, agent_id: str, limit: int | None, action: str = "deny", user: str = "operator", **extra: Any) -> Any:
        body = {"daily_call_limit": limit, "action": action, **extra}
        return self.client.put(f"/v1/passports/{agent_id}/budget", json=body, headers=self.h(user))

    def report(self, agent_id: str, calls: int, instance: str = INSTANCE, day: date | None = None, token: str | None = SERVICE_TOKEN) -> Any:
        body = {"instance_id": instance, "items": [{"agent_id": agent_id, "day_key": (day or self.today()).isoformat(), "calls": calls}]}
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post("/internal/v1/usage", json=body, headers=headers)

    def context(self, agent_id: str, instance: str | None = INSTANCE, org: str = DEFAULT_ORG_ID) -> Any:
        params = {"agent_id": agent_id, "organization_id": org, "server": "xero"}
        if instance:
            params["instance_id"] = instance
        return self.client.get("/internal/v1/gateway-context", params=params, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})

    def budget_of(self, agent_id: str) -> dict[str, Any]:
        resp = self.context(agent_id)
        assert resp.status_code == 200, resp.text
        return dict(resp.json()["agent"]["budget"])

    def actions(self, name: str) -> list[dict[str, Any]]:
        return [e for e in self.audit() if e["action"] == name]


@pytest.fixture
def env() -> Env:
    return Env()


def _agent(env: Env, name: str = "Alpha") -> str:
    return str(env.register(name)["id"])


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------


def test_the_local_day_follows_the_organization_offset() -> None:
    now = datetime(2026, 11, 4, 17, 30, tzinfo=timezone.utc)  # 01:30 on the 5th in UTC+8
    assert budget.local_day(now, 480) == date(2026, 11, 5)
    assert budget.local_day(now, 0) == date(2026, 11, 4)
    assert budget.local_day(now, -300) == date(2026, 11, 4)
    assert budget.next_reset_utc(now, 480) == datetime(2026, 11, 5, 16, 0, tzinfo=timezone.utc)
    assert budget.next_reset_utc(now, 0) == datetime(2026, 11, 5, 0, 0, tzinfo=timezone.utc)
    midnight = datetime(2026, 11, 4, 16, 0, tzinfo=timezone.utc)  # exactly 00:00 on the 5th in UTC+8
    assert budget.local_day(midnight, 480) == date(2026, 11, 5)
    assert budget.next_reset_utc(midnight, 480) == datetime(2026, 11, 5, 16, 0, tzinfo=timezone.utc) + timedelta(days=0)


@pytest.mark.parametrize("raw", [None, "480", True, 1.5, 10_000, -10_000])
def test_a_bad_stored_offset_falls_back_to_the_default(raw: Any) -> None:
    assert budget.normalize_offset(raw) == 480


def test_offsets_are_written_readably() -> None:
    assert budget.format_offset(480) == "UTC+8"
    assert budget.format_offset(-300) == "UTC-5"
    assert budget.format_offset(330) == "UTC+5:30"


@pytest.mark.parametrize(
    ("old_limit", "new_limit", "old_action", "new_action", "relaxes"),
    [
        (None, 100, "deny", "deny", False),   # setting a first limit restricts
        (100, 50, "deny", "deny", False),     # lowering restricts
        (100, 100, "deny", "deny", False),    # no change
        (100, 200, "deny", "deny", True),     # raising relaxes
        (100, None, "deny", "deny", True),    # removing relaxes
        (None, None, "deny", "freeze", False),  # turning auto-freeze on restricts
        (100, 100, "freeze", "deny", True),   # turning auto-freeze off relaxes
        (100, 50, "freeze", "deny", True),    # lowering AND turning auto-freeze off relaxes
    ],
)
def test_which_changes_relax_a_restriction(old_limit: Any, new_limit: Any, old_action: str, new_action: str, relaxes: bool) -> None:
    assert budget.is_relaxation(old_limit, new_limit, old_action, new_action) is relaxes


# ---------------------------------------------------------------------------
# Setting limits
# ---------------------------------------------------------------------------


def test_a_security_operator_can_set_and_lower_a_limit_and_it_is_audited(env: Env) -> None:
    agent_id = _agent(env)
    resp = env.set_budget(agent_id, 100, reason="cap it")
    assert resp.status_code == 200, resp.text
    assert resp.json()["changed"] is True and resp.json()["passport"]["daily_call_limit"] == 100
    entry = env.actions("passport.budget_changed")[0]
    assert entry["target_id"] == agent_id and entry["reason"] == "cap it"
    assert entry["details"] == {"old_limit": None, "new_limit": 100, "old_action": "deny", "new_action": "deny"}

    assert env.set_budget(agent_id, 40).json()["passport"]["daily_call_limit"] == 40  # lowering
    assert env.set_budget(agent_id, 40, "freeze").json()["passport"]["budget_action"] == "freeze"  # auto-freeze on
    listed = {p["id"]: p for p in env.client.get("/v1/passports", headers=env.h("viewer")).json()}
    assert listed[agent_id]["daily_call_limit"] == 40 and listed[agent_id]["budget_action"] == "freeze"


def test_setting_the_same_values_again_changes_nothing(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 100)
    again = env.set_budget(agent_id, 100)
    assert again.status_code == 200 and again.json()["changed"] is False
    assert len(env.actions("passport.budget_changed")) == 1


def test_raising_or_removing_a_limit_needs_an_admin_and_confirmation(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 100, "freeze")
    for relaxing in ({"limit": 200, "action": "freeze"}, {"limit": None, "action": "freeze"}, {"limit": 100, "action": "deny"}):
        assert env.set_budget(agent_id, relaxing["limit"], relaxing["action"], user="operator", confirm=True).status_code == 403
        assert env.set_budget(agent_id, relaxing["limit"], relaxing["action"], user="admin").status_code == 400
        assert env.set_budget(agent_id, relaxing["limit"], relaxing["action"], user="admin", confirm=False).status_code == 400
    assert env.budget_of(agent_id)["daily_call_limit"] == 100 and env.budget_of(agent_id)["action"] == "freeze"

    assert env.set_budget(agent_id, 200, "freeze", user="admin", confirm=True).status_code == 200
    assert env.set_budget(agent_id, None, "deny", user="owner", confirm=True).status_code == 200
    assert env.budget_of(agent_id)["daily_call_limit"] is None


def test_viewers_and_anonymous_callers_cannot_change_limits(env: Env) -> None:
    agent_id = _agent(env)
    assert env.set_budget(agent_id, 10, user="viewer").status_code == 403
    assert env.client.put(f"/v1/passports/{agent_id}/budget", json={"daily_call_limit": 10}).status_code == 401
    assert env.actions("passport.budget_changed") == []


@pytest.mark.parametrize(
    "body",
    [{"daily_call_limit": 0}, {"daily_call_limit": -5}, {"daily_call_limit": 10_000_001}, {"daily_call_limit": "5"},
     {"daily_call_limit": True}, {"daily_call_limit": 1.5}, {"action": "ignore"}, {"extra": 1}, {"reason": "x" * 501}],
)
def test_invalid_limit_requests_are_rejected(env: Env, body: dict[str, Any]) -> None:
    agent_id = _agent(env)
    resp = env.client.put(f"/v1/passports/{agent_id}/budget", json=body, headers=env.h("admin"))
    assert resp.status_code == 422
    assert env.budget_of(agent_id)["daily_call_limit"] is None


def test_unknown_foreign_and_revoked_agents(env: Env) -> None:
    foreign = str(uuid4())
    env.store.tables["agents"].append(
        {"id": foreign, "organization_id": OTHER_ORG, "external_agent_id": "f", "name": "F", "status": "active", "scopes": [],
         "version": 1, "safe_mode": False, "daily_call_limit": None, "budget_action": "deny", "expires_at": "2099-01-01T00:00:00+00:00"}
    )
    assert env.set_budget(foreign, 5, user="owner").status_code == 404
    assert env.set_budget(str(uuid4()), 5, user="owner").status_code == 404
    assert next(a for a in env.store.tables["agents"] if a["id"] == foreign)["daily_call_limit"] is None

    agent_id = _agent(env)
    env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h("admin"))
    assert env.set_budget(agent_id, 5, user="owner").status_code == 409


def test_a_failed_audit_write_leaves_the_limit_unchanged(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    agent_id = _agent(env)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("audit table unwritable")

    monkeypatch.setattr("redhand_core.services.local_rpc._append_audit", boom)
    with pytest.raises(RuntimeError):
        env.set_budget(agent_id, 5)
    monkeypatch.undo()
    assert env.budget_of(agent_id)["daily_call_limit"] is None


def test_a_concurrent_change_cannot_turn_a_lowering_into_an_unauthorised_relaxation(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Regression (found in review): the role and confirmation decision was made against a pre-read, then
    applied as an absolute write. The write is now compare-and-set against what the decision was made on.
    """
    from redhand_core.passports import service

    agent_id = _agent(env)
    env.set_budget(agent_id, 500)
    real_get = service.get_passport_row
    stale = dict(next(a for a in env.store.tables["agents"] if a["id"] == agent_id))  # what the operator saw: limit 500

    async def stale_read(supabase: Any, operator: Any, agent: Any) -> dict[str, Any]:
        row = await real_get(supabase, operator, agent)
        return {**row, "daily_call_limit": stale["daily_call_limit"]}  # the operator "saw" 500

    # meanwhile an admin lowered it to 50
    next(a for a in env.store.tables["agents"] if a["id"] == agent_id)["daily_call_limit"] = 50
    monkeypatch.setattr(service, "get_passport_row", stale_read)
    resp = env.set_budget(agent_id, 100, user="operator")  # a lowering relative to what the operator saw (500)
    assert resp.status_code == 409  # refused: the state changed under the decision
    assert next(a for a in env.store.tables["agents"] if a["id"] == agent_id)["daily_call_limit"] == 50
    assert [e["details"]["new_limit"] for e in env.actions("passport.budget_changed")] == [500]


def test_changing_the_limit_makes_the_new_limit_alert_and_freeze_again(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 5, "freeze")
    env.link()
    env.report(agent_id, 6)  # limit alert and auto-freeze
    assert env.statuses()["Alpha"] == "frozen"
    env.client.post(f"/v1/passports/{agent_id}/unfreeze", json={"confirm": True}, headers=env.h("operator"))
    assert env.set_budget(agent_id, 10, "freeze", user="admin", confirm=True).status_code == 200
    env.report(agent_id, 9)
    assert "(80%)" in _budget_alerts(env, 1001)[-1]  # 80% of the NEW limit
    env.report(agent_id, 12)
    assert env.statuses()["Alpha"] == "frozen"  # frozen again at the new limit
    assert len(env.actions("passport.frozen")) == 2
    assert "reached its daily limit of 10" in _budget_alerts(env, 1001)[-1]


def test_changing_only_the_action_does_not_repeat_alerts(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 5)
    env.link()
    env.report(agent_id, 6)
    before = len(_budget_alerts(env, 1001))
    env.set_budget(agent_id, 5, "freeze")
    env.report(agent_id, 7)
    assert len(_budget_alerts(env, 1001)) == before


def test_many_events_in_one_report_are_handled_together(env: Env) -> None:
    ids = [_agent(env, f"Bot {i}") for i in range(12)]
    for agent_id in ids:
        env.set_budget(agent_id, 5)
    env.link()
    body = {"instance_id": INSTANCE, "items": [{"agent_id": i, "day_key": env.today().isoformat(), "calls": 9} for i in ids]}
    resp = env.client.post("/internal/v1/usage", json=body, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})
    assert resp.status_code == 200 and resp.json()["accepted"] == 12
    assert len(_budget_alerts(env, 1001)) == 12


# ---------------------------------------------------------------------------
# What the gateway is told
# ---------------------------------------------------------------------------


def test_the_gateway_context_carries_the_budget(env: Env) -> None:
    agent_id = _agent(env)
    unlimited = env.budget_of(agent_id)
    assert unlimited["daily_call_limit"] is None and unlimited["used_by_other_instances"] == 0
    assert unlimited["action"] == "deny" and unlimited["day_key"] == env.today().isoformat()
    resets = datetime.fromisoformat(unlimited["resets_at"])
    assert utcnow() < resets <= utcnow() + timedelta(days=1)

    env.set_budget(agent_id, 100, "freeze")
    limited = env.budget_of(agent_id)
    assert limited["daily_call_limit"] == 100 and limited["action"] == "freeze"


def test_usage_by_other_instances_excludes_the_caller(env: Env) -> None:
    agent_id = _agent(env)
    env.report(agent_id, 5, INSTANCE)
    env.report(agent_id, 3, OTHER_INSTANCE)
    assert env.context(agent_id, INSTANCE).json()["agent"]["budget"]["used_by_other_instances"] == 3
    assert env.context(agent_id, OTHER_INSTANCE).json()["agent"]["budget"]["used_by_other_instances"] == 5
    assert env.context(agent_id, "gateway-instance-cccc").json()["agent"]["budget"]["used_by_other_instances"] == 8
    assert env.context(agent_id, None).json()["agent"]["budget"]["used_by_other_instances"] == 8  # an old gateway


def test_a_malformed_stored_limit_means_nothing_is_allowed(env: Env) -> None:
    agent_id = _agent(env)
    for stored in (0, -1, "5", True, 1.5):
        next(a for a in env.store.tables["agents"] if a["id"] == agent_id)["daily_call_limit"] = stored
        assert env.budget_of(agent_id)["daily_call_limit"] == 0


def test_the_day_follows_the_organization_offset(env: Env) -> None:
    agent_id = _agent(env)
    org = next(o for o in env.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)
    org["utc_offset_minutes"] = -300
    # The reset moment shows the offset at any time of day: local midnight is 05:00 UTC at UTC-5 and 16:00 UTC at the default UTC+8. A day-only
    # check passed while production ignored the setting (the column was never selected), because the two offsets share a calendar day
    # for most of the clock.
    assert datetime.fromisoformat(env.budget_of(agent_id)["resets_at"]).astimezone(timezone.utc).hour == 5
    assert env.budget_of(agent_id)["day_key"] == budget.local_day(utcnow(), -300).isoformat()
    org["utc_offset_minutes"] = "garbage"
    assert env.budget_of(agent_id)["day_key"] == budget.local_day(utcnow(), 480).isoformat()
    assert datetime.fromisoformat(env.budget_of(agent_id)["resets_at"]).astimezone(timezone.utc).hour == 16  # garbage falls back to UTC+8


def test_a_failed_usage_lookup_makes_the_context_unavailable(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    agent_id = _agent(env)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("database down")

    monkeypatch.setitem(local_rpc.HANDLERS, "usage_by_others", boom)
    assert env.context(agent_id).status_code == 503  # the gateway treats this as "deny"


# ---------------------------------------------------------------------------
# Usage reports
# ---------------------------------------------------------------------------


def test_usage_reports_need_the_service_token(env: Env) -> None:
    agent_id = _agent(env)
    for token in (None, "wrong-token", ""):
        assert env.report(agent_id, 5, token=token).status_code == 401
    assert env.context(agent_id).json()["agent"]["budget"]["used_by_other_instances"] == 0
    assert env.report(agent_id, 5, OTHER_INSTANCE).status_code == 200


def test_usage_reports_are_closed_when_no_service_token_is_configured() -> None:
    closed = Env(INTERNAL_SERVICE_TOKEN=None)
    assert closed.report(str(uuid4()), 1).status_code == 503


@pytest.mark.parametrize(
    "body",
    [
        {"instance_id": "short", "items": []},
        {"instance_id": "gateway instance with spaces", "items": []},
        {"instance_id": INSTANCE, "items": [{"agent_id": "not-a-uuid", "day_key": "2026-11-04", "calls": 1}]},
        {"instance_id": INSTANCE, "items": [{"agent_id": str(uuid4()), "day_key": "yesterday", "calls": 1}]},
        {"instance_id": INSTANCE, "items": [{"agent_id": str(uuid4()), "day_key": "2026-11-04", "calls": -1}]},
        {"instance_id": INSTANCE, "items": [{"agent_id": str(uuid4()), "day_key": "2026-11-04", "calls": 1, "extra": 1}]},
        {"instance_id": INSTANCE, "items": [{"agent_id": str(uuid4()), "day_key": "2026-11-04", "calls": 1}] * 1001},
        {"instance_id": INSTANCE},
    ],
)
def test_malformed_usage_reports_are_rejected(env: Env, body: dict[str, Any]) -> None:
    resp = env.client.post("/internal/v1/usage", json=body, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})
    assert resp.status_code == 422


def test_reports_are_cumulative_and_never_lower_a_count(env: Env) -> None:
    agent_id = _agent(env)
    seen = lambda: env.context(agent_id, OTHER_INSTANCE).json()["agent"]["budget"]["used_by_other_instances"]  # noqa: E731
    env.report(agent_id, 5)
    assert seen() == 5
    env.report(agent_id, 3)  # a stale report arrives late
    assert seen() == 5  # it did not lower the count, even briefly
    env.report(agent_id, 5)  # resent
    assert seen() == 5
    env.report(agent_id, 9)
    assert env.context(agent_id, OTHER_INSTANCE).json()["agent"]["budget"]["used_by_other_instances"] == 9


def test_unknown_agents_far_away_days_and_a_mix_are_counted_as_rejected(env: Env) -> None:
    agent_id = _agent(env)
    body = {
        "instance_id": INSTANCE,
        "items": [
            {"agent_id": str(uuid4()), "day_key": env.today().isoformat(), "calls": 4},
            {"agent_id": agent_id, "day_key": (env.today() + timedelta(days=30)).isoformat(), "calls": 4},
            {"agent_id": agent_id, "day_key": env.today().isoformat(), "calls": 4},
        ],
    }
    resp = env.client.post("/internal/v1/usage", json=body, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})
    assert resp.json() == {"accepted": 1, "rejected": 2}


def test_usage_never_crosses_tenants(env: Env) -> None:
    mine = _agent(env)
    foreign = str(uuid4())
    env.store.tables["agents"].append(
        {"id": foreign, "organization_id": OTHER_ORG, "external_agent_id": "f", "name": "Theirs", "status": "active", "scopes": [],
         "version": 1, "safe_mode": False, "daily_call_limit": None, "budget_action": "deny", "expires_at": "2099-01-01T00:00:00+00:00"}
    )
    env.report(foreign, 77)
    env.report(mine, 5)
    names = {a["name"]: a["calls"] for a in env.client.get("/v1/usage", headers=env.h("viewer")).json()["agents"]}
    assert "Theirs" not in names and names["Alpha"] == 5
    # asking for the foreign agent under our organization id finds nothing
    assert env.context(foreign, org=DEFAULT_ORG_ID).status_code == 404
    # asked by a different instance, my agent shows exactly its own 5 calls: the foreign 77 never leaks in
    assert env.context(mine, OTHER_INSTANCE).json()["agent"]["budget"]["used_by_other_instances"] == 5


# ---------------------------------------------------------------------------
# Alerts and auto-freeze
# ---------------------------------------------------------------------------


def _budget_alerts(env: Env, chat: int) -> list[str]:
    return [t for t in env.fake.to(chat) if t.startswith("Budget Guard:")]


def test_alerts_fire_once_at_80_percent_and_once_at_the_limit(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 10)
    env.link()
    env.report(agent_id, 7)
    assert _budget_alerts(env, 1001) == []
    env.report(agent_id, 8)
    env.report(agent_id, 8)
    env.report(agent_id, 9, OTHER_INSTANCE)  # 17 in total: past the limit
    env.report(agent_id, 12)
    alerts = _budget_alerts(env, 1001)
    assert alerts[0] == "Budget Guard: Alpha has used 8 of its 10 daily tool calls (80%)."
    assert "reached its daily limit of 10 tool calls" in alerts[1] and "(UTC+8)" in alerts[1]
    assert "frozen" not in alerts[1] and len(alerts) == 2
    assert all("spend" not in a.lower() and "$" not in a for a in alerts)  # calls, never money


def test_jumping_past_the_limit_raises_a_single_alert(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 10)
    env.link()
    env.report(agent_id, 50)
    assert len(_budget_alerts(env, 1001)) == 1


def test_an_agent_without_a_limit_is_counted_but_never_alerts(env: Env) -> None:
    agent_id = _agent(env)
    env.link()
    env.report(agent_id, 5000)
    assert _budget_alerts(env, 1001) == []
    usage = {a["name"]: a for a in env.client.get("/v1/usage", headers=env.h("viewer")).json()["agents"]}
    assert usage["Alpha"]["calls"] == 5000 and usage["Alpha"]["percent"] is None


def test_the_deny_action_does_not_freeze(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 5, "deny")
    env.report(agent_id, 6)
    assert env.statuses()["Alpha"] == "active"


def test_the_freeze_action_freezes_the_agent_once_under_the_system_actor(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 5, "freeze")
    env.link()
    env.report(agent_id, 6)
    assert env.statuses()["Alpha"] == "frozen"
    entry = env.actions("passport.frozen")[0]
    assert entry["actor_user_id"] == str(budget.SYSTEM_ACTOR_ID) != DEV_OPERATORS["owner"]["id"]
    assert entry["reason"] == "Budget Guard: daily call limit reached" and entry["target_id"] == agent_id
    assert "It has also been frozen" in _budget_alerts(env, 1001)[-1]

    env.client.post(f"/v1/passports/{agent_id}/unfreeze", json={"confirm": True}, headers=env.h("operator"))
    env.report(agent_id, 20)  # more usage the same day: no second freeze
    assert env.statuses()["Alpha"] == "active"
    assert len(env.actions("passport.frozen")) == 1


def test_an_already_frozen_or_revoked_agent_does_not_break_the_report(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 5, "freeze")
    env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h("admin"))
    resp = env.report(agent_id, 9)
    assert resp.status_code == 200 and env.statuses()["Alpha"] == "revoked"


def test_a_telegram_failure_never_breaks_the_report_or_the_freeze(env: Env) -> None:
    agent_id = _agent(env)
    env.set_budget(agent_id, 5, "freeze")
    env.link()
    env.fake.fail = True
    resp = env.report(agent_id, 6)
    assert resp.status_code == 200 and resp.json()["accepted"] == 1
    assert env.statuses()["Alpha"] == "frozen"


def test_a_failure_recording_usage_is_reported_as_unavailable(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    agent_id = _agent(env)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("database down: password=hunter2")

    monkeypatch.setitem(local_rpc.HANDLERS, "record_usage", boom)
    resp = env.report(agent_id, 3)
    assert resp.status_code == 503 and "hunter2" not in resp.text


# ---------------------------------------------------------------------------
# The operator's usage view
# ---------------------------------------------------------------------------


def test_the_usage_view_shows_today_against_each_limit(env: Env) -> None:
    alpha, beta = _agent(env, "Alpha"), _agent(env, "Beta")
    env.set_budget(alpha, 10)
    env.report(alpha, 7)
    env.report(beta, 2)
    resp = env.client.get("/v1/usage", headers=env.h("viewer"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["day_key"] == env.today().isoformat() and body["utc_offset_minutes"] == 480
    by_name = {a["name"]: a for a in body["agents"]}
    assert by_name["Alpha"]["percent"] == 70 and by_name["Alpha"]["daily_call_limit"] == 10
    assert by_name["Beta"]["calls"] == 2 and by_name["Beta"]["percent"] is None
    assert env.client.get("/v1/usage").status_code == 401


def test_revoked_agents_are_left_out_of_the_usage_view(env: Env) -> None:
    agent_id = _agent(env)
    env.client.post(f"/v1/passports/{agent_id}/revoke", json={"confirm": True}, headers=env.h("admin"))
    assert "Alpha" not in [a["name"] for a in env.client.get("/v1/usage", headers=env.h("viewer")).json()["agents"]]


# ---------------------------------------------------------------------------
# Organization default limit for NEW agents
# ---------------------------------------------------------------------------


def _set_default(env: Env, limit: int | None, user: str = "admin", **extra: Any) -> Any:
    return env.client.put("/v1/organization/budget-default", json={"default_daily_call_limit": limit, **extra}, headers=env.h(user))


def _get_default(env: Env, user: str = "viewer") -> Any:
    return env.client.get("/v1/organization/budget-default", headers=env.h(user)).json()["default_daily_call_limit"]


def test_an_admin_sets_the_default_and_it_is_audited(env: Env) -> None:
    assert _get_default(env) is None
    resp = _set_default(env, 200, reason="cap new agents")
    assert resp.status_code == 200 and resp.json() == {"default_daily_call_limit": 200, "changed": True}
    assert _get_default(env) == 200
    entry = env.actions("organization.budget_default_changed")[0]
    assert entry["target_type"] == "organization" and entry["reason"] == "cap new agents"
    assert entry["details"] == {"old_limit": None, "new_limit": 200}
    again = _set_default(env, 200)
    assert again.json()["changed"] is False and len(env.actions("organization.budget_default_changed")) == 1


def test_only_admins_can_change_the_default_and_viewers_can_read_it(env: Env) -> None:
    assert _set_default(env, 50, user="operator").status_code == 403
    assert _set_default(env, 50, user="viewer").status_code == 403
    assert env.client.put("/v1/organization/budget-default", json={"default_daily_call_limit": 50}).status_code == 401
    assert env.client.get("/v1/organization/budget-default").status_code == 401
    assert _get_default(env, "viewer") is None and env.actions("organization.budget_default_changed") == []


@pytest.mark.parametrize("value", [0, -1, 10_000_001, "5", True, 1.5])
def test_invalid_defaults_are_rejected(env: Env, value: Any) -> None:
    assert _set_default(env, value).status_code == 422
    assert _get_default(env) is None


def test_raising_or_removing_the_default_needs_confirmation_lowering_does_not(env: Env) -> None:
    _set_default(env, 100)
    assert _set_default(env, 50).status_code == 200  # lowering restricts
    for relaxing in (200, None):
        assert _set_default(env, relaxing).status_code == 400
        assert _set_default(env, relaxing, confirm=False).status_code == 400
    assert _get_default(env) == 50
    assert _set_default(env, 200, confirm=True).status_code == 200
    assert _set_default(env, None, confirm=True).status_code == 200 and _get_default(env) is None


def test_the_default_is_per_organization(env: Env) -> None:
    from uuid import UUID

    from core_helpers import operator_headers

    _set_default(env, 77)
    other = operator_headers(settings=env.settings, user_id=UUID("00000000-0000-0000-0000-0000000000f3"))
    assert env.client.get("/v1/organization/budget-default", headers=other).json()["default_daily_call_limit"] is None


def test_new_agents_start_with_the_default_limit_and_it_is_audited(env: Env) -> None:
    _set_default(env, 100)
    created = env.register("Fresh")
    assert created["daily_call_limit"] == 100 and created["budget_action"] == "deny"
    assert env.budget_of(created["id"])["daily_call_limit"] == 100  # the gateway sees it at once
    entry = next(e for e in env.actions("passport.budget_changed") if e["target_id"] == created["id"])
    assert entry["reason"] == "Organization default daily limit"
    assert entry["actor_user_id"] == DEV_OPERATORS["admin"]["id"]  # the person who registered the agent
    assert entry["details"]["new_limit"] == 100


def test_without_a_default_new_agents_have_no_limit(env: Env) -> None:
    assert env.register("Fresh")["daily_call_limit"] is None
    assert env.actions("passport.budget_changed") == []


def test_the_default_never_changes_existing_agents_or_later_changes_of_the_default(env: Env) -> None:
    before = env.register("Before")
    _set_default(env, 100)
    after = env.register("After")
    _set_default(env, 40)  # lowering the default later
    assert env.budget_of(before["id"])["daily_call_limit"] is None  # registered before: untouched
    assert env.budget_of(after["id"])["daily_call_limit"] == 100  # keeps the value it started with


def test_a_failure_applying_the_default_never_blocks_registration(env: Env, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    _set_default(env, 100)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("database hiccup: password=hunter2")

    monkeypatch.setitem(local_rpc.HANDLERS, "control_agent_budget", boom)
    created = env.register("Fresh")  # still 201
    assert created["daily_call_limit"] is None
    assert "hunter2" not in caplog.text and "Could not apply the organization default limit" in caplog.text
