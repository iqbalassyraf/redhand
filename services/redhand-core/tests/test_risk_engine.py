"""
The Risk Engine, core side (Phase 4.5 B1, ADR 0019): who may read scores and change the ladder, that nothing crosses organizations, that
the score follows the signals real reports create, that each rung acts once (alert on by default; Safe Mode and freeze only when opted in,
with a confirmation), that a person's release is respected, and that a failure in the engine never fails the report that triggered it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import SecretStr
import pytest

from redhand_core.passports.budget import SYSTEM_ACTOR_ID
from redhand_core.services.local_store import DEFAULT_ORG_ID
from redhand_core.services.metrics import get_metrics

from core_helpers import operator_headers
from test_telegram import OTHER_ORG, OWNER_CHAT, Env as TelegramEnv

SERVICE_TOKEN = "risk-core-test-internal-service-token-0123456789"
GATEWAY = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
ROOT = Path(__file__).resolve().parents[3]


def counter(name: str, **labels: str) -> float:
    return float(get_metrics()._counters.get(name, {}).get(tuple(sorted(labels.items())), 0.0))


def finding(rule: str = "RAD-INJ-001", confidence: str = "medium", tool: str = "get_ticket") -> dict[str, Any]:
    return {
        "rule_id": rule, "kind": "injection" if rule.startswith("RAD-INJ") else "output", "family": "override", "severity": "high",
        "confidence": confidence, "place": "text", "evasion": [], "tool_name": tool, "server": "helpdesk", "would_block": False,
        "occurrences": 1,
    }


class Env(TelegramEnv):
    def __init__(self) -> None:
        super().__init__(INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE_TOKEN))
        self.agent = self.register("Risky bot")["id"]
        self.link()

    # gateway reports
    def honeytoken(self) -> str:
        """A decoy that only alerts (a honeytoken's own default is to freeze the agent, which would hide what the engine does)."""
        resp = self.client.post("/v1/honeytokens", json={"label": "Decoy key", "kind": "api_key", "action_on_use": "alert"}, headers=self.h("admin"))
        assert resp.status_code == 201, resp.text
        return str(resp.json()["id"])

    def trip(self, ref: str, agent: str | None = None) -> Any:
        body = {"organization_id": DEFAULT_ORG_ID, "trip_id": str(uuid4()), "agent_id": agent or self.agent, "kind": "honeytoken",
                "ref_id": ref, "seen_in": "arguments", "tool_name": "send_email", "server": "mail"}
        resp = self.client.post("/internal/v1/trips", json=body, headers=GATEWAY)
        assert resp.status_code == 200, resp.text
        return resp

    def report(self, items: list[dict[str, Any]], agent: str | None = None) -> Any:
        resp = self.client.post("/internal/v1/findings", json={"organization_id": DEFAULT_ORG_ID, "agent_id": agent or self.agent, "items": items},
                                headers=GATEWAY)
        assert resp.status_code == 200, resp.text
        return resp

    # operator calls
    def risk(self, user: str = "operator") -> Any:
        return self.client.get("/v1/risk/agents", headers=self.h(user))

    def detail(self, agent: str | None = None, user: str = "operator", headers: dict[str, str] | None = None) -> Any:
        return self.client.get(f"/v1/risk/agents/{agent or self.agent}", headers=headers or self.h(user))

    def ladder_put(self, user: str = "admin", **body: Any) -> Any:
        full = {"alert_at": 50, "safe_mode_at": None, "freeze_at": None, **body}
        return self.client.put("/v1/risk/ladder", json=full, headers=self.h(user))

    def me(self) -> dict[str, Any]:
        return next(a for a in self.risk().json()["agents"] if a["agent_id"] == self.agent)

    def agent_row(self) -> dict[str, Any]:
        return next(a for a in self.store.tables["agents"] if str(a["id"]) == self.agent)

    def messages(self) -> list[str]:
        return [t for t in self.fake.to(OWNER_CHAT) if not t.startswith("Linked.")]

    def risk_alerts(self) -> list[str]:
        """The Risk Engine's paragraphs. A report's own alert and the engine's leave as ONE message (paragraphs), so look inside."""
        return [p for t in self.messages() for p in t.split("\n\n") if p.startswith("Risk:")]

    def audit(self, action: str) -> list[dict[str, Any]]:
        return [r for r in self.store.tables.get("control_audit_log", []) if r["action"] == action]


@pytest.fixture
def env() -> Env:
    return Env()


# --- reading ------------------------------------------------------------------------------------------------------------------

def test_a_new_agent_has_a_zero_score_and_the_default_ladder_only_alerts(env: Env) -> None:
    body = env.risk().json()
    me = next(a for a in body["agents"] if a["agent_id"] == env.agent)
    assert (me["score"], me["level"], me["action_score"], me["reason"]) == (0, "low", 0, "no signals")
    ladder = body["ladder"]
    assert (ladder["alert_at"], ladder["safe_mode_at"], ladder["freeze_at"]) == (50, None, None)
    assert ladder["capabilities"]["can_change"] is False  # an operator reads but cannot change
    assert body["model"] == "2026-11-14"


@pytest.mark.parametrize(("user", "code"), [("viewer", 403), ("operator", 200), ("admin", 200)])
def test_reading_needs_the_security_operator_role(env: Env, user: str, code: int) -> None:
    assert env.risk(user).status_code == code
    assert env.detail(user=user).status_code == code
    assert env.client.get("/v1/risk/ladder", headers=env.h(user)).status_code == code


def test_reading_without_a_token_is_refused(env: Env) -> None:
    assert env.client.get("/v1/risk/agents").status_code == 401


@pytest.mark.parametrize(("user", "code"), [("viewer", 403), ("operator", 403), ("admin", 200)])
def test_changing_the_ladder_needs_an_admin(env: Env, user: str, code: int) -> None:
    assert env.ladder_put(user, alert_at=60).status_code == code


def test_a_trip_raises_the_score_and_is_named_as_the_reason(env: Env) -> None:
    env.trip(env.honeytoken())
    me = env.me()
    assert (me["score"], me["level"]) == (40, "elevated")
    assert me["reason"] == "honeytoken or canary trip (1)"
    detail = env.detail().json()
    assert [s["signal"] for s in detail["agent"]["signals"]] == ["trip"] and detail["agent"]["signals"][0]["points"] == 40
    assert {w["signal"] for w in detail["weights"]} == {"trip", "confirmed_finding", "destination_open", "radar_open", "loop_open",
                                                        "refusal", "budget_limit"}


def test_a_finding_marked_false_alarm_counts_zero(env: Env) -> None:
    env.report([finding()])
    assert env.me()["score"] == 4
    fid = env.client.get("/v1/findings", headers=env.h("operator")).json()["findings"][0]["id"]
    assert env.client.post(f"/v1/findings/{fid}/review", json={"status": "false_alarm"}, headers=env.h("operator")).status_code == 200
    assert (env.me()["score"], env.me()["level"]) == (0, "low")


def test_low_confidence_findings_do_not_count(env: Env) -> None:
    env.report([finding(confidence="low")])
    assert env.me()["score"] == 0


def test_refusals_outside_the_passport_count_and_other_blocks_do_not(env: Env) -> None:
    now = datetime.now(timezone.utc)
    for seq, reason in enumerate([
        "Tool 'x' on server 's' is not in this agent's passport scopes.",
        "Tool 'y' on server 's' is not approved: its current version has not been reviewed.",
        "safe_mode",
    ]):
        env.store.tables["agent_events"].append({"organization_id": DEFAULT_ORG_ID, "agent_id": env.agent, "seq": 9000 + seq,
                                                 "occurred_at": now.isoformat(), "decision": "BLOCK", "reasons": [reason]})
    detail = env.detail().json()["agent"]
    refusal = next(s for s in detail["signals"] if s["signal"] == "refusal")
    assert (refusal["recent"], refusal["points"]) == (2, 4)


def test_the_gateway_still_uses_the_refusal_wording_the_sql_matches() -> None:
    """agent_risk_signals() recognizes a refusal outside the passport by the gateway's fixed reason text. If the gateway rewords it, the
    refusal signal silently disappears; this test fails first."""
    gateway = (ROOT / "agentwall" / "src" / "gateway" / "service.py").read_text(encoding="utf-8")
    sql = (ROOT / "supabase" / "migrations" / "20261122000000_risk_engine.sql").read_text(encoding="utf-8")
    for suffix in ("is not in this agent's passport scopes.", "is not approved: its current version has not been reviewed."):
        assert suffix in gateway
        assert suffix.replace("'", "''") in sql


# --- tenancy ------------------------------------------------------------------------------------------------------------------

def test_another_organization_cannot_read_this_agents_score(env: Env) -> None:
    env.trip(env.honeytoken())
    other = operator_headers(settings=env.settings, user_id=UUID(OTHER_OWNER))
    assert env.detail(headers=other).status_code == 404
    assert all(a["agent_id"] != env.agent for a in env.client.get("/v1/risk/agents", headers=other).json()["agents"])


def test_a_report_claiming_another_organization_changes_nothing(env: Env) -> None:
    env.ladder_put(freeze_at=50, confirm=True)
    hostile = {"organization_id": OTHER_ORG, "agent_id": env.agent, "items": [finding()]}
    env.client.post("/internal/v1/findings", json=hostile, headers=GATEWAY)
    assert env.agent_row()["status"] == "active"
    assert env.store.tables["organizations"][-1]["id"] == OTHER_ORG  # the other organization exists and kept its own defaults


def test_changing_the_ladder_never_touches_another_organization(env: Env) -> None:
    assert env.ladder_put(alert_at=30).status_code == 200
    other = next(o for o in env.store.tables["organizations"] if o["id"] == OTHER_ORG)
    assert other.get("risk_alert_threshold", 50) == 50


# --- the ladder -----------------------------------------------------------------------------------------------------------------

def test_by_default_crossing_50_alerts_once_and_changes_nothing(env: Env) -> None:
    env.trip(env.honeytoken())
    assert env.risk_alerts() == []  # 40: below the alert rung
    env.trip(env.honeytoken())
    alerts = env.risk_alerts()
    assert len(alerts) == 1
    assert "Risky bot" in alerts[0] and "80 (critical)" in alerts[0] and "Nothing was changed automatically" in alerts[0]
    assert "send_email" not in alerts[0] and "Decoy key" not in alerts[0]  # counts and fixed labels only
    env.trip(env.honeytoken())
    assert len(env.risk_alerts()) == 1  # one per agent per hour
    row = env.agent_row()
    assert row["status"] == "active" and not row.get("safe_mode")


def test_after_the_cooldown_a_new_signal_alerts_again(env: Env) -> None:
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    env.agent_row()["risk_last_alert_at"] = (datetime.now(timezone.utc) - timedelta(minutes=61)).isoformat()
    env.trip(env.honeytoken())
    assert len(env.risk_alerts()) == 2


def test_with_every_rung_off_nothing_happens(env: Env) -> None:
    assert env.ladder_put(alert_at=None).status_code == 200
    for _ in range(3):
        env.trip(env.honeytoken())
    assert env.risk_alerts() == [] and env.agent_row()["status"] == "active"


def test_turning_freeze_on_needs_a_confirmation_and_is_audited(env: Env) -> None:
    refused = env.ladder_put(freeze_at=90)
    assert refused.status_code == 400 and "confirm" in refused.json()["detail"]
    ok = env.ladder_put(freeze_at=90, confirm=True, reason="trial")
    assert ok.status_code == 200 and ok.json()["freeze_at"] == 90
    rows = env.audit("organization.risk_ladder_changed")
    assert len(rows) == 1 and rows[0]["details"]["new"]["freeze"] == 90 and rows[0]["reason"] == "trial"


@pytest.mark.parametrize(
    ("first", "second", "needs_confirm"),
    [
        ({"freeze_at": 90}, {"freeze_at": 80}, True),  # lowering widens the action
        ({"freeze_at": 80}, {"freeze_at": 90}, False),  # raising narrows it
        ({"freeze_at": 80}, {"freeze_at": None}, False),  # off narrows it
        ({"safe_mode_at": 70}, {"safe_mode_at": 60}, True),
        ({}, {"alert_at": 20}, False),  # the alert rung only notifies
    ],
)
def test_only_widening_an_automatic_action_needs_a_confirmation(env: Env, first: dict[str, Any], second: dict[str, Any],
                                                                 needs_confirm: bool) -> None:
    assert env.ladder_put(confirm=True, **first).status_code == 200
    assert env.ladder_put(**{**first, **second}).status_code == (400 if needs_confirm else 200)


@pytest.mark.parametrize(
    "body",
    [{"alert_at": 0}, {"alert_at": 101}, {"alert_at": 80, "safe_mode_at": 60}, {"safe_mode_at": 90, "freeze_at": 70},
     {"alert_at": 60, "freeze_at": 50}, {"alert_at": "50"}, {"unknown": 1}],
)
def test_a_bad_ladder_is_refused(env: Env, body: dict[str, Any]) -> None:
    assert env.ladder_put(confirm=True, **body).status_code == 422


def test_opted_in_freeze_freezes_through_the_audited_path_with_the_reason(env: Env) -> None:
    env.ladder_put(freeze_at=90, confirm=True)
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())  # 80: alert only
    assert env.agent_row()["status"] == "active"
    env.report([finding()])  # 84
    fid = env.client.get("/v1/findings", headers=env.h("operator")).json()["findings"][0]["id"]
    env.client.post(f"/v1/findings/{fid}/review", json={"status": "confirmed"}, headers=env.h("operator"))  # 80 + 25 -> 100
    row = env.agent_row()
    assert row["status"] == "frozen"
    frozen = [r for r in env.audit("passport.frozen") if r["target_id"] == env.agent]
    assert len(frozen) == 1 and frozen[0]["actor_user_id"] == str(SYSTEM_ACTOR_ID)
    assert frozen[0]["reason"].startswith("Risk Engine: score 100 (critical): ")
    assert any("frozen it" in a for a in env.risk_alerts())
    # The gateway reads the status per call: the next call is refused within the revocation SLO.
    context = env.client.get("/internal/v1/gateway-context", params={"agent_id": env.agent, "organization_id": DEFAULT_ORG_ID, "server": "xero"},
                             headers=GATEWAY)
    assert context.status_code == 200 and context.json()["agent"]["status"] == "frozen"
    assert counter("risk_actions_total", action="freeze") >= 1


def test_a_person_s_release_is_respected_and_only_new_signals_act(env: Env) -> None:
    env.ladder_put(freeze_at=80, confirm=True)
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    assert env.agent_row()["status"] == "frozen"
    unfreeze = env.client.post(f"/v1/passports/{env.agent}/unfreeze", json={"confirm": True}, headers=env.h("admin"))
    assert unfreeze.status_code == 200, unfreeze.text
    assert env.agent_row()["risk_released_at"] is not None
    env.report([finding()])  # evaluates again: the shown score stays high, the action score counts only what came after the release
    me = env.me()
    assert me["score"] >= 80 and me["action_score"] == 4
    assert env.agent_row()["status"] == "active"
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())  # new trips after the release: they can freeze again
    assert env.agent_row()["status"] == "frozen"


def test_opted_in_safe_mode_turns_it_on_and_does_not_freeze(env: Env) -> None:
    env.ladder_put(safe_mode_at=70, confirm=True)
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    row = env.agent_row()
    assert row["safe_mode"] is True and row["status"] == "active"
    audited = [r for r in env.audit("passport.safe_mode_enabled") if r["target_id"] == env.agent]
    assert len(audited) == 1 and audited[0]["actor_user_id"] == str(SYSTEM_ACTOR_ID)
    assert any("Safe Mode on" in a for a in env.risk_alerts())


def test_the_engine_never_touches_a_frozen_or_revoked_agent(env: Env) -> None:
    env.ladder_put(safe_mode_at=50, freeze_at=60, confirm=True)
    env.agent_row()["status"] = "revoked"
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    assert env.agent_row()["status"] == "revoked" and not env.agent_row().get("safe_mode")


def test_the_ladder_shows_how_many_agents_reach_each_rung(env: Env) -> None:
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    ladder = env.client.get("/v1/risk/ladder", headers=env.h("operator")).json()
    assert ladder["reaching"] == {"alert": 1, "safe_mode": 0, "freeze": 0}
    assert ladder["reaching_agents"] == {"alert": ["Risky bot"], "safe_mode": [], "freeze": []}  # names, so an admin sees who


# --- failure modes --------------------------------------------------------------------------------------------------------------

def test_an_engine_failure_never_fails_the_report(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services import local_rpc

    def boom(store: Any, p: dict[str, Any]) -> Any:
        raise local_rpc._error("XX000", "simulated database failure")

    monkeypatch.setitem(local_rpc.HANDLERS, "agent_risk_signals", boom)
    before = counter("risk_evaluations_total", outcome="error")
    env.ladder_put(freeze_at=50, confirm=True)
    resp = env.report([finding()])
    assert resp.status_code == 200 and resp.json()["new"] == 1  # the report is stored
    assert counter("risk_evaluations_total", outcome="error") == before + 1
    assert env.agent_row()["status"] == "active"  # and nothing was done on a failed evaluation


def test_reading_scores_when_the_database_fails_is_an_error_not_a_zero(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services import local_rpc

    def boom(store: Any, p: dict[str, Any]) -> Any:
        raise local_rpc._error("XX000", "simulated database failure")

    monkeypatch.setitem(local_rpc.HANDLERS, "agent_risk_signals", boom)
    resp = env.risk()
    assert resp.status_code == 503 and resp.json()["detail"] == "Risk scores could not be read. Try again shortly."  # never a clean zero


# --- every report that carries a signal re-evaluates the agent ------------------------------------------------------------------

def test_reaching_the_daily_limit_is_evaluated_from_the_usage_report(env: Env) -> None:
    from redhand_core.passports import budget
    from redhand_core.passports.models import utcnow

    env.ladder_put(alert_at=10)
    env.agent_row()["daily_call_limit"] = 2
    day = budget.local_day(utcnow(), 480).isoformat()
    body = {"instance_id": "gw-risk-test", "items": [{"agent_id": env.agent, "day_key": day, "calls": 5}]}
    assert env.client.post("/internal/v1/usage", json=body, headers=GATEWAY).status_code == 200
    assert env.me()["reason"] == "daily call limit reached (1)"
    assert len(env.risk_alerts()) == 1


def test_a_refused_call_in_a_black_box_batch_is_evaluated(env: Env) -> None:
    env.ladder_put(alert_at=2)
    reason = "Tool 'delete_file' on server 'fs' is not in this agent's passport scopes."
    item = {"agent_id": env.agent, "occurred_at": datetime.now(timezone.utc).isoformat(), "gateway_instance": "gw-risk-test",
            "server": "fs", "method": "tools/call", "tool_name": "delete_file", "decision": "BLOCK", "reasons": [reason],
            "upstream_status": None, "latency_ms": 1.0, "argument_keys": [], "arguments_sha256": "a" * 64, "result_size_bytes": None,
            "redaction_count": 0, "credential_jti": "jti-1"}
    body = {"instance_id": "gw-risk-test", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": [item]}
    resp = env.client.post("/internal/v1/events", json=body, headers=GATEWAY)
    assert resp.status_code == 200 and resp.json()["accepted"] == 1, resp.text
    assert env.me()["reason"] == "call refused (outside the passport) (1)"
    assert len(env.risk_alerts()) == 1


def test_the_engine_asked_about_another_organizations_agent_does_nothing(env: Env) -> None:
    import asyncio

    from redhand_core.passports.models import utcnow
    from redhand_core.risk import service as risk_service

    env.ladder_put(freeze_at=40, confirm=True)
    other = next(o for o in env.store.tables["organizations"] if o["id"] == OTHER_ORG)
    other.update({"risk_alert_threshold": 1, "risk_safe_mode_threshold": 1, "risk_freeze_threshold": 1})
    env.trip(env.honeytoken())  # 40: this organization's own ladder freezes it at 40
    env.agent_row()["status"] = "active"  # undo that, then ask the engine in the OTHER organization's name
    asyncio.run(risk_service.evaluate_agents(env.store, env.fake, UUID(OTHER_ORG), [UUID(env.agent)], utcnow()))
    assert env.agent_row()["status"] == "active" and not env.agent_row().get("safe_mode")


def test_a_frozen_agent_is_not_given_safe_mode(env: Env) -> None:
    env.ladder_put(safe_mode_at=50, confirm=True)
    env.agent_row()["status"] = "frozen"
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    assert env.agent_row()["status"] == "frozen" and not env.agent_row().get("safe_mode")


def test_an_automatic_action_is_reported_even_with_the_alert_rung_off(env: Env) -> None:
    env.ladder_put(alert_at=None, freeze_at=80, confirm=True)
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    assert env.agent_row()["status"] == "frozen"
    alerts = env.risk_alerts()
    assert len(alerts) == 1 and "frozen it" in alerts[0]


def test_when_both_rungs_are_reached_the_stronger_one_acts(env: Env) -> None:
    env.ladder_put(safe_mode_at=50, freeze_at=60, confirm=True)
    env.trip(env.honeytoken())
    env.trip(env.honeytoken())
    row = env.agent_row()
    assert row["status"] == "frozen" and not row.get("safe_mode")



def test_a_trip_and_the_risk_it_raises_reach_the_phone_as_one_message(env: Env) -> None:
    env.trip(env.honeytoken())
    before = len(env.messages())
    env.trip(env.honeytoken())  # this trip alerts AND crosses the alert rung: still one notification
    new = env.messages()[before:]
    assert len(new) == 1
    paragraphs = new[0].split("\n\n")
    assert paragraphs[0].startswith("Honeytoken used") and paragraphs[1].startswith("Risk:")


def test_the_preview_names_at_most_ten_agents_per_rung_highest_first(env: Env) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for i in range(12):
        agent = env.register(f"Bot {i:02d}")["id"]
        for _ in range(i % 3 + 1):  # 1 to 3 recent refusals: 2 to 6 points
            env.store.tables["agent_events"].append({"organization_id": DEFAULT_ORG_ID, "agent_id": agent, "seq": 7000 + len(env.store.tables["agent_events"]),
                                                     "occurred_at": now, "decision": "BLOCK",
                                                     "reasons": ["Tool 'x' on server 's' is not in this agent's passport scopes."]})
    env.ladder_put(alert_at=2)
    ladder = env.client.get("/v1/risk/ladder", headers=env.h("operator")).json()
    assert ladder["reaching"]["alert"] == 12 and len(ladder["reaching_agents"]["alert"]) == 10
    assert ladder["reaching_agents"]["alert"][:4] == ["Bot 02", "Bot 05", "Bot 08", "Bot 11"]  # 6 points each, then by name


def test_each_evaluation_counts_the_level_it_found(env: Env) -> None:
    before = counter("risk_evaluations_by_level_total", level="elevated")
    env.trip(env.honeytoken())
    assert counter("risk_evaluations_by_level_total", level="elevated") == before + 1


# --- behaviour baseline (Phase 4.5 B2, watch only) ------------------------------------------------------------------------------

def _seed_hours(env: Env, agent: str, hours: range, per_hour: int, tool: str = "read_ticket", org: str = DEFAULT_ORG_ID) -> None:
    top = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    rows = env.store.tables.setdefault("agent_tool_hourly", [])
    for back in hours:
        rows.append({"organization_id": org, "agent_id": agent, "hour": top - timedelta(hours=back), "tool_name": tool, "calls": per_hour,
                     "refused": 0})


def test_a_new_agent_is_warming_up(env: Env) -> None:
    behaviour = env.detail().json()["behaviour"]
    assert behaviour["status"] == "ok" and behaviour["warm"] is False and behaviour["warmup_days"] == 7 and behaviour["warning"] is False


def test_a_surge_on_a_warm_agent_is_a_behaviour_warning_but_not_part_of_the_score(env: Env) -> None:
    _seed_hours(env, env.agent, range(1, 15 * 24), per_hour=2)
    _seed_hours(env, env.agent, range(0, 1), per_hour=40)
    detail = env.detail().json()
    b = detail["behaviour"]
    assert b["warm"] is True and b["usual_hourly"] == 2.0 and b["spike_threshold"] == 30 and b["spike"] is True and b["warning"] is True
    assert b["backtest"]["hours"] == 168 and b["backtest"]["flagged_hours"] == 0
    assert detail["agent"]["score"] == 0  # watch only: no points
    assert env.risk_alerts() == []  # and no alert


def test_a_tool_never_used_before_is_listed_as_new(env: Env) -> None:
    _seed_hours(env, env.agent, range(1, 15 * 24), per_hour=2)
    _seed_hours(env, env.agent, range(3, 4), per_hour=1, tool="export_customers")
    assert env.detail().json()["behaviour"]["new_tools"] == ["export_customers"]


def test_recorded_tool_calls_feed_the_hourly_counts(env: Env) -> None:
    item = {"agent_id": env.agent, "occurred_at": datetime.now(timezone.utc).isoformat(), "gateway_instance": "gw-risk-test", "server": "xero",
            "method": "tools/call", "tool_name": "list_invoices", "decision": "ALLOW", "reasons": [], "upstream_status": 200, "latency_ms": 1.0,
            "argument_keys": [], "arguments_sha256": "a" * 64, "result_size_bytes": 10, "redaction_count": 0, "credential_jti": "jti-1"}
    other = {**item, "method": "tools/list", "tool_name": ""}
    body = {"instance_id": "gw-risk-test", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": [item, item, other]}
    assert env.client.post("/internal/v1/events", json=body, headers=GATEWAY).json()["accepted"] == 3
    rows = [r for r in env.store.tables["agent_tool_hourly"] if r["agent_id"] == env.agent]
    assert len(rows) == 1 and rows[0]["calls"] == 2 and rows[0]["tool_name"] == "list_invoices"  # tools/list is not a tool call
    assert env.detail().json()["behaviour"]["hour_calls"] == 2


def test_if_the_counts_cannot_be_read_the_score_is_still_shown(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services import local_rpc

    def boom(store: Any, p: dict[str, Any]) -> Any:
        raise local_rpc._error("XX000", "simulated database failure")

    env.trip(env.honeytoken())
    monkeypatch.setitem(local_rpc.HANDLERS, "agent_behaviour_hours", boom)
    resp = env.detail()
    assert resp.status_code == 200 and resp.json()["agent"]["score"] == 40
    assert resp.json()["behaviour"]["status"] == "unavailable" and resp.json()["behaviour"]["warning"] is False
    assert env.client.get("/v1/risk/behaviour/summary", headers=env.h("operator")).status_code == 503


@pytest.mark.parametrize(("user", "code"), [("viewer", 403), ("operator", 200), ("admin", 200)])
def test_the_behaviour_summary_needs_the_security_operator_role(env: Env, user: str, code: int) -> None:
    assert env.client.get("/v1/risk/behaviour/summary", headers=env.h(user)).status_code == code


def test_the_behaviour_summary_counts_this_organization_only(env: Env) -> None:
    _seed_hours(env, env.agent, range(1, 15 * 24), per_hour=2)
    _seed_hours(env, env.agent, range(0, 1), per_hour=40)
    other = str(uuid4())
    env.store.tables["agents"].append({"id": other, "organization_id": OTHER_ORG, "name": "Other bot", "external_agent_id": "o", "status": "active"})
    _seed_hours(env, other, range(0, 1), per_hour=500, org=OTHER_ORG)
    summary = env.client.get("/v1/risk/behaviour/summary", headers=env.h("operator")).json()
    assert summary["warnings_now"] == 1 and summary["spikes_now"] == 1 and summary["flagged_agents"] == ["Risky bot"]
    assert summary["warm_agents"] == 1 and summary["backtest"]["hours"] == 168
    theirs = env.client.get("/v1/risk/behaviour/summary", headers=operator_headers(settings=env.settings, user_id=UUID(OTHER_OWNER))).json()
    assert theirs["flagged_agents"] == [] and theirs["warnings_now"] == 0  # their own agent is not warm; ours is not theirs


def test_an_agent_s_behaviour_is_its_own(env: Env) -> None:
    noisy = env.register("Noisy bot")["id"]
    _seed_hours(env, noisy, range(1, 15 * 24), per_hour=2)
    _seed_hours(env, noisy, range(0, 1), per_hour=40)
    _seed_hours(env, env.agent, range(1, 15 * 24), per_hour=2)
    assert env.detail(noisy).json()["behaviour"]["spike"] is True
    assert env.detail().json()["behaviour"]["spike"] is False  # the other agent's surge is not this one's


def test_the_in_memory_twin_scopes_hourly_counts_by_organization(env: Env) -> None:
    import asyncio

    _seed_hours(env, env.agent, range(0, 3), per_hour=1)
    now = datetime.now(timezone.utc)
    params = {"p_agent": env.agent, "p_since": (now - timedelta(days=1)).isoformat(), "p_until": now.isoformat()}
    mine = asyncio.run(env.store.rpc("agent_behaviour_hours", {"p_org": DEFAULT_ORG_ID, **params}).execute()).data
    theirs = asyncio.run(env.store.rpc("agent_behaviour_hours", {"p_org": OTHER_ORG, **params}).execute()).data
    assert len(mine) == 3 and theirs == []  # the same agent id asked for under another organization: nothing, like the SQL function


# --- scoring never delays the Black Box reply (H1.4) ---------------------------------------------------------------------------

def _block_item(agent: str, n: int = 0) -> dict[str, Any]:
    return {"agent_id": agent, "occurred_at": datetime.now(timezone.utc).isoformat(), "gateway_instance": "gw-risk-test", "server": "fs",
            "method": "tools/call", "tool_name": f"t{n}", "decision": "BLOCK",
            "reasons": ["Tool 'x' on server 'fs' is not in this agent's passport scopes."], "upstream_status": None, "latency_ms": 1.0,
            "argument_keys": [], "arguments_sha256": "a" * 64, "result_size_bytes": None, "redaction_count": 0, "credential_jti": "jti-1"}


def test_the_black_box_reply_is_sent_before_risk_scoring_runs(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    """ASGI order: the response must start before the evaluation begins. Scoring used to be awaited inside the handler, so a slow database
    delayed the reply, the gateway's 5 s report timeout fired, and the batch was resent."""
    import asyncio
    import json

    from redhand_core.risk import service as risk_service

    order: list[str] = []
    real = risk_service.evaluate_agents

    async def recording(*args: Any, **kwargs: Any) -> None:
        order.append("evaluate")
        await real(*args, **kwargs)

    monkeypatch.setattr(risk_service, "evaluate_agents", recording)
    body = json.dumps({"instance_id": "gw-risk-test", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": [_block_item(env.agent)]}).encode()
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": "/internal/v1/events", "raw_path": b"/internal/v1/events",
             "query_string": b"", "root_path": "", "scheme": "http", "server": ("test", 80), "client": ("test", 1),
             "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                         (b"authorization", f"Bearer {SERVICE_TOKEN}".encode())]}

    async def run() -> None:
        sent = False

        async def receive() -> dict[str, Any]:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                order.append("response")

        await env.client.app(scope, receive, send)  # type: ignore[attr-defined]

    asyncio.run(run())
    assert order == ["response", "evaluate"]


def test_a_batch_naming_many_agents_reads_signals_once(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services import local_rpc

    agents = [env.register(f"Fleet {i}")["id"] for i in range(6)]
    calls: list[Any] = []
    real = local_rpc.HANDLERS["agent_risk_signals"]

    def counting(store: Any, p: dict[str, Any]) -> Any:
        calls.append(p.get("p_agent"))
        return real(store, p)

    monkeypatch.setitem(local_rpc.HANDLERS, "agent_risk_signals", counting)
    body = {"instance_id": "gw-risk-test", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": [_block_item(a, i) for i, a in enumerate(agents)]}
    assert env.client.post("/internal/v1/events", json=body, headers=GATEWAY).json()["accepted"] == 6
    assert calls == [None]  # one organization-wide read, not one per agent


def test_a_few_agents_are_read_one_by_one(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services import local_rpc

    calls: list[Any] = []
    real = local_rpc.HANDLERS["agent_risk_signals"]

    def counting(store: Any, p: dict[str, Any]) -> Any:
        calls.append(p.get("p_agent"))
        return real(store, p)

    monkeypatch.setitem(local_rpc.HANDLERS, "agent_risk_signals", counting)
    body = {"instance_id": "gw-risk-test", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": [_block_item(env.agent)]}
    env.client.post("/internal/v1/events", json=body, headers=GATEWAY)
    assert calls == [env.agent]


def test_evaluations_are_capped_and_a_skipped_one_is_counted_not_lost(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.risk import service as risk_service

    env.ladder_put(alert_at=2)
    monkeypatch.setattr(risk_service, "MAX_EVALUATIONS_IN_FLIGHT", 0)
    before = counter("risk_evaluations_total", outcome="skipped")
    body = {"instance_id": "gw-risk-test", "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": [_block_item(env.agent)]}
    assert env.client.post("/internal/v1/events", json=body, headers=GATEWAY).status_code == 200
    assert counter("risk_evaluations_total", outcome="skipped") == before + 1
    assert env.risk_alerts() == []  # nothing ran; the signal is stored, so the next report evaluates it
    monkeypatch.setattr(risk_service, "MAX_EVALUATIONS_IN_FLIGHT", 8)
    env.report([finding()])
    assert env.me()["reason"].startswith("Radar finding")  # the refusal recorded earlier is still counted by the next evaluation
