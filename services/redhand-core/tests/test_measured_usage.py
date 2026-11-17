"""
Measured model usage in redhand-core (Phase 4.5 B5b, ADR 0025): the gateway's model proxy reports the tokens the PROVIDER counted, in batches. They are stored apart from what an
agent's SDK reports and are never added to it; the organization always comes from the agent's own row; a batch sent twice counts once; a bad row is rejected without losing the rest.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_spend_api import SONNET, Env as SpendEnv

SERVICE = "measured-internal-service-token-0123456789abcdef"
SERVICE_HEADERS = {"Authorization": f"Bearer {SERVICE}"}
URL = "/internal/v1/model-usage"


class Env(SpendEnv):
    def __init__(self) -> None:
        super().__init__(INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE))

    def item(self, agent_id: str, model: str = SONNET, calls: int = 1, input_tokens: int = 1000, output_tokens: int = 500, **extra: Any) -> dict[str, Any]:
        return {"agent_id": agent_id, "provider": "anthropic", "model": model, "calls": calls, "input_tokens": input_tokens, "output_tokens": output_tokens,
                "calls_without_usage": 0, "occurred_at": datetime.now(timezone.utc).isoformat(), **extra}

    def send(self, items: list[dict[str, Any]], batch_id: str | None = None, headers: dict[str, str] | None = None) -> Any:
        return self.client.post(URL, json={"batch_id": batch_id or str(uuid4()), "items": items}, headers=SERVICE_HEADERS if headers is None else headers)

    def agent_row(self, agent_id: str, who: str = "owner") -> dict[str, Any]:
        rows = self.client.get("/v1/spend/agents", headers=self.h(who)).json()["agents"]
        return next(r for r in rows if r["agent_id"] == agent_id)


@pytest.fixture
def env() -> Env:
    return Env()


# --- who may report ---------------------------------------------------------------------------------------------------------------------

def test_the_route_needs_the_internal_service_token(env: Env) -> None:
    agent = env.report("agent-m1", SONNET, 10)
    before = {k: list(v) for k, v in env.store.tables.items()}
    for headers in ({}, {"Authorization": "Bearer wrong"}, env.h("owner"), env.h("admin")):
        response = env.send([env.item(agent)], headers=headers)
        assert response.status_code in (401, 403), headers
    assert {k: list(v) for k, v in env.store.tables.items()} == before


# --- recording --------------------------------------------------------------------------------------------------------------------------

def test_a_batch_is_recorded_for_the_agents_own_organization(env: Env) -> None:
    agent = env.report("agent-m2", SONNET, 10)
    response = env.send([env.item(agent, calls=2, input_tokens=1_000_000, output_tokens=100_000)])
    assert response.status_code == 200, response.text
    assert response.json() == {"accepted": 1, "rejected": 0, "duplicate": False}
    row = env.store.tables["agent_model_measured_daily"][0]
    assert row["agent_id"] == agent and row["organization_id"] == DEFAULT_ORG_ID
    measured = env.agent_row(agent)["measured"]
    assert measured["calls"] == 2 and measured["prompt_tokens"] == 1_000_000 and measured["completion_tokens"] == 100_000
    assert measured["estimated_micro_usd"] == 3_000_000, "1M input at $2 plus 100k output at $10 per million"


def test_a_batch_sent_twice_counts_once(env: Env) -> None:
    agent = env.report("agent-m3", SONNET, 10)
    batch = str(uuid4())
    assert env.send([env.item(agent, calls=3)], batch_id=batch).json()["duplicate"] is False
    again = env.send([env.item(agent, calls=3)], batch_id=batch)
    assert again.status_code == 200 and again.json() == {"accepted": 0, "rejected": 0, "duplicate": True}
    assert env.agent_row(agent)["measured"]["calls"] == 3


def test_the_organization_cannot_be_named_in_the_request(env: Env) -> None:
    agent = env.report("agent-m4", SONNET, 10)
    before = len(env.store.tables.get("agent_model_measured_daily", []))
    assert env.send([env.item(agent, organization_id=str(uuid4()))]).status_code == 422
    assert len(env.store.tables.get("agent_model_measured_daily", [])) == before


def test_a_bad_row_is_rejected_and_the_rest_of_the_batch_lands(env: Env) -> None:
    agent = env.report("agent-m5", SONNET, 10)
    response = env.send([env.item(str(uuid4())), env.item(agent, calls=4)])
    assert response.status_code == 200
    assert response.json()["accepted"] == 1 and response.json()["rejected"] == 1
    assert env.agent_row(agent)["measured"]["calls"] == 4


@pytest.mark.parametrize("bad", [{"calls": 0}, {"calls": -1}, {"input_tokens": -5}, {"model": ""}, {"model": "x" * 129}, {"provider": "x" * 65}, {"calls": 10**7}, {"input_tokens": 10**13}, {"occurred_at": "yesterday"}])
def test_malformed_rows_are_refused_at_the_boundary(env: Env, bad: dict[str, Any]) -> None:
    agent = env.report("agent-m6", SONNET, 10)
    assert env.send([env.item(agent, **bad)]).status_code == 422


def test_an_oversize_batch_and_unknown_fields_are_refused(env: Env) -> None:
    agent = env.report("agent-m7", SONNET, 10)
    assert env.send([env.item(agent) for _ in range(501)]).status_code == 422
    assert env.client.post(URL, json={"batch_id": str(uuid4()), "items": [], "extra": 1}, headers=SERVICE_HEADERS).status_code == 422
    assert env.client.post(URL, json={"batch_id": "not-a-uuid", "items": []}, headers=SERVICE_HEADERS).status_code == 422


def test_an_empty_batch_is_accepted_and_changes_nothing(env: Env) -> None:
    response = env.send([])
    assert response.status_code == 200 and response.json() == {"accepted": 0, "rejected": 0, "duplicate": False}


def test_a_database_failure_is_a_plain_503_that_leaks_nothing(env: Env) -> None:
    from redhand_core.services import local_rpc

    original = local_rpc.HANDLERS["record_model_usage"]

    def boom(store: Any, params: dict[str, Any]) -> Any:
        raise RuntimeError("password=hunter2 host=db.internal")

    local_rpc.HANDLERS["record_model_usage"] = boom
    try:
        response = env.send([env.item(env.report("agent-m8", SONNET, 10))])
    finally:
        local_rpc.HANDLERS["record_model_usage"] = original
    assert response.status_code == 503 and "hunter2" not in response.text and "db.internal" not in response.text


# --- reading ----------------------------------------------------------------------------------------------------------------------------

def test_measured_and_reported_are_never_added_together(env: Env) -> None:
    agent = env.report("agent-m9", SONNET, 2_000_000, 0)  # reported by the SDK: $4
    env.send([env.item(agent, input_tokens=1_000_000, output_tokens=0)])  # measured: $2
    row = env.agent_row(agent)
    assert row["estimated_micro_usd"] == 4_000_000 and row["prompt_tokens"] == 2_000_000
    assert row["measured"]["estimated_micro_usd"] == 2_000_000 and row["measured"]["prompt_tokens"] == 1_000_000


def test_an_agent_with_no_measured_usage_has_none_not_zero(env: Env) -> None:
    agent = env.report("agent-m10", SONNET, 10)
    row = env.agent_row(agent)
    assert row["measured"] is None and row["measured_unavailable"] is False


def test_an_unknown_model_is_price_unknown_never_free(env: Env) -> None:
    agent = env.report("agent-m11", SONNET, 10)
    env.send([env.item(agent, model="mystery-model", input_tokens=5000)])
    measured = env.agent_row(agent)["measured"]
    assert measured["unpriced_tokens"] >= 5000 and "anthropic/mystery-model" in measured["unpriced_models"]
    assert next(m for m in measured["models"] if m["model"] == "mystery-model")["estimated_micro_usd"] is None


def test_calls_the_provider_gave_no_usage_for_are_counted_apart(env: Env) -> None:
    agent = env.report("agent-m12", SONNET, 10)
    env.send([env.item(agent, calls=3, input_tokens=0, output_tokens=0, calls_without_usage=3)])
    measured = env.agent_row(agent)["measured"]
    assert measured["calls"] == 3 and measured["calls_without_usage"] == 3 and measured["estimated_micro_usd"] == 0


def test_a_failed_measured_read_says_so_and_still_shows_the_reported_numbers(env: Env) -> None:
    from redhand_core.services import local_rpc

    agent = env.report("agent-m13", SONNET, 1000)
    original = local_rpc.HANDLERS["agent_model_measured_usage"]

    def boom(store: Any, params: dict[str, Any]) -> Any:
        raise RuntimeError("down")

    local_rpc.HANDLERS["agent_model_measured_usage"] = boom
    try:
        row = env.agent_row(agent)
    finally:
        local_rpc.HANDLERS["agent_model_measured_usage"] = original
    assert row["measured"] is None and row["measured_unavailable"] is True and row["prompt_tokens"] == 1000


def test_another_organization_never_sees_the_measured_usage(env: Env) -> None:
    agent = env.report("agent-m14", SONNET, 10)
    env.send([env.item(agent, calls=9)])
    from test_telegram import OTHER_OWNER

    other = env.client.get("/v1/spend/agents", headers=__import__("core_helpers").operator_headers(settings=env.settings, user_id=OTHER_OWNER, org=None)).json()["agents"]
    assert all(a["agent_id"] != agent for a in other)


def test_the_twin_applies_the_same_day_future_and_age_rules(env: Env) -> None:
    agent = env.report("agent-m15", SONNET, 10)
    now = datetime.now(timezone.utc)
    env.send([env.item(agent, model="future-m", occurred_at=(now + timedelta(days=3)).isoformat()), env.item(agent, model="ancient-m", occurred_at=(now - timedelta(days=40)).isoformat())])
    models = {r["model"] for r in env.store.tables["agent_model_measured_daily"]}
    assert "future-m" in models and "ancient-m" not in models
    future = next(r for r in env.store.tables["agent_model_measured_daily"] if r["model"] == "future-m")
    assert future["day"] <= (now + timedelta(minutes=480)).date().isoformat()


# --- the wire contract between the gateway's reporter and this route ---------------------------------------------------------------------

async def test_the_gateways_own_reporter_is_understood_by_core(env: Env) -> None:
    """Not a fake: the gateway's ReportingUsageSink posts to the real core app, and the numbers come back on the spend view."""
    import httpx

    from agentwall.src.gateway.model_proxy import ModelUsage
    from agentwall.src.gateway.model_usage_reporter import ReportingUsageSink

    agent = env.report("agent-m16", SONNET, 10)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=env.client.app), base_url="http://core.test")  # type: ignore[arg-type]
    sink = ReportingUsageSink(core_url="http://core.test", service_token=SERVICE, http_client=client)
    org = UUID(DEFAULT_ORG_ID)
    sink.record(ModelUsage(UUID(agent), org, SONNET, 1_000_000, 100_000, False, "ok"))
    sink.record(ModelUsage(UUID(agent), org, SONNET, 0, 0, True, "usage_not_reported"))
    assert await sink.flush() is True and sink.stats["reported_batches"] == 1
    measured = env.agent_row(agent)["measured"]
    assert measured["calls"] == 2 and measured["calls_without_usage"] == 1 and measured["estimated_micro_usd"] == 3_000_000
    await client.aclose()
