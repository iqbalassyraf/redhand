"""
B5c, core side (ADR 0025): for the model proxy's lookup (server "model") the gateway context carries the agent's daily dollar limit and today's MEASURED spend, so the proxy can refuse
over the limit. Only measured usage counts (what the SDK reports is never used to refuse); the lookup for any other server carries nothing and costs nothing extra; a limit that cannot be
checked (an unpriced model, an unreadable table) fails closed.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from redhand_core.services import local_rpc
from redhand_core.services.local_store import DEFAULT_ORG_ID
from redhand_core.spend.prices import PRICES, price_for

from test_measured_usage import SERVICE_HEADERS, Env as MeasuredEnv
from test_spend_api import SONNET


class Env(MeasuredEnv):
    def context(self, agent_id: str, server: str = "model", org: str = DEFAULT_ORG_ID) -> Any:
        return self.client.get("/internal/v1/gateway-context", params={"agent_id": agent_id, "organization_id": org, "server": server}, headers=SERVICE_HEADERS)

    def model_spend(self, agent_id: str) -> dict[str, Any] | None:
        response = self.context(agent_id)
        assert response.status_code == 200, response.text
        return response.json()["agent"]["model_spend"]


@pytest.fixture
def env() -> Env:
    return Env()


def test_no_limit_means_nothing_is_sent_and_nothing_is_looked_up(env: Env) -> None:
    agent = env.report("agent-c1", SONNET, 10)
    calls: list[str] = []
    original = local_rpc.HANDLERS["agent_model_measured_usage"]
    local_rpc.HANDLERS["agent_model_measured_usage"] = lambda store, p: calls.append("read") or original(store, p)
    try:
        assert env.model_spend(agent) is None
    finally:
        local_rpc.HANDLERS["agent_model_measured_usage"] = original
    assert calls == [], "no limit, no extra lookup on the proxy's hot path"


def test_the_lookup_for_a_tool_server_carries_nothing_even_with_a_limit(env: Env) -> None:
    agent = env.report("agent-c2", SONNET, 10)
    assert env.set_limit(agent, 5_000_000).status_code == 200
    response = env.context(agent, server="xero")
    assert response.status_code == 200 and response.json()["agent"]["model_spend"] is None


def test_with_a_limit_the_proxy_gets_the_limit_the_measured_spend_and_the_priced_models(env: Env) -> None:
    agent = env.report("agent-c3", SONNET, 10)
    env.set_limit(agent, 5_000_000)
    state = env.model_spend(agent)
    assert state is not None
    assert state["limit_micro_usd"] == 5_000_000 and state["measured_micro_usd"] == 0 and state["spend_known"] is True
    assert SONNET in state["priced_models"]
    env.send([env.item(agent, input_tokens=1_000_000, output_tokens=100_000)])
    assert env.model_spend(agent)["measured_micro_usd"] == 3_000_000


def test_only_measured_usage_counts_never_what_the_sdk_reported(env: Env) -> None:
    agent = env.report("agent-c4", SONNET, 5_000_000, 5_000_000)  # reported by the SDK: a lot
    env.set_limit(agent, 1_000_000)
    assert env.model_spend(agent)["measured_micro_usd"] == 0


def test_unpriced_measured_tokens_make_the_spend_unknown_not_free(env: Env) -> None:
    agent = env.report("agent-c5", SONNET, 10)
    env.set_limit(agent, 1_000_000)
    env.send([env.item(agent, model="mystery-model", input_tokens=5000)])
    state = env.model_spend(agent)
    assert state["spend_known"] is False and state["measured_micro_usd"] == 0


def test_another_organizations_usage_is_never_counted(env: Env) -> None:
    agent = env.report("agent-c6", SONNET, 10)
    env.set_limit(agent, 5_000_000)
    other_org = "00000000-0000-0000-0000-00000000ffff"
    other_agent = str(uuid4())
    env.store.tables["organizations"].append({"id": other_org, "name": "Other", "slug": "other-c6"})
    env.store.tables["agents"].append({"id": other_agent, "organization_id": other_org, "external_agent_id": "x", "name": "x", "status": "active"})
    env.store.tables.setdefault("agent_model_measured_daily", []).append(
        {"organization_id": other_org, "agent_id": other_agent, "day": "2099-01-01", "provider": "anthropic", "model": SONNET, "calls": 1, "prompt_tokens": 10**9, "completion_tokens": 0, "calls_without_usage": 0})
    assert env.model_spend(agent)["measured_micro_usd"] == 0


def test_an_unreadable_measured_table_fails_the_lookup_closed(env: Env) -> None:
    agent = env.report("agent-c7", SONNET, 10)
    env.set_limit(agent, 5_000_000)
    original = local_rpc.HANDLERS["agent_model_measured_usage"]

    def boom(store: Any, params: dict[str, Any]) -> Any:
        raise RuntimeError("password=hunter2")

    local_rpc.HANDLERS["agent_model_measured_usage"] = boom
    try:
        response = env.context(agent)
    finally:
        local_rpc.HANDLERS["agent_model_measured_usage"] = original
    assert response.status_code == 503 and "hunter2" not in response.text


def test_a_malformed_stored_limit_is_read_the_restrictive_way(env: Env) -> None:
    agent = env.report("agent-c8", SONNET, 10)
    row = next(a for a in env.store.tables["agents"] if str(a["id"]) == agent)
    row["spend_limit_micro_usd"] = "lots"
    assert env.model_spend(agent)["limit_micro_usd"] == 0, "limit 0: the proxy refuses everything"


def test_every_listed_model_is_really_priced_and_the_date_stamp_rule_is_shared(env: Env) -> None:
    agent = env.report("agent-c9", SONNET, 10)
    env.set_limit(agent, 5_000_000)
    listed = env.model_spend(agent)["priced_models"]
    assert listed and all(price_for("anthropic", m) is not None for m in listed)
    assert set(listed) == {p.model for p in PRICES if p.provider == "anthropic"}
    assert price_for("anthropic", f"{SONNET}-20261101") is not None, "a dated id resolves through the same rule the gateway copies"


def test_another_agent_in_the_same_organization_never_counts_towards_this_ones_limit(env: Env) -> None:
    mine = env.report("agent-c10", SONNET, 10)
    neighbour = env.report("agent-c11", SONNET, 10)
    env.set_limit(mine, 5_000_000)
    env.send([env.item(neighbour, input_tokens=1_000_000, output_tokens=100_000)])
    assert env.model_spend(mine)["measured_micro_usd"] == 0


@pytest.mark.parametrize("model", [SONNET, f"{SONNET}-20261101", SONNET.upper(), f" {SONNET} ", "claude-haiku-5-5", "claude-haiku-5-5-20260101", "mystery-model", "mystery-model-20261101", "x-2026", "-20261101", "claude-sonnet-5-5-2026110"])
def test_the_gateways_price_key_rule_agrees_with_cores_price_table(model: str) -> None:
    """The gateway cannot see the price table, so it copies the date-stamp rule. This pins the copy to the original on every id above."""
    from agentwall.src.gateway.model_proxy import _price_key

    listed = {p.model for p in PRICES if p.provider == "anthropic"}
    assert (_price_key(model) in listed) == (price_for("anthropic", model) is not None), model
