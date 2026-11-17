"""
B5c, gateway side: the passport lookup carries the agent's model spend state (`model_spend`). The key is REQUIRED (null when there is nothing to check) so a core that predates it
makes the lookup fail and the proxy deny, instead of silently skipping the limit. Strict values: anything malformed denies.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentwall.src.gateway.context import ContextUnavailableError

from test_gateway import INVOICES_READ, ORG, Harness

GOOD = {"limit_micro_usd": 5_000_000, "measured_micro_usd": 1_234_567, "spend_known": True, "priced_models": ["claude-sonnet-5-5", "claude-haiku-5-5"]}


def setup(model_spend: Any) -> tuple[Harness, Any]:
    h = Harness(ttl=0.0)
    return h, h.add_agent(INVOICES_READ, model_spend=model_spend)


async def lookup(h: Harness, agent: Any) -> Any:
    return await h.gateway.contexts.get(agent, ORG, "xero")


async def test_a_context_with_model_spend_is_parsed() -> None:
    h, agent = setup(GOOD)
    spend = (await lookup(h, agent)).model_spend
    assert spend.limit_micro_usd == 5_000_000 and spend.measured_micro_usd == 1_234_567 and spend.spend_known is True
    assert spend.priced_models == frozenset({"claude-sonnet-5-5", "claude-haiku-5-5"})


async def test_null_means_nothing_to_check() -> None:
    h, agent = setup(None)
    assert (await lookup(h, agent)).model_spend is None


async def test_a_core_that_does_not_send_the_key_is_an_older_core_and_the_lookup_fails() -> None:
    h, agent = setup(None)
    del h.core.agents[str(agent)]["model_spend"]
    with pytest.raises(ContextUnavailableError):
        await lookup(h, agent)


@pytest.mark.parametrize(
    "bad",
    [
        {**GOOD, "limit_micro_usd": -1}, {**GOOD, "limit_micro_usd": "5"}, {**GOOD, "limit_micro_usd": True}, {**GOOD, "limit_micro_usd": 10**12 + 1},
        {**GOOD, "measured_micro_usd": -1}, {**GOOD, "measured_micro_usd": 1.5}, {**GOOD, "spend_known": "yes"}, {**GOOD, "spend_known": None},
        {**GOOD, "priced_models": "claude-sonnet-5-5"}, {**GOOD, "priced_models": [1]}, {**GOOD, "priced_models": ["x" * 129]}, {**GOOD, "priced_models": ["a"] * 201},
        {"limit_micro_usd": 1}, "limited", 5,
    ],
    ids=["negative limit", "string limit", "bool limit", "huge limit", "negative spend", "float spend", "string known", "null known", "string models", "int model",
         "long model", "201 models", "missing fields", "string", "int"],
)
async def test_a_malformed_model_spend_denies(bad: Any) -> None:
    h, agent = setup(GOOD)
    h.core.agents[str(agent)]["model_spend"] = bad
    with pytest.raises(ContextUnavailableError):
        await lookup(h, agent)
