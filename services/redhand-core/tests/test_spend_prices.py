"""
Model prices and cost arithmetic (Phase 4.5 B4). Costs are estimates from what an agent's SDK reported, so the arithmetic is exact integer
micro-dollars (never floats), an unknown model is "price unknown" and never $0, and the price table carries its source and date and goes stale
on purpose (a test fails when it is older than 90 days, so a person reviews it).
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from redhand_core.spend import prices
from redhand_core.spend.prices import (
    PRICES,
    PRICES_AS_OF,
    Usage,
    cost_micro_usd,
    estimate,
    format_dollars,
    price_for,
)

SONNET = "claude-sonnet-5-5"  # $2 input, $10 output per million tokens on the source page


def test_a_known_models_cost_is_exact_integer_micro_dollars() -> None:
    price = price_for("anthropic", SONNET)
    assert price is not None
    assert cost_micro_usd(price, 1_000_000, 1_000_000) == 12_000_000  # $2 + $10
    assert cost_micro_usd(price, 500_000, 0) == 1_000_000
    assert cost_micro_usd(price, 0, 250_000) == 2_500_000


def test_a_partial_micro_dollar_rounds_up_never_down() -> None:
    price = price_for("anthropic", SONNET)
    assert price is not None
    assert cost_micro_usd(price, 1, 0) == 2, "one input token is 2 micro-dollars at $2 per million"
    assert cost_micro_usd(price, 0, 0) == 0
    haiku = price_for("anthropic", "claude-haiku-5-5")  # $0.10 per million: one token is 0.1 micro-dollar, which must count as 1
    assert haiku is not None
    assert cost_micro_usd(haiku, 1, 0) == 1 and cost_micro_usd(haiku, 11, 0) == 2 and cost_micro_usd(haiku, 10, 0) == 1
    assert isinstance(cost_micro_usd(price, 123_456, 789), int)


@pytest.mark.parametrize(("prompt", "completion"), [(-1, 0), (0, -1)])
def test_negative_token_counts_are_refused(prompt: int, completion: int) -> None:
    price = price_for("anthropic", SONNET)
    assert price is not None
    with pytest.raises(ValueError):
        cost_micro_usd(price, prompt, completion)


def test_an_unknown_model_has_no_price_it_is_not_free() -> None:
    assert price_for("anthropic", "claude-made-up-9") is None
    assert price_for("openai", "gpt-anything") is None, "no OpenAI price was readable when the table was built"
    assert price_for("", "") is None
    assert price_for("", SONNET) is None, "a model with no provider named is unknown, not assumed to be Anthropic"


def test_the_provider_must_match_because_other_clouds_price_the_same_model_differently() -> None:
    assert price_for("anthropic", SONNET) is not None
    assert price_for("Anthropic", SONNET) is not None
    assert price_for("bedrock", SONNET) is None
    assert price_for("google-vertex", SONNET) is None


def test_a_dated_model_id_matches_but_look_alikes_do_not() -> None:
    assert price_for("anthropic", f"{SONNET}-20260301") is not None
    assert price_for("anthropic", f"{SONNET}x") is None
    assert price_for("anthropic", "claude-sonnet-5") is None
    assert price_for("anthropic", f"{SONNET}-latest") is None
    assert price_for("anthropic", f"x{SONNET}") is None


def test_a_tiered_model_is_a_lower_bound_because_daily_totals_cannot_see_prompt_length() -> None:
    haiku = price_for("anthropic", "claude-haiku-5-5")
    assert haiku is not None and haiku.lower_bound is True
    assert price_for("anthropic", SONNET).lower_bound is False  # type: ignore[union-attr]


def test_an_estimate_adds_priced_usage_and_reports_what_it_could_not_price() -> None:
    result = estimate([
        Usage("anthropic", SONNET, calls=3, prompt_tokens=1_000_000, completion_tokens=0),
        Usage("openai", "gpt-x", calls=2, prompt_tokens=400, completion_tokens=100),
        Usage("anthropic", "claude-haiku-5-5", calls=1, prompt_tokens=1_000_000, completion_tokens=0),
    ])
    assert result.micro_usd == 2_000_000 + 100_000  # sonnet $2 + haiku $0.10
    assert result.unpriced_tokens == 500 and result.unpriced_models == ("openai/gpt-x",)
    assert result.lower_bound is True and result.calls == 6


def test_an_estimate_of_nothing_is_zero_and_exact() -> None:
    result = estimate([])
    assert (result.micro_usd, result.unpriced_tokens, result.unpriced_models, result.lower_bound, result.calls) == (0, 0, (), False, 0)


def test_usage_with_no_model_or_no_tokens_is_not_reported_not_free() -> None:
    result = estimate([Usage("", "", 1, 10, 5), Usage("anthropic", SONNET, 1, 0, 0)])
    assert result.micro_usd == 0 and result.not_reported_calls == 2
    assert result.unpriced_tokens == 0


def test_dollars_are_formatted_without_pretending_to_precision() -> None:
    assert format_dollars(0) == "$0.00"
    assert format_dollars(1) == "less than $0.01"
    assert format_dollars(9_999) == "less than $0.01"
    assert format_dollars(10_000) == "$0.01"
    assert format_dollars(12_345_678) == "$12.35"
    assert format_dollars(1_000_000_000) == "$1,000.00"


# --- the table itself --------------------------------------------------------------------------------------------------------------------

def test_every_row_has_a_source_positive_prices_and_a_provider() -> None:
    assert PRICES, "the table is not empty"
    for row in PRICES:
        assert row.provider and row.model and row.source.startswith("https://"), row
        assert row.input_micro_usd_per_mtok > 0 and row.output_micro_usd_per_mtok >= row.input_micro_usd_per_mtok, row


def test_no_two_rows_share_a_model() -> None:
    keys = [(r.provider, r.model) for r in PRICES]
    assert len(keys) == len(set(keys))


def test_the_table_is_reviewed_at_least_every_ninety_days() -> None:
    """Fails on purpose when the table gets old (owner decision D2): update the prices from the provider pages, set PRICES_AS_OF, and say so in
    the pull request."""
    age = date.today() - PRICES_AS_OF
    assert timedelta(0) <= age <= timedelta(days=90), f"the price table is {age.days} days old: review it"


def test_the_date_is_not_in_the_future() -> None:
    assert PRICES_AS_OF <= date.today()


def test_the_module_exposes_the_table_date_for_the_dashboard() -> None:
    assert prices.PRICES_AS_OF_TEXT == PRICES_AS_OF.isoformat()
