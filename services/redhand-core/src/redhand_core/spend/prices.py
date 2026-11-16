"""
Model prices and cost arithmetic for the spend view (Phase 4.5 B4, docs/plans/phase45-b4-spend.md).

What a number here means. Tokens are what an agent's own SDK REPORTED, and prices are the provider's public standard rates on PRICES_AS_OF,
so a cost is an ESTIMATE, never a measurement and never an invoice (RedHand only measures spend for traffic that flows through a proxy, B5).
It ignores prompt caching, batch discounts, data-residency surcharges and other rates a provider may apply.

Rules the code keeps:
  - Arithmetic is integer micro-dollars (1 micro-dollar = $0.000001), rounded UP, never floats.
  - A model without a row is "price unknown": it is never $0 and never counted as zero towards a limit.
  - The provider must match: another cloud may price the same model differently, so that is unknown too.
  - A tiered model (a higher rate above some prompt length) is a LOWER BOUND, because daily totals cannot see each request's length.
  - The table carries its source and date; a test fails when it is older than 90 days so a person reviews it (owner decision D2).

Where the numbers came from: https://platform.claude.com/docs/en/about-claude/pricing, read 2026-11-16 ("Base input tokens" and "Output tokens"
columns). OpenAI's pricing hosts were unreachable from the build environment, so no OpenAI model has a price yet: they show "price unknown".
That page prints display names, not API ids, so only models whose id is known from this project's environment are listed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

PRICES_AS_OF = date(2026, 11, 16)
PRICES_AS_OF_TEXT = PRICES_AS_OF.isoformat()

MICRO = 1_000_000  # micro-dollars per dollar; also tokens per "million tokens"
MAX_TOKENS = 10**15  # far above any real day; refuses garbage that would overflow a database bigint


@dataclass(frozen=True, slots=True)
class Price:
    provider: str
    model: str
    input_micro_usd_per_mtok: int  # micro-dollars per million input tokens ($8 per million is 8_000_000)
    output_micro_usd_per_mtok: int
    lower_bound: bool  # tiered pricing: the table holds the lowest tier
    source: str


_SOURCE = "https://platform.claude.com/docs/en/about-claude/pricing"

PRICES: tuple[Price, ...] = (
    Price("anthropic", "claude-fable-5-2", 8_000_000, 40_000_000, False, _SOURCE),
    Price("anthropic", "claude-opus-5-5", 4_000_000, 20_000_000, False, _SOURCE),
    Price("anthropic", "claude-sonnet-5-5", 2_000_000, 10_000_000, False, _SOURCE),
    # Haiku 5.5 costs $0.10 / $0.50 for prompts up to 100,000 tokens and $0.50 / $2.50 above that: the lowest tier is listed.
    Price("anthropic", "claude-haiku-5-5", 100_000, 500_000, True, _SOURCE),
)

_BY_KEY = {(p.provider, p.model): p for p in PRICES}
_DATED = re.compile(r"^(?P<base>.+)-(?P<date>[0-9]{8})$")


def price_for(provider: str, model: str) -> Price | None:
    """The row for a provider and model id (a trailing -YYYYMMDD version stamp is ignored), or None: unknown, never free."""
    provider = provider.strip().lower()
    model = model.strip().lower()
    if not provider or not model:
        return None
    found = _BY_KEY.get((provider, model))
    if found is not None:
        return found
    dated = _DATED.match(model)
    return _BY_KEY.get((provider, dated.group("base"))) if dated else None


def cost_micro_usd(price: Price, prompt_tokens: int, completion_tokens: int) -> int:
    """Estimated cost in micro-dollars, rounded up. Negative or absurd counts are refused rather than priced."""
    for count in (prompt_tokens, completion_tokens):
        if count < 0 or count > MAX_TOKENS:
            raise ValueError("token counts must be between 0 and 10^15")
    numerator = prompt_tokens * price.input_micro_usd_per_mtok + completion_tokens * price.output_micro_usd_per_mtok
    return -(-numerator // MICRO)


@dataclass(frozen=True, slots=True)
class Usage:
    """One agent-day-model row of reported usage."""

    provider: str
    model: str
    calls: int
    prompt_tokens: int
    completion_tokens: int


@dataclass(frozen=True, slots=True)
class Estimate:
    micro_usd: int  # priced usage only
    calls: int
    unpriced_tokens: int  # reported tokens of models with no price (so the total is not the whole story)
    unpriced_models: tuple[str, ...]  # "provider/model", sorted, at most 20
    not_reported_calls: int  # rows with no model, or a model but no tokens
    lower_bound: bool  # some priced usage is a tiered model


def estimate(rows: Iterable[Usage]) -> Estimate:
    total = calls = unpriced_tokens = not_reported = 0
    unpriced: set[str] = set()
    lower = False
    for row in rows:
        calls += row.calls
        if not row.model.strip() or (row.prompt_tokens == 0 and row.completion_tokens == 0):
            not_reported += row.calls
            continue
        price = price_for(row.provider, row.model)
        if price is None:
            unpriced_tokens += row.prompt_tokens + row.completion_tokens
            unpriced.add(f"{row.provider.strip().lower() or 'unknown'}/{row.model.strip().lower()}")
            continue
        total += cost_micro_usd(price, row.prompt_tokens, row.completion_tokens)
        lower = lower or price.lower_bound
    return Estimate(total, calls, unpriced_tokens, tuple(sorted(unpriced))[:20], not_reported, lower)


def format_dollars(micro_usd: int) -> str:
    """Dollars for people: two decimals, and "less than $0.01" rather than a misleading $0.00 for a real amount."""
    if micro_usd <= 0:
        return "$0.00"
    if micro_usd < 10_000:
        return "less than $0.01"
    cents = (micro_usd + 5_000) // 10_000  # to the nearest cent
    return f"${cents // 100:,}.{cents % 100:02d}"
