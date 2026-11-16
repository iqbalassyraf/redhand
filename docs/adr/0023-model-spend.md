# ADR 0023: Model spend (detective, from what the agent's SDK reports)

**Status:** Proposed (2026-11-16), awaiting the owner's review with the pull request. Phase 4.5 B4a, decision B-D2. Plan:
`docs/plans/phase45-b4-spend.md` (approved, D1 to D5 as recommended). Builds on ADR 0019 (alert batching, Risk Engine) and ADR 0010 (Budget Guard's day).

## Context
Owners ask what their agents spend on models and want a warning before a bill surprises them. RedHand does not see the model call: agents talk to
the model provider directly. The only record of model use is what the agent's own SDK reports on each trace span (provider, model, token counts).

## Decision
- **Detective only.** Reported use is rolled up, priced and compared with an optional per-agent daily dollar limit. A limit sends one Telegram alert
  per agent per local day. Nothing is ever refused because of spend. (B5, a proxy in front of the model, would make spend authoritative; it is gated
  and not built.)
- **SDK:** the LangChain handler reports usage when a call ends (`on_llm_end`) and no longer invents a model (`google-vertex` / `gemini-2.5-pro` were
  defaults nobody chose). A call with no usage sends nothing. CrewAI and MCP adapters expose no usage and are unchanged.
- **Roll-up:** `agent_model_daily` (agent, local day, provider, model, calls, prompt tokens, completion tokens), kept by a **statement** trigger on
  `execution_traces`. The day follows the organization's UTC offset (Budget Guard's rule). Counts and model names only: no thought text or payload is read.
- **Prices in code:** `spend/prices.py`, integer micro-dollars rounded up, a source URL and `PRICES_AS_OF`; a test fails when the table is older than
  90 days so a person reviews it. A model without a row is **"price unknown"**, never $0 and never counted as zero. The provider must match. A tiered
  model is a lower bound ("at least"). Anthropic rows only: OpenAI's pricing hosts were unreachable when the table was built. USD only.
- **Limit:** `agents.spend_limit_micro_usd`, admin only, audited (`passport.spend_limit_changed`), compare-and-set, confirmation to raise or remove.
  `spend_mark_alerted()` allows one alert per agent per day; changing the limit clears the day's mark. Adds no Risk points (D4).
- **Check:** after an ingest batch that reported usage, a background task (bounded, 5 s, at most 8 at once, never raises) compares today's estimate with
  the limit. Unpriced usage is named in the alert and excluded from the figure.

## Alternatives considered
- **Read `execution_traces` live per page view.** Slow, and it touches thought text and payloads. Rejected.
- **A row trigger** (as B2's). Two concurrent batches from one agent could deadlock on each other's roll-up rows; the statement trigger groups the batch
  and writes in one fixed order. Chosen instead.
- **A third-party price feed.** An outbound dependency and a licence question for a table that changes a few times a year. Rejected.
- **A hard cap that refuses calls.** Impossible without being in the call path, and the numbers are self-reported. Rejected for now.

## Consequences
- **Self-reported:** an organization's SDK key can name any of its agents, and an agent whose SDK does not report (or misreports) shows less than it used.
  Every figure says "Estimated from what the agent's SDK reported; prices as of DATE. Not an invoice."
- **Ingest cost** (local PostgreSQL, 500-span batches): about 1 to 3 ms more per batch (10.0 ms without the trigger, 11.3 to 12.8 ms with it; 13.7 ms with 50
  distinct models); the pure batch summary in core adds about 0.1 ms. Ingest is off the call path.
- **Failure:** the trigger catches its own errors and logs a WARNING: the spans are kept and the roll-up for that batch is missing (the repair is
  `SELECT model_spend_backfill(30)`). This deliberately differs from B2, where a failing trigger rolls the batch back: spend is detective and must never
  fail an ingest. A failed read shows "Spend could not be read", never zero.
- **Bounds:** at most 50 distinct models per agent and day (the rest fold into one "(other)" row), 35-day window, a future-dated span counts as now,
  a token count above 1,000,000,000 on one side is "not reported", sums are capped at 10^15 on read.
- **Not unit-tested:** the fixed lock order that prevents the concurrent-batch deadlock.
- **A re-sent span is not re-counted** (the ingest upserts; only inserts count), so a span re-sent with different numbers keeps its first numbers.

## Differences from the approved plan
- A statement trigger instead of a row trigger (above).
- The alert's record is `agents.spend_alerted_day`, a log line and the `spend_alerts_total` metric, not an audit row: audit is for control actions by a person.
- Any limit change needs an admin (the plan said admin; Budget Guard lets operators tighten).
