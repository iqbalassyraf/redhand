# Plan: Phase 4.5 B4, model spend and approved models (detective)

**Status:** Draft for the owner's approval (2026-11-16). B4 is approved in principle (`docs/plans/phase4.5-build-plan.md`, decision B-D2);
this plan needs approval before code because it adds a price table that must be kept current and a recurring roll-up.

## 1. Goal
Show each agent's model use and estimated cost per day, alert when it passes a dollar budget, and flag a model the organization has not
approved. Detective only: RedHand reports what the agent's own SDK said; it does not stop a model call (that is B5, the proxy).
Done tests (proposed, new numbering under Phase 4.5):
1. An agent's SDK reports model calls; Passports shows its tokens and estimated dollars today, per model, with the price table's date.
2. Crossing the agent's daily dollar budget raises one Telegram alert per agent per day and a Black Box-style record; nothing is refused.
3. A model not on the organization's approved list raises a finding (`RAD-MDL-001`) and an alert; adding it to the list stops new findings.
4. A model with no known price is shown as "price unknown", never as $0, and never counts towards a budget as zero.

## 2. Current state (read on `main`, 2026-11-16)
- The SDK already sends `model_provider`, `model_name`, `prompt_tokens`, `completion_tokens` on every trace span
  (`packages/redhand-sdk`, ingested by `POST /v1/telemetry/ingest`, `services/redhand-core/src/redhand_core/routers/telemetry.py`), authenticated
  with an organization SDK key (`sdk_api_keys`), resolved to the same `agents` rows as passports, refused when the passport is not active.
- Spans are stored in `execution_traces` with those fields, next to thought text and payloads (sensitive, and not needed by B4).
- Budget Guard counts gateway tool calls per agent per day (`agent_usage_daily`); the Risk Engine and alert batching exist (B1).
- No price table, no dollar figures, no approved-model list anywhere.

## 3. Approach
- **Roll-up, not raw reads.** A row trigger on `execution_traces` keeps `agent_model_daily` (organization, agent, day in the organization's
  offset, provider, model, calls, prompt tokens, completion tokens), the same pattern as B2's `agent_tool_hourly`. Kept 90 days. B4 never reads
  thought text or payloads.
- **Versioned price table in code.** `services/redhand-core/src/redhand_core/spend/prices.py`: provider, model, input and output price per
  million tokens, a `PRICES_AS_OF` date and source notes, shown wherever a dollar figure is shown. Initially Anthropic and OpenAI models only
  (B-D5). A model not in the table is "price unknown". A test fails when the table is older than 90 days, so it is reviewed, not forgotten.
- **Dollar budget per agent** (optional, admin, audited, confirmation to raise or remove, like Budget Guard): estimated spend today crossing it
  raises one alert per agent per day. **No refusal.** Optional: feed "spend over budget" into the Risk Engine as a new signal (decision D4).
- **Approved models per organization** (empty list means "no list", nothing flagged): a model outside a non-empty list raises finding
  `RAD-MDL-001` through the existing findings pipeline, with its own 10-minute alert cooldown, and silences work as for other rules.
- **Dashboard:** a "Model use" column on Passports (tokens and estimated dollars today, "price unknown" when so) and a Spend card on the
  agent's Risk panel or timeline; an Approved models card on the Radar page (admin edits, confirmation to narrow).
- **Alternative rejected:** reading `execution_traces` live per page view (slow, and it touches sensitive columns); a third-party price feed
  (an outbound dependency and licence question for a table that changes a few times a year).

## 4. Changes
Migration `2026112500000x_model_spend.sql` with rollback (roll-up table, trigger, read function, purge, budget and approved-model columns,
audit actions); core `spend/` (prices, models, service), router `/v1/spend/...`, hooks in telemetry ingest for budget and approved-model checks;
twin; dashboard column and cards; ADR 0023; runbook; threat-model rows; OpenAPI; a night part.

## 5. Security impact
- **Self-reported numbers.** The SDK key is per organization, and any holder can name any agent of that organization; tokens are what the SDK
  says. B4 is labelled as reported, never as measured, and is never used to refuse. B5 (the proxy) is what makes spend authoritative.
- **No new outbound calls.** Prices are in code. No prompt or completion text is read or stored by B4.
- Budgets and approved models are admin-only, audited, confirmation-gated where they relax a control, tenant-scoped.

## 6. Data and migrations
Additive. The trigger runs inside the existing ingest transaction (as B2's does); a 30-day backfill from `execution_traces` once. Rollback drops
the roll-up and columns; traces are untouched.

## 7. Tests
Price arithmetic and "unknown" handling (pure); roll-up equals a direct count over traces; budget alert once per day per agent; approved-list
finding, cooldown, silence; tenant isolation; roles; deliberate breakages; SQL tests with rollback; browser run; the price-table age test.

## 8. Cost and performance
No gateway change. One trigger row per span (B2 measured about 0.05 ms per row for the same pattern); one roll-up row per agent, model and
day. No third-party calls. Recurring cost per agent: storage of a few rows a day; negligible.

## 9. Risks and open questions (decisions for the owner)
- **D1** Build B4 as described (detective, reported numbers)? *Recommended: yes.*
- **D2** Who keeps the price table current, and how often? *Recommended: Claude Code proposes an update in a PR whenever the age test fails
  (90 days) or a provider announces a change; the owner approves.*
- **D3** Currency: US dollars only for now (providers price in USD), with Malaysian ringgit shown later? *Recommended: USD only, labelled.*
- **D4** Should "spend over budget" add points to the Risk score? *Recommended: not yet; alert only, like B2 was watch-only first.*
- **D5** Default approved-model list: empty (nothing flagged until an admin sets one)? *Recommended: yes.*
- Risk: owners read an estimate as an invoice. Mitigation: every figure says "estimated from what the agent's SDK reported, prices as of DATE".
