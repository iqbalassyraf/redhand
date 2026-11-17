# Runbook: model spend (estimated from what the agent's SDK reports)

**Product truth (shown in the dashboard):** RedHand does not see the model call. Spend is estimated from the token counts each agent's own SDK
reports, at the provider's public prices on a stated date. It is not measured and not an invoice. A daily limit only sends an alert; RedHand never
refuses a call because of spend.

## What an operator sees
- **Passports, "Model use today":** the estimate and token count. "usage not reported" means the SDK sent no model use today (not that it cost nothing).
  "price unknown" means the model has no price in the table (not $0). "at least $X" is a tiered model (the real cost may be higher).
- **Click the cell:** per-model rows, the last 7 days, and the daily limit (admin changes it; raising or removing it asks for confirmation).
- **Alert:** one Telegram message per agent per local day when the estimate reaches the limit, starting "Spend alert:". It ends "Nothing was refused".
  Changing the limit lets the same day alert again.

## Common questions
| Symptom | Check | Fix |
|---|---|---|
| Every agent shows "usage not reported" | Is the agent on the updated SDK (`on_llm_end` reports usage)? Does its provider return usage? CrewAI and MCP adapters report none | Update the SDK; otherwise nothing to fix |
| A model shows "price unknown" | `spend/prices.py`: is the provider spelled as in the table (`anthropic`) and the model id exact (a dated suffix `-YYYYMMDD` is allowed)? Metric `spend_unpriced_models_total` counts them | Add a row from the provider's page, set `PRICES_AS_OF`, review in a PR |
| The price-table age test fails | The table is older than 90 days | Re-read the provider's pricing page, update rows and date, say so in the PR |
| "Spend could not be read" | Core log `Spend could not be read: <type>`; database reachable? | Fix the database; nothing was recorded as zero |
| Roll-up seems low | Core/database log WARNING `model_spend_rollup skipped (SQLSTATE ...)` | `SELECT public.model_spend_backfill(30);` rebuilds the last 30 days from the spans (safe to repeat) |
| No alert although over the limit | Estimate counts priced usage only; `spend_checks_total{outcome=...}` (skipped, timeout, error) and `spend_alerts_total`; was today already alerted (`agents.spend_alerted_day`)? | Change the limit to re-arm the day |

## Facts
- Day = the organization's UTC offset (same as Budget Guard). Roll-up kept 90 days (`purge_model_spend()`, scheduled daily when pg_cron exists).
- At most 50 distinct models per agent and day; extra ones appear as "(other)".
- Metrics: `spend_checks_total{outcome}`, `spend_alerts_total`, `spend_unpriced_models_total` (no model names in labels).
- Rollback: `supabase/rollbacks/20261125000000_model_spend.down.sql` (loses the roll-up and every dollar limit; spans are untouched).

## Approved models (B4b)
- **Radar page, "Approved models":** an admin lists models, one `provider/model` per line (at most 50). With a non-empty list, a model an agent's SDK reports that is not on it is a finding "Model not on the approved list" (rule `RAD-MDL-001`) and one Telegram message starting "Model alert:" per agent per 10 minutes. An empty list means no check. It never refuses a call and adds nothing to the Risk score.
- **A dated id of an approved model is approved** (`claude-sonnet-5-5-20260301` for `claude-sonnet-5-5`). Spelling and case do not matter.
- **Too many alerts?** Add the model to the list, or silence `RAD-MDL-001` for one agent (Radar, silences). Findings still list under kind "Model not on the approved list".
- **No finding although a model is not listed?** The list may be empty (check off); the agent's SDK may not report a model; the agent may have a live silence; check `model_checks_total{outcome=...}` and the core log `Approved-model check failed`.
- Metrics: `model_checks_total{outcome}`, `model_findings_total`, `model_alerts_total` (no model names in labels). Rollback: `supabase/rollbacks/20261126000000_approved_models.down.sql` (loses the lists and deletes model findings).

## Measured usage from the model proxy (B5b, off unless the proxy is on)
- **What it is:** the tokens the provider reported for calls that went through RedHand's model proxy, shown as "measured by RedHand" beside the SDK-reported figure. Stored in `agent_model_measured_daily`; never added to the reported figure.
- **No measured line for an agent:** the proxy never saw a call for it today. That is normal and is not a zero.
- **"measured usage could not be read":** core's read of the measured table failed; the reported figure is unaffected. Check core logs for "Measured spend could not be read" and that migration `20261201000000_model_measured_usage` is applied.
- **Measured figures are missing though the proxy is on:** the gateway reports in the background. `curl` the gateway's `/metrics` (service token): `agentwall_model_usage_failed_batches_total` rising means core is refusing or unreachable
  (check `AGENTWALL_CORE_URL` and `AGENTWALL_CORE_SERVICE_TOKEN` equal core's `INTERNAL_SERVICE_TOKEN`); `agentwall_model_usage_dropped_total{reason="refused"}` means core answered a 4xx (a token or version mismatch);
  `{reason="overflow"}` means more distinct agent-and-model pairs than the memory bound during an outage; `{reason="not_configured"}` means no service token is set on the gateway.
- **Purge:** `purge_model_measured()` (daily 19:57 UTC when pg_cron exists, else schedule it yourself) keeps 90 days of usage and 7 days of batch ids.

## Refusals over the daily dollar limit (B5c, model proxy only)
- **What happens:** with the proxy on, an agent that has a spend limit is refused (HTTP 429, "This agent has reached its daily model spend limit...") once what the proxy MEASURED reaches it. It can call again after the day resets (the organization's UTC offset) or when an admin raises the limit (raising needs the confirm tick, as always).
- **A refusal for a model with no price (HTTP 403, "cannot be priced"):** while a limit is set, a model the price table does not know (or an agent with unpriced measured tokens today) is refused. Add the model to `spend/prices.py` (an owner-approved table update) or remove the limit.
- **The limit was overshot a little:** expected. The figure arrives a few seconds late (see ADR 0025); tune `AGENTWALL_MODEL_USAGE_FLUSH_INTERVAL_SECONDS` if it matters.
- **Every call is refused with a limit set, spend looks low:** check `agentwall_model_proxy_requests_total{outcome="spend_unpriced"}`; if the measured figure is zero but refusals say limit reached, the stored limit may be malformed (reads as 0): look at `agents.spend_limit_micro_usd`.
- **Deploy order:** core before the gateway (the gateway requires the new `model_spend` key). A gateway newer than core denies every proxy lookup.

