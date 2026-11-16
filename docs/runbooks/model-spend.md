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
