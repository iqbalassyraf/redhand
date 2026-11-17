// Run with: npm test   (node --test tests/*.test.mjs; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import test from "node:test";

import {
  LIMIT_CONFIRM_TEXT,
  MAX_LIMIT_MICRO_USD,
  SPEND_LIMITS_TEXT,
  basisLine,
  dollarsInput,
  formatTokens,
  MEASURED_BASIS,
  limitNeedsConfirmation,
  measuredLine,
  modelCost,
  parseDollars,
  shownModel,
  spendCell,
} from "../src/lib/spend.ts";

const agent = (over = {}) => ({
  agent_id: "a", name: "A", status: "active", usage_reported: true, calls: 2, prompt_tokens: 1000, completion_tokens: 500,
  estimated_micro_usd: 2_000_000, estimated_text: "$2.00", lower_bound: false, unpriced_tokens: 0, unpriced_models: [],
  spend_limit_micro_usd: null, spend_limit_text: null, percent_of_limit: null, models: [], ...over,
});
const model = (over = {}) => ({
  provider: "anthropic", model: "m", calls: 1, prompt_tokens: 1, completion_tokens: 1, price_known: true,
  estimated_micro_usd: 5, estimated_text: "less than $0.01", lower_bound: false, ...over,
});

test("every dollar figure comes with the sentence that says what it is", () => {
  const line = basisLine("2026-11-16");
  assert.match(line, /Estimated from what the agent's SDK reported/);
  assert.match(line, /prices as of 2026-11-16/);
  assert.match(line, /Not an invoice/);
  assert.match(SPEND_LIMITS_TEXT, /cannot stop it/);
  assert.match(SPEND_LIMITS_TEXT, /price unknown/);
  assert.match(SPEND_LIMITS_TEXT, /one exception/, "the proxy is the one case where a limit refuses");
  assert.match(SPEND_LIMITS_TEXT, /off by default/);
  assert.match(SPEND_LIMITS_TEXT, /a few seconds late/);
});

test("token counts are grouped by plain digits in every locale", () => {
  assert.equal(formatTokens(0), "0");
  assert.equal(formatTokens(999), "999");
  assert.equal(formatTokens(1000), "1,000");
  assert.equal(formatTokens(1234567), "1,234,567");
  assert.equal(formatTokens(-5), "0");
  assert.equal(formatTokens(Number.NaN), "0");
});

test("dollars typed in a box become exact micro-dollars with no floating point", () => {
  assert.equal(parseDollars(""), null);
  assert.equal(parseDollars("  "), null);
  assert.equal(parseDollars("5"), 5_000_000);
  assert.equal(parseDollars("$5"), 5_000_000);
  assert.equal(parseDollars("0.25"), 250_000);
  assert.equal(parseDollars("1.1"), 1_100_000);
  assert.equal(parseDollars("0.000001"), 1);
  assert.equal(parseDollars("19.99"), 19_990_000);
  assert.equal(parseDollars("1000000"), MAX_LIMIT_MICRO_USD);
  for (const bad of ["0", "0.0", "-1", "1e3", "5.1234567", "abc", "1,000", "1000001", "99999999", ".5", "5.", "1 000", "$$5"]) {
    assert.equal(parseDollars(bad), "invalid", bad);
  }
});

test("the box is filled back without trailing zeros", () => {
  assert.equal(dollarsInput(null), "");
  assert.equal(dollarsInput(2_000_000), "2");
  assert.equal(dollarsInput(2_500_000), "2.5");
  assert.equal(dollarsInput(1), "0.000001");
  assert.equal(parseDollars(dollarsInput(19_990_000)), 19_990_000);
});

test("only raising or removing a limit needs the confirmation tick", () => {
  assert.equal(limitNeedsConfirmation(null, 5), false);
  assert.equal(limitNeedsConfirmation(null, null), false);
  assert.equal(limitNeedsConfirmation(5, 4), false);
  assert.equal(limitNeedsConfirmation(5, 5), false);
  assert.equal(limitNeedsConfirmation(5, 6), true);
  assert.equal(limitNeedsConfirmation(5, null), true);
  assert.match(LIMIT_CONFIRM_TEXT, /later, or never/);
});

test("agent-supplied names are shown as plain, short text", () => {
  assert.equal(shownModel("anthropic", "claude-sonnet-5-5"), "anthropic/claude-sonnet-5-5");
  assert.equal(shownModel("", "m"), "m");
  assert.equal(shownModel("a\u0000b", "c\u202ed"), "a?b/c?d");
  assert.equal(shownModel("x", "y".repeat(500)).length, 60);
  assert.ok(shownModel("x", "y".repeat(500)).endsWith("…"));
  assert.equal(shownModel("<img src=x onerror=alert(1)>", "m"), "<img src=x onerror=alert(1)>/m", "markup is left as text; React escapes it, nothing is injected as HTML");
});

test("a model without a known price is never a dollar amount, and a tiered model is a floor", () => {
  assert.equal(modelCost(model({ price_known: false, estimated_micro_usd: null, estimated_text: null })), "price unknown");
  assert.equal(modelCost(model({ price_known: true, estimated_text: null })), "price unknown");
  assert.equal(modelCost(model({ price_known: false, estimated_text: "$1.00" })), "price unknown", "a figure on a model the server calls unpriced is not shown");
  assert.equal(modelCost(model({ estimated_text: "$1.00" })), "$1.00");
  assert.equal(modelCost(model({ estimated_text: "$1.00", lower_bound: true })), "at least $1.00");
});

test("the Model use cell says why there is no figure instead of showing zero", () => {
  assert.deepEqual(spendCell(undefined), { headline: "-", detail: "", tone: "none" });
  const silent = spendCell(agent({ usage_reported: false, estimated_micro_usd: 0, estimated_text: "$0.00" }));
  assert.equal(silent.headline, "usage not reported");
  assert.ok(!silent.headline.includes("$"));
  const priced = spendCell(agent());
  assert.equal(priced.headline, "$2.00");
  assert.equal(priced.detail, "1,500 tokens");
});

test("unpriced usage is named next to the priced figure, or stands alone as price unknown", () => {
  const both = spendCell(agent({ unpriced_tokens: 7000 }));
  assert.equal(both.headline, "$2.00");
  assert.match(both.detail, /plus 7,000 tokens with no known price/);
  const only = spendCell(agent({ estimated_micro_usd: 0, estimated_text: "$0.00", unpriced_tokens: 7000 }));
  assert.equal(only.headline, "price unknown");
  assert.ok(!only.headline.includes("$0"));
});

test("a tiered model's figure is shown as a floor and the tone follows the limit", () => {
  assert.equal(spendCell(agent({ lower_bound: true })).headline, "at least $2.00");
  assert.equal(spendCell(agent({ percent_of_limit: 50 })).tone, "ok");
  assert.equal(spendCell(agent({ percent_of_limit: 80 })).tone, "warn");
  assert.equal(spendCell(agent({ percent_of_limit: 100 })).tone, "alert");
  assert.equal(spendCell(agent({ percent_of_limit: null })).tone, "ok");
});

// --- measured by the model proxy (B5b) -------------------------------------------------------------------------------------------------

const measured = (over = {}) => ({
  calls: 4, calls_without_usage: 0, prompt_tokens: 3000, completion_tokens: 1000, estimated_micro_usd: 3_000_000, estimated_text: "$3.00",
  lower_bound: false, unpriced_tokens: 0, unpriced_models: [], models: [], ...over,
});

test("no proxy traffic means no measured line at all, not a zero", () => {
  assert.equal(measuredLine(agent({ measured: null, measured_unavailable: false })), null);
  assert.equal(measuredLine(agent({})), null, "an older core has no measured field");
});

test("a measured figure says it was measured by RedHand and keeps tokens and calls beside it", () => {
  const line = measuredLine(agent({ measured: measured() }));
  assert.equal(line.headline, "$3.00 measured by RedHand");
  assert.match(line.detail, /4,000 tokens/);
  assert.match(line.detail, /4 calls/);
});

test("calls the provider gave no usage for are said out loud, never counted as free", () => {
  const line = measuredLine(agent({ measured: measured({ calls: 5, calls_without_usage: 2 }) }));
  assert.match(line.detail, /2 calls with no usage reported/);
});

test("an unknown price is price unknown, and a tiered model is a floor", () => {
  assert.equal(measuredLine(agent({ measured: measured({ estimated_micro_usd: 0, estimated_text: "$0.00", unpriced_tokens: 900 }) })).headline, "price unknown, measured by RedHand");
  assert.equal(measuredLine(agent({ measured: measured({ lower_bound: true }) })).headline, "at least $3.00 measured by RedHand");
  assert.match(measuredLine(agent({ measured: measured({ unpriced_tokens: 900 }) })).detail, /plus 900 tokens with no known price/);
});

test("a measured read that failed says so and points at the reported figure", () => {
  const line = measuredLine(agent({ measured: null, measured_unavailable: true }));
  assert.equal(line.headline, "measured usage could not be read");
  assert.match(line.detail, /reported figure is unaffected/);
});

test("the basis text says what measured means and that it is never added to the reported number", () => {
  assert.match(MEASURED_BASIS, /provider reported/);
  assert.match(MEASURED_BASIS, /off by default/);
  assert.match(MEASURED_BASIS, /never added/);
  assert.doesNotMatch(MEASURED_BASIS, /guarantee|protect/i);
});
