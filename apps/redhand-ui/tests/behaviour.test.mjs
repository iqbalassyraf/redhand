// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import { BEHAVIOUR_LIMITS_TEXT, backtestText, behaviourHeadline, hourText, shownToolName } from "../src/lib/behaviour.ts";

const base = {
  status: "ok", warm: true, history_days: 14, warmup_days: 7, hour_calls: 3, usual_hourly: 2, spike_threshold: 30, spike: false, new_tools: [],
  warning: false, backtest: { hours: 168, flagged_hours: 0, spike_hours: 0, new_tool_starts: 0 },
};

test("the headline says what is unusual, or that nothing is", () => {
  assert.equal(behaviourHeadline(base), "Usual behaviour.");
  assert.equal(behaviourHeadline({ ...base, spike: true }), "Unusual: a surge of calls this hour.");
  assert.equal(behaviourHeadline({ ...base, new_tools: ["x"] }), "Unusual: a tool it has not used before.");
  assert.equal(behaviourHeadline({ ...base, spike: true, new_tools: ["x"] }), "Unusual: a surge of calls and a tool it has not used before.");
});

test("a young agent is warming up and nothing is judged", () => {
  assert.equal(behaviourHeadline({ ...base, warm: false, history_days: 3 }), "Warming up: 3 of 7 days of history. Nothing is judged yet.");
});

test("an unreadable baseline says so and does not touch the score", () => {
  assert.match(behaviourHeadline({ ...base, status: "unavailable" }), /could not be read.*not affected/);
});

test("the hour and the back-test are explained in plain words", () => {
  assert.equal(hourText({ ...base, hour_calls: 40, usual_hourly: 2 }), "This hour: 40 calls. Usual hour: 2.0 calls (a surge starts at 30).");
  assert.equal(hourText({ ...base, hour_calls: 1 }), "This hour: 1 call. Usual hour: 2.0 calls (a surge starts at 30).");
  assert.equal(backtestText({ ...base, backtest: { hours: 168, flagged_hours: 2, spike_hours: 1, new_tool_starts: 1 } }),
    "Over the last 168 hours this would have flagged 2 hours (1 surge, 1 new tool).");
  assert.equal(backtestText({ ...base, backtest: null }), null);
  assert.equal(backtestText({ ...base, backtest: { hours: 0, flagged_hours: 0, spike_hours: 0, new_tool_starts: 0 } }), null);
});

test("a long tool name is cut for display", () => {
  assert.equal(shownToolName("short_tool"), "short_tool");
  const cut = shownToolName("x".repeat(200));
  assert.equal(cut.length, 64);
  assert.ok(cut.endsWith("…"));
});

test("the limits say it is watch only and catches sudden change only", () => {
  assert.match(BEHAVIOUR_LIMITS_TEXT, /Watch only/);
  assert.match(BEHAVIOUR_LIMITS_TEXT, /only catches sudden change/);
});
