// Run with: node --test tests/*.test.mjs   (or: npm test once PR 61 is merged; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { LOOP_RULE_ID, RADAR_RULES, describeRule } from "../src/lib/radarRules.ts";
import { LOOP_LIMITS_TEXT, clampLoopNumber, loopConfirmText, loopNeedsConfirmation, validateLoopSettings } from "../src/lib/loopForm.ts";

test("a limit of 3 to 1000 and a window of 10 to 600 seconds are accepted, whole numbers only", () => {
  assert.equal(validateLoopSettings(20, 60), null);
  assert.equal(validateLoopSettings(3, 10), null);
  assert.equal(validateLoopSettings(1000, 600), null);
  for (const limit of [2, 1001, 0, -1, 20.5, Number.NaN, Infinity]) assert.match(validateLoopSettings(limit, 60) ?? "", /between 3 and 1000/, String(limit));
  for (const window of [9, 601, 0, 59.5, Number.NaN]) assert.match(validateLoopSettings(20, window) ?? "", /between 10 and 600/, String(window));
});

test("only turning throttling on, or detection off, needs the confirmation tick", () => {
  assert.equal(loopNeedsConfirmation("observe", "throttle"), true);
  assert.equal(loopNeedsConfirmation("off", "throttle"), true);
  assert.equal(loopNeedsConfirmation("observe", "off"), true);
  assert.equal(loopNeedsConfirmation("throttle", "off"), true);
  assert.equal(loopNeedsConfirmation("throttle", "throttle"), false);
  assert.equal(loopNeedsConfirmation("off", "off"), false);
  assert.equal(loopNeedsConfirmation("throttle", "observe"), false);
  assert.equal(loopNeedsConfirmation("off", "observe"), false);
  assert.equal(loopNeedsConfirmation("observe", "observe"), false);
});

test("the confirmation sentence says what will happen", () => {
  assert.match(loopConfirmText("throttle"), /refused/);
  assert.match(loopConfirmText("off"), /stops recording/);
});

test("typed numbers are clamped into range and an empty box falls back", () => {
  assert.equal(clampLoopNumber(2, 3, 1000, 20), 3);
  assert.equal(clampLoopNumber(5000, 3, 1000, 20), 1000);
  assert.equal(clampLoopNumber(20.4, 3, 1000, 20), 20);
  assert.equal(clampLoopNumber(Number.NaN, 3, 1000, 20), 20);
  assert.equal(clampLoopNumber(Infinity, 3, 1000, 20), 20);
});

test("the loop rule has plain wording of its own, is not in the Radar's text-rule table, and the limits are stated", () => {
  assert.match(describeRule(LOOP_RULE_ID), /same tool call/);
  assert.equal(LOOP_RULE_ID in RADAR_RULES, false); // RADAR_RULES must equal radar.py's table exactly (radar.test.mjs)
  assert.match(describeRule("RAD-LOOP-999"), /RAD-LOOP-999/); // an unknown id is shown as itself
  assert.match(LOOP_LIMITS_TEXT, /changes its arguments/);
  assert.match(LOOP_LIMITS_TEXT, /several gateway instances/);
  assert.match(LOOP_LIMITS_TEXT, /Nothing about the call is stored/);
});

test("the page never renders untrusted text as HTML, and the card needs the server's capability to offer a change", () => {
  const page = readFileSync(new URL("../src/app/radar/page.tsx", import.meta.url), "utf8");
  assert.equal(page.includes("dangerouslySetInnerHTML"), false);
  assert.match(page, /loop\.capabilities\.can_change_modes/);
  assert.match(page, /expected_mode: loop\.loop_mode/);
});
