// Run with: npm test   (node --test tests/*.test.mjs; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import test from "node:test";

import {
  LADDER_CONFIRM_TEXT,
  RISK_LIMITS_TEXT,
  automaticActorLabel,
  ladderNeedsConfirmation,
  parseThreshold,
  signalDetail,
  validateLadder,
} from "../src/lib/riskForm.ts";

const ladder = (alert_at, safe_mode_at, freeze_at) => ({ alert_at, safe_mode_at, freeze_at });

test("a threshold box is a whole number from 1 to 100, or empty for off", () => {
  assert.equal(parseThreshold(""), null);
  assert.equal(parseThreshold("  "), null);
  assert.equal(parseThreshold("50"), 50);
  assert.equal(parseThreshold(" 1 "), 1);
  assert.equal(parseThreshold("100"), 100);
  for (const bad of ["0", "101", "-5", "5.5", "50%", "abc", "1e2", "0050"]) assert.equal(parseThreshold(bad), "invalid", bad);
});

test("the ladder must rise: alert, then Safe Mode, then freeze (off rungs are skipped)", () => {
  assert.equal(validateLadder(ladder(50, null, null)), null);
  assert.equal(validateLadder(ladder(50, 70, 90)), null);
  assert.equal(validateLadder(ladder(80, 80, 80)), null);
  assert.equal(validateLadder(ladder(null, null, 90)), null);
  assert.equal(validateLadder(ladder(null, null, null)), null);
  assert.match(validateLadder(ladder(80, 60, null)) ?? "", /must rise/);
  assert.match(validateLadder(ladder(60, null, 50)) ?? "", /must rise/);
  assert.match(validateLadder(ladder(null, 90, 70)) ?? "", /must rise/);
  assert.match(validateLadder(ladder(0, null, null)) ?? "", /1 to 100/);
  assert.match(validateLadder(ladder(50.5, null, null)) ?? "", /whole number/);
});

test("only turning Safe Mode or freeze on, or lowering it, needs the confirmation tick", () => {
  assert.equal(ladderNeedsConfirmation(ladder(50, null, null), ladder(50, null, 90)), true);
  assert.equal(ladderNeedsConfirmation(ladder(50, null, 90), ladder(50, null, 80)), true);
  assert.equal(ladderNeedsConfirmation(ladder(50, null, null), ladder(50, 70, null)), true);
  assert.equal(ladderNeedsConfirmation(ladder(50, 70, 90), ladder(50, 70, 95)), false);
  assert.equal(ladderNeedsConfirmation(ladder(50, 70, 90), ladder(50, null, null)), false);
  assert.equal(ladderNeedsConfirmation(ladder(50, null, null), ladder(20, null, null)), false); // the alert rung only notifies
  assert.match(LADDER_CONFIRM_TEXT, /by itself/);
});

test("an audit row by RedHand itself is named after what wrote it", () => {
  assert.equal(automaticActorLabel("Risk Engine: score 92 (critical): honeytoken or canary trip (2)"), "RedHand Risk Engine");
  assert.equal(automaticActorLabel("Budget Guard: daily call limit reached"), "RedHand Budget Guard");
  assert.equal(automaticActorLabel("Honeytoken trip: Decoy key"), "RedHand honeytoken");
  assert.equal(automaticActorLabel(null), "RedHand (automatic)");
  assert.equal(automaticActorLabel("something else"), "RedHand (automatic)");
});

test("a signal is explained in plain words", () => {
  assert.equal(signalDetail({ recent: 1, older: 2, points: 80, capped: true }), "80 points: 1 in the last 24 hours, 2 older (the most this signal can add)");
  assert.equal(signalDetail({ recent: 0, older: 1, points: 2, capped: false }), "2 points: 1 older");
});

test("the limits sentence says what the score is not", () => {
  assert.match(RISK_LIMITS_TEXT, /not a measured probability/);
  assert.match(RISK_LIMITS_TEXT, /connected through RedHand/);
  assert.match(RISK_LIMITS_TEXT, /only new signals/);
});
