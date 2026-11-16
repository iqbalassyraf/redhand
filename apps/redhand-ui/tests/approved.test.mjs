// Run with: npm test   (node --test tests/*.test.mjs; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import test from "node:test";

import {
  APPROVED_MODELS_TEXT,
  CLEAR_CONFIRM_TEXT,
  MAX_APPROVED,
  clearNeedsConfirmation,
  describeChange,
  formatModelLines,
  parseModelLines,
} from "../src/lib/approvedModels.ts";
import { MODEL_RULE_ID, describeRule } from "../src/lib/radarRules.ts";

const m = (provider, model) => ({ provider, model });

test("one provider/model per line becomes a clean, de-duplicated list", () => {
  assert.deepEqual(parseModelLines("anthropic/claude-sonnet-5-5\n  OpenAI/GPT-4o \n\nanthropic/claude-sonnet-5-5\r\n"), [
    m("anthropic", "claude-sonnet-5-5"),
    m("openai", "gpt-4o"),
  ]);
  assert.deepEqual(parseModelLines(""), []);
  assert.deepEqual(parseModelLines("  \n \n"), []);
});

test("a model may itself contain slashes and colons", () => {
  assert.deepEqual(parseModelLines("bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0\nmeta/llama/3"), [
    m("bedrock", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
    m("meta", "llama/3"),
  ]);
});

test("a line that is not provider/model says which line and how to write it", () => {
  for (const bad of ["claude", "/model", "provider/", "a b/model", "p/<script>", "p/m n", "-p/m", "p/-m"]) {
    const result = parseModelLines(`ok/fine\n${bad}`);
    assert.equal(typeof result, "string", bad);
    assert.match(result, /^Line 2:/, bad);
  }
});

test("more than 50 models are refused", () => {
  const lines = Array.from({ length: MAX_APPROVED + 1 }, (_, n) => `p/m${n}`).join("\n");
  assert.match(parseModelLines(lines), /At most 50/);
  assert.equal(parseModelLines(Array.from({ length: MAX_APPROVED }, (_, n) => `p/m${n}`).join("\n")).length, 50);
});

test("names longer than the server allows are refused", () => {
  assert.equal(typeof parseModelLines(`p/${"m".repeat(129)}`), "string");
  assert.equal(typeof parseModelLines(`${"p".repeat(65)}/m`), "string");
  assert.equal(parseModelLines(`${"p".repeat(64)}/${"m".repeat(128)}`).length, 1);
});

test("the box is filled back one entry per line", () => {
  assert.equal(formatModelLines([m("a", "b"), m("c", "d/e")]), "a/b\nc/d/e");
  assert.deepEqual(parseModelLines(formatModelLines([m("a", "b"), m("c", "d/e")])), [m("a", "b"), m("c", "d/e")]);
});

test("only clearing a non-empty list needs the confirmation", () => {
  assert.equal(clearNeedsConfirmation([m("a", "b")], []), true);
  assert.equal(clearNeedsConfirmation([], []), false);
  assert.equal(clearNeedsConfirmation([m("a", "b")], [m("c", "d")]), false);
  assert.equal(clearNeedsConfirmation([], [m("a", "b")]), false);
  assert.match(CLEAR_CONFIRM_TEXT, /turns the check off/);
});

test("the change is described in numbers", () => {
  assert.equal(describeChange([m("a", "b")], [m("a", "b")]), "No change.");
  assert.equal(describeChange([m("a", "b")], [m("a", "b"), m("c", "d")]), "1 added, 0 removed.");
  assert.equal(describeChange([m("a", "b"), m("c", "d")], [m("e", "f")]), "1 added, 2 removed.");
});

test("the card says what the check is not", () => {
  assert.match(APPROVED_MODELS_TEXT, /cannot stop a model call/);
  assert.match(APPROVED_MODELS_TEXT, /empty list means no check/);
  assert.match(APPROVED_MODELS_TEXT, /do not change the Risk score/);
});

test("the new rule is described in plain words", () => {
  assert.equal(MODEL_RULE_ID, "RAD-MDL-001");
  assert.match(describeRule("RAD-MDL-001"), /not on the approved list/);
});
