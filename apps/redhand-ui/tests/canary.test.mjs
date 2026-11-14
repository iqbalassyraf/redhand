// Run with: node --test tests/*.test.mjs   (or: npm test; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { CANARY_LABEL, CANARY_LIMITS, actionsFor, canarySentence } from "../src/lib/canary.ts";

const PAGE = readFileSync(new URL("../src/app/honeytokens/page.tsx", import.meta.url), "utf8");
const API = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");

test("a canary refuses and alerts, and never freezes by default; other kinds keep their defaults", () => {
  assert.deepEqual(actionsFor("canary"), { onUse: "alert", onRead: "alert" });
  for (const kind of ["api_key", "aws_key", "password"]) assert.deepEqual(actionsFor(kind), { onUse: "freeze", onRead: "alert" }, kind);
});

test("the sentence to paste carries the value once, in plain text, with the do-not-repeat guidance", () => {
  const sentence = canarySentence("Ab3dEf6hIj9lMn2pQr5tUv8x");
  assert.equal(sentence.split("Ab3dEf6hIj9lMn2pQr5tUv8x").length - 1, 1);
  assert.match(sentence, /never repeat it/);
  assert.doesNotMatch(sentence, /redhand|canary/i, "no marker inside the prompt text: an attacker could spot and strip it");
});

test("the limits say what a canary cannot do", () => {
  const text = CANARY_LIMITS.join(" ");
  for (const needle of [/gateway/, /chat/, /re-encodes/, /legitimately/, /replay/, /not freeze/]) assert.match(text, needle);
  assert.doesNotMatch(text, /\b(prevents|guarantees|protects against|proves)\b.*\b(leak|safe)/i, "no promise it cannot keep");
});

test("the dashboard knows the canary kind and the API type allows it", () => {
  assert.match(API, /HoneytokenKind = "api_key" \| "aws_key" \| "password" \| "canary"/);
  assert.match(PAGE, /canary:\s*"System-prompt canary"/);
  assert.equal(CANARY_LABEL, "System prompt canary");
});

test("the Honeytokens page offers the preset and shows the sentence and limits only in the one-time view", () => {
  assert.match(PAGE, /Create a system-prompt canary/);
  assert.match(PAGE, /canarySentence\(revealed\.value\)/);
  assert.match(PAGE, /CANARY_LIMITS/);
  // The value exists in the page state only through `revealed` (cleared by "I have saved it"); the table shows the last four characters.
  const valueUses = [...PAGE.matchAll(/(?<!target)\.value\b/g)].length; // `e.target.value` is a form field, not a honeytoken value
  const revealedUses = [...PAGE.matchAll(/revealed\.value\b/g)].length;
  assert.equal(valueUses, revealedUses, "every use of a value is the revealed one");
  assert.match(PAGE, /…\{t\.hint\}/);
});

test("the Honeytokens page does not call a hook after its early return (React crashes the page otherwise)", () => {
  const early = PAGE.indexOf("if (!session || !token) return null;");
  assert.ok(early > 0);
  assert.doesNotMatch(PAGE.slice(early), /\buse(State|Effect|Callback|Memo|Ref)\(/);
});

test("the page never renders untrusted markup: no dangerouslySetInnerHTML", () => {
  assert.doesNotMatch(PAGE, /dangerouslySetInnerHTML/);
});
