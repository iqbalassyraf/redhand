// Run with: node --test tests/*.test.mjs   (or: npm test once PR 61 is merged; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { DESTINATION_RULE_ID, RADAR_RULES, describeRule } from "../src/lib/radarRules.ts";
import {
  DESTINATION_LIMITS_TEXT,
  destinationConfirmText,
  destinationNeedsConfirmation,
  enforceBlockedReason,
  removeBlockedReason,
  validateHostInput,
} from "../src/lib/destinationForm.ts";

test("a plain host name or address is accepted", () => {
  for (const ok of ["files.example.com", "Example.COM", "example.com.", "xn--bcher-kva.de", "bücher.de", "203.0.113.7", "0x7f.1", "[::1]", "2001:db8::1", "localhost"]) {
    assert.equal(validateHostInput(ok), null, ok);
  }
});

test("the usual mistakes are refused with a plain reason", () => {
  assert.match(validateHostInput("") ?? "", /Type a host/);
  assert.match(validateHostInput("   ") ?? "", /Type a host/);
  assert.match(validateHostInput("x".repeat(301)) ?? "", /300/);
  assert.match(validateHostInput("a b.com") ?? "", /no spaces/);
  for (const bad of ["https://example.com", "example.com/path", "example.com?x=1", "example.com#a", "exa\\mple.com"]) assert.match(validateHostInput(bad) ?? "", /host only/, bad);
  assert.match(validateHostInput("alice@example.com") ?? "", /not an email/);
  assert.match(validateHostInput("*.example.com") ?? "", /Wildcards/);
  assert.match(validateHostInput("example.com:8080") ?? "", /port/);
  assert.match(validateHostInput("example.com:") ?? "", /port/);
});

test("only turning enforcement on, or the check off, needs the confirmation tick", () => {
  assert.equal(destinationNeedsConfirmation("observe", "enforce"), true);
  assert.equal(destinationNeedsConfirmation("off", "enforce"), true);
  assert.equal(destinationNeedsConfirmation("enforce", "off"), true);
  assert.equal(destinationNeedsConfirmation("observe", "off"), true);
  for (const [a, b] of [["enforce", "enforce"], ["off", "off"], ["enforce", "observe"], ["off", "observe"], ["observe", "observe"]]) {
    assert.equal(destinationNeedsConfirmation(a, b), false, `${a} -> ${b}`);
  }
});

test("the confirmation sentences say what will happen", () => {
  assert.match(destinationConfirmText("enforce"), /refused/);
  assert.match(destinationConfirmText("off"), /stops checking/);
});

test("enforcement needs a list, and the last host cannot be removed while enforcing", () => {
  assert.match(enforceBlockedReason("enforce", 0) ?? "", /at least one/);
  assert.equal(enforceBlockedReason("enforce", 1), null);
  assert.equal(enforceBlockedReason("observe", 0), null);
  assert.match(removeBlockedReason("enforce", 1) ?? "", /last allowed destination/);
  assert.equal(removeBlockedReason("enforce", 2), null);
  assert.equal(removeBlockedReason("observe", 1), null);
});

test("the destination rule has plain wording of its own, is not in the Radar's text-rule table, and the limits are stated", () => {
  assert.match(describeRule(DESTINATION_RULE_ID), /not on its allowed list/);
  assert.equal(DESTINATION_RULE_ID in RADAR_RULES, false); // RADAR_RULES must equal radar.py's table exactly (radar.test.mjs)
  for (const phrase of [/plain word/, /encoded/, /does not see what a tool does/, /exact/, /too large to read/, /last two parts/]) assert.match(DESTINATION_LIMITS_TEXT, phrase);
});

test("the panel never renders server text as HTML and only offers changes the server allows", () => {
  const panel = readFileSync(new URL("../src/app/passports/DestinationsPanel.tsx", import.meta.url), "utf8");
  assert.equal(panel.includes("dangerouslySetInnerHTML"), false);
  assert.match(panel, /capabilities\.can_change === true/);
  assert.match(panel, /expected_mode: data\.destination_mode/);
  assert.match(panel, /confirm: true/); // adding always sends the tick the user ticked
});
