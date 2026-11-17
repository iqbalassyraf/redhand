// Run with: npm test   (node --test tests/*.test.mjs; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import test from "node:test";

import { REVOKE_CONFIRM_TEXT, SDK_KEYS_TEXT, SHOW_ONCE_TEXT, lastUsedText, parseDays, parseName, stateLabel, usableCount } from "../src/lib/sdkKeys.ts";

const key = (over = {}) => ({ id: "k", name: "ci", key_prefix: "rh_live_abcd", state: "active", created_at: null, expires_at: null, last_used_at: null, revoked_at: null, ...over });

test("the expiry box takes 1 to 365 whole days, empty means 90", () => {
  assert.equal(parseDays(""), 90);
  assert.equal(parseDays(" 30 "), 30);
  assert.equal(parseDays("1"), 1);
  assert.equal(parseDays("365"), 365);
  for (const bad of ["0", "366", "-1", "1.5", "abc", "1e2", "9999"]) assert.equal(parseDays(bad), "invalid", bad);
});

test("the name box takes 1 to 100 characters after trimming", () => {
  assert.equal(parseName("  ci pipeline "), "ci pipeline");
  assert.equal(parseName(""), "invalid");
  assert.equal(parseName("   "), "invalid");
  assert.equal(parseName("x".repeat(100)), "x".repeat(100));
  assert.equal(parseName("x".repeat(101)), "invalid");
});

test("only active keys count towards the limit", () => {
  assert.equal(usableCount([key(), key({ state: "revoked" }), key({ state: "expired" }), key()]), 2);
});

test("an unused key says never and states read plainly", () => {
  assert.equal(lastUsedText(key()), "never");
  assert.notEqual(lastUsedText(key({ last_used_at: "2026-11-17T01:00:00Z" })), "never");
  assert.equal(stateLabel("revoked"), "revoked");
});

test("the card warns that a key is shown once and acts for the whole organization", () => {
  assert.match(SHOW_ONCE_TEXT, /will not be shown again/);
  assert.match(SDK_KEYS_TEXT, /any agent of the organization/);
  assert.match(REVOKE_CONFIRM_TEXT, /refused from the next batch/);
});
