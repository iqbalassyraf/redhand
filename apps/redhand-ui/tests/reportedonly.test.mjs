// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import { REPORTED_ONLY_LABEL, REPORTED_ONLY_HELP, canPromote, promoteConfirmText } from "../src/lib/reportedOnly.ts";

const passport = (over = {}) => ({ name: "Brand new", status: "active", reported_only: true, ...over });

test("only a reported-only passport that is not revoked offers Promote", () => {
  assert.equal(canPromote(passport()), true);
  assert.equal(canPromote(passport({ status: "frozen" })), true);
  assert.equal(canPromote(passport({ status: "revoked" })), false);
  assert.equal(canPromote(passport({ reported_only: false })), false);
  assert.equal(canPromote(passport({ reported_only: undefined })), false, "an older core without the field shows no Promote");
});

test("the label and help say it has no gateway access and who created it", () => {
  assert.equal(REPORTED_ONLY_LABEL, "reported by SDK");
  assert.match(REPORTED_ONLY_HELP, /no gateway access/);
  assert.match(REPORTED_ONLY_HELP, /admin/);
});

test("the confirmation names the agent and says promotion grants no tools by itself", () => {
  const text = promoteConfirmText("Brand new");
  assert.match(text, /^Promote Brand new\?/);
  assert.match(text, /scopes/);
});
