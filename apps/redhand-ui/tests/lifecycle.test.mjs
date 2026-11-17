// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import { ORG_TEXT, exportFilename, formatUtc, isDeletionPendingMessage, pendingText, slugMatches } from "../src/lib/lifecycle.ts";

test("the typed address name must match exactly", () => {
  assert.equal(slugMatches("acme-ltd", "acme-ltd"), true);
  assert.equal(slugMatches("  acme-ltd ", "acme-ltd"), true);
  for (const typed of ["Acme-ltd", "acme", "acme-ltd-x", ""]) assert.equal(slugMatches(typed, "acme-ltd"), false, typed);
  assert.equal(slugMatches("", ""), false, "an unknown slug never matches");
});

test("core's pending-deletion refusal is recognised, and nothing else is", () => {
  assert.ok(isDeletionPendingMessage("This organization is scheduled for deletion. You can export your data or cancel the deletion."));
  assert.equal(isDeletionPendingMessage("Operator is not a member of the requested organization."), false);
});

test("the grace period end is shown in UTC, the same for everyone", () => {
  assert.equal(formatUtc("2026-11-24T07:36:05.088554+00:00"), "2026-11-24 07:36 UTC");
  assert.equal(formatUtc("not a date"), "an unknown date");
  assert.match(pendingText("2026-11-24T07:36:05Z"), /scheduled for deletion on 2026-11-24 07:36 UTC\. Export your data or cancel/);
});

test("the export file name is safe and dated", () => {
  assert.equal(exportFilename("acme-ltd", new Date("2026-11-18T10:00:00Z")), "redhand-export-acme-ltd-2026-11-18.json");
  assert.equal(exportFilename("../../etc", new Date("2026-11-18T10:00:00Z")), "redhand-export-etc-2026-11-18.json");
  assert.equal(exportFilename("", new Date("2026-11-18T10:00:00Z")), "redhand-export-organization-2026-11-18.json");
});

test("the screen tells the owner what deleting does and what cancelling does not undo", () => {
  assert.match(ORG_TEXT.deleteIntro, /frozen at once/);
  assert.match(ORG_TEXT.deleteIntro, /After 7 days/);
  assert.match(ORG_TEXT.cancelDone, /Agents stay frozen/);
  assert.match(ORG_TEXT.exportIntro, /hashes are left out/);
});
