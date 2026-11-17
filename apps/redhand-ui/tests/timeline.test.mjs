// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import { FILTERS, IN_EFFECT_AT_REGISTRATION, actionLabel, dayKey, describeItem, matchesFilter, TIMELINE_LIMITS_TEXT, FREEZE_REASON } from "../src/lib/timeline.ts";
import { describeRule } from "../src/lib/radarRules.ts";

const base = { at: "2026-11-16T03:04:05+00:00", seq: null, tool_name: "", server: "", reasons: [], calls: null, refused: null,
  finding_id: null, rule_id: "", finding_kind: "", confidence: "", review_status: "", occurrences: null, trip_kind: "", seen_in: "",
  action: "", reason: null, automatic: null };

test("a refusal names the tool and quotes the gateway's own reason, and links to its Black Box event", () => {
  const d = describeItem({ ...base, kind: "refusal", seq: 41, tool_name: "delete_invoice", server: "xero",
    reasons: ["Tool 'delete_invoice' on server 'xero' is not in this agent's passport scopes."] });
  assert.equal(d.title, "Call refused: delete_invoice (xero)");
  assert.equal(d.detail, "Tool 'delete_invoice' on server 'xero' is not in this agent's passport scopes.");
  assert.deepEqual(d.link, { href: "/blackbox", label: "Black Box event #41" });
  assert.equal(d.tone, "bad");
});

test("a failed call is told apart from a refusal", () => {
  const d = describeItem({ ...base, kind: "error", seq: 7, tool_name: "list_invoices", server: "xero", reasons: ["Upstream MCP server is unreachable."] });
  assert.equal(d.title, "Call failed: list_invoices (xero)");
  assert.equal(d.tone, "warn");
});

test("activity is counted per hour, with refusals when there were any", () => {
  assert.equal(describeItem({ ...base, kind: "activity", calls: 1, refused: 0 }).title, "1 tool call in this hour");
  assert.equal(describeItem({ ...base, kind: "activity", calls: 25, refused: 3 }).title, "25 tool calls in this hour, 3 refused");
});

test("a finding names its rule, confidence and review, and links to the Radar", () => {
  const d = describeItem({ ...base, kind: "finding", rule_id: "RAD-INJ-001", finding_kind: "injection", confidence: "high",
    review_status: "open", occurrences: 2, tool_name: "get_ticket", server: "helpdesk", finding_id: "f-1" });
  assert.equal(d.title, "Finding RAD-INJ-001: instructions aimed at the agent (high confidence)");
  assert.equal(d.detail, `${describeRule("RAD-INJ-001")} In get_ticket (helpdesk), seen 2 times. Not reviewed yet.`);
  assert.deepEqual(d.link, { href: "/radar", label: "Open the Radar" });
  for (const [status, words] of [["confirmed", "Marked real."], ["false_alarm", "Marked a false alarm."]]) {
    assert.ok(describeItem({ ...base, kind: "finding", rule_id: "RAD-LOOP-001", finding_kind: "loop", confidence: "high",
      review_status: status, occurrences: 1, tool_name: "t", server: "s" }).detail.endsWith(words));
  }
});

test("a trip says what was touched and where, never a value", () => {
  assert.equal(describeItem({ ...base, kind: "trip", trip_kind: "honeytoken", seen_in: "arguments", tool_name: "send_email", server: "mail" }).title,
    "Honeytoken used in a call to send_email (mail)");
  assert.equal(describeItem({ ...base, kind: "trip", trip_kind: "honeytoken", seen_in: "result", tool_name: "read_config", server: "files" }).title,
    "Honeytoken read in the answer of read_config (files)");
  assert.equal(describeItem({ ...base, kind: "trip", trip_kind: "honey_tool", seen_in: "call", tool_name: "export_all", server: "crm" }).title,
    "Decoy tool called: export_all (crm)");
});

test("an action names who did it: a person, or which part of RedHand", () => {
  const person = describeItem({ ...base, kind: "action", action: "passport.frozen", reason: "Looks wrong", automatic: false });
  assert.equal(person.title, "Frozen by a person");
  assert.equal(person.detail, "Reason: Looks wrong");
  const engine = describeItem({ ...base, kind: "action", action: "passport.frozen", reason: "Risk Engine: score 80 (critical): ...", automatic: true });
  assert.equal(engine.title, "Frozen by RedHand Risk Engine");
  const created = describeItem({ ...base, kind: "action", action: "passport.created", reason: null, automatic: false });
  assert.equal(created.title, "Registered by a person");
  assert.equal(created.detail, "");
});

test("every known action has a plain name, and an unknown one is shown as it is", () => {
  for (const action of ["passport.frozen", "passport.unfrozen", "passport.revoked", "passport.created", "passport.scopes_changed",
    "passport.key_rotated", "passport.renewed", "passport.safe_mode_enabled", "passport.safe_mode_disabled", "passport.budget_changed",
    "passport.destination_added", "passport.destination_removed", "passport.destination_mode_changed"]) {
    assert.ok(!actionLabel(action).includes("."), action);
  }
  assert.equal(actionLabel("something.new"), "something.new");
});

test("filters keep the right kinds", () => {
  const items = [
    { ...base, kind: "refusal" }, { ...base, kind: "error" }, { ...base, kind: "activity" }, { ...base, kind: "finding" },
    { ...base, kind: "trip" }, { ...base, kind: "action", automatic: false }, { ...base, kind: "action", automatic: true },
  ];
  const count = (f) => items.filter((i) => matchesFilter(i, f)).length;
  assert.deepEqual(FILTERS.map((f) => f.id), ["all", "refusals", "findings", "trips", "actions"]);
  assert.equal(count("all"), 7);
  assert.equal(count("refusals"), 2);
  assert.equal(count("findings"), 1);
  assert.equal(count("trips"), 1);
  assert.equal(count("actions"), 2);
});

test("items are grouped by local day", () => {
  assert.equal(dayKey("2026-11-16T03:04:05+00:00"), new Date("2026-11-16T03:04:05+00:00").toLocaleDateString());
});

test("the page says what the timeline is and is not", () => {
  assert.match(TIMELINE_LIMITS_TEXT, /only what RedHand recorded/);
  assert.match(TIMELINE_LIMITS_TEXT, /No call contents/);
  assert.equal(FREEZE_REASON, "Frozen from the incident view");
});

test("organization-wide actions say they covered every agent", () => {
  const all = describeItem({ ...base, kind: "action", action: "organization.frozen_all", reason: "Incident drill", automatic: false, organization_wide: true });
  assert.equal(all.title, "Every agent frozen (freeze all) by a person");
  assert.equal(all.detail, "Reason: Incident drill");
  assert.equal(describeItem({ ...base, kind: "action", action: "organization.safe_mode_enabled", reason: null, automatic: false, organization_wide: true }).title,
    "Safe Mode turned on for every agent by a person");
  assert.equal(actionLabel("organization.safe_mode_disabled"), "Safe Mode turned off for every agent");
  assert.equal(actionLabel("radar_suppression.created"), "A Radar rule silenced for this agent");
  assert.equal(actionLabel("passport.timeline_exported"), "Timeline exported");
  assert.equal(actionLabel("radar_suppression.revoked"), "Radar silence removed");
});

test("Safe Mode for all that was already on at registration says so before its reason", () => {
  const item = { ...base, kind: "action", action: "organization.safe_mode_enabled", reason: "still on", automatic: false, organization_wide: true };
  const carried = describeItem({ ...item, in_effect_at_registration: true });
  assert.equal(carried.detail, `${IN_EFFECT_AT_REGISTRATION} Reason: still on`);
  assert.equal(describeItem(item).detail, "Reason: still on", "an item from the agent's own lifetime is unchanged");
  assert.equal(describeItem({ ...item, reason: null, in_effect_at_registration: true }).detail, IN_EFFECT_AT_REGISTRATION);
});
