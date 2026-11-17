// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import {
  CODE_PATTERN, canManageMember, grantableRoles, invitableRoles, isAdmin, isNoOrganizationMessage, isSecurityOperator, joinUrl, parseCode, parseInviteToken,
  parseOrgName, tokenFromPasted, inviteStateLabel,
} from "../src/lib/onboarding.ts";

const code = "rh_inv_" + "a".repeat(32);
const invite = "rh_join_" + "b".repeat(32);

test("a sign-up code is checked by shape before anything is sent", () => {
  assert.equal(parseCode(` ${code} `), code);
  for (const bad of ["", "rh_inv_short", "rh_live_" + "a".repeat(32), "rh_inv_" + "a".repeat(80), "rh_inv_" + "a b".repeat(10)]) assert.equal(parseCode(bad), "invalid", bad);
  assert.ok(CODE_PATTERN.test(code));
});

test("an invite token is taken from a link or pasted bare", () => {
  assert.equal(tokenFromPasted(invite), invite);
  assert.equal(tokenFromPasted(`https://app.example/join?token=${invite}`), invite);
  assert.equal(tokenFromPasted(`https://app.example/join?x=1&token=${invite}#top`), invite);
  assert.equal(tokenFromPasted("https://app.example/join?token=nope"), "invalid");
  assert.equal(parseInviteToken(undefined), "invalid");
  assert.equal(parseInviteToken(null), "invalid");
});

test("the organization name takes 1 to 100 characters after trimming", () => {
  assert.equal(parseOrgName("  Acme Ltd "), "Acme Ltd");
  assert.equal(parseOrgName("   "), "invalid");
  assert.equal(parseOrgName("x".repeat(101)), "invalid");
});

test("roles: who is an admin, who may grant what", () => {
  assert.equal(isAdmin("admin"), true);
  assert.equal(isAdmin("owner"), true);
  assert.equal(isAdmin("security_operator"), false);
  assert.equal(isAdmin(null), false);
  assert.equal(isSecurityOperator("security_operator"), true);
  assert.equal(isSecurityOperator("viewer"), false);
  assert.deepEqual(grantableRoles("viewer"), []);
  assert.deepEqual(grantableRoles("security_operator"), []);
  assert.deepEqual(grantableRoles("admin"), ["viewer", "security_operator", "admin"]);
  assert.deepEqual(grantableRoles("owner"), ["viewer", "security_operator", "admin", "owner"]);
  assert.deepEqual(invitableRoles("owner"), ["viewer", "security_operator", "admin"], "an invite never carries owner");
  assert.deepEqual(invitableRoles(undefined), []);
});

test("an admin cannot act on an owner, and a non-admin on nobody", () => {
  assert.equal(canManageMember("admin", "viewer"), true);
  assert.equal(canManageMember("admin", "admin"), true);
  assert.equal(canManageMember("admin", "owner"), false);
  assert.equal(canManageMember("owner", "owner"), true);
  assert.equal(canManageMember("security_operator", "viewer"), false);
  assert.equal(canManageMember(null, "viewer"), false);
});

test("labels and links", () => {
  assert.equal(inviteStateLabel("pending"), "Waiting");
  assert.equal(inviteStateLabel("weird"), "weird");
  assert.equal(joinUrl("https://app.example/", "/join?token=x"), "https://app.example/join?token=x");
  assert.equal(isNoOrganizationMessage("Operator is not a member of the requested organization."), true);
  assert.equal(isNoOrganizationMessage("Nope"), false);
});
