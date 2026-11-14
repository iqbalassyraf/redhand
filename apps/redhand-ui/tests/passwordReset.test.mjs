// Run with: node --test tests/*.test.mjs   (or: npm test; Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import test from "node:test";

import { recoveryTokensFromHash, validateNewPassword } from "../src/lib/passwordReset.ts";

test("a recovery link yields its tokens", () => {
  const hash = "#access_token=a.b.c&refresh_token=r1&expires_in=3600&token_type=bearer&type=recovery";
  assert.deepEqual(recoveryTokensFromHash(hash), { accessToken: "a.b.c", refreshToken: "r1" });
});

test("expired, malformed and other link types give no tokens", () => {
  const bad = [
    "#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired",
    "#access_token=a&refresh_token=r&type=magiclink",
    "#access_token=a&type=recovery",
    "#refresh_token=r&type=recovery",
    "#access_token=a&refresh_token=r&type=recovery&error=x",
    "#access_token=&refresh_token=&type=recovery",
    "#type=signup&access_token=a&refresh_token=r",
    "",
    "#",
    "access_token=a&refresh_token=r",
  ];
  for (const hash of bad) assert.equal(recoveryTokensFromHash(hash), null, hash);
});

test("passwords must be long enough, not too long, and confirmed", () => {
  assert.equal(validateNewPassword("a".repeat(12), "a".repeat(12)), null);
  assert.match(validateNewPassword("short", "short") ?? "", /at least 12/);
  assert.match(validateNewPassword("a".repeat(11), "a".repeat(11)) ?? "", /at least 12/);
  assert.match(validateNewPassword("a".repeat(129), "a".repeat(129)) ?? "", /at most 128/);
  assert.match(validateNewPassword("a".repeat(12), "b".repeat(12)) ?? "", /do not match/);
  assert.match(validateNewPassword("", "") ?? "", /at least 12/);
});
