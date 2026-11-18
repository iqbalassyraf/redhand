import assert from "node:assert/strict";
import test from "node:test";

import { FALLBACK_REFRESH_MS, MAX_REFRESH_MS, MIN_REFRESH_MS, nextRefreshDelayMs, readLifetime } from "../src/lib/clerkToken.ts";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims) => `${b64({ alg: "RS256", typ: "JWT" })}.${b64(claims)}.sig`;
const NOW = 1_700_000_000_000;

test("the lifetime is read from the claims without trusting them", () => {
  assert.deepEqual(readLifetime(jwt({ iat: 100, exp: 700 })), { iat: 100, exp: 700 });
  for (const bad of ["", "a.b", "a.b.c", jwt({ exp: "soon", iat: 1 }), jwt({ iat: 1 }), `${b64({})}.!!!.sig`]) assert.equal(readLifetime(bad), null, bad);
});

test("renewal is scheduled at 60% of the remaining life, between 30 s and 4 min", () => {
  assert.equal(nextRefreshDelayMs(jwt({ iat: NOW / 1000, exp: NOW / 1000 + 60 }), NOW), 36_000); // the default 60 s lifetime
  assert.equal(nextRefreshDelayMs(jwt({ iat: NOW / 1000, exp: NOW / 1000 + 600 }), NOW), MAX_REFRESH_MS); // 10 min: capped at 4
  assert.equal(nextRefreshDelayMs(jwt({ iat: NOW / 1000, exp: NOW / 1000 + 20 }), NOW), MIN_REFRESH_MS); // a very short one: not faster than 30 s
});

test("an expired, missing or unreadable token retries soon and never returns a bad number", () => {
  assert.equal(nextRefreshDelayMs(jwt({ iat: 1, exp: 2 }), NOW), MIN_REFRESH_MS);
  assert.equal(nextRefreshDelayMs(null, NOW), FALLBACK_REFRESH_MS);
  assert.equal(nextRefreshDelayMs("garbage", NOW), FALLBACK_REFRESH_MS);
});
