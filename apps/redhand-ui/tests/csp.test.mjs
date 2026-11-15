// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import { SECURITY_HEADERS } from "../security-headers.mjs";
import { buildCsp, makeNonce, originOf } from "../src/lib/csp.ts";

const env = {
  coreUrl: "https://core.example.com/api",
  gatewayUrl: "https://gateway.example.com",
  supabaseUrl: "https://abc.supabase.co",
};

const directives = (csp) => Object.fromEntries(csp.split("; ").map((d) => { const [k, ...v] = d.split(" "); return [k, v]; }));

test("scripts run only with the nonce: no inline script, no eval in production", () => {
  const d = directives(buildCsp({ ...env, nonce: "NONCE", development: false }));
  assert.deepEqual(d["script-src"], ["'self'", "'nonce-NONCE'", "'strict-dynamic'"]);
  assert.ok(!d["script-src"].includes("'unsafe-inline'") && !d["script-src"].includes("'unsafe-eval'"));
});

test("development adds eval (the dev server needs it) and nothing else weakens", () => {
  const d = directives(buildCsp({ ...env, nonce: "N", development: true }));
  assert.ok(d["script-src"].includes("'unsafe-eval'"));
  assert.ok(!d["script-src"].includes("'unsafe-inline'"));
});

test("the page cannot be framed, cannot be rebased, cannot load plugins and forms stay on the site", () => {
  const d = directives(buildCsp({ ...env, nonce: "N", development: false }));
  assert.deepEqual(d["frame-ancestors"], ["'none'"]);
  assert.deepEqual(d["base-uri"], ["'self'"]);
  assert.deepEqual(d["object-src"], ["'none'"]);
  assert.deepEqual(d["form-action"], ["'self'"]);
  assert.deepEqual(d["default-src"], ["'self'"]);
});

test("connect-src names exactly this site, core, the gateway and Supabase, by origin only", () => {
  const d = directives(buildCsp({ ...env, nonce: "N", development: false }));
  assert.deepEqual(d["connect-src"], ["'self'", "https://core.example.com", "https://gateway.example.com", "https://abc.supabase.co"]);
});

test("an unset or invalid address adds nothing (it never widens the policy to a wildcard)", () => {
  const d = directives(buildCsp({ coreUrl: "https://core.example.com", gatewayUrl: undefined, supabaseUrl: "not a url", nonce: "N", development: false }));
  assert.deepEqual(d["connect-src"], ["'self'", "https://core.example.com"]);
  assert.ok(!JSON.stringify(d).includes("*"));
});

test("production upgrades insecure requests; development does not", () => {
  assert.ok("upgrade-insecure-requests" in directives(buildCsp({ ...env, nonce: "N", development: false })));
  assert.ok(!("upgrade-insecure-requests" in directives(buildCsp({ ...env, nonce: "N", development: true }))));
});

test("origins are reduced to scheme, host and port", () => {
  assert.equal(originOf("https://core.example.com:8443/a/b?c=d"), "https://core.example.com:8443");
  assert.equal(originOf("javascript:alert(1)"), null);
  assert.equal(originOf(""), null);
  assert.equal(originOf(undefined), null);
});

test("a nonce is unguessable and different every time", () => {
  const a = makeNonce();
  const b = makeNonce();
  assert.notEqual(a, b);
  assert.match(a, /^[A-Za-z0-9+/=]{22,}$/);
});

test("the fixed headers cover sniffing, referrers, powerful features and transport", () => {
  const h = Object.fromEntries(SECURITY_HEADERS.map((x) => [x.key, x.value]));
  assert.equal(h["X-Content-Type-Options"], "nosniff");
  assert.equal(h["Referrer-Policy"], "strict-origin-when-cross-origin");
  assert.match(h["Strict-Transport-Security"], /max-age=\d{7,}/);
  assert.match(h["Permissions-Policy"], /camera=\(\)/);
  assert.match(h["Permissions-Policy"], /geolocation=\(\)/);
  assert.equal(h["X-Frame-Options"], "DENY");
});
