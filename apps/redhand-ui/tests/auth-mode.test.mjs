// Supabase mode must not ship Clerk: only the files that exist for Clerk may import @clerk/*, and the shared code loads them lazily (ADR 0032).
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const SRC = new URL("../src", import.meta.url).pathname;
const files = [];
(function walk(dir) { for (const n of readdirSync(dir)) { const p = join(dir, n); if (statSync(p).isDirectory()) walk(p); else if (/\.tsx?$/.test(n)) files.push(p); } })(SRC);

test("only the Clerk components import @clerk packages", () => {
  const importers = files.filter((f) => /from "@clerk\//.test(readFileSync(f, "utf8"))).map((f) => f.replace(SRC + "/", ""));
  assert.deepEqual(importers.sort(), ["components/clerk/ClerkAuthProvider.tsx", "components/clerk/ClerkLogin.tsx"]);
});

test("the shared code loads the Clerk components dynamically, never with a static import", () => {
  for (const f of ["lib/auth.tsx", "app/login/page.tsx"]) {
    const text = readFileSync(join(SRC, f), "utf8");
    assert.ok(/dynamic\(\(\) => import\("@\/components\/clerk\//.test(text), `${f} must load Clerk lazily`);
    assert.ok(!/^import .* from "@\/components\/clerk\//m.test(text), `${f} must not import Clerk statically`);
  }
});

test("a Clerk token is never written to browser storage", () => {
  const text = readFileSync(join(SRC, "components/clerk/ClerkAuthProvider.tsx"), "utf8");
  assert.ok(!/sessionStorage|localStorage|document\.cookie/.test(text));
});

test("Clerk mode only trusts the build-time provider switch", () => {
  assert.match(readFileSync(join(SRC, "lib/auth.tsx"), "utf8"), /NEXT_PUBLIC_AUTH_PROVIDER === "clerk"/);
});
