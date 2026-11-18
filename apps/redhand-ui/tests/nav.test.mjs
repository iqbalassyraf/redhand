import assert from "node:assert/strict";
import test from "node:test";

import { activeNavHref, NAV_ITEMS, roleLabel } from "../src/lib/nav.ts";

test("the active nav item is the longest matching href, and the home item matches only the home page", () => {
  assert.equal(activeNavHref("/"), "/");
  assert.equal(activeNavHref("/passports"), "/passports");
  assert.equal(activeNavHref("/passports/abc/timeline"), "/passports");
  assert.equal(activeNavHref("/radar"), "/radar");
  assert.equal(activeNavHref("/demo"), null);
  assert.equal(activeNavHref("/passportsX"), null);
});

test("every nav item has a unique href and a label", () => {
  assert.equal(new Set(NAV_ITEMS.map((i) => i.href)).size, NAV_ITEMS.length);
  assert.ok(NAV_ITEMS.every((i) => i.label.length > 0));
});

test("role labels read as words", () => {
  assert.equal(roleLabel("security_operator"), "security operator");
  assert.equal(roleLabel(null), "");
});
