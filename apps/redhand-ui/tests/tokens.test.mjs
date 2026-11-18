// Run with: npm test   (node --test tests/*.test.mjs)
// The design tokens (src/app/globals.css) are the only source of colour. This checks that every text-on-surface pair
// meets WCAG AA (4.5:1 for text, 3.0:1 for marks) across opaque and composited Dark Navy Glass surfaces, that muted text
// is never used for information in shell/primitives, that focus rings are crimson, and that tailwind maps every token.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");
const tailwind = readFileSync(new URL("../tailwind.config.ts", import.meta.url), "utf8");
const appShell = readFileSync(new URL("../src/components/shell/AppShell.tsx", import.meta.url), "utf8");
const primitives = readFileSync(new URL("../src/components/ui/primitives.tsx", import.meta.url), "utf8");

const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
const channel = (c) => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
const luminance = (hex) => { const [r, g, b] = rgb(hex).map(channel); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const ratio = (a, b) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
const blend = (fg, bg, alpha) => "#" + rgb(fg).map((c, i) => Math.round(alpha * c + (1 - alpha) * rgb(bg)[i]).toString(16).padStart(2, "0")).join("");

const rawToken = (name) => {
  const m = css.match(new RegExp(`--${name}:\\s*([^;]+);`));
  assert.ok(m, `token --${name} missing`);
  return m[1].trim();
};

const hasToken = (name) => new RegExp(`--${name}:\\s*[^;]+;`).test(css);

const parseRgba = (value) => {
  if (/^#[0-9A-Fa-f]{6}$/.test(value)) return { hex: value, alpha: 1 };
  const m = value.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([0-9.]+))?\s*\)$/);
  assert.ok(m, `unsupported colour token value: ${value}`);
  const hex = "#" + [m[1], m[2], m[3]].map((n) => Number(n).toString(16).padStart(2, "0")).join("");
  const alpha = m[4] !== undefined ? Number(m[4]) : 1;
  return { hex, alpha };
};

const toHex = (value, backdrop = "#060913") => {
  const { hex, alpha } = parseRgba(value);
  return alpha >= 1 ? hex : blend(hex, backdrop, alpha);
};

const token = (name, backdrop) => {
  const base = backdrop ?? (name === "rh-bg-base" || name === "rh-canvas-bg" ? "#060913" : toHex(rawToken(hasToken("rh-bg-base") ? "rh-bg-base" : "rh-canvas-bg"), "#060913"));
  return toHex(rawToken(name), base);
};

const SURFACES = [
  "rh-canvas-bg",
  "rh-surface-card",
  "rh-surface-elevated",
  "rh-surface-subtle",
  "rh-bg-base",
  "rh-bg-elevated",
  "rh-bg-rail",
  "rh-glass-bg",
  "rh-glass-bg-hover",
];

test("Dark Navy Glass + Crimson tokens are active with no pine-green or flat-charcoal regressions", () => {
  assert.equal(token("rh-bg-base").toLowerCase(), "#060913");
  assert.equal(token("rh-canvas-bg").toLowerCase(), "#060913");
  assert.equal(token("rh-bg-elevated").toLowerCase(), "#0b1022");
  assert.equal(token("rh-accent-crimson").toLowerCase(), "#e11d48");
  const banned = /10231E|17332C|1E4239|1F3D35|111417|181C20|1E2328|14181C|rh-chrome-active-wash/i;
  for (const [name, src] of [["globals.css", css], ["tailwind.config.ts", tailwind], ["AppShell.tsx", appShell], ["primitives.tsx", primitives]]) {
    assert.ok(!banned.test(src), `${name} contains banned pine-green, charcoal, or broken wash token`);
  }
});

test("primary and secondary text meet AA (4.5:1) on every opaque and composited glass surface", () => {
  for (const s of SURFACES) {
    assert.ok(ratio(token("rh-text-primary"), token(s)) >= 4.5, `primary on ${s}`);
    assert.ok(ratio(token("rh-text-secondary"), token(s)) >= 4.5, `secondary on ${s}`);
  }
});

test("text on navigation chrome and active crimson nav pill meets AA", () => {
  if (hasToken("rh-chrome-bg")) {
    for (const s of ["rh-chrome-bg", "rh-chrome-hover", "rh-chrome-active"]) {
      assert.ok(ratio(token("rh-text-primary"), token(s)) >= 4.5, `primary on ${s}`);
    }
    assert.ok(ratio(token("rh-text-secondary"), token("rh-chrome-bg")) >= 4.5);
    assert.ok(ratio(token("rh-text-secondary"), token("rh-chrome-hover")) >= 4.5, "secondary text on a hovered nav item");
  }
  const activeRail = token("rh-accent-crimson-soft", token("rh-bg-rail"));
  assert.ok(ratio(token("rh-text-primary"), activeRail) >= 4.5, "primary on active crimson nav wash");
  assert.ok(ratio(token("rh-text-secondary"), activeRail) >= 4.5, "secondary on active crimson nav wash");
});

test("chips put primary text on a wash: readable on opaque cards and composited glass", () => {
  for (const washName of ["rh-teal-wash", "rh-steel-wash", "rh-ochre-wash", "rh-crimson-wash", "rh-slate-purple-wash", "rh-accent-crimson-soft"]) {
    for (const surface of ["rh-surface-card", "rh-glass-bg"]) {
      const wash = token(washName, token(surface));
      assert.ok(ratio(token("rh-text-primary"), wash) >= 4.5, `${washName} on ${surface}`);
    }
  }
});

test("chart marks and dots meet 3:1 against opaque cards and composited glass", () => {
  for (const name of [
    "rh-teal",
    "rh-steel",
    "rh-ochre",
    "rh-crimson",
    "rh-slate-purple",
    "rh-accent-crimson",
    "rh-accent-crimson-bright",
    "rh-status-allowed",
    "rh-status-flagged",
    "rh-status-blocked",
  ]) {
    for (const surface of ["rh-surface-card", "rh-glass-bg"]) {
      assert.ok(ratio(token(name), token(surface)) >= 3, `${name} on ${surface}`);
    }
  }
});

test("the muted text colour is below AA on purpose and is never used for information", () => {
  assert.ok(ratio(token("rh-text-muted"), token("rh-surface-card")) < 4.5);
  assert.ok(ratio(token("rh-text-muted"), token("rh-glass-bg")) < 4.5);
  for (const [name, src] of [["AppShell.tsx", appShell], ["primitives.tsx", primitives]]) {
    assert.ok(!/text-rh-muted|text-control-subtle/.test(src), `${name} must not use muted/subtle text token`);
  }
});

test("the keyboard focus ring in .rh-dark uses crimson, not teal", () => {
  assert.match(css, /\.rh-dark :focus-visible\s*{[^}]*outline:[^;]*var\(--rh-(?:accent-crimson-bright|accent-crimson|crimson)\)/);
  assert.doesNotMatch(css, /\.rh-dark :focus-visible\s*{[^}]*var\(--rh-teal\)/);
});

test("glass utilities exist, pure black hex is absent, and primitives use glass + crimson CTAs", () => {
  assert.match(css, /\.rh-glass\s*{[^}]*backdrop-filter:\s*blur\(/);
  assert.match(css, /\.rh-glass\s*{[^}]*box-shadow:\s*var\(--rh-glass-glow\)/);
  for (const [name, src] of [["globals.css", css], ["primitives.tsx", primitives]]) {
    assert.ok(!/(#000000\b|#000\b)/i.test(src.replace(/\/\*[\s\S]*?\*\//g, "")), `${name} contains pure black hex`);
  }
  assert.match(primitives, /rh-glass/);
  assert.doesNotMatch(primitives, /primary:[^\n]*bg-rh-teal/);
});

test("every colour and design token in globals.css is mapped in tailwind.config.ts", () => {
  for (const [, name] of css.matchAll(/--(rh-[a-z-]+):/g)) {
    assert.ok(tailwind.includes(`var(--${name})`), `--${name} is not mapped in tailwind.config.ts`);
  }
});

test("text-safe accent siblings and crimson CTA white text meet AA on surfaces and washes", () => {
  for (const [text, washName] of [
    ["rh-teal-text", "rh-teal-wash"],
    ["rh-crimson-text", "rh-crimson-wash"],
    ["rh-steel-text", "rh-steel-wash"],
    ["rh-purple-text", "rh-slate-purple-wash"],
    ["rh-ochre", "rh-ochre-wash"],
  ]) {
    for (const surface of ["rh-surface-card", "rh-surface-elevated", "rh-canvas-bg", "rh-bg-base", "rh-bg-elevated", "rh-glass-bg"]) {
      assert.ok(ratio(token(text), token(surface)) >= 4.5, `${text} on ${surface}`);
    }
    for (const surface of ["rh-surface-card", "rh-glass-bg"]) {
      assert.ok(ratio(token(text), token(washName, token(surface))) >= 4.5, `${text} on ${washName} over ${surface}`);
    }
  }
  assert.ok(ratio("#FFFFFF", token("rh-accent-crimson")) >= 4.5, "white text on --rh-accent-crimson");
  assert.ok(ratio("#FFFFFF", token("rh-accent-crimson-deep")) >= 4.5, "white text on --rh-accent-crimson-deep");
});

test(".rh-glass is declared inside @layer components so Tailwind border-* utilities win the cascade", () => {
  const layerStart = css.indexOf("@layer components");
  assert.ok(layerStart !== -1, "@layer components block missing in globals.css");
  const openBrace = css.indexOf("{", layerStart);
  assert.ok(openBrace !== -1, "@layer components opening brace missing");
  let depth = 0;
  let layerBody = "";
  for (let i = openBrace; i < css.length; i++) {
    const ch = css[i];
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    layerBody += ch;
    if (depth === 0) break;
  }
  assert.match(layerBody, /\.rh-glass\s*{[^}]*backdrop-filter:\s*blur\(/, ".rh-glass must sit inside @layer components");
  assert.match(css, /\.rh-control-room\s*:focus-visible\s*{\s*outline:\s*none\s*;?\s*}/, ".rh-control-room focus rule must remain intact for M2");
});

test("auth and onboarding pages do not apply .rh-control-room (preserves .rh-dark :focus-visible outlines)", () => {
  for (const route of ["login/page.tsx", "welcome/page.tsx", "join/page.tsx", "reset-password/page.tsx"]) {
    const src = readFileSync(new URL(`../src/app/${route}`, import.meta.url), "utf8");
    assert.ok(!/\brh-control-room\b/.test(src), `${route} must not contain rh-control-room`);
  }
});

test("non-control-room components do not pair hover:bg-control-crimsonBright or hover:brightness-110 on crimson buttons", () => {
  const srcRoot = new URL("../src", import.meta.url).pathname;
  const nonControlRoomTsx = [];
  (function walk(dir) {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith(".tsx") && p !== `${srcRoot}/app/page.tsx` && !p.startsWith(`${srcRoot}/components/control-room/`)) {
        nonControlRoomTsx.push(p);
      }
    }
  })(srcRoot);

  assert.ok(nonControlRoomTsx.length > 0, "expected non-control-room .tsx files");
  for (const file of nonControlRoomTsx) {
    const src = readFileSync(file, "utf8");
    const rel = file.replace(srcRoot, "src");
    assert.ok(!/\bhover:bg-control-crimsonBright\b/.test(src), `${rel} uses hover:bg-control-crimsonBright (< 4.5:1 AA with white text)`);
    for (const m of src.matchAll(/\bhover:brightness-110\b/g)) {
      const start = Math.max(0, m.index - 200);
      const end = Math.min(src.length, m.index + 200);
      assert.ok(!/crimson/i.test(src.slice(start, end)), `${rel} pairs hover:brightness-110 with crimson (< 4.5:1 AA with white text)`);
    }
  }
});
