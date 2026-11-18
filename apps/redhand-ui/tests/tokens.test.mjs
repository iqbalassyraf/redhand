// Run with: npm test   (node --test tests/*.test.mjs)
// The design tokens (src/app/globals.css) are the only source of colour. This checks that every text-on-surface pair the UI primitives use meets
// WCAG AA (4.5:1 for text), that the muted text colour is never used for information, and that tailwind maps every token.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");
const tailwind = readFileSync(new URL("../tailwind.config.ts", import.meta.url), "utf8");
const primitives = readFileSync(new URL("../src/components/ui/primitives.tsx", import.meta.url), "utf8");

const token = (name) => {
  const m = css.match(new RegExp(`--${name}:\\s*(#[0-9A-Fa-f]{6})`));
  assert.ok(m, `token --${name} missing`);
  return m[1];
};
const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
const channel = (c) => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
const luminance = (hex) => { const [r, g, b] = rgb(hex).map(channel); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const ratio = (a, b) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
const blend = (fg, bg, alpha) => "#" + rgb(fg).map((c, i) => Math.round(alpha * c + (1 - alpha) * rgb(bg)[i]).toString(16).padStart(2, "0")).join("");

const SURFACES = ["rh-canvas-bg", "rh-surface-card", "rh-surface-elevated", "rh-surface-subtle"];

test("primary and secondary text meet AA (4.5:1) on every application surface", () => {
  for (const s of SURFACES) {
    assert.ok(ratio(token("rh-text-primary"), token(s)) >= 4.5, `primary on ${s}`);
    assert.ok(ratio(token("rh-text-secondary"), token(s)) >= 4.5, `secondary on ${s}`);
  }
});

test("text on the navigation chrome meets AA, including the active item", () => {
  for (const s of ["rh-chrome-bg", "rh-chrome-hover", "rh-chrome-active"]) {
    assert.ok(ratio(token("rh-text-primary"), token(s)) >= 4.5, `primary on ${s}`);
  }
  assert.ok(ratio(token("rh-text-secondary"), token("rh-chrome-bg")) >= 4.5);
  assert.ok(ratio(token("rh-text-secondary"), token("rh-chrome-hover")) >= 4.5, "secondary text on a hovered nav item");
});

test("chips put primary text on a wash: readable for every tone", () => {
  for (const [name, alpha] of [["rh-teal", 0.14], ["rh-steel", 0.14], ["rh-ochre", 0.14], ["rh-crimson", 0.15], ["rh-slate-purple", 0.15]]) {
    const wash = blend(token(name), token("rh-surface-card"), alpha);
    assert.ok(ratio(token("rh-text-primary"), wash) >= 4.5, `${name} chip`);
  }
});

test("chart marks and dots meet 3:1 against the card they sit on", () => {
  for (const name of ["rh-teal", "rh-steel", "rh-ochre", "rh-crimson", "rh-slate-purple"]) {
    assert.ok(ratio(token(name), token("rh-surface-card")) >= 3, `${name} on card`);
  }
});

test("the muted text colour is below AA on purpose and is never used for information", () => {
  assert.ok(ratio(token("rh-text-muted"), token("rh-surface-card")) < 4.5);
  for (const file of ["../src/components/shell/AppShell.tsx", "../src/components/ui/primitives.tsx"]) {
    const src = readFileSync(new URL(file, import.meta.url), "utf8");
    assert.ok(!/text-rh-muted/.test(src), `${file} must not use text-rh-muted`);
  }
});

test("the keyboard focus ring is a 1px outline, not a glow", () => {
  assert.match(css, /\.rh-dark :focus-visible\s*{[^}]*outline:\s*1px solid var\(--rh-teal\)/);
});

test("no shadows, glows, gradients, blur or pure black in the tokens or primitives", () => {
  for (const [name, src] of [["globals.css", css], ["primitives", primitives]]) {
    assert.ok(!/(box-shadow|text-shadow|drop-shadow|backdrop|blur\(|gradient|#000000\b|#000\b)/i.test(src.replace(/\/\*[\s\S]*?\*\//g, "")), `${name} has a banned style`);
  }
});

test("every colour token is mapped in the tailwind config", () => {
  for (const [, name] of css.matchAll(/--(rh-[a-z-]+):/g)) {
    assert.ok(tailwind.includes(`var(--${name})`), `--${name} is not mapped in tailwind.config.ts`);
  }
});

test("the text-safe accent siblings meet AA on cards, elevated surfaces and their own washes", () => {
  for (const [text, wash, alpha] of [["rh-teal-text", "rh-teal", 0.14], ["rh-crimson-text", "rh-crimson", 0.15], ["rh-steel-text", "rh-steel", 0.14], ["rh-purple-text", "rh-slate-purple", 0.15]]) {
    for (const surface of ["rh-surface-card", "rh-surface-elevated", "rh-canvas-bg"]) assert.ok(ratio(token(text), token(surface)) >= 4.5, `${text} on ${surface}`);
    assert.ok(ratio(token(text), blend(token(wash), token("rh-surface-card"), alpha)) >= 4.5, `${text} on its wash`);
  }
  assert.ok(ratio(token("rh-ochre"), blend(token("rh-ochre"), token("rh-surface-card"), 0.14)) >= 4.5, "ochre text on its wash");
});
