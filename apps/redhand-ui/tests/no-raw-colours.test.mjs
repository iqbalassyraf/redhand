// Every colour in the dashboard comes from the design tokens (src/app/globals.css). A raw hex colour, a shadow, a glow, a gradient or a blur in
// the source means someone bypassed the system: this fails until it goes through a token (docs/design/matte-executive-dark.md).
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const SRC = new URL("../src", import.meta.url).pathname;
const isControlRoomFile = (p) =>
  p === `${SRC}/app/page.tsx` ||
  p.startsWith(`${SRC}/components/control-room/`) ||
  p === `${SRC}/lib/tokens.ts` ||
  p === `${SRC}/lib/control-room-data.ts`;

const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(tsx?|css)$/.test(name)) files.push(p);
  }
})(SRC);

const strip = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

test("no raw hex colour outside the token block", () => {
  const offenders = [];
  for (const f of files) {
    if (isControlRoomFile(f)) continue;
    let text = readFileSync(f, "utf8");
    if (f.endsWith("globals.css")) {
      text = text.split("/* === AGENT CONTROL ROOM GLASS TOKENS === */")[0].replace(/:root\s*{[\s\S]*?\n}/, ""); // the token definitions themselves
    }
    for (const m of strip(text).matchAll(/#[0-9A-Fa-f]{3,8}\b/g)) offenders.push(`${f.replace(SRC, "src")}: ${m[0]}`);
  }
  assert.deepEqual(offenders.slice(0, 20), [], `raw colours found (${offenders.length}); use an rh-* token`);
});

test("no shadows, glows, gradients, blur, pure black or white, or the old palette", () => {
  const banned = /(\bshadow(?:-[a-z0-9\[\]_,.()#\/-]+)?\b|drop-shadow|box-shadow|text-shadow|backdrop-blur|\bblur(?:-[a-z0-9]+)?\b|bg-gradient|\bbg-(?:black|white)\b|\btext-(?:black|white)\b|\bbroadcast\b|font-roboto)/;
  const offenders = [];
  for (const f of files) {
    if (isControlRoomFile(f)) continue;
    let raw = readFileSync(f, "utf8");
    if (f.endsWith("globals.css")) raw = raw.split("/* === AGENT CONTROL ROOM GLASS TOKENS === */")[0];
    const text = strip(raw);
    text.split("\n").forEach((line, i) => { if (banned.test(line)) offenders.push(`${f.replace(SRC, "src")}:${i + 1}: ${line.trim().slice(0, 90)}`); });
  }
  assert.deepEqual(offenders.slice(0, 20), [], `banned styles found (${offenders.length})`);
});

test("every page except the sign-in pages sits inside the app shell", () => {
  const bare = new Set(["login", "welcome", "join", "reset-password"]);
  const missing = [];
  for (const f of files.filter((p) => /\/app\/(?:.*\/)?page\.tsx$/.test(p))) {
    const name = f.replace(SRC + "/app/", "").replace(/\/?page\.tsx$/, "").split("/")[0];
    if (bare.has(name) || name === "demo" || name === "") continue; // / (Agent Control Room) and /demo draw their own chrome
    if (!readFileSync(f, "utf8").includes("<AppShell")) missing.push(f.replace(SRC, "src"));
  }
  assert.deepEqual(missing, [], "these pages draw their own chrome instead of using AppShell");
});
