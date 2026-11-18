// Every colour in the dashboard comes from the design tokens (src/app/globals.css). Raw hex colours, pure black/white fills,
// arbitrary/un-tokenized shadows, and legacy pine-green/charcoal tokens fail until they go through the unified Dark Navy Glass + Crimson tokens.
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
      text = text
        .replace(/:root\s*{[\s\S]*?\n}/, "")
        .replace(/\.rh-control-room\s*{[\s\S]*?\n}/, "");
    }
    for (const m of strip(text).matchAll(/#[0-9A-Fa-f]{3,8}\b/g)) offenders.push(`${f.replace(SRC, "src")}: ${m[0]}`);
  }
  assert.deepEqual(offenders.slice(0, 20), [], `raw colours found (${offenders.length}); use an rh-* or control-* token`);
});

test("no legacy palette, pure black/white fills, broken wash classes, or un-tokenized shadows", () => {
  const bannedCommon = /(10231E|17332C|1E4239|1F3D35|111417|181C20|1E2328|14181C|#000000\b|#000\b|\brh-chrome-active-wash\b|\bbroadcast\b|font-roboto)/i;
  const bannedTs = /(\bbg-(?:black|white)\b|\btext-black\b|\bdrop-shadow\b|\btext-shadow\b|\bbox-shadow\b|\bshadow-\[|\bshadow-(?!rh-|none\b)[a-z0-9-]+\b|\bbg-rh-chrome(?:-(?:hover|active|border))?\b)/;
  const offenders = [];
  for (const f of files) {
    if (isControlRoomFile(f)) continue;
    const raw = readFileSync(f, "utf8");
    const text = strip(raw);
    const isCss = f.endsWith(".css");
    text.split("\n").forEach((line, i) => {
      if (bannedCommon.test(line) || (!isCss && bannedTs.test(line))) {
        offenders.push(`${f.replace(SRC, "src")}:${i + 1}: ${line.trim().slice(0, 90)}`);
      }
    });
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
