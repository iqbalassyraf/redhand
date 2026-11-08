// Run with: node --test tests/   (Node 22.18+ runs the TypeScript helpers directly)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { RADAR_RULES, describeRule } from "../src/lib/radarRules.ts";
import { clampDays, settingsNeedConfirmation, shorten, validateNote, validateSuppression } from "../src/lib/radarForm.ts";

const PY = readFileSync(new URL("../../../agentwall/src/firewall/radar.py", import.meta.url), "utf8");

// Parses the RULES table in radar.py: "RAD-xxx-nnn": ("family", "kind", "severity", "reason"),
function pythonRules() {
  const rules = {};
  const re = /"(RAD-(?:INJ|OUT)-\d{3})": \("([a-z-]+)", "(injection|output)", "(low|medium|high)", "((?:[^"\\]|\\.)*)"\)/g;
  for (const m of PY.matchAll(re)) rules[m[1]] = { family: m[2], kind: m[3], severity: m[4], reason: m[5] };
  return rules;
}

test("the dashboard rule table matches radar.py exactly (ids, family, kind, severity, wording)", () => {
  const py = pythonRules();
  assert.ok(Object.keys(py).length >= 19, "found the Python rules");
  assert.deepEqual(Object.keys(RADAR_RULES).sort(), Object.keys(py).sort());
  for (const [id, rule] of Object.entries(py)) assert.deepEqual({ ...RADAR_RULES[id] }, rule, id);
});

test("an unknown rule id is shown as itself, not hidden", () => {
  assert.match(describeRule("RAD-INJ-999"), /RAD-INJ-999/);
  assert.equal(describeRule("RAD-INJ-001"), RADAR_RULES["RAD-INJ-001"].reason);
});

test("a review note is optional but limited to 300 characters", () => {
  assert.equal(validateNote(""), null);
  assert.equal(validateNote("a".repeat(300)), null);
  assert.match(validateNote("a".repeat(301)) ?? "", /300/);
  assert.equal(validateNote(" ".repeat(400)), null);
});

test("a silence needs a reason, 1 to 90 whole days, and the tick", () => {
  assert.equal(validateSuppression("Known noisy tool", 30, true), null);
  assert.match(validateSuppression("ab", 30, true) ?? "", /at least 3/);
  assert.match(validateSuppression("   ", 30, true) ?? "", /at least 3/);
  assert.match(validateSuppression("x".repeat(301), 30, true) ?? "", /300/);
  for (const days of [0, -1, 91, 1.5, Number.NaN]) assert.match(validateSuppression("Known noisy tool", days, true) ?? "", /between 1 and 90/, String(days));
  assert.equal(validateSuppression("Known noisy tool", 1, true), null);
  assert.equal(validateSuppression("Known noisy tool", 90, true), null);
  assert.match(validateSuppression("Known noisy tool", 30, false) ?? "", /Tick the box/);
});

test("only turning a check off needs the confirmation tick", () => {
  const on = { radar: "observe", output: "observe" };
  assert.equal(settingsNeedConfirmation(on, { radar: "off", output: "observe" }), true);
  assert.equal(settingsNeedConfirmation(on, { radar: "observe", output: "off" }), true);
  assert.equal(settingsNeedConfirmation(on, on), false);
  assert.equal(settingsNeedConfirmation({ radar: "off", output: "off" }, { radar: "off", output: "off" }), false);
  assert.equal(settingsNeedConfirmation({ radar: "off", output: "off" }, on), false);
});

test("day counts are clamped into range and long text is cut for display", () => {
  assert.equal(clampDays(0), 1);
  assert.equal(clampDays(500), 90);
  assert.equal(clampDays(Number.NaN), 30);
  assert.equal(clampDays(12.4), 12);
  assert.equal(shorten("a".repeat(100)).length, 60);
  assert.equal(shorten("short"), "short");
});

import { isCoverageData, measured, statusStyle } from "../src/lib/coverage.ts";

const COVERAGE = JSON.parse(readFileSync(new URL("../public/coverage.json", import.meta.url), "utf8"));

test("the committed coverage file has the shape the page needs", () => {
  assert.equal(isCoverageData(COVERAGE), true);
  assert.equal(isCoverageData(null), false);
  assert.equal(isCoverageData({}), false);
  assert.equal(isCoverageData({ ...COVERAGE, languages: "x" }), false);
  assert.equal(isCoverageData({ ...COVERAGE, corpus: 5 }), false);
  assert.equal(isCoverageData({ ...COVERAGE, languages: [{ code: "en" }] }), false);
});

test("no language is shown as reviewed, Chinese is not covered, and Indonesian attacks are not measured", () => {
  const byCode = Object.fromEntries(COVERAGE.languages.map((l) => [l.code, l]));
  assert.deepEqual(Object.keys(byCode), ["en", "ms", "id", "zh"]);
  for (const l of COVERAGE.languages) assert.equal(l.native_reviewed, false, l.code);
  assert.match(byCode.zh.note, /Not covered/);
  assert.equal(byCode.zh.blind3, null);
  assert.equal(byCode.id.blind3.attacks, 0);
  assert.equal(measured(byCode.id.blind3.attacks_found, byCode.id.blind3.attacks), "not measured");
  assert.equal(measured(30, 69), "30 of 69");
});

test("statuses are shaded cautiously and an unknown status is shown as it is", () => {
  assert.equal(statusStyle("covered").label, "covered");
  assert.match(statusStyle("weak").classes, /B42318/);
  assert.equal(statusStyle("something new").label, "something new");
  assert.match(statusStyle("something new").classes, /606060/);
});

test("the coverage file lists the known gaps and the three frozen blind rounds", () => {
  assert.ok(COVERAGE.known_gaps.length >= 5);
  assert.deepEqual(COVERAGE.blind_rounds.map((r) => r.key), ["round1", "round2", "round3"]);
  assert.ok(JSON.stringify(COVERAGE).length < 40_000);
});
