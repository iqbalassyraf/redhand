// Run with: node --test tests/*.test.mjs   (or: npm test; Node 22.18+ runs the TypeScript helpers directly)
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
  assert.match(statusStyle("weak").classes, /rh-crimson/);
  assert.equal(statusStyle("something new").label, "something new");
  assert.match(statusStyle("something new").classes, /rh-text-2/);
});

test("the coverage file lists the known gaps and the three frozen blind rounds", () => {
  assert.ok(COVERAGE.known_gaps.length >= 5);
  assert.deepEqual(COVERAGE.blind_rounds.map((r) => r.key), ["round1", "round2", "round3"]);
  assert.ok(JSON.stringify(COVERAGE).length < 40_000);
});

import { falseAlarmText, foundText, pct, selfTestProblem, CHECK_LABEL } from "../src/lib/selfTest.ts";

const CAT = { category: "output_path", malicious: 20, benign: 20, detected: 19, false_alarms: 0, detection_low: 0.76, detection_high: 0.99, false_alarm_low: 0, false_alarm_high: 0.16, hard_benign: 10, hard_false_alarms: 0 };

test("self-test wording shows counts with their ranges and treats zero as a bound", () => {
  assert.equal(pct(0.955), "96%");
  assert.equal(foundText(CAT), "19 of 20 (95%, range 76% to 99%)");
  assert.equal(falseAlarmText(CAT), "0 of 20 (at most 16% with 95% confidence)");
  assert.equal(falseAlarmText({ ...CAT, false_alarms: 3, false_alarm_low: 0.05, false_alarm_high: 0.36 }), "3 of 20 (15%, range 5% to 36%)");
  assert.equal(foundText({ ...CAT, malicious: 0, detected: 0 }), "0 of 0 (0%, range 76% to 99%)");
});

test("every check has a plain name and a failed run says nothing was measured", () => {
  for (const key of ["injection_indirect", "output_xss", "output_ssrf", "output_path"]) assert.ok(CHECK_LABEL[key].length > 5, key);
  for (const status of [429, 403, 502, 503, 500, null]) assert.ok(selfTestProblem(status).length > 20, String(status));
  assert.match(selfTestProblem(502), /Nothing was measured/);
  assert.match(selfTestProblem(429), /minute/);
});

test("the Radar page tells readers the self-test flatters the rules and points to the independent results", () => {
  const page = readFileSync(new URL("../src/app/radar/page.tsx", import.meta.url), "utf8");
  assert.match(page, /Do not read these numbers as how well the Radar works in real life/);
  assert.match(page, /about 4 in 10 hidden instructions/);
  assert.match(page, /href="\/coverage"/);
});

test("changing a switch clears the old notice and shows that the change is not saved yet", () => {
  const page = readFileSync(new URL("../src/app/radar/page.tsx", import.meta.url), "utf8");
  assert.equal((page.match(/setNotice\(null\); setError\(null\); setDraft(Radar|Output)\(/g) ?? []).length, 2);
  assert.match(page, /Not saved yet: press Save to apply this change\./);
});

// --- the block gate section (M4.6a) ---------------------------------------------------------------------------

test("the coverage file carries the block gate: blocking not available, nothing eligible, every check explained", () => {
  const gate = COVERAGE.block_gate;
  assert.equal(gate.block_available, false);
  assert.deepEqual(gate.eligible, []);
  assert.deepEqual(gate.checks.map((c) => c.category), ["injection_indirect", "output_xss", "output_ssrf", "output_path"]);
  for (const check of gate.checks) {
    assert.equal(check.eligible, false);
    assert.deepEqual(check.results.map((r) => r.id), ["G1", "G2", "G3", "G4", "G5"]);
    assert.ok(check.results.every((r) => r.detail.length > 10));
  }
});

test("a coverage file that says blocking is available, or has no gate, is refused instead of shown", () => {
  assert.equal(isCoverageData(COVERAGE), true);
  assert.equal(isCoverageData({ ...COVERAGE, block_gate: { ...COVERAGE.block_gate, block_available: true } }), false);
  const { block_gate: _gone, ...without } = COVERAGE;
  assert.equal(isCoverageData(without), false);
  assert.equal(isCoverageData({ ...COVERAGE, block_gate: { ...COVERAGE.block_gate, checks: [{ label: 1 }] } }), false);
});

test("the Radar page no longer says anything would have been blocked, and points to the Coverage page", () => {
  const radarPage = readFileSync(new URL("../src/app/radar/page.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(radarPage, /would have been blocked|would be blocked/);
  assert.match(radarPage, /strong findings/);
  assert.match(radarPage, /href="\/coverage"/);
  const coveragePage = readFileSync(new URL("../src/app/coverage/page.tsx", import.meta.url), "utf8");
  assert.match(coveragePage, /Ready to block\? Not yet\./);
});

// --- the readiness panel (M4.6b) --------------------------------------------------------------------------------

import { conditionsMet, evidenceFor, falseAlarmText as readinessFalseAlarmText, headline, isReadinessResult, trafficText } from "../src/lib/readiness.ts";

function readinessCheck(over = {}) {
  return {
    kind: "injection", label: "Hidden instructions in tool answers", ready: false, scanned: 250, strong: 3, strong_rate: 0.012,
    false_alarms_worst_case: 1, false_alarm_upper: 0.0277,
    conditions: [{ id: "R1", name: "Watching the whole time", passed: true, detail: "On Watch for the whole window." }, { id: "R2", name: "Enough traffic", passed: false, detail: "150 results scanned (need at least 200)." }],
    ...over,
  };
}
const readinessResult = (over = {}) => ({ block_available: false, window_start: "2026-11-03T00:00:00Z", window_days: 7, checks: [readinessCheck()], note: "n", ...over });

test("a readiness answer is accepted only in the expected shape, and never one that claims blocking is available", () => {
  assert.equal(isReadinessResult(readinessResult()), true);
  assert.equal(isReadinessResult(readinessResult({ block_available: true })), false);
  assert.equal(isReadinessResult(readinessResult({ checks: [] })), false);
  assert.equal(isReadinessResult(readinessResult({ checks: [readinessCheck({ kind: "other" })] })), false);
  assert.equal(isReadinessResult(readinessResult({ checks: [readinessCheck({ conditions: [{ id: 1 }] })] })), false);
  assert.equal(isReadinessResult(null), false);
  assert.equal(isReadinessResult("ready"), false);
});

test("the traffic and false alarm wording is honest about little or no data", () => {
  assert.match(trafficText(readinessCheck()), /3 strong findings in 250 results scanned \(1\.2%\)/);
  assert.match(trafficText(readinessCheck({ strong: 1, scanned: 400, strong_rate: 0.0025 })), /1 strong finding in 400/);
  assert.match(trafficText(readinessCheck({ scanned: 0, strong_rate: null })), /No results scanned yet/);
  assert.match(readinessFalseAlarmText(readinessCheck()), /counted the hard way: 1 \(95% upper bound 2\.8%; the limit is 3\.0%\)/);
  assert.match(readinessFalseAlarmText(readinessCheck({ false_alarm_upper: null })), /nothing was scanned/);
});

test("the headline never promises blocking, even for a check that meets every condition", () => {
  assert.deepEqual(conditionsMet(readinessCheck()), { met: 1, total: 2 });
  assert.match(headline(readinessCheck()), /1 of 2 conditions met/);
  const ready = headline(readinessCheck({ ready: true }));
  assert.match(ready, /nothing can be switched on/);
  assert.doesNotMatch(ready, /enable|turn on blocking|safe/i);
});

test("our independent tests are summarised per category from the public coverage file", () => {
  const lines = evidenceFor(COVERAGE.block_gate, "output");
  assert.deepEqual(lines.map((l) => l.label).sort(), ["Internal and cloud-metadata addresses", "Script and active markup", "Sensitive file paths"]);
  assert.ok(lines.every((l) => l.total === 5 && l.passed < 5 && l.eligible === false));
  assert.equal(evidenceFor(COVERAGE.block_gate, "injection").length, 1);
  assert.deepEqual(evidenceFor(null, "injection"), []);
});

test("the Radar page shows the panel, text only, with no way to switch blocking on", () => {
  const page = readFileSync(new URL("../src/app/radar/page.tsx", import.meta.url), "utf8");
  assert.match(page, /Could blocking ever be switched on\?/);
  assert.match(page, /radarApi\.readiness/);
  assert.doesNotMatch(page, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(page, /saveSettings\([^)]*block/);
  assert.doesNotMatch(page, /<option value="block"/);
});

test("every hook on the Radar page is called before the page's early return (React crashes the page otherwise)", () => {
  const page = readFileSync(new URL("../src/app/radar/page.tsx", import.meta.url), "utf8");
  const early = page.indexOf("if (!session || !token) return null;");
  assert.ok(early > 0);
  const after = page.slice(early);
  assert.doesNotMatch(after, /\buse(State|Effect|Callback|Memo|Ref)\(/);
});
