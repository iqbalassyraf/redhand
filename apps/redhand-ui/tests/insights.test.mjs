// Run with: npm test   (node --test tests/*.test.mjs)
import assert from "node:assert/strict";
import test from "node:test";

import {
  bucketLabel, controlChips, formatBytes, formatCount, formatMs, hasCalls, outcomeSlices, percent, reasonLabel, reasonRows, seriesSummary, REASON_LABELS,
} from "../src/lib/insights.ts";

const summary = (over = {}) => ({
  window: "24h", window_start: "2026-11-17T10:00:00Z", window_end: "2026-11-18T10:00:00Z", bucket_seconds: 3600,
  totals: { decisions: 12640, allowed: 11250, refused: 1390, errors: 0, bytes_returned: 5_600_000_000 },
  series: [], agents: [], tools: [], servers: [], reasons: [], latency: { samples: 0, p50_ms: null, p95_ms: null }, flow: [],
  passports: { managed_active: 3, frozen: 0, revoked: 0, reported_only: 0 }, controls: { safe_mode: false, radar_mode: "observe" }, ...over,
});

test("figures read the same everywhere: thousands separators, sizes, milliseconds", () => {
  assert.equal(formatCount(12640), "12,640");
  assert.equal(formatCount(0), "0");
  assert.equal(formatCount(1234567.4), "1,234,567");
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(1500), "1.5 kB");
  assert.equal(formatBytes(5_600_000_000), "5.6 GB");
  assert.equal(formatBytes(250_000_000), "250 MB");
  assert.equal(formatMs(null), "no data");
  assert.equal(formatMs(4.256), "4.26 ms");
  assert.equal(formatMs(42.34), "42.3 ms");
  assert.equal(formatMs(312.6), "313 ms");
});

test("a percentage is never NaN and a zero total reads as zero", () => {
  assert.equal(percent(1, 4), 25);
  assert.equal(percent(0, 0), 0);
  assert.equal(percent(5, 0), 0);
});

test("outcome slices keep their order and tones: allowed teal, refused crimson, errors ochre", () => {
  const s = outcomeSlices(summary().totals);
  assert.deepEqual(s.map((x) => [x.key, x.tone, x.value]), [["allowed", "teal", 11250], ["refused", "crimson", 1390], ["errors", "ochre", 0]]);
});

test("every gateway reason category has a plain label; an unknown one reads as Other and is never shown raw", () => {
  for (const code of Object.keys(REASON_LABELS)) assert.notEqual(reasonLabel(code), "Other");
  assert.equal(reasonLabel("Tool 'x' on server 'evil.example.com' is not allowed"), "Other");
});

test("unknown reasons are merged into one Other row and the counts still add up", () => {
  const rows = reasonRows([{ reason: "out_of_scope", count: 5 }, { reason: "weird-1", count: 2 }, { reason: "weird-2", count: 1 }, { reason: "safe_mode", count: 3 }]);
  assert.deepEqual(rows, [
    { label: "Outside the agent's passport scope", count: 5 },
    { label: "Safe Mode (write tools paused)", count: 3 },
    { label: "Other", count: 3 },
  ].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)));
  assert.equal(rows.reduce((s, r) => s + r.count, 0), 11);
});

test("bucket labels are UTC: time of day for short windows, the date for a week, empty for garbage", () => {
  assert.equal(bucketLabel("2026-11-18T09:05:00Z", "1h"), "09:05");
  assert.equal(bucketLabel("2026-11-18T23:00:00Z", "24h"), "23:00");
  assert.equal(bucketLabel("2026-11-18T06:00:00Z", "7d"), "Nov 18");
  assert.equal(bucketLabel("not a date", "1h"), "");
});

test("the control chips put restrictions first and only mention frozen or revoked when there are some", () => {
  assert.deepEqual(controlChips(summary()).map((c) => c.label), ["Safe Mode off", "Radar watching"]);
  const busy = summary({ controls: { safe_mode: true, radar_mode: "block" }, passports: { managed_active: 1, frozen: 2, revoked: 1, reported_only: 4 } });
  assert.deepEqual(controlChips(busy).map((c) => [c.label, c.tone]), [["Safe Mode on", "ochre"], ["Radar blocking", "crimson"], ["2 frozen", "ochre"], ["1 revoked", "crimson"]]);
});

test("an empty window is recognised and the screen-reader summary states the totals", () => {
  assert.equal(hasCalls(summary({ totals: { decisions: 0, allowed: 0, refused: 0, errors: 0, bytes_returned: 0 } })), false);
  assert.equal(hasCalls(summary()), true);
  assert.match(seriesSummary(summary()), /12,640 gateway decisions in the past 24 hours: 11,250 allowed, 1,390 refused, 0 errors\./);
});
