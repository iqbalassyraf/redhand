/**
 * Insights (dashboard redesign S3): the view model for the home page. Pure functions over `GET /v1/insights/summary`, so the rules for
 * wording, formatting and empty states are tested without a browser. No `@/` imports: the node tests load this file directly.
 *
 * Claims discipline: latency is the whole call as the gateway saw it, tool time included (never presented as the gateway's own overhead);
 * "refused" and "errors" are distinct; every value from core is rendered as text.
 */

export type InsightsWindow = "1h" | "24h" | "7d";

export const WINDOW_OPTIONS: { value: InsightsWindow; label: string }[] = [
  { value: "1h", label: "Past hour" },
  { value: "24h", label: "Past 24 hours" },
  { value: "7d", label: "Past 7 days" },
];

export type Decision = "ALLOW" | "BLOCK" | "ERROR";

export interface InsightsTotals { decisions: number; allowed: number; refused: number; errors: number; bytes_returned: number }
export interface InsightsPoint { bucket_start: string; allowed: number; refused: number; errors: number; bytes: number }
export interface InsightsAgent { agent_id: string; name: string | null; framework: string | null; decisions: number; refused: number; errors: number }
export interface InsightsTool { server: string; tool: string; calls: number; refused: number }
export interface InsightsServer { server: string; decisions: number; allowed: number; refused: number; errors: number }
export interface InsightsReason { reason: string; count: number }
export interface InsightsLatency { samples: number; p50_ms: number | null; p95_ms: number | null }
export interface InsightsFlow { agent_id: string; server: string; decision: Decision; count: number }
export interface InsightsPassports { managed_active: number; frozen: number; revoked: number; reported_only: number }
export interface InsightsControls { safe_mode: boolean; radar_mode: "off" | "observe" | "block" }

export interface InsightsSummary {
  window: InsightsWindow;
  window_start: string;
  window_end: string;
  bucket_seconds: number;
  totals: InsightsTotals;
  series: InsightsPoint[];
  agents: InsightsAgent[];
  tools: InsightsTool[];
  servers: InsightsServer[];
  reasons: InsightsReason[];
  latency: InsightsLatency;
  flow: InsightsFlow[];
  passports: InsightsPassports;
  controls: InsightsControls;
}

export type Tone = "teal" | "steel" | "ochre" | "crimson" | "purple" | "neutral";

/** The gateway's refusal reasons arrive as fixed categories (never the raw sentence); an unknown one reads as "Other". */
export const REASON_LABELS: Record<string, string> = {
  out_of_scope: "Outside the agent's passport scope",
  safe_mode: "Safe Mode (write tools paused)",
  daily_limit: "Daily call limit reached",
  agent_not_active: "Agent frozen or revoked",
  token_stale: "Out-of-date agent token",
  honeytoken: "Honeytoken or decoy tool",
  tool_unapproved: "Tool changed and not yet approved",
  destination: "Address not on the allowed list",
  loop: "Repeated identical call paused",
  firewall_rule: "Firewall rule (arguments)",
  upstream_error: "Tool server failed to answer",
};

export function reasonLabel(code: string): string {
  return REASON_LABELS[code] ?? "Other";
}

/** Thousands separators without locale surprises (the dashboard is read by people in several countries; figures are always shown the same way). */
export function formatCount(n: number): string {
  return Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

export function formatBytes(n: number): string {
  if (n < 1000) return `${Math.round(n)} B`;
  const units = ["kB", "MB", "GB", "TB"];
  let value = n / 1000;
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i += 1;
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

export function formatMs(ms: number | null): string {
  if (ms === null) return "no data";
  return ms >= 100 ? `${Math.round(ms)} ms` : `${ms.toFixed(ms < 10 ? 2 : 1)} ms`;
}

/** Whole-number percentage of `part` in `total` (0 when there is no total: never NaN). */
export function percent(part: number, total: number): number {
  return total <= 0 ? 0 : Math.round((part / total) * 100);
}

export function hasCalls(summary: InsightsSummary): boolean {
  return summary.totals.decisions > 0;
}

export interface OutcomeSlice { key: "allowed" | "refused" | "errors"; label: string; value: number; tone: Tone }

export function outcomeSlices(totals: InsightsTotals): OutcomeSlice[] {
  return [
    { key: "allowed", label: "Allowed", value: totals.allowed, tone: "teal" },
    { key: "refused", label: "Refused", value: totals.refused, tone: "crimson" },
    { key: "errors", label: "Errors", value: totals.errors, tone: "ochre" },
  ];
}

/** An axis label for a bucket start (UTC): the time of day for short windows, the date for a week. */
export function bucketLabel(iso: string, window: InsightsWindow): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  if (window === "7d") {
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return `${months[d.getUTCMonth()]} ${d.getUTCDate()}`;
  }
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

export function windowLabel(window: InsightsWindow): string {
  return WINDOW_OPTIONS.find((o) => o.value === window)?.label ?? window;
}

/** Collapses rows whose reason is not a known category into one "Other" row (the counts add up; nothing unknown is displayed). */
export function reasonRows(reasons: InsightsReason[]): { label: string; count: number }[] {
  const merged = new Map<string, number>();
  for (const r of reasons) {
    const label = reasonLabel(r.reason);
    merged.set(label, (merged.get(label) ?? 0) + r.count);
  }
  return [...merged.entries()].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

export interface ControlChip { label: string; tone: Tone }

/** The organization's control state as chips, in the order an owner scans: what is restricted first. */
export function controlChips(summary: InsightsSummary): ControlChip[] {
  const chips: ControlChip[] = [];
  chips.push(summary.controls.safe_mode ? { label: "Safe Mode on", tone: "ochre" } : { label: "Safe Mode off", tone: "neutral" });
  const radar = summary.controls.radar_mode;
  chips.push(
    radar === "block" ? { label: "Radar blocking", tone: "crimson" } : radar === "observe" ? { label: "Radar watching", tone: "purple" } : { label: "Radar off", tone: "neutral" }
  );
  if (summary.passports.frozen > 0) chips.push({ label: `${formatCount(summary.passports.frozen)} frozen`, tone: "ochre" });
  if (summary.passports.revoked > 0) chips.push({ label: `${formatCount(summary.passports.revoked)} revoked`, tone: "crimson" });
  return chips;
}

/** Text summary of a chart for screen readers (every chart carries one; the visual is not the only way to read it). */
export function seriesSummary(summary: InsightsSummary): string {
  const t = summary.totals;
  return `${formatCount(t.decisions)} gateway decisions in the ${windowLabel(summary.window).toLowerCase()}: ${formatCount(t.allowed)} allowed, ${formatCount(t.refused)} refused, ${formatCount(t.errors)} errors.`;
}
