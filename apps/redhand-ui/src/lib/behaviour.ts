/**
 * Plain-words helpers for the behaviour baseline (Phase 4.5 B2) in the Risk panel, kept apart from the page so they can be unit-tested
 * (node --test tests/*.test.mjs). Watch only: nothing here affects the score, alerts or actions. Tool names come from MCP servers and agents,
 * so they are capped here and always rendered as text.
 */

export interface BehaviourLike {
  status: "ok" | "unavailable";
  warm: boolean;
  history_days: number;
  warmup_days: number;
  hour_calls: number;
  usual_hourly: number;
  spike_threshold: number;
  spike: boolean;
  new_tools: string[];
  warning: boolean;
  backtest: { hours: number; flagged_hours: number; spike_hours: number; new_tool_starts: number } | null;
}

export const TOOL_NAME_SHOWN_MAX = 64;

export const BEHAVIOUR_LIMITS_TEXT =
  "Watch only: this does not change the score, send alerts or act. It compares this hour with the agent's own last 7 days " +
  "(a surge is at least 5 times the usual hour and at least 30 calls) and lists tools it had not used in 14 days. It only " +
  "catches sudden change: an agent that changes slowly teaches the baseline as it goes.";

export function behaviourHeadline(b: BehaviourLike): string {
  if (b.status === "unavailable") return "Behaviour could not be read right now. The score above is not affected.";
  if (!b.warm) return `Warming up: ${Math.min(b.history_days, b.warmup_days)} of ${b.warmup_days} days of history. Nothing is judged yet.`;
  if (b.spike && b.new_tools.length > 0) return "Unusual: a surge of calls and a tool it has not used before.";
  if (b.spike) return "Unusual: a surge of calls this hour.";
  if (b.new_tools.length > 0) return "Unusual: a tool it has not used before.";
  return "Usual behaviour.";
}

/** "This hour: 40 calls. Usual hour: 2.0 calls (a surge starts at 30)." */
export function hourText(b: BehaviourLike): string {
  return `This hour: ${b.hour_calls} ${b.hour_calls === 1 ? "call" : "calls"}. Usual hour: ${b.usual_hourly.toFixed(1)} calls (a surge starts at ${b.spike_threshold}).`;
}

export function shownToolName(name: string): string {
  return name.length > TOOL_NAME_SHOWN_MAX ? `${name.slice(0, TOOL_NAME_SHOWN_MAX - 1)}…` : name;
}

/** "Over the last 168 hours this would have flagged 2 hours (1 surge, 1 new tool)." The noise measure, in the reader's terms. */
export function backtestText(b: BehaviourLike): string | null {
  const t = b.backtest;
  if (!t || t.hours === 0) return null;
  const parts = [`${t.spike_hours} ${t.spike_hours === 1 ? "surge" : "surges"}`, `${t.new_tool_starts} new ${t.new_tool_starts === 1 ? "tool" : "tools"}`];
  return `Over the last ${t.hours} hours this would have flagged ${t.flagged_hours} ${t.flagged_hours === 1 ? "hour" : "hours"} (${parts.join(", ")}).`;
}
