/**
 * Wording and checks for the Radar page's "Could blocking ever be switched on?" panel (Phase 4 M4.6b). Pure, so it can be unit-tested.
 * Nothing here can turn blocking on: the server refuses it, and a result that claims blocking is available is refused instead of shown.
 */

import type { ReadinessCheck, ReadinessResult } from "./api";
import type { BlockGate, GateCheck } from "./coverage";

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Structural check on the readiness answer: a broken or surprising answer shows "not available", never a verdict. */
export function isReadinessResult(value: unknown): value is ReadinessResult {
  if (!isRecord(value) || value.block_available !== false || typeof value.window_days !== "number" || !Array.isArray(value.checks)) return false;
  if (value.checks.length === 0) return false;
  return value.checks.every(
    (c) =>
      isRecord(c) && (c.kind === "injection" || c.kind === "output") && typeof c.ready === "boolean" && typeof c.scanned === "number" &&
      typeof c.strong === "number" && Array.isArray(c.conditions) &&
      c.conditions.every((x) => isRecord(x) && typeof x.id === "string" && typeof x.passed === "boolean" && typeof x.detail === "string"),
  );
}

/** Which independent-test categories (Coverage page) stand behind each check. */
export const GATE_CATEGORIES: Readonly<Record<"injection" | "output", readonly string[]>> = {
  injection: ["injection_indirect"],
  output: ["output_xss", "output_ssrf", "output_path"],
};

export function pct1(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

/** "3 strong findings in 250 results scanned (1.2%)" or an honest "nothing scanned yet". */
export function trafficText(check: ReadinessCheck): string {
  if (check.scanned === 0 || check.strong_rate === null) return "No results scanned yet in the last 7 days.";
  const noun = check.strong === 1 ? "strong finding" : "strong findings";
  return `${check.strong} ${noun} in ${check.scanned} results scanned (${pct1(check.strong_rate)}).`;
}

/** The false alarm figure, counted the hard way, or why there is none. */
export function falseAlarmText(check: ReadinessCheck): string {
  if (check.false_alarm_upper === null) return "No false alarm figure yet: nothing was scanned.";
  return `False alarms, counted the hard way: ${check.false_alarms_worst_case} (95% upper bound ${pct1(check.false_alarm_upper)}; the limit is 3.0%).`;
}

export function conditionsMet(check: ReadinessCheck): { met: number; total: number } {
  return { met: check.conditions.filter((c) => c.passed).length, total: check.conditions.length };
}

/** One line for the top of each card. "Ready" only ever means "worth a human's consideration". */
export function headline(check: ReadinessCheck): string {
  const { met, total } = conditionsMet(check);
  if (check.ready) return "Your traffic meets every condition. A person would still have to decide, and nothing can be switched on.";
  return `${met} of ${total} conditions met. Not enough clean evidence yet.`;
}

export interface EvidenceLine {
  label: string;
  passed: number;
  total: number;
  eligible: boolean;
}

/** From the public coverage file: for each independent-test category behind this check, how many of the gate's rules it passes. */
export function evidenceFor(gate: BlockGate | null, kind: "injection" | "output"): EvidenceLine[] {
  if (!gate) return [];
  const wanted = new Set(GATE_CATEGORIES[kind]);
  return gate.checks
    .filter((c: GateCheck) => wanted.has(c.category))
    .map((c) => ({ label: c.label, passed: c.results.filter((r) => r.passed).length, total: c.results.length, eligible: c.eligible }));
}
