/**
 * Small pure helpers for the Risk Engine (Phase 4.5 B1) on the Passports page, kept apart from the page so they can be unit-tested
 * (node --test tests/*.test.mjs). redhand-core decides everything again: these only explain, validate obvious mistakes, and say when a
 * change needs the confirmation tick. The rules mirror risk/service.py and risk/scoring.py.
 */

export type RiskLevelName = "low" | "elevated" | "high" | "critical";
export type Rung = "alert" | "safe_mode" | "freeze";

export interface LadderValues {
  alert_at: number | null;
  safe_mode_at: number | null;
  freeze_at: number | null;
}

export const LEVEL_LABEL: Readonly<Record<RiskLevelName, string>> = {
  low: "Low",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

export const LEVEL_STYLE: Readonly<Record<RiskLevelName, string>> = {
  low: "bg-rh-elevated text-rh-text-2",
  elevated: "bg-rh-ochre-wash text-rh-ochre",
  high: "bg-rh-ochre-wash text-rh-ochre",
  critical: "bg-rh-crimson-wash text-rh-crimson-text",
};

export const RUNG_LABEL: Readonly<Record<Rung, string>> = {
  alert: "Alert (Telegram message)",
  safe_mode: "Safe Mode (read-only tools only)",
  freeze: "Freeze (every call refused)",
};

/** What the score is and is not, in plain words. Shown on the panel and the ladder card. */
export const RISK_LIMITS_TEXT =
  "The risk score adds up what RedHand has already recorded about this agent in the last 7 days (honeytoken trips, findings, refused " +
  "calls, the daily limit), with fixed weights you can see below: the last 24 hours count in full, older days count half. It is not a " +
  "measured probability, and it only sees agents connected through RedHand. Findings marked as a false alarm, silenced rules and " +
  "low-confidence findings count zero. After a person unfreezes an agent or turns its Safe Mode off, only new signals can make RedHand " +
  "act on it again.";

/** A threshold box: empty means the rung is off. Returns the number, null for off, or "invalid". */
export function parseThreshold(raw: string): number | null | "invalid" {
  const text = raw.trim();
  if (text === "") return null;
  if (!/^\d{1,3}$/.test(text)) return "invalid";
  const value = Number(text);
  return value >= 1 && value <= 100 ? value : "invalid";
}

/** An error sentence, or null. The server checks the same rules (and the database once more). */
export function validateLadder(next: LadderValues): string | null {
  const set = [next.alert_at, next.safe_mode_at, next.freeze_at].filter((v): v is number => v !== null);
  if (set.some((v) => !Number.isInteger(v) || v < 1 || v > 100)) return "Each threshold is a whole number from 1 to 100, or empty for off.";
  for (let i = 1; i < set.length; i += 1) {
    if (set[i] < set[i - 1]) return "The thresholds must rise: alert, then Safe Mode, then freeze.";
  }
  return null;
}

/** Turning Safe Mode or freeze on, or lowering its threshold, lets RedHand act on agents without a person: it needs the tick. */
export function ladderNeedsConfirmation(current: LadderValues, next: LadderValues): boolean {
  const widens = (old: number | null, value: number | null) => value !== null && (old === null || value < old);
  return widens(current.safe_mode_at, next.safe_mode_at) || widens(current.freeze_at, next.freeze_at);
}

export const LADDER_CONFIRM_TEXT =
  "I understand: RedHand will turn Safe Mode on or freeze agents by itself when their risk score reaches these numbers. A person can undo it.";

/** The label for an audit row written by RedHand itself (the fixed system actor), from the reason it recorded. */
export function automaticActorLabel(reason: string | null): string {
  if (reason?.startsWith("Risk Engine:")) return "RedHand Risk Engine";
  if (reason?.startsWith("Budget Guard:")) return "RedHand Budget Guard";
  if (reason?.startsWith("Honeytoken trip:")) return "RedHand honeytoken";
  return "RedHand (automatic)";
}

/** "40 points: 1 in the last 24 hours, 2 older" (and "the most this signal can add" when capped). */
export function signalDetail(signal: { recent: number; older: number; points: number; capped: boolean }): string {
  const parts = [];
  if (signal.recent > 0) parts.push(`${signal.recent} in the last 24 hours`);
  if (signal.older > 0) parts.push(`${signal.older} older`);
  return `${signal.points} points: ${parts.join(", ")}${signal.capped ? " (the most this signal can add)" : ""}`;
}
