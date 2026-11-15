/**
 * Small pure helpers for the "Repeated calls" card on the Radar page (Phase 4 M6), kept apart from the page so they can be unit-tested
 * (node --test tests/). The server re-checks everything here; these only stop obviously wrong input from being sent.
 */

export const LOOP_LIMIT_MIN = 3;
export const LOOP_LIMIT_MAX = 1000;
export const LOOP_WINDOW_MIN = 10;
export const LOOP_WINDOW_MAX = 600;

export type LoopModeChoice = "off" | "observe" | "throttle";

export const LOOP_MODE_LABEL: Readonly<Record<LoopModeChoice, string>> = {
  observe: "Watch (record repeats)",
  throttle: "Throttle (also pause repeats)",
  off: "Off",
};

/** What this check can and cannot see, in plain words. Shown next to the switch. */
export const LOOP_LIMITS_TEXT =
  "Counts identical tool calls (same tool, same arguments) that go through the RedHand gateway. A call that changes its arguments " +
  "each time is not caught. With several gateway instances each one counts for itself, so the real limit can be higher. " +
  "Nothing about the call is stored: only the agent, the tool and how often.";

/** An error sentence for a limit and window that the server would refuse, or null. */
export function validateLoopSettings(limit: number, windowSeconds: number): string | null {
  if (!Number.isInteger(limit) || limit < LOOP_LIMIT_MIN || limit > LOOP_LIMIT_MAX) {
    return `Choose a limit between ${LOOP_LIMIT_MIN} and ${LOOP_LIMIT_MAX} calls.`;
  }
  if (!Number.isInteger(windowSeconds) || windowSeconds < LOOP_WINDOW_MIN || windowSeconds > LOOP_WINDOW_MAX) {
    return `Choose a window between ${LOOP_WINDOW_MIN} and ${LOOP_WINDOW_MAX} seconds.`;
  }
  return null;
}

/** Turning throttling on (it refuses calls) or turning detection off (it removes a safeguard) needs the tick; other changes do not. */
export function loopNeedsConfirmation(current: LoopModeChoice, next: LoopModeChoice): boolean {
  return (next === "throttle" && current !== "throttle") || (next === "off" && current !== "off");
}

export function loopConfirmText(next: LoopModeChoice): string {
  return next === "throttle"
    ? "I understand: a call repeated more often than the limit will be refused until the time window passes."
    : "I understand: while this is off, RedHand stops recording repeated calls.";
}

/** A typed number can be empty or out of range: keep it a whole number the server may accept. */
export function clampLoopNumber(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.round(value)));
}
