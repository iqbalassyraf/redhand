/**
 * Small pure helpers for the Radar page, kept apart from the page so they can be unit-tested (node --test tests/).
 * The server re-checks everything here; these only stop obviously wrong input from being sent.
 */

export const NOTE_MAX = 300;
export const REASON_MIN = 3;
export const SUPPRESSION_DAYS_MIN = 1;
export const SUPPRESSION_DAYS_MAX = 90;

/** A review note is optional; when given it must fit. Returns an error sentence or null. */
export function validateNote(note: string): string | null {
  return note.trim().length > NOTE_MAX ? `Keep the note to ${NOTE_MAX} characters or fewer.` : null;
}

/** A silence needs a real reason (3 to 300 characters after trimming), a whole number of days from 1 to 90, and an explicit tick. */
export function validateSuppression(reason: string, days: number, confirmed: boolean): string | null {
  const trimmed = reason.trim();
  if (trimmed.length < REASON_MIN) return `Give a reason of at least ${REASON_MIN} characters.`;
  if (trimmed.length > NOTE_MAX) return `Keep the reason to ${NOTE_MAX} characters or fewer.`;
  if (!Number.isInteger(days) || days < SUPPRESSION_DAYS_MIN || days > SUPPRESSION_DAYS_MAX) {
    return `Choose between ${SUPPRESSION_DAYS_MIN} and ${SUPPRESSION_DAYS_MAX} days.`;
  }
  if (!confirmed) return "Tick the box to confirm: this stops the Radar from recording this rule for this agent.";
  return null;
}

/** Turning a check from observe to off needs the explicit tick; turning one on, or leaving it, does not. */
export function settingsNeedConfirmation(current: { radar: string; output: string }, next: { radar: string; output: string }): boolean {
  return (next.radar === "off" && current.radar !== "off") || (next.output === "off" && current.output !== "off");
}

/** Keeps a day count inside 1 to 90 (typed values can be empty or out of range). */
export function clampDays(value: number): number {
  if (!Number.isFinite(value)) return 30;
  return Math.min(SUPPRESSION_DAYS_MAX, Math.max(SUPPRESSION_DAYS_MIN, Math.round(value)));
}

/** Long values from tool servers or operators are cut for display only. */
export function shorten(value: string, max = 60): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}
