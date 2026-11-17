/**
 * The owner's organization data screen (Phase 4.5 D1, ADR 0027): export, delete with a 7-day grace period, cancel. Pure helpers and the on-screen text,
 * so they are tested and the test-day brief can promise the exact words. redhand-core decides everything (owner only, typed address name, one export an hour).
 */

export const ORG_TEXT = {
  title: "Organization data",
  notOwner: "Only an owner can export or delete this organization's data.",
  exportTitle: "Export your data",
  exportIntro: "Downloads everything RedHand holds for this organization as one JSON file: agents, passports, audit log, Black Box events, findings, members. Key and token hashes are left out. One export per hour; each one is recorded in the audit log.",
  exportButton: "Download export",
  exportDone: "Export downloaded. Keep the file safe: it holds your organization's data.",
  deleteTitle: "Delete this organization",
  deleteIntro: "Every agent is frozen at once, SDK keys stop working and pending invites are revoked. After 7 days everything is deleted for good. Until then you can cancel, and only this page and the export still work.",
  deleteLabel: "Type the organization's address name to confirm",
  deleteButton: "Request deletion",
  deleteConfirm: "Request deletion of this organization? Every agent stops working now. You have 7 days to cancel.",
  cancelButton: "Cancel the deletion",
  cancelDone: "Deletion cancelled. Agents stay frozen: unfreeze each one on Passports when you are ready, and create new SDK keys.",
} as const;

/** The banner text while deletion is pending, with the end of the grace period in UTC (no locale: the same words for everyone). */
export function pendingText(purgeAfterIso: string): string {
  return `This organization is scheduled for deletion on ${formatUtc(purgeAfterIso)}. Export your data or cancel the deletion before then.`;
}

export function formatUtc(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "an unknown date";
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** The typed confirmation must equal the address name exactly (core checks it again). An empty slug never matches. */
export function slugMatches(typed: string, slug: string): boolean {
  return slug.length > 0 && typed.trim() === slug;
}

/** Core's 403 while deletion is pending: the Passports page sends the person here instead of showing an error. */
export function isDeletionPendingMessage(message: string): boolean {
  return /scheduled for deletion/i.test(message);
}

export function exportFilename(slug: string, now: Date): string {
  const safe = slug.replace(/[^a-z0-9-]/g, "") || "organization";
  return `redhand-export-${safe}-${now.toISOString().slice(0, 10)}.json`;
}
