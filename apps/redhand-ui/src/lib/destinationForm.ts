/**
 * Small pure helpers for the "Allowed destinations" panel (Phase 4 M7), kept apart from the page so they can be unit-tested
 * (node --test tests/*.test.mjs). The server re-checks everything here with the SAME normalizer the gateway uses; these only stop
 * obviously wrong input from being sent and say why in plain words.
 */

export const HOST_INPUT_MAX = 300;
export const MAX_ALLOWED_DESTINATIONS = 100;

export type DestinationModeChoice = "off" | "observe" | "enforce";

export const DESTINATION_MODE_LABEL: Readonly<Record<DestinationModeChoice, string>> = {
  observe: "Watch (record addresses outside the list)",
  enforce: "Enforce (also refuse the call)",
  off: "Off",
};

/** What this check can and cannot see, in plain words. Shown next to the switch. */
export const DESTINATION_LIMITS_TEXT =
  "RedHand reads the web addresses (http, https, ftp, ws, sftp) and email addresses an agent writes into a call that goes through the " +
  "RedHand gateway, and compares each with this list. An address written as a plain word, encoded, split across fields or built by the " +
  "tool itself is not seen, and the check does not see what a tool does with the data afterwards. Matches are exact: sub.example.com is " +
  "not example.com. The port and the scheme are ignored. When enforcing, a call too large to read is refused. Findings show only the " +
  "last two parts of an address.";

/** An error sentence for a host the server would refuse, or null. The server is the authority: this only catches the usual mistakes. */
export function validateHostInput(raw: string): string | null {
  const host = raw.trim();
  if (host === "") return "Type a host name or address.";
  if (host.length > HOST_INPUT_MAX) return `Keep it to ${HOST_INPUT_MAX} characters or fewer.`;
  if (/\s/.test(host)) return "A host has no spaces.";
  if (host.includes("://") || /[/\\?#]/.test(host)) return "Enter the host only, for example files.example.com: no http://, no path.";
  if (host.includes("@")) return "Enter the host only, not an email address or a user name.";
  if (host.includes("*")) return "Wildcards are not supported: list each host.";
  const colons = host.split(":").length - 1;
  if (colons === 1 && /:\d*$/.test(host)) return "Leave out the port number: it is ignored.";
  return null;
}

/** Turning enforcement on (it refuses calls) or the check off (it removes a safeguard) needs the confirmation tick. */
export function destinationNeedsConfirmation(current: DestinationModeChoice, next: DestinationModeChoice): boolean {
  return (next === "enforce" && current !== "enforce") || (next === "off" && current !== "off");
}

export function destinationConfirmText(next: DestinationModeChoice): string {
  return next === "enforce"
    ? "I understand: a call with an address that is not on this list will be refused."
    : "I understand: while this is off, RedHand stops checking where this agent sends data.";
}

/** Enforcement with an empty list would refuse every address, so the server refuses it; say so before the request. */
export function enforceBlockedReason(next: DestinationModeChoice, entryCount: number): string | null {
  return next === "enforce" && entryCount < 1 ? "Add at least one allowed destination before turning enforcement on." : null;
}

/** The last entry cannot be removed while the agent is enforcing (an empty list would refuse every address). */
export function removeBlockedReason(mode: DestinationModeChoice, entryCount: number): string | null {
  return mode === "enforce" && entryCount <= 1 ? "This is the last allowed destination: switch to Watch or Off first." : null;
}
