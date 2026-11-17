/**
 * "Reported only" passports (Phase 4.5 C1b): an agent id first seen in SDK telemetry becomes a passport that is shown but cannot use the gateway
 * until an admin promotes it. The server enforces this; these helpers only decide what the Passports page shows.
 */

export const REPORTED_ONLY_LABEL = "reported by SDK";

export const REPORTED_ONLY_HELP =
  "Created by an SDK key's telemetry, not by a person: no gateway access until an admin promotes it. Its name and numbers are whatever that key sent.";

export interface PromotablePassport {
  status: string;
  reported_only?: boolean;
}

export function canPromote(p: PromotablePassport): boolean {
  return p.reported_only === true && p.status !== "revoked";
}

export function promoteConfirmText(name: string): string {
  return `Promote ${name}? It becomes a managed passport. It still needs scopes and an agent key before it can call any tool.`;
}
