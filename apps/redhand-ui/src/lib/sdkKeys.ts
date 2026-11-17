/**
 * Organization SDK keys (Phase 4.5 C1a) for the Passports page: the shapes of redhand-core's /v1/organization/sdk-keys routes and small pure helpers,
 * kept apart from the card so they can be unit-tested (node --test tests/*.test.mjs). redhand-core decides everything again: admins only for create
 * and revoke, the plaintext key exists only in the create response, and the page never stores it.
 */

export type KeyState = "active" | "expired" | "revoked";

export interface SdkKey {
  id: string;
  name: string;
  key_prefix: string;
  state: KeyState;
  created_at: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface SdkKeyList {
  keys: SdkKey[];
  max_active: number;
}

export interface SdkKeyCreated {
  secret: string;
  key: SdkKey;
  notice: string;
}

export const SDK_KEYS_TEXT =
  "An SDK key lets your agents' RedHand SDK send traces and model use for this organization. Anyone with a key can report for any agent of the " +
  "organization, so treat it like a password: store it in a secrets manager, never in code. RedHand keeps only a hash: a key is shown once, when it is created.";

export const SHOW_ONCE_TEXT = "Copy this key now. It will not be shown again: RedHand stores only its hash.";

export const REVOKE_CONFIRM_TEXT = "Revoke this key? Anything still using it will be refused from the next batch. This cannot be undone.";

const STATE_LABEL: Readonly<Record<KeyState, string>> = { active: "active", expired: "expired", revoked: "revoked" };

export function stateLabel(state: KeyState): string {
  return STATE_LABEL[state] ?? state;
}

/** The expiry box: a whole number of days from 1 to 365, or "invalid". Empty means the default (90). */
export function parseDays(raw: string): number | "invalid" {
  const text = raw.trim();
  if (text === "") return 90;
  if (!/^\d{1,3}$/.test(text)) return "invalid";
  const days = Number(text);
  return days >= 1 && days <= 365 ? days : "invalid";
}

/** The name box: trimmed, 1 to 100 characters, or "invalid". */
export function parseName(raw: string): string | "invalid" {
  const text = raw.trim();
  return text.length >= 1 && text.length <= 100 ? text : "invalid";
}

export function usableCount(keys: SdkKey[]): number {
  return keys.filter((k) => k.state === "active").length;
}

/** "never" rather than an empty cell, so an unused key is obvious. */
export function lastUsedText(key: SdkKey): string {
  return key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "never";
}
