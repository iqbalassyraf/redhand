/**
 * Pure helpers for the password-reset flow (kept free of React and network calls so they can be tested).
 *
 * Supabase sends the recovery session in the URL fragment (#access_token=...&refresh_token=...&type=recovery),
 * which browsers never send to a server or in a Referer header. The page reads it once and removes it from the
 * address bar straight away.
 */

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128; // bcrypt-based stores truncate beyond 72 bytes; this keeps the form honest

export interface RecoveryTokens {
  accessToken: string;
  refreshToken: string;
}

/** Returns the tokens from a recovery link fragment, or null for anything else (errors, other link types, junk). */
export function recoveryTokensFromHash(hash: string): RecoveryTokens | null {
  const params = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  if (params.get("error") || params.get("error_code")) return null;
  if (params.get("type") !== "recovery") return null;
  const accessToken = params.get("access_token");
  const refreshToken = params.get("refresh_token");
  if (!accessToken || !refreshToken) return null;
  return { accessToken, refreshToken };
}

/** A message describing why the password is not acceptable, or null when it is. */
export function validateNewPassword(password: string, confirmation: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (password.length > MAX_PASSWORD_LENGTH) return `Use at most ${MAX_PASSWORD_LENGTH} characters.`;
  if (password !== confirmation) return "The two passwords do not match.";
  return null;
}
