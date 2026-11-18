/**
 * Pure helpers for the Clerk session token (ADR 0032). No `@/` imports: the node tests load this file directly.
 */

export const MIN_REFRESH_MS = 30_000;
export const MAX_REFRESH_MS = 240_000;
export const FALLBACK_REFRESH_MS = 30_000;

/** The `exp` and `iat` claims of a JWT, read WITHOUT verifying it (only to schedule a renewal; redhand-core verifies the token). Null if unreadable. */
export function readLifetime(token: string): { iat: number; exp: number } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(parts[1].length / 4) * 4, "="));
    const claims = JSON.parse(json) as { iat?: unknown; exp?: unknown };
    if (typeof claims.exp !== "number" || typeof claims.iat !== "number") return null;
    return { iat: claims.iat, exp: claims.exp };
  } catch {
    return null;
  }
}

/** When to renew: at 60% of the token's remaining life, never sooner than 30 s nor later than 4 min; a missing or unreadable token retries after 30 s. */
export function nextRefreshDelayMs(token: string | null, nowMs: number = Date.now()): number {
  if (!token) return FALLBACK_REFRESH_MS;
  const life = readLifetime(token);
  if (!life) return FALLBACK_REFRESH_MS;
  const remaining = life.exp * 1000 - nowMs;
  if (remaining <= 0) return MIN_REFRESH_MS;
  return Math.min(MAX_REFRESH_MS, Math.max(MIN_REFRESH_MS, Math.round(remaining * 0.6)));
}
