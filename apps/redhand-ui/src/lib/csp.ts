/**
 * Browser security policy for the dashboard (CLAUDE.md section 5.4: no untrusted data is ever executed or rendered unsanitized; this is the
 * second line if one slips through).
 *
 * Scripts run only with a per-response nonce, and 'strict-dynamic' lets those trusted scripts load the chunks Next.js needs, so there is no
 * 'unsafe-inline' for scripts. Styles keep 'unsafe-inline' because React inline style attributes (and the flow-diagram library) need it; a
 * style cannot run code. The page cannot be framed (frame-ancestors), and the browser may talk only to this site, core, the gateway and
 * Supabase. The UI is never a security boundary: core and the gateway still authorize every action.
 */

export interface CspInput {
  coreUrl: string | undefined;
  gatewayUrl: string | undefined;
  supabaseUrl: string | undefined;
  /** Clerk mode (ADR 0032): the publishable key, from which the instance's own origin is derived. Absent in Supabase mode: nothing of Clerk is allowed. */
  clerkPublishableKey?: string | undefined;
  nonce: string;
  development: boolean;
}

/** scheme://host[:port] of an http(s) URL, or null. Anything else adds nothing to the policy. */
export function originOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.origin : null;
  } catch {
    return null;
  }
}

/** The Clerk instance's frontend origin, read from a publishable key (pk_test_ or pk_live_ followed by base64 of "host$"). Null for anything else. */
export function clerkFrontendOrigin(publishableKey: string | undefined): string | null {
  const match = /^pk_(?:test|live)_([A-Za-z0-9+/=_-]+)$/.exec(publishableKey ?? "");
  if (!match) return null;
  try {
    const decoded = atob(match[1].replace(/-/g, "+").replace(/_/g, "/"));
    if (!decoded.endsWith("$")) return null; // a real key always carries the terminator
    const host = decoded.slice(0, -1);
    return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) ? `https://${host}` : null;
  } catch {
    return null;
  }
}

/** Hosts Clerk's sign-in widgets need besides the instance itself: user images, and Cloudflare's bot challenge. */
export const CLERK_IMAGE_ORIGIN = "https://img.clerk.com";
export const CLERK_CHALLENGE_ORIGIN = "https://challenges.cloudflare.com";

/** 128 random bits, base64. Works in the Edge runtime (Web Crypto). */
export function makeNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export function buildCsp(input: CspInput): string {
  const connect = ["'self'"];
  for (const origin of [originOf(input.coreUrl), originOf(input.gatewayUrl), originOf(input.supabaseUrl)]) {
    if (origin && !connect.includes(origin)) connect.push(origin);
  }
  const clerk = clerkFrontendOrigin(input.clerkPublishableKey);
  if (clerk) connect.push(clerk);
  const script = ["'self'", `'nonce-${input.nonce}'`, "'strict-dynamic'"];
  if (clerk) script.push(clerk, CLERK_CHALLENGE_ORIGIN); // ignored by browsers that honour 'strict-dynamic'; for the ones that do not
  if (input.development) script.push("'unsafe-eval'"); // the development server's hot reload; never in production
  const directives = [
    "default-src 'self'",
    `script-src ${script.join(" ")}`,
    "style-src 'self' 'unsafe-inline'",
    clerk ? `img-src 'self' data: blob: ${CLERK_IMAGE_ORIGIN}` : "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src ${connect.join(" ")}`,
    ...(clerk ? ["worker-src 'self' blob:", `frame-src 'self' ${CLERK_CHALLENGE_ORIGIN}`] : []),
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];
  if (!input.development) directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}
