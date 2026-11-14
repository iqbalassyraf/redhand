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
  const script = ["'self'", `'nonce-${input.nonce}'`, "'strict-dynamic'"];
  if (input.development) script.push("'unsafe-eval'"); // the development server's hot reload; never in production
  const directives = [
    "default-src 'self'",
    `script-src ${script.join(" ")}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src ${connect.join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];
  if (!input.development) directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}
