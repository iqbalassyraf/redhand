import { NextResponse, type NextRequest } from "next/server";

import { buildCsp, makeNonce } from "@/lib/csp";

/**
 * Puts the Content-Security-Policy on every page response with a fresh nonce. The policy is also placed on the forwarded request, which is how
 * Next.js learns the nonce and stamps it on its own scripts. Static assets and image routes are excluded by the matcher.
 */
export function middleware(request: NextRequest): NextResponse {
  const nonce = makeNonce();
  const csp = buildCsp({
    coreUrl: process.env.NEXT_PUBLIC_REDHAND_CORE_URL || "http://localhost:8000",
    gatewayUrl: process.env.NEXT_PUBLIC_REDHAND_GATEWAY_URL || "http://localhost:8080",
    supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL,
    clerkPublishableKey: process.env.NEXT_PUBLIC_AUTH_PROVIDER === "clerk" ? process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY : undefined,
    nonce,
    development: process.env.NODE_ENV !== "production",
  });
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [{ source: "/((?!_next/static|_next/image|favicon.ico).*)" }],
};
