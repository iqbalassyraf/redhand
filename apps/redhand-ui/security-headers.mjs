/**
 * Headers that do not depend on the request. Plain JavaScript on purpose: next.config.mjs is loaded by Node before any TypeScript is built.
 * The Content-Security-Policy carries a per-response nonce, so src/middleware.ts sets it (see src/lib/csp.ts).
 */
export const SECURITY_HEADERS = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
  { key: "X-Frame-Options", value: "DENY" }, // older browsers; frame-ancestors in the policy is the real control
];
