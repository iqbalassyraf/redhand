# ADR 0007: Operator tokens can be verified with a JWKS (asymmetric keys)

- **Status:** Accepted (2026-11-02). Supersedes the "HS256 only" part of ADR 0005; the rest of
  ADR 0005 (tenant from membership, roles, dev login) stands.
- **Phase:** 1 (hardening)
- **Plan:** `docs/plans/operator-jwks-verification.md`

## Context
New Supabase projects sign logins with asymmetric keys (the staging project shows one current
ECC P-256 key), so tokens are ES256 with a `kid`. Core accepted only HS256 with a shared secret.

## Decision
Core verifies operator tokens in one of two mutually exclusive modes chosen by configuration:
- **JWKS mode** (`OPERATOR_JWKS_URL` and `OPERATOR_JWT_ISSUER`): ES256 (P-256) and RS256 (>= 2048
  bits) against the project's public keys. `iss`, `aud=authenticated`, `exp`, `sub`, `iat` are
  required. HS256 and every other algorithm are rejected before any key lookup.
- **HS256 mode** (`OPERATOR_JWT_SECRET`): for a project on its legacy secret and for local
  development.
Outside development and test, core refuses to start unless exactly one mode is configured.

Keys are cached 10 minutes; an unknown `kid` or stale cache refetches at most once per 30 s; if
refreshing fails, cached keys keep working for at most one hour in total, then everything is
denied. A refresh that yields no usable key never replaces a working key set.

## Alternatives
- **Revert the project to the legacy shared secret:** Supabase is moving away from it, and a
  shared secret in core lets anyone who obtains it mint operator tokens.
- **Validate each token with Supabase's `/auth/v1/user`:** a network call on every request and a
  hard dependency on Supabase's availability.

## Consequences
- Verification is local, so a signed-out or removed operator's token stays valid until it expires
  (Supabase default one hour). Shorten the access-token lifetime in the Supabase project settings
  to narrow this.
- New outbound call from core to a public JWKS URL; no new secrets or dependencies.
- The HS256 secret is no longer needed on projects that use asymmetric keys.
