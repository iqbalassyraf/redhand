# Plan: verify operator logins signed with Supabase's asymmetric keys (JWKS)

**Status:** Approved 2026-11-02 and implemented (ADR 0007).
**Follows up:** ADR 0005 and `docs/plans/phase1-plan.md` §9, item 3.

## 1. Goal
Operators can sign in to the dashboard against the staging Supabase project and use redhand-core.
Serves "done" test 1 (passport visible in the dashboard) and every operator action on staging.

## 2. Current state
- `redhand_core/auth/operator.py` verifies operator tokens with **HS256 only**, using a shared
  secret (`OPERATOR_JWT_SECRET`).
- The staging project (`qxxiksevqfmkqstrdkxi`) shows one signing key in *Project Settings → JWT
  Keys*: **Current, ECC (P-256)** (screenshot from the project owner, 2026-11-02), so its logins
  are signed with **ES256** and carry a `kid`. Core would reject every one of them (401).
- The dev login and all tests use HS256 with a local secret and must keep working.

## 3. Approach
Add a second verification mode that uses the project's public keys, selected by configuration.

- New settings: `OPERATOR_JWKS_URL` (e.g. `https://<ref>.supabase.co/auth/v1/.well-known/jwks.json`)
  and `OPERATOR_JWT_ISSUER` (e.g. `https://<ref>.supabase.co/auth/v1`).
- **JWKS mode** (when `OPERATOR_JWKS_URL` is set): accept only `ES256` and `RS256`; pick the key by
  the token's `kid`; verify signature, `iss`, `aud = authenticated`, `exp`, `sub`, with 30 s leeway.
- **The two modes are mutually exclusive.** In JWKS mode an HS256 token is rejected outright and
  `OPERATOR_JWT_SECRET` is ignored. This removes the classic algorithm-confusion attack (an
  attacker signing with HS256 using the public key as the "secret").
- Key cache: fetched with a 3 s timeout, reused for 10 minutes; an unknown `kid` triggers at most
  one refetch per 30 s (key rotation). If a refresh fails, cached keys are still used for up to
  1 hour in total, then the mode denies everything (fail closed).
- Outside development and test, core refuses to start unless exactly one mode is configured, so
  a missing setting is caught at deploy time rather than as mysterious 401s.
- The JWKS URL must be `https` outside development.

**Alternatives considered**
1. *Switch the Supabase project back to its legacy shared secret:* rejected. Supabase is moving
   away from it, and a shared secret held by core lets anyone who obtains it mint operator tokens;
   public keys carry no such risk.
2. *Validate each token by calling Supabase's `/auth/v1/user`:* rejected. It puts a network call on
   every request and makes core's availability depend on Supabase's.
3. *Share one verifier with the gateway:* rejected for now. The two are small and live in
   separate packages; revisit if a third caller appears.

## 4. Changes
- `redhand_core/auth/operator.py`: a token verifier with HS256 and JWKS strategies; the
  `get_operator` dependency uses it.
- `redhand_core/config.py`: the two settings plus the startup validation.
- Tests (new file `test_operator_jwks.py`), `.env.example`, ADR 0007 (supersedes the "HS256 only"
  part of ADR 0005), threat model row, a short runbook for "operators get 401 on staging".
- No new dependencies: PyJWT (with `cryptography`) and httpx are already locked.

## 5. Security impact
- **New outbound call from core** to the Supabase JWKS endpoint (public data, no credentials).
- **No new secrets.** The HS256 secret is no longer needed on staging or production.
- **Failure modes all deny:** JWKS unreachable with no usable cached key, unknown `kid`, wrong
  `alg`, wrong `iss`, wrong `aud`, expired or malformed token, key type not matching the algorithm.
- **Known limitation:** verification is local, so a signed-out or removed operator's token stays
  valid until it expires (Supabase default: 1 hour). Recommended mitigation, a setting in your
  Supabase project: shorten the access-token lifetime (for example 15 minutes) under
  Authentication settings.
- Tenant and role still come from `organization_members`, never from the token.

## 6. Data and migrations
None.

## 7. Tests
Using a locally generated ES256 key and a fake JWKS endpoint:
- allowed: valid token; key rotation (new `kid` appears after the first fetch);
- denied: wrong signature, wrong `iss`, wrong `aud`, expired, no `exp`, `alg: none`, HS256-signed
  token including one signed with the public key as secret (confusion attack), `alg` not matching
  the key type, unknown `kid` after refetch, malformed header;
- failure modes: JWKS down on cold start (deny), JWKS down with fresh cache (still works), JWKS down
  past the 1-hour limit (deny), refetch rate limit;
- configuration: both modes set, neither set outside development (startup error), http URL
  outside development rejected;
- existing HS256 tests and the dev login keep passing unchanged.

## 8. Cost and performance
ES256 verification is local (well under 1 ms) and one JWKS fetch happens per 10 minutes. No
effect on the agent gateway.

## 9. Risks and open questions
- The exact `iss` value must match what Supabase puts in tokens. Supabase's documented form is
  `https://<ref>.supabase.co/auth/v1`; I will confirm it against a real token during the staging
  login test. My sandbox cannot reach the Supabase address, so I cannot inspect the live JWKS
  from here; unit tests use a generated key.
- Question for you: are you willing to shorten the access-token lifetime in Supabase (see §5)?
