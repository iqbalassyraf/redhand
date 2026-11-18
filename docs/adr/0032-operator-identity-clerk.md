# ADR 0032: Operator identity through Clerk (sign-in, sign-up, Google SSO)

**Status:** Accepted by the owner (2026-11-18: "plan that entire implementation to use clerk", plan approved). It is built in slices C1 to C4. **The dependency `@clerk/nextjs` still needs the owner's explicit yes (CLAUDE.md section 13) before C3.**

## Context
Operators (the people who use the dashboard) sign in with Supabase Auth: email and password, with Supabase's own e-mails. The owner wants sign-up and sign-in through Clerk, including **Google SSO**, and holds a Clerk subscription. Supabase stays the database (Postgres, row-level security, all tenant data).

Core already verifies operator JWTs against a JWKS (RS256/ES256 allowlist, issuer, audience, expiry: `auth/operator_jwks.py`) and resolves tenant and role from `organization_members`. That resolution uses the token's `sub` as a **UUID**, and 11 foreign keys point at `auth.users(id)`. Clerk subjects are strings (`user_...`).

## Decision
1. **Our own operator id.** A new `operators` table owns a UUID per person. `operator_identities(provider, subject) -> operator_id` maps an identity provider's subject to it. The 11 foreign keys move from `auth.users` to `operators`; existing Supabase users are backfilled with provider `supabase`.
2. **Just-in-time creation, never email linking.** On a Clerk user's first verified request core creates their operator and identity. **An existing account is never matched by e-mail** (owner decision): a person who used Supabase sign-in before is re-invited through the normal invite link. This removes "claim someone's address, take their account".
3. **Strict token contract.** A Clerk JWT template named `redhand` issues the token core accepts:
   - **Claims:** `aud` = `redhand-core` (our own audience, so a token minted for anything else is refused), `email`, `email_verified`.
   - **Algorithm and issuer:** RS256 only, issuer = the Clerk instance URL, JWKS fetched from the instance.
   - **Lifetime:** `exp` and `nbf` with 30 s leeway, `sub` required.
   - **Refused:** a token without a verified e-mail.
   - **Unchanged:** roles and tenants stay in our database; Clerk Organizations are not used.
4. **A switch, not a cut-over.** `OPERATOR_AUTH_PROVIDER = supabase | clerk` in core and `NEXT_PUBLIC_AUTH_PROVIDER` in the dashboard. Staging can go back to Supabase in one deploy. Removing the Supabase path later is its own change.
5. **Dashboard:**
   - `@clerk/nextjs` provides sign-in, sign-up and the Google button, themed with our tokens.
   - Our sign-up-code (`/welcome`) and invite (`/join`) steps run after Clerk sign-in.
   - The CSP gains only the Clerk instance's origins.
   - Only the publishable key reaches the browser; core does not need Clerk's secret key.

## Alternatives considered
- **Change every user-id column to text:** about 30 functions and their tests, and UUID guarantees lost. Rejected.
- **Clerk Organizations as tenants:** splits tenant isolation across two systems. Rejected.
- **Google sign-in through Supabase Auth:** smaller (about half a day), but no path to enterprise SAML SSO and no hosted sign-in. The owner chose Clerk.
- **Link by verified e-mail:** convenient, but an account-takeover path if any provider's verification is weak. Rejected by the owner.

## Consequences
- **New trust boundary:** Clerk becomes the identity provider. If its JWKS is unreachable, operators are refused (fail closed); the gateway and agents are unaffected (agents never use operator tokens).
- **Two identity paths** exist until the Supabase one is removed. Both are tested on every build, and the route sweep runs for both.
- **E-mail:** Clerk sends the confirmation and reset e-mails when Clerk is on, so the Supabase SMTP item in the owner checklist applies only to the Supabase mode.
- **Rollback:** the migration's rollback re-points the keys to `auth.users`, and refuses once any Clerk-only operator exists (their rows would have nowhere to point).
- **Cost:** Clerk's own plan (owner's subscription). No added per-request cost in RedHand beyond a cached JWKS.

## Dependency request: `@clerk/nextjs` (owner approval needed)
- **Purpose:** Clerk's official Next.js SDK. It provides the sign-in and sign-up UI with social and SSO providers, the session cookie, and `getToken({ template })` for the token core verifies.
- **Version:** pin `7.9.24` (published 2026-11-03, more than two weeks old); exact version in `package.json`, lockfile committed. Peer ranges cover our Next 15.5 and React 19.3.
- **Pulls in:** `@clerk/react`, `@clerk/shared`, `@clerk/backend`, `server-only`.
- **Licence:** MIT.
- **Maintenance:** Clerk's own SDK, released weekly.
- **Alternatives:** Clerk's raw Frontend API by hand (much more security-sensitive code of our own); Supabase Google sign-in (see above).
- **Security:** it runs in the browser and in Next.js middleware; it never sees RedHand's service tokens. `npm audit` gates its production tree on every build.
