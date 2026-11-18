# Clerk sign-in (ADR 0032)

Operators can sign in, sign up and use **Google** through Clerk instead of Supabase Auth. Supabase stays the database. This is a switch: the default is Supabase, and going back is a configuration change plus a deploy. Nothing here has been run against a real Clerk instance by Claude Code; Antigravity's Clerk brief (`docs/testing/briefs/2026-11-19-clerk.md`) is the first real test.

## What you set up in Clerk (owner)
1. **A Clerk application** (use a *development* instance first, a *production* one for launch). Enable **Email** and **Google** (Configure, SSO connections). In production, Google needs your own OAuth client (Clerk's guide), not Clerk's shared development one.
2. **Require verified e-mail** for sign-up (Configure, Email, Verification). RedHand refuses a token whose e-mail is not verified.
3. **JWT template named exactly `redhand`** (Configure, JWT templates, New template). Claims:
   ```json
   {
     "aud": "redhand-core",
     "email": "{{user.primary_email_address}}",
     "email_verified": "{{user.email_addresses[0].verification.status == 'verified'}}"
   }
   ```
   Check in Clerk's template preview that `email_verified` comes out as the JSON value `true` (a boolean, not the text "true"): core refuses anything else. Set the **token lifetime to 10 minutes or more**; the dashboard renews it before it expires. Signing algorithm: RS256 (the default).
4. **Allowed origins and redirect URLs:** the dashboard origin (for example `https://redhand.archtificial.com`) and `/login`.
5. Copy three values (none is a secret): the **publishable key** (`pk_test_...` or `pk_live_...`), the **Frontend API / issuer URL** (for example `https://clean-heron-12.clerk.accounts.dev`; the issuer is the `iss` claim of a token from the template preview).

## Configure RedHand
**Core (Cloud Run):**
```
OPERATOR_AUTH_PROVIDER=clerk
CLERK_ISSUER=<the issuer URL>
# CLERK_JWKS_URL defaults to <issuer>/.well-known/jwks.json
# CLERK_AUDIENCE defaults to redhand-core (it must equal the template's aud)
```
Core refuses to start in Clerk mode without `CLERK_ISSUER`, and without https outside development. In Clerk mode Supabase and shared-secret operator tokens are refused. Apply migration `20261203000000_operator_identity` first.

**Dashboard (Vercel), then redeploy (these are read at build time):**
```
NEXT_PUBLIC_AUTH_PROVIDER=clerk
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=<publishable key>
NEXT_PUBLIC_CLERK_TELEMETRY_DISABLED=1
```
The content-security policy then allows only your Clerk instance, `img.clerk.com` and `challenges.cloudflare.com` (the bot check). No Clerk secret key is needed anywhere.

## How people get in
- Clerk people start **fresh**: they are never matched to an existing Supabase account by e-mail (no account takeover). Add them with an invite link or a sign-up code, as before.
- First sign-in creates their RedHand operator id. They then land on `/welcome` (create an organization with a code) or `/join` (accept an invite).
- Password reset and e-mail confirmation are Clerk's. The Supabase SMTP checklist item applies only to Supabase mode.

## Switch back to Supabase
Set `OPERATOR_AUTH_PROVIDER=supabase` on core (and keep the Supabase JWKS settings), set `NEXT_PUBLIC_AUTH_PROVIDER=supabase` (or remove it) on Vercel, redeploy both. Clerk-only people cannot sign in until you switch again; their data stays. The database rollback of the identity migration refuses while any Clerk-only person exists.

## Failure modes
| Symptom | Likely cause |
|---|---|
| Everyone gets "Invalid or expired operator token" (401) after signing in | JWT template missing or not named `redhand`; `aud` not `redhand-core`; `CLERK_ISSUER` differs from the token's `iss` |
| 401 "A verified e-mail address is required" | `email_verified` missing, false or a string in the template |
| Sign-in page blank or a CSP error in the console | `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` missing or rebuilt without it; wrong key for the instance |
| 503 "Sign-in could not be completed" | core cannot reach the database (migration not applied?) |
| 401 for a while after Clerk had an outage | Clerk's public keys unreachable and the cache expired: core refuses rather than guess |
