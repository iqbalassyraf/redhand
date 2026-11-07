# Test brief: dashboard access fixes (password reset, scrolling, multi-origin CORS) and helpdesk scan

- **Date / PRs:** 2026-11-07, PRs 29 (multi-origin deploy), 31 (password reset), 32 (page scrolling)
- **Written by:** Claude Code. **To be run by:** Antigravity. Steps marked *owner-assisted* need the owner.
- **Environment:** staging. Dashboard `https://redhand.archtificial.com` (also `https://redhand-dashboard.vercel.app`);
  core `https://redhand-core-64rxezjt6q-as.a.run.app`; gateway `https://redhand-gateway-64rxezjt6q-as.a.run.app`;
  helpdesk MCP server `https://helpdesk-mcp-825574069297.asia-southeast1.run.app`.
- **Prerequisites:** Vercel production deploy of `main` finished; Supabase Auth Site URL set to
  `https://redhand.archtificial.com` and the redirect URLs `https://redhand.archtificial.com` and `.../**` added.
  Sign-in is owner-assisted. No secrets in this brief or in your results.

## What changed
1. Password reset: login page "Forgot password?" and a `/reset-password` page (`apps/redhand-ui/src/app/reset-password/`,
   `src/lib/passwordReset.ts`, `src/lib/auth.tsx`).
2. Scrolling: a global `overflow: hidden` on `body` was removed; it now applies only to the home view (`globals.css`, `app/page.tsx`).
3. `deploy/cloudrun/deploy.sh` accepts several comma-separated dashboard origins, validated in `deploy/cloudrun/origins.sh`.
4. The helpdesk MCP server (built by Antigravity) is registered in RedHand as `kedai-kita` and was scanned once.

## Already verified by Claude Code
- `node --test tests/` in `apps/redhand-ui`: 3 pass (the recovery-link and password-rule helpers). `npx tsc --noEmit` and `npm run build` pass.
- `uv run pytest tests/deploy`: 24 pass (origin validation and `deploy.sh` against a stub gcloud).
- Local production build in a browser: expired-link message and fragment removal, form shown for a recovery-style link, short
  password rejected; wheel scroll on `/login` with a tall probe element moved the page after the fix and not before.
- Live helpdesk server: `/health` ok; unauthenticated `tools/call`, an unknown tool and the admin endpoint return 401.

## Not verified by Claude Code
The real emailed reset link, the live scrolling of the data pages, a live deploy with two origins, and everything below.

## Steps
| # | Do | Expected | Type |
|---|---|---|---|
| 1 | Open `/reset-password` with no `#...` part | Message: this reset link is invalid or has expired; link to sign in | negative |
| 2 | Open `/reset-password#error=access_denied&error_code=otp_expired` | Same message; the `#...` part disappears from the address bar | negative |
| 3 | `/login` -> **Forgot password?** -> enter an email that has no account -> **Send reset link** | A neutral message ("If an account exists..."), no error that reveals the account status | abuse |
| 4 | Same as 3 with the owner's real email (*owner-assisted*) | The identical neutral message; an email arrives | normal |
| 5 | Open the emailed link once, in the same browser (*owner-assisted*) | Set-password form shows; address bar has no tokens after load (`location.hash` is empty) | normal |
| 6 | Submit a password under 12 characters; then two different passwords | Each is rejected with a clear message; nothing is changed | negative |
| 7 | Submit a valid new password (12+ characters, matching) (*owner-assisted; do not record it*) | "password was changed" message; link to sign in | normal |
| 8 | Open the same email link again | Invalid or expired message | abuse |
| 9 | Sign in with the new password (*owner-assisted*) | Reaches `/passports` | normal |
| 10 | Check browser storage after step 9 | No recovery token stored; only the normal `redhand.operator.session` entry | abuse |
| 11 | On `/passports`, `/blackbox`, `/scanner`, `/honeytokens` (signed in): scroll with the mouse wheel; repeat in mobile emulation with touch | Each page scrolls to the bottom; the `/scanner` results table is fully reachable | normal |
| 12 | Open `/` (home view) | Layout fits the window, the page itself does not scroll, inner panels still work | regression |
| 13 | CORS: for each origin in {`https://redhand.archtificial.com`, `https://redhand-dashboard.vercel.app`}, send `OPTIONS` to core `/v1/passports` and gateway `/health` with `Origin` and `Access-Control-Request-Method: GET` | `access-control-allow-origin` echoes that origin on both services | normal |
| 14 | Same as 13 with `Origin: https://evil.example.com` | No `access-control-allow-origin` header | abuse |
| 15 | Scanner page: find `kedai-kita`, run **Scan now** | Verdict WARN; 6 tools scanned; only low findings, all MCP-SEC-008 (unbounded string fields); no high findings | normal |
| 16 | After the helpdesk schemas gain `maxLength` or `pattern` and are redeployed: rescan | Fewer or no MCP-SEC-008 findings; a lower risk score than the first scan | regression |

## Out of scope
Production, real customer data, creating or resetting accounts yourself, changing Supabase or Cloud Run settings, and the
helpdesk agent's n8n/Telegram flow (covered by its own project). Do not run `deploy.sh`.

## Follow-up
(Claude Code fills in after reading the result.)
