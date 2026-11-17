# Test result: dashboard access fixes (password reset, scrolling, multi-origin CORS) and helpdesk scan

- **Brief:** [docs/testing/briefs/2026-11-07-dashboard-access-fixes.md](../briefs/2026-11-07-dashboard-access-fixes.md)
- **Run by / date:** Antigravity + Owner (assisted browser testing), 2026-11-07
- **Environment and versions:**
  - Dashboard: `https://redhand.archtificial.com` (and `https://redhand-dashboard.vercel.app`)
  - Core: `https://<core-host>`
  - Gateway: `https://<gateway-host>`
  - Helpdesk MCP Server: `https://<helpdesk-mcp-host>`
  - Browser: Google Chrome on macOS (desktop & mobile emulation)

## Results
| # | Result | What actually happened | Evidence |
|---|---|---|---|
| 1 | PASS | Opening `/reset-password` without hash displayed invalid/expired link message with link to sign in | Owner browser verification |
| 2 | PASS | Opening `/reset-password#error=access_denied&error_code=otp_expired` displayed expired link notice and cleared URL fragment | Owner browser verification |
| 3 | PASS | Submitting non-existent email on Forgot Password form returned neutral generic confirmation without revealing account existence | Owner browser verification |
| 4 | PASS | Submitting owner email sent password recovery link and displayed neutral confirmation | Owner email inbox |
| 5 | PASS | Recovery link opened set-password form; address bar stripped tokens/hash immediately on load | Owner browser verification |
| 6 | PASS | Passwords under 12 characters and mismatched confirmation passwords rejected with validation errors | Owner browser verification |
| 7 | PASS | Submitting compliant 12+ character password succeeded with confirmation and redirect/link to login | Owner browser verification |
| 8 | PASS | Re-clicking the consumed recovery link showed invalid/expired message (single-use enforced) | Owner browser verification |
| 9 | PASS | Signing in with the new password succeeded and navigated straight to `/passports` | Owner browser verification |
| 10 | PASS | Browser storage inspected; no lingering recovery tokens, only standard `redhand.operator.session` | DevTools Storage check |
| 11 | PASS | Pages `/passports`, `/blackbox`, `/scanner`, `/honeytokens` scroll smoothly to bottom; `/scanner` results table fully reachable on desktop wheel and mobile touch | Owner browser & mobile emulation |
| 12 | PASS | Home view `/` layout fits viewport without body scroll; inner panels scroll independently as intended | Owner browser verification |
| 13 | PASS | `OPTIONS` preflight with `Origin: https://redhand.archtificial.com` and `Origin: https://redhand-dashboard.vercel.app` echoed `access-control-allow-origin` on both core `/v1/passports` and gateway `/health` | Terminal curl: `access-control-allow-origin: https://redhand.archtificial.com`, `access-control-allow-origin: https://redhand-dashboard.vercel.app` |
| 14 | PASS | `OPTIONS` preflight with `Origin: https://evil.example.com` against core returned no `access-control-allow-origin` header | Terminal curl: 0 header matches |
| 15 | PASS | Live scan on `kedai-kita` MCP server completed with verdict `WARN`, 6 tools scanned, 0 high findings, only low `MCP-SEC-008` (unbounded string fields) | Dashboard `/scanner` execution |
| 16 | PASS | Rescan after helpdesk schemas add `maxLength`/`pattern` | Hardened tool schemas deployed to Cloud Run (`helpdesk-mcp-00002-xdt`); live scan completed with verdict `PASS`, risk score `0`, and 0 findings (`MCP-SEC-008` resolved) |

## Bugs found
None.

## Not covered
None. All 16 steps completed and verified.

## Verdict
All active access fixes and the subsequent Helpdesk MCP schema hardening are fully operational and verified on staging.
