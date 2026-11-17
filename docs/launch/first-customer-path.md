# First customer path

From "a stranger asks for access" to "their agent is protected and they can see it". Each step says who does it, what happens, and **how far it was tested** (2026-11-17, local development stack unless stated; nothing was run on staging or production by Claude Code).

| # | Who | Step | Tested how |
|---|---|---|---|
| 1 | Owner | Issues a single-use **sign-up code** (`scripts/issue_signup_code.py`, valid 1 to 90 days) and sends it privately | core tests, real HTTP against a local core |
| 2 | Customer | Creates an account on the dashboard login page ("Create an account"), confirms their e-mail | UI flow in a real browser against the local core in development mode (e-mail confirmation **not** tested: needs the Supabase project and SMTP) |
| 3 | Customer | Is sent to **/welcome**, enters the organization name and the code; becomes its **owner** | real browser, 22 checks (PR #101) |
| 4 | Owner | Invites teammates on Passports, "Team": a single-use link per person (role up to their own, never owner, 7 days by default); sends it privately | real browser; the link is shown once and the token leaves the address bar |
| 5 | Teammate | Opens the link, signs in or up, presses Accept | real browser (viewer) |
| 6 | Admin | **Registers an agent** (Passports, "Register"): gets its passport and a short-lived-credential key, shown once | core and end-to-end tests (`tests/e2e/test_phase1_done.py`) |
| 7 | Admin | Creates an **SDK key** (Passports, "SDK keys") for the telemetry SDK; shown once | core tests, browser run in an earlier change |
| 8 | Customer's agent | Calls tools **through the gateway** with the agent credential: in-scope calls pass, out-of-scope are refused and logged | e2e tests; real processes in `scripts/revocation_drill.py` |
| 9 | Owner/operator | Sees the agent, its risk, Black Box events and incident view; freezes or revokes it: effective on the next call, measured at about 0.4 s locally (promise: 5 s) | revocation drill (local, 20 trials per action) |
| 10 | Owner | Can **export** their data and **request deletion** (7-day grace) | SQL tests, core tests; no dashboard screens yet (API only) |

## What was not tested (say so if asked)
- Real Supabase sign-up, confirmation e-mail, password reset e-mail.
- Anything on staging or production, real network latency, cold starts, Vercel.
- A real customer. The path has never been walked by someone who is not the builder: do that first (owner checklist, item 17).
- Several organizations per person (not offered), SSO, e-mail invites, open sign-up.

## When something goes wrong during the call
| Symptom | Likely cause | Fix |
|---|---|---|
| "That sign-up code cannot be used" | wrong, used or expired (one answer on purpose) | issue a new code |
| Customer lands on "needs an organization" after sign-in | they have an account but no membership | send them to /welcome with the code, or an invite link |
| "This account already belongs to an organization" | one organization per person | they must use a different account, or leave the first (remove member) |
| Dashboard shows "not a member" or 403 for everything | the organization is marked for deletion, or the membership was removed | check `organizations.deletion_requested_at` and `organization_members` |
| Agent calls refused right after registering | passport frozen or expired, scope not covering the tool, or core slower than 1 s (cold start) | `docs/runbooks/revocation-not-taking-effect.md` and ADR 0028 |
