# Tonight's checklist (2026-11-17, 7pm): owner + Antigravity

> **Superseded:** do not run this checklist. Its open steps moved to `docs/testing/briefs/2026-11-18-test-day.md`, which also deploys the C1 and D1 changes.

One page, in order, about 30 to 40 minutes. The rules are the same as the night brief: **never paste a key, token or secret into chat; NOT RUN is not PASS;
take a screenshot or copy the on-screen text for every step.** Write the results in a new file, `docs/testing/results/2026-11-17-tonight.md`, using
`docs/testing/results/TEMPLATE-result.md`, plus a `docs/handoff.md` entry, on a branch named `docs/tonight-2026-11-17`. Then tell Claude Code, which will check
the database read-only.

Dashboard: `https://redhand.archtificial.com`. You need the admin, operator (`<operator test account>`) and viewer (`<viewer test account>`) sign-ins, and Telegram on the phone.

## 1. Redeploy core from `main` (5 min)
Main now has the corrected approved-model alert text (#88). There are no new migrations since the last run.
`deploy/cloudrun/deploy.sh core` with the same settings as last night (`DASHBOARD_ORIGIN` as in night brief Part 0). Then run `deploy/cloudrun/smoke.sh <core-url> <gateway-url>`.
**Expected:** it ends with "ALL CHECKS PASSED". Paste the last lines.

## 2. The steps that did not run last night (15 min)
`night-incident`, `night-spend` and `night-model` are revoked now. These steps use agents that still exist or need no agent key. **Do them before step 3**, because steps 2b and 2c use `night-radar`.

| # | Do | Expected (exact on-screen text) |
|---|---|---|
| 2a (N7) | Sign in as **viewer**, open Passports, then **Timeline** on any agent | "Your role cannot see the incident view. Ask an owner or admin to give you the security operator role." and no items |
| 2b (O8) | As **operator**, open `night-radar`'s "Model use today" cell, type `1` under "US dollars per day" and press **Save limit**. Then repeat as **viewer** | Both are refused: "This action requires the 'admin' role or higher." |
| 2c (P8) | As **operator**, on `/radar` "Approved models", type `anthropic/claude-sonnet-5-5` and press **Save approved models** | Refused: "This action requires the 'admin' role or higher." The card still says "Check is off: no list, nothing is flagged." |
| 2d (P5) | As **admin**, on `/radar` set the findings filter to "Model not on the approved list" | One finding for `night-model`: "An agent's SDK reported a model that is not on the approved list." |
| 2e (P6) | Optional: open `night-model`'s Risk box on Passports (if a revoked agent's box opens) | No points from that finding. Claude Code already confirmed this in the database (0 signals), so skipping is fine |

**Moved to the next milestone, not tonight:** N9 (needs a fresh agent with a key and a honeytoken) and P7 (needs model use sent with an SDK key). Wait for C1, which
gives a "Create SDK key" button in the dashboard. Do not make keys by hand in SQL again.

## 3. Clean-up (5 min)
- Revoke `pin-test`, `night-radar` and `night-dest` on Passports. Confirm each dialog. **Expected:** "<name> revoked." and a Telegram message for each.
- Check the Cloud Run gateway and core settings: no variable starting with `AGENTWALL_` and ending `_ENABLED` is set, and minimum instances is 0 on both. Report what you see.
- In the terminal: `unset RH_SDK_KEY RH_CORE RH_AGENT_KEY TOKEN`

## 4. Real-world exposure (owner, 5 min)
The old battleground values in git history looked like a live Stripe key (`sk_live_...`) and an OpenAI key (`sk-proj-...`). In the Stripe and OpenAI dashboards,
compare the last four characters or simply revoke both. Report only "revoked" or "not ours". **Never paste the values.**

## 5. Decisions only you can make (5 min, just reply in chat)
1. **PR #89 (the C1 plan):** merge it, or say what to change. Claude Code is already building to it, assuming admin-only key management.
2. **Dependabot #73 (GitHub Actions):** merge as is, or ask Claude Code to pin each action to a commit SHA first. Also the recreated **#74** (dashboard, without Tailwind 4), if Dependabot made it.
3. **`RAD-INJ-003`:** open it on the staging Radar page and mark it real or false alarm.
4. **Blind round 4:** who writes it (an outside writer, not Gemini or Grok, in a clean session).
5. **CLAUDE.md "Current phase" line:** say "apply" and Claude Code will update it to "Phase 4.5 B1 to B4 merged and staging-tested; C1 (SDK keys) next; B5 gated".

## What Claude Code checks afterwards (read-only)
- Step 2: no new `passport.spend_limit_changed` or `organization.approved_models_changed` rows from the refusals.
- Step 3: `pin-test`, `night-radar` and `night-dest` are revoked.
- The audit rows match the times you report.
