# Test brief: the block gate, the readiness panel and the real-life proof (M4.6)

- **Date:** 2026-11-09. **Written by:** Claude Code. **Run by:** Antigravity with the owner, after the migration, then core, then the gateway, then the dashboard (Vercel) are deployed. The owner (or Claude Code on the owner's word) does the deploys; you do not.
- **Standing rules from the owner:** do NOT create sessions as the owner, do NOT read shell history, do NOT deploy anything, do NOT change settings, agents or scopes that this brief does not name. If you need a login, a key or a token, ask the owner and wait. List every change you make to staging, and undo the ones this brief names.
- **Rules about evidence (new, because an earlier report was not trustworthy):** quote every on-screen text you rely on **exactly, in quotation marks**, and attach a screenshot for steps 1, 4, 5, 6 and 9. Do **not** mark a step PASS unless you saw it with your own eyes in this run. If you could not do a step, write NOT RUN and why. Never paste a key or token; paste only numbers.
- **Environment:** dashboard `https://redhand.archtificial.com/radar` and `/coverage`; core and gateway on Cloud Run. Sign-in is owner-assisted. **Nobody else may call through the staging gateway during steps 3 to 5**, otherwise the exact-count proof is spoiled.

## What changed (plain)
1. The **Coverage** page has a new section "Ready to block? Not yet." It shows, for each check, five rules that independent test results must pass before blocking could ever be offered. Today none passes.
2. The **Radar** page has a new panel "Could blocking ever be switched on?" It shows, per check, **your own traffic** over the last 7 days (results scanned, strong findings, false alarms) and seven conditions, next to a summary of our independent tests. It cannot switch anything on.
3. The gateway now counts every result it scans and sends the totals to core about once a minute. This brief proves those counts are exact with real documents.
4. The Radar page says **"strong findings"** (it used to say "would have been blocked"). Nothing is blocked: blocking does not exist.

## Already verified by Claude Code (local only)
Full Python suite, ruff, mypy, `tsc`, `next build`, UI tests, SQL tests on a throwaway PostgreSQL (apply, rollback, re-apply), mutation checks (48 deliberate breakages, all caught), an end-to-end test through the real gateway and real core, and browser runs of both pages (desktop and phone width) against a local core. **Not verified:** anything on staging, a real third-party server, two core instances, real network timing.

## Part A: the real-life proof (the important part)
The proof plays a real agent against the staging gateway and asks a real third-party MCP server (DeepWiki) for the wiki of 120 well-known public repositories. Those are long documents nobody wrote for our tests. Then it checks, with exact numbers, that the gateway scanned every one and that core's numbers match.

| # | Do | Expected (and what a failure looks like) |
|---|---|---|
| 1 | Sign in as a **security operator or higher**, open `/radar`, scroll to **"Could blocking ever be switched on?"**. Write down, for BOTH checks, **"results scanned in the last 7 days"** (the line "... in N results scanned") and the **strong findings** number. Screenshot. These are the *baseline* numbers B | Panel visible, two cards, text "Blocking is not available", each card has "Your traffic, last 7 days", seven conditions and "Our independent tests". FAIL: the panel is missing, shows "not available" for the figures, or any button or option that could enable blocking |
| 2 | **Owner-assisted, admin:** in **Passports**, register a NEW agent named `radar-proof` (framework: custom) with exactly one scope: server `deepwiki`, tool `read_wiki_contents`, access `read`. (If the server `deepwiki` does not exist, register it first as in `docs/runbooks/staging-agent-test.md`.) Copy its agent key into the terminal as `RH_AGENT_KEY` — never into chat | Agent visible with that one scope |
| 3 | **Owner-assisted, in a terminal on the owner's Mac** (keys never in chat): `export RH_AGENT_KEY=...` and `export RH_INTERNAL_TOKEN=...` (the gateway service token, see `docs/runbooks/latency-baseline.md`), then `python3 scripts/radar_real_life_proof.py --calls 120 --out /tmp/radar-proof.json`. It takes about 3 minutes (120 calls, then a 75 second wait for the gateway's one-minute report). Paste the **whole printed output** into the report | The script ends with six lines starting `GOOD`: *every result was scanned*, *nothing was lost*, *counts reached core*, *real long documents were used*, *enough calls to mean something*, *no call failed*, and exit code 0. **If any line says `BAD`, that is the result: report it exactly; do not rerun to make it pass.** If calls fail because DeepWiki does not know some repository, say how many; the proof needs at least 100 results |
| 4 | Back on `/radar`, press **Refresh**. For both checks read the new **"results scanned"** number N. Compute N − B. Screenshot | **N − B equals the number of results received printed by the script (exactly), for BOTH checks.** Also: *Counts are complete* shows **pass**; *Same rules the whole time* shows **pass** with "The same rules ran the whole window"; *Watching the whole time* may say "changed during the window" if the switches were touched in the last 7 days (that is correct, not a failure). FAIL: any difference, even by one |
| 5 | Read and write down, for both checks: **strong findings**, and the line **"False alarms, counted the hard way"** (the number and the 95% upper bound). In **Findings**, open every finding from agent `radar-proof` and mark each **Real** or **False alarm** after looking at the rule explanation (these are public documentation pages, so almost all should be false alarms; a real attack would be a surprise: describe it, do not quote it). Refresh and read the figures again. Screenshot both states | Before reviewing: *Every strong finding reviewed* says "still not reviewed". After reviewing all of them it says "Every strong finding was marked real or a false alarm". The false alarm figure rises when you mark false alarms. **The numbers themselves are the result: report them, good or bad.** Do not expect them to look good |
| 6 | Look for any way to switch blocking on: the two dropdowns, the Save button, the page text. Screenshot the dropdown options open | Only **Watch (record findings)** and **Off**. No Block. The text still says blocking is not available. FAIL: any Block option or any text that says blocking can be enabled |

## Part B: roles, isolation and the other pages

| # | Do | Expected |
|---|---|---|
| 7 | Sign in as a **viewer** and open `/radar`; then (owner-assisted) call `GET /v1/radar/readiness` with the viewer's token | The page says the role cannot see the Radar; the call returns **403** |
| 8 | If a second organization exists (owner-assisted): sign in there and open `/radar` | Its panel shows none of the numbers from steps 3 to 5 (its own scanned count only) |
| 9 | Open `/coverage` (any role). Find **"Ready to block? Not yet."** and the **"Known gaps"** list. Quote the first two lines of the Known gaps and the reason lines for **"Script and active markup"** | The section lists five rules; every check shows "not yet" overall; script and markup passes the *Independent evidence*, *Measured on these rules* and *Catches enough* rules and fails *False alarms low enough* (0 of 120, upper bound 3.1%, limit 3.0%) and the long-samples rule. Known gaps include a line about 10 of 10 real web pages and 186 READMEs |
| 10 | Narrow screen (375 px wide) on `/radar` and `/coverage` | No sideways page scroll; text readable |
| 11 | Call core's counts route with no token: `POST https://redhand-core-64rxezjt6q-as.a.run.app/internal/v1/radar/scan-counts` with the body `{}` and no `Authorization` header | **401** (or 403), nothing stored. (Only the gateway, with the service token, may send counts.) |

## Part C: cleanup and report
| # | Do | Expected |
|---|---|---|
| 12 | **Owner:** revoke the `radar-proof` agent in Passports. Leave the Radar switches on **Watch** for both checks | Agent shows revoked; the switches still say Watch |

## Out of scope
Blocking (does not exist), changing any rule, production, deploying anything yourself, the helper model.

## Report back (simple English first)
Start with one line: **GOOD** (every step passed and the counts matched exactly) or **NOT GOOD** (and which step failed). Then for each step: PASS, FAIL or NOT RUN, with the exact quoted text and numbers, and the screenshots named. For step 3 paste the script output. For step 5 write the strong-finding numbers and the false alarm figures before and after your review. List every change you made to staging and whether it was undone.

## How Claude Code will check your report
Claude Code compares your numbers with the staging database (the counts tables and the audit log) before accepting any claim, and reads any "PASS" that has no quoted text or screenshot as NOT RUN.
