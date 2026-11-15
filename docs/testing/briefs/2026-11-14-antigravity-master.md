# Master checklist for Antigravity: everything to test, in order

- **Date:** 2026-11-14. **Written by:** Claude Code. **Run by:** Antigravity with the owner. **One branch:** `test/night-1` (a throwaway integration branch that merges PRs 57 to 66; nothing on `main` changes; the owner merges the real PRs one by one afterwards).
- **What this is:** the list of every test that is open, with the file that holds its steps. The steps themselves are **not** copied here: open the file and follow it exactly. Each part stands alone; a failure in one does not stop the others.

## Read first (the owner's rules, they apply to every part)
1. Do **NOT** create sessions as the owner (no admin-API magic links, no minting tokens). Do **NOT** read shell history or look for keys. Do **NOT** deploy anything yourself. Do **NOT** change settings, agents, scopes, hosts or switches that a brief does not name.
2. Never paste a key, token or secret into chat or into a result. Write "set", "worked" or "refused". Keys go only into the terminal, at a hidden prompt.
3. Quote every on-screen text you rely on **exactly, in quotation marks**. Attach a screenshot for every step marked *screenshot*. For terminal steps paste the printed output (it holds no keys or call arguments).
4. Mark a step PASS only if you saw it in this run. If you could not do it, write **NOT RUN** and why. **NOT RUN is not PASS.** Do not write GOOD if any step failed or was not run.
5. List **every change you make** to staging (agents, modes, hosts, silences, switches) and whether you undid it. Claude Code checks your report against the database and corrects it where it does not match: be exact, not optimistic.
6. Both Cloud Run services start at zero instances: the first call after a quiet period is slow. Wait about 10 seconds and retry before calling it a failure.

## Before anything (owner)
| # | What | Why |
|---|---|---|
| 1 | Check out `test/night-1` and note `git rev-parse --short HEAD` (it goes in the report) | Everything below is deployed from it |
| 2 | Look at the **battleground/database** key question separately (compare the last four characters of the key in `battleground/database/db.py` with the OpenAI and Stripe dashboards; revoke it if unsure) | Open since the security review; not part of the test run |
| 3 | Approve the deploy and the two migrations (loop, then destination), in this order: migrations, **core**, then **gateway**, then the dashboard | The gateway denies every call against a core that lacks the new fields |
| 4 | Have the phone with Telegram ready, and the three logins (admin, `iassyraf+operator@gmail.com`, `iassyraf+viewer@gmail.com`) | Parts B, C and D use them |

## The run, in this order
| Part | What it proves | Steps are in | Who |
|---|---|---|---|
| **0** | Migrations applied, core then gateway then dashboard deployed, `smoke.sh` ends "ALL CHECKS PASSED" (13 checks). **If this fails, stop and report.** | `docs/testing/briefs/2026-11-13-night-1.md`, Part 0 | owner, Antigravity watches and records |
| **A** | Tool pinning in enforce mode (Phase 4 done test 4): the unapproved tool is hidden and refused, the operator cannot approve, mode restored | `docs/testing/briefs/2026-11-12-f1b-tool-pin-enforce.md` (all steps, as written) | Antigravity + owner (terminal) |
| **B** | Loop detection (M6): watch, Telegram alert (one per 10 minutes), finding `RAD-LOOP-001`, throttle refuses call 5 and later, refused calls use no budget, Black Box, recovery, exemption, roles, cleanup | night-1 brief, Part B (17 steps) | Antigravity + owner (terminal, phone) |
| **C** | Destination allowlist (M7): host stored in canonical form, watch records, enforce refuses, six bypass attempts all refused, last-host guard, no address text anywhere, roles, cleanup | night-1 brief, Part C (19 steps) | Antigravity + owner (terminal, phone) |
| **D** | Quieter Radar rules (M4.7b) on the deployed gateway: the self-test shows the exact numbers, three documentation pages that the old rules flagged raise no `RAD-INJ-003`, `RAD-INJ-005` or `RAD-OUT-007` finding, the Coverage page says every round needs a new one | night-1 brief, Part D | Antigravity + owner |
| **F** | Regression: smoke run, freeze takes effect within 5 seconds, unfreeze, revoke, the Radar switches unchanged | night-1 brief, Part F | Antigravity + owner |
| **H** | Risk Engine (Phase 4.5 B1), **only if its branch is deployed**: score from trips, one message per event, opt-in freeze acts on the next signal, a person's release is respected, roles | night-1 brief, Part H | Antigravity + owner (terminal, phone) |
| **I** | Behaviour baseline (Phase 4.5 B2), **only if its branch is deployed**: warm-up shown, an older agent's surge shown as watch-only (no score change, no message) | night-1 brief, Part I | Antigravity + owner |
| **J** | Hardening round H1 (budget day, bounded audit chain, faster ingest and context), **only if its branch is deployed**: smoke test, audit verify answer, a refusal flow | night-1 brief, Part J | Antigravity + owner |
| **K** | Hardening round H2 (body limits, pinned upstream connection, one call deadline), **only if its branch is deployed**: oversized bodies refused with 413 on core and gateway, a normal request still works, the real upstream still works with the connection pinned, no startup flag set | night-1 brief, Part K | Antigravity + owner (terminal) |
| **E** | Latency with everything on (four runs; budget p50 at most 10 ms, p99 at most 50 ms). It keeps both services warm, so it goes **last** | night-1 brief, Part E | owner runs, Antigravity pastes |
| **Cleanup** | Every `night-*` and `pin-test` agent revoked, every host removed, every silence removed, loop card back to Watch 20 / 60, services back at minimum 0, no `AGENTWALL_LOOP_DETECTION_ENABLED` or `AGENTWALL_DESTINATION_CHECK_ENABLED` left set, `unset RH_AGENT_KEY RH_INTERNAL_TOKEN` | night-1 brief, Cleanup | everyone |

Already proven on staging and **not** repeated here: the MCP Scanner, the role screens, the second-organization isolation (F1 sweep, 2026-11-12), the system-prompt canary and its roles (M5a, including step 17), the gateway cache fix (2026-11-12 speed runs).

## A separate job: write blind round 4 (do this in its own, clean session)
Round 4 only counts if the writer has seen **nothing** from RedHand.
1. Start a **new** Antigravity session in an empty workspace that has no access to the repository. Use a model that has **not** written a blind round before (**not Gemini, not Grok**). If that is impossible, say which model it was.
2. Give it **only** the text of `docs/testing/briefs/2026-11-13-m4-7b-blind-round-4.md`. It contains the rules, the exact file format and the checker script. Do not give it any other file, rule, earlier round or document.
3. It writes `blind4-injection_indirect.jsonl` (at least 100 attacks and 150 benign texts; English, Bahasa Malaysia, Indonesian) and runs the checker on its own file until there is no `PROBLEM` line.
4. The owner puts the file in `docs/testing/exports/`. **Nobody scores it or runs it through RedHand.** Claude Code scores it once with `scripts/score_blind_round.py` on the final rules and freezes `docs/security/blind-round-4.md`.

## Report back (simple English first)
Write `docs/testing/results/2026-11-14-night-1.md` from `docs/testing/TEMPLATE-result.md`. First line: **GOOD** or **NOT GOOD**, naming every part and step that failed or was not run. Then each part and step PASS, FAIL or NOT RUN with the quoted text, terminal output and screenshot names; the commit hash; the latency numbers from Part E; the list of every change to staging and whether it was undone.

## What Claude Code does with your report
Checks it against the staging database and Cloud Run (audit rows for loop settings, destinations, silences; findings by rule and agent; agent statuses; every mode back to its safe value; services at minimum 0), corrects the result file where it does not match, scores round 4, and then tells the owner which PRs are safe to merge and in what order.

## What this run does not cover
- The attack side of the Radar on staging (DeepWiki returns only its own pages): the self-test and the local tests cover it.
- Anything on production, and the Phase 3 items older than 2026-11-09 that the handoff lists as "not verified": they are not re-run here.
- Real merge order: PR 61 is already merged. PRs 59 and 62 now carry the matching one-line fix in the benchmark script (loop and destination fields), so `main` stays green as they merge. Planned order: 57, 58, 60, 59, 62, 63, 66, 64, 65; Claude Code confirms it after the night report.
