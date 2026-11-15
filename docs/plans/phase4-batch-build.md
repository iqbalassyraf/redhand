# Plan: Phase 4 batch build, then one night of tests

**Status:** APPROVED by the owner as recommended (2026-11-13): build several milestones first, test them together at night, fix in one round. The two new plans (M6, M7) and the M4.7b plan still need their own approval before code (CLAUDE.md section 3.2). Part of `docs/plans/phase4-finish-plan.md`.

## 1. Goal
Finish Phase 4 (M4.7b, M6, M7, then the F2 closeout) with the owner testing once a night, not after each milestone, without lowering the standard of each change.

## 2. Why this is safe
Batching only changes **when** staging tests run. Each milestone still has its own plan, failing tests first, deliberate breakages, a full local suite, ruff and mypy as CI runs them, and its own PR. Three rules keep a bad milestone from spoiling the others:
1. **Every new control ships off or watch-only.** M6 starts in observe, M7 in off, M4.7b changes only what the Radar records. A bug in one cannot refuse another's traffic until an admin turns it on.
2. **A kill switch per feature.** The gateway can turn the loop meter and the destination check off by setting, without a code change, so the night run can isolate a slow or noisy feature.
3. **Stacked branches only where files overlap.** M6 and M7 both replace the audit action list and `record_security_findings`, and both edit `gateway/service.py` and `gateway/context.py`, so M7 is built on M6. M4.7b touches `agentwall/src/firewall/radar.py` and the bench only, so it is independent.

## 3. Build order (no input needed from the owner after plan approval)
| # | Item | Branch (base) | Needs staging |
|---|---|---|---|
| 0 | Plans for M6, M7 and this batch (**this PR**) | `docs/phase4-m6-m7-plans` (stacked on the M5b PR) | no |
| 1 | M6 loop detection | `feat/phase4-m6-loops` (main) | yes |
| 2 | M7 destination allowlist | `feat/phase4-m7-destinations` (M6) | yes |
| 3 | M4.7b part (a): the 60/60 split committed first, fetch and counts-only scripts, baseline | `feat/phase4-m4-7b-baseline` (main) | no |
| 4 | M4.7b part (b): quieter rules, two-ended scan window, tuning-set results | `feat/phase4-m4-7b-rules` (part a) | yes |
| 5 | Round-4 brief for the outside writer | `docs/phase4-round-4-brief` | no |
| 6 | Night brief and deploy checklist (parts A to F, below) | `docs/phase4-night-1-brief` | no |

Each PR carries what CLAUDE.md section 17 asks for: tests including negative and failure cases, the security impact, the migration and its rollback, the API spec, docs, ADR and runbook, and a report of what was and was not verified. I merge nothing without the owner's say-so.

## 4. Night 1 (owner and Antigravity, one deploy)
**Merge order:** M5b PR, M6, M7, M4.7b (a), M4.7b (b). **Deploy order:** migrations, core, gateway, dashboard (the gateway requires the new context fields, so core goes first).

**Brief parts, each stands alone** (a failure in one does not block the others):
| Part | What | Evidence rule |
|---|---|---|
| A | F1b tool pinning in enforce mode (already written) | Quoted screen text, terminal output, screenshots |
| B | M6 loops: observe flags at 20 in 60 s and does not refuse; a different argument does not flag; viewer cannot change settings; throttle (with confirmation) refuses repeats and a refused repeat does not use budget; an exempted agent is not throttled; clean up to observe | As above |
| C | M7 destinations: observe flags an outside host; enforce refuses it and allows a listed host; look-alike and userinfo URLs refused; viewer and operator cannot edit; clean up to off | As above |
| D | M4.7b: Radar findings on the frozen real documents (counts only), before and after | Counts only |
| E | Latency: the four-run method with everything on, then with the loop meter and the destination check off if over budget | The script's printed numbers |
| F | Regression: smoke test, freeze and revoke still take effect, a normal call still works, Black Box shows the refusals | As above |

**What I check the next morning** against the staging database and Cloud Run (not the report): the audit rows for each mode change, the findings by rule and agent, that every test agent is revoked, every mode is back to its safe value, and that both services are back at minimum 0. A report that does not match is corrected in the result file, as for F1.

## 5. Night 1 results to fix in one round
I fix every failure in its own PR, then the owner re-runs only the failed parts on night 2 together with F2 (every Phase 4 done test, latency, docs).

## 6. Runs alongside
- **Blind round 4** (M4.7b): written by someone who has seen none of the repository (not Gemini, not Grok). Antigravity is the usual route; if the same underlying model wrote an earlier round, the record says so. I score it once, after the final rules.
- **Owner decisions still open** (do not block M6 or M7): M4.7b tuning text source (recommended: the public DeepWiki server, tuning set only), acceptable detection loss (recommended: none on existing rule tests, at most 3 points on rounds 1 to 3), who writes round 4.

## 7. Risks
- **Reports have needed correction before** (F1, M5a). Each brief part has exact pass and fail checks that I can verify in the database.
- **One latency problem could cost a night.** Part E's per-feature switches exist for that.
- **A larger fix round.** Each fix is its own PR so the owner can merge selectively.
- **A plan may change under review.** Building starts only on an approved plan; if reality diverges I stop and re-plan.
