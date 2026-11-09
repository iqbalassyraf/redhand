# Plan: finish Phase 4 ("Check inputs")

**Status:** APPROVED by the owner as recommended (2026-11-09), decisions F-D1 to F-D7 below. F0 is in progress; the rest is not built.
Refines `phase4-plan.md` sections 1 and 7 and the follow-up decision D10 in `phase4-m4-plan.md`.

## 1. Goal
Close every Phase 4 done test (`phase4-plan.md` section 1), each one proven on staging or openly re-worded by the owner, and leave
the Radar quiet enough on real documents that an owner keeps it switched on.

## 2. Current state (checked 2026-11-09 against the repo and the staging database)

| Done test | What | State | Evidence or gap |
|---|---|---|---|
| 1 | Measured coverage | **Done** | `python -m agentwall.src.bench`; `test_bench.py` runs in CI and fails on a worse baseline |
| 2 | Scanner, poisoned manifest | Built, **not proven on staging** | `tests/e2e/test_phase4_scanner.py` only; no result file |
| 3 | Live server scan | Built, **not proven on staging** | No result file |
| 4 | Tool pinning | Built, **partly seen on staging** | Audit log: 1 `tool_pin.pending`, 1 `tool_pin.approved`; enforce mode never seen; no result file |
| 5 | Radar catches and records | **Watch half done**; the block half does not exist | M4.3 and M4.6 results |
| 6 | Output checks | **Done** (Watch) | M4.3 and M4.6 results |
| 7 | Canary | **Not started** | Honeytoken kinds are `api_key`, `aws_key`, `password` only |
| 8 | Secrets in prompts | **Not started** | `redhand scan` reads Python only |
| 9 | Loop detection | **Not started** | No code |
| 10 | Fail behaviour | **Watch half done**; the block half does not exist | `_note_scan` and e2e tests |

M0, M1 and the M4 sub-plan are built. Other open items:
- **No staging result** for the M4.5a Coverage brief or the M4.5b self-test brief. The M4.6 run covered part of the Coverage page only.
- **The viewer and second-organization checks have been NOT RUN three times**, because staging has one owner and one organization.
- **Commit `1ec6b63`** (the M4.6 result file) is on the branch, not on `main`.
- **Not built:** the destination allowlist (D10, "right after M4"), and the ATT&CK and ATLAS labels (Phase 4.5 piece A).

### What the M4.6 run really showed (from the staging database)
1. **The 20 "failed" calls were not DeepWiki failing.** The Black Box shows 100 ALLOW then 20 BLOCK, each with "Daily limit of 100
   tool calls reached". Budget Guard stopped them, correctly. The result file's explanation is wrong.
2. **The 11 reviewed findings are correct.** Those are all the `radar-proof` findings. The other unreviewed ones date from 2026-11-08,
   from earlier tests. Findings left open: 6 injection and 1 output.
3. **The "81 false alarms" figure is a display bug that overstates.** `false_alarms_worst_case` adds every rule's strong flags, so a
   document hit by two rules counts twice, and a rule with no per-rule count adds the whole check's strong count (`RAD-INJ-008`, 36).
   It is capped at results scanned; it should be capped at strong results (36 here). It errs on the safe side and is display-only.
4. **The noisiest rule is `RAD-INJ-003` (fake role markers): 48 flagged, 30 strong in 100 documents.** Next are `RAD-INJ-005` (10
   strong) and `RAD-OUT-007` (4 strong). `RAD-OUT-001`, which I named earlier, had 0 strong in this run.
5. **Only the start of each document is read.** All 100 results were marked truncated. `radar.py` keeps the first 16 KiB and the
   average document was about 617 KiB. "100 scanned" means 100 openings of documents.

## 3. Approach, milestones in order (each its own PR and staging check)

| # | Milestone | Done test | Size | Staging test |
|---|---|---|---|---|
| F0 | Paperwork: correct the M4.6 result, land it on `main`, fix stale statuses | - | S | no |
| F1 | Staging sweep of what is built: M2, M3, M4.5a, M4.5b, roles, second organization (**brief written 2026-11-09**: `docs/testing/briefs/2026-11-09-f1-phase4-staging-sweep.md`) | 2, 3, 4 | S (test only) | **yes** |
| M4.7a | Readiness figure fix and proof script reports refusal reasons (**built 2026-11-09**, PR pending) | - | S | with M4.7b |
| M4.7b | Quieter rules, scan window, new blind round | 5, 6 | L | **yes** |
| M5a | Canary (**built 2026-11-09**: `docs/plans/phase4-m5a-canary.md`; brief `docs/testing/briefs/2026-11-09-m5a-canary.md`; staging test pending) | 7 | S to M | **yes** |
| M5b | Secrets in prompts and config files | 8 | M | no (local) |
| M6 | Loop detection | 9 | M | **yes** |
| M7 | Per-agent destination allowlist (D10) | new 11 | L | **yes** |
| F2 | Closeout: every done test re-run, latency, docs | all | S | **yes** |

F1 needs no code, so it runs while M4.7 is built. M5a, M5b, M6 and M7 do not depend on each other.

### M4.7b Quieter rules
- Take the text from a split decided **before** any tuning: the 120 repositories become 60 for tuning and 60 frozen, never opened.
  Third-party text stays out of the repository (P4-D10); only counts and hashes are committed.
- Tighten `RAD-INJ-003`, `RAD-INJ-005` and `RAD-OUT-007` for documentation that merely shows these patterns.
- Scan window: replace "first 16 KiB" with the first and last parts inside the **same** total budget, so CPU does not grow. An attack
  in the middle is still missed, and the page keeps saying so.
- A new Antigravity blind round on unseen samples, sized for the gate: at least 125 harmless, 40 of them hard, 40 of them 2 KiB or
  longer. Any rule change restarts the evidence, because the fingerprint changes.
- The result is reported whatever it is, including any loss in detection.

**Alternatives rejected:** silencing the rules per agent (hides the problem, one customer at a time); raising the scan limit (CPU on
a shared instance, unmeasured); an LLM judge (cost, and P4-D8).

### M5a Canary
A `canary` honeytoken kind with a dashboard preset that gives a line to paste into a system prompt. It uses the existing 24-character
format, so **the gateway needs no change**: its scanner already finds that format by digest. Same trip path, audit and Telegram alert.
Limits shown in the UI: the gateway only sees tool calls and results, so a prompt leaked to a user in chat is not seen, and a
reworded or encoded leak is not caught.

**Alternative rejected:** a visible `RH-CANARY-` prefix (an attacker can strip it; ADR 0012 says no RedHand marker).

### M5b Secrets in prompts and config files
`redhand scan` also reads prompt and config files (`.env`, YAML, JSON, TOML, Markdown, text), prints file, line and type, and **never
the value**, not in the console, SARIF or any fingerprint. Bounded: 1 MiB per file, no symlinks, skips `.git`, `node_modules`, `.venv`.
No new dependency; a test keeps its patterns in step with `EgressTaintGuardrail`, and it is measured on the `secret_leak` corpus.

**Alternative rejected:** importing from `agentwall` (the SDK must install alone).

### M6 Loop detection
A bounded in-memory counter per gateway instance: same agent, tool and arguments, N times in T seconds. Arguments are hashed with a
per-process salt and never stored. Modes per organization: off, **observe (default)**, throttle. Findings reuse `security_findings`
(`RAD-LOOP-001`, kind `loop`) for review, alerts at most once per ten minutes, and retention. Throttled calls are refused before they
use budget. Approximate with several instances, as Budget Guard is. A loop that changes its arguments each time is not caught.

**Alternatives rejected:** counting in Postgres (hot-path latency); a new findings table (duplicates review and alerts).

### M7 Destination allowlist (D10)
Radar cannot block, so this is the one Phase 4 control that can **prevent** data leaving. Per agent: a list of allowed hosts, checked
against URLs and email domains in tool-call **arguments**. Modes: off (default, since an empty list would flag everything), observe,
enforce. No DNS on the hot path. Hosts are normalised (case, punycode, trailing dot, IP forms). Encoded or bare-word destinations are
not caught, and the UI says so. Editing the list is a control action: admin only, audited, idempotent, and adding a host needs explicit
confirmation.

**Alternative rejected:** one list per organization (one agent's needs would widen every agent).

## 4. Changes
- **F0:** `docs/testing/results/2026-11-09-*.md`, `docs/plans/phase4-plan.md`, `docs/briefing.md`, `docs/handoff.md`.
- **F1:** a new brief in `docs/testing/briefs/`, and its result file.
- **M4.7a:** `redhand_core/radar/readiness.py`, `scripts/radar_real_life_proof.py`, tests.
- **M4.7b:** `firewall/radar.py`, `bench/` and corpus, `coverage.json`, coverage matrix, ADR.
- **M5a:** migration, `honeytokens/` in core, `apps/redhand-ui/src/app/honeytokens`, `bench/report.py` (the LLM07 row), ADR 0012 note.
- **M5b:** `redhand_sdk/scanner/secrets.py`, `cli.py`, `sarif.py`, tests.
- **M6:** `gateway/loops.py`, `gateway/service.py`, `gateway/context.py`, migration, core settings, Radar page, metrics, ADR.
- **M7:** `firewall/destinations.py`, `gateway/service.py`, `gateway/context.py`, migration, core control action, Passports page, ADR.
- **All:** threat model, runbooks, OpenAPI, changelog, handoff, as each applies.

## 5. Security impact
- **M6 throttle and M7 enforce are Phase 4's first new ways of refusing a call.** Any unexpected error in those modes denies. In observe
  mode an error never changes the decision and is counted.
- **New limits an attacker will test:** the M6 counter is capped per agent, so one agent cannot push out another's counts. M7 parsing
  is bounded, and arguments over the budget deny in enforce mode.
- **New data:** M6 stores no arguments. M7 findings keep only the registrable part of a host, length-capped, because a subdomain can
  carry stolen data.
- **M5a:** canary values are shown once and stored as digests only, as honeytokens are.
- **M5b:** the value never leaves the scanner's memory.
- **Tenant isolation:** every new query and key is scoped by organization, with wrong-tenant tests.
- **No blocking is added to the Radar.** The gate is unchanged.

## 6. Data and migrations
Each is additive with a tested rollback. Order: migration, core, gateway, dashboard.
- **M5a:** extend the `honeytokens.kind` check with `canary`.
- **M6:** `organizations.loop_mode` and limits; widen the `security_findings` rule and kind checks; audit action.
- **M7:** per-agent allowlist and mode, capped at 100 hosts; audit actions; finding rule `RAD-DST-001`.
Widening a check briefly locks `security_findings`; the table is small and purged at 90 days. Older core versions must ignore the new
kinds, and `radar_summary` and readiness must stay per kind (tested).

## 7. Tests
- **For each authorization rule:** allowed, wrong tenant, wrong role, missing and tampered token.
- **M4.7:** a test that false alarms can never exceed strong results; the blind round; the 60 frozen real documents; no silent loss.
- **M5a:** a canary in arguments and in a result trips; an unrelated 24-character string does not.
- **M5b:** a test that greps console, SARIF and fingerprints for the planted value and finds nothing; a scan of this repository.
- **M6:** N-1 passes, N flags; window expiry with a fake clock; flood of distinct arguments stays bounded; throttle error denies, observe error does not.
- **M7:** allowed and refused hosts; look-alikes, IP forms, punycode, userinfo tricks (`good.com@evil.com`); oversized arguments deny.
- **All:** mutation checks like M4.6, the full suite, and an Antigravity brief with quoted text and screenshots, checked against the database.

## 8. Cost and performance
No LLM calls, no new services, no new dependencies. Storage per agent is negligible (a few rows a day). M6 and M7 add a dictionary
lookup and bounded parsing to the hot path, expected well under 1 ms and **measured before and after** against the 10 ms p50 budget.
M4.7b keeps the Radar's CPU budget unchanged. Per-agent running cost does not change measurably.

## 9. Risks and open questions
- **Quieter rules may catch fewer attacks.** The blind round shows it, and the owner decides whether the trade is worth it.
- **Harmless real documents are assumed harmless.** A sample is reviewed, not all.
- **The gate may still say "not yet" after M4.7b.** That is an acceptable result.
- **Legitimate polling tools may look like loops.** This is why M6 starts in observe mode and is measured first.
- **Malay rules still have no native-speaker review.** It needs a person, and is not blocked by this plan.

### Decisions (owner approved as recommended, 2026-11-09)
| | Question | Decided |
|---|---|---|
| F-D1 | Done tests 5 and 10 mention block mode, which does not exist | Re-word them: Phase 4 closes as Watch only, and block mode waits for the gate |
| F-D2 | Is the allowlist (M7) part of finishing Phase 4? | Yes |
| F-D3 | A canary found in a tool call | Refuse the call and alert, do not freeze |
| F-D4 | Loop limit to start with | 20 identical calls in 60 seconds, observe |
| F-D5 | Target for strong findings on real documents | Under 5% on the frozen 60; the block gate stays at 3% |
| F-D6 | A viewer and a second organization on staging | Yes; the owner creates them |
| F-D7 | ATT&CK and ATLAS labels | Move to the start of Phase 4.5 (needs a licence check first) |

### Not in this plan
Blocking in the Radar, Indonesian and Chinese samples (postponed by the owner), always-on CPU on Cloud Run (a cost decision), running
the UI tests in CI (needs separate approval), and anything in Phase 4.5 or 5.
