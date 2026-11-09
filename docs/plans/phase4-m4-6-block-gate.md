# Plan: Phase 4 M4.6, the measured gate for block mode

Status: APPROVED by the owner and BUILT (2026-11-09, not yet committed); see section 10 for what changed while building. Part of `docs/plans/phase4-m4-plan.md` (11.2, 11.6). It changes the approved
design in three places, listed in section 9 for the owner to decide. Two releasable pieces: M4.6a (the gate) and M4.6b (evidence from real traffic).

## 1. Goal
Replace "blocking is not available" with a measured answer, per check: what blocking would need, what we have, and what is missing, computed
from evidence and impossible to pass by editing a label. Phase 4 "done" test served: the owner sees honest, measured detection, and block mode
cannot be switched on until it has been earned.

## 2. Current state
- Block is refused in three places: `control_radar_settings` in SQL (`supabase/migrations/20261117000000_radar_findings.sql`), the core API, and
  the gateway context, which denies any mode other than off or observe (`agentwall/src/gateway/context.py`). The scan is off the call path
  (`agentwall/src/gateway/radar_scan.py`). There is no code that could block.
- `would_block` on a finding means "not low confidence" (`finding_item`). The Radar page reports "9 would have been blocked".
- Frozen independent results live in `BLIND_ROUNDS` (`agentwall/src/bench/report.py`). Nothing in code evaluates a gate.
- There is no count of results scanned per organization. Findings are coalesced (30 s repeat limit in the gateway, 5-minute windows in SQL), so
  `occurrences` counts reports, not calls. A real false alarm rate on an organization's traffic cannot be computed today.

### What I measured for this plan (2026-11-09, local, rules only)
| Check | Latest independent round | Attacks found (95% range) | False alarms (95% range) | Harmless samples / hard |
|---|---|---|---|---|
| Hidden instructions | round 3 (Grok) | 34/94 = 36% (27% to 46%) | 10/146 = 6.8% (up to 12.1%) | 146 / 48 |
| Script and active markup | round 2 (Gemini) | 74/80 = 92.5% (85% to 97%) | 0/120 (up to 3.1%) | 120 / 45 |
| Internal addresses | round 2 (Gemini) | 50/80 = 62.5% (51.5% to 72%) | 3/120 = 2.5% (up to 7.1%) | 120 / 45 |
| Sensitive file paths | round 2 (Gemini) | 51/80 = 63.8% (52.8% to 73%) | 6/120 = 5% (up to 10.5%) | 120 / 45 |

Four further findings:
1. **The approved gate contains an arithmetic error.** 11.2 asks for a 95% upper bound of 3% and says 100 harmless samples with zero or one false
   alarm reach it. On the interval the product uses (Wilson), 100 samples with zero false alarms gives 3.7%, and with one gives 5.5%. Reaching 3%
   needs **125 samples with zero false alarms, 185 with one, 239 with two.** As written, the gate would have let a check through on evidence that does
   not meet its own limit.
2. **No check passes today.** Script and markup is closest, and fails narrowly (3.1% against 3%, 120 samples against 125). I am not rounding that up.
3. **The samples do not look like real tool answers.** None of the 1,256 harmless samples in the bundled set is 2 KiB or longer (the longest is 824
   characters). An ordinary web page with an analytics script and an `onload` raises `RAD-OUT-001` at high confidence, so an agent with a web-fetch tool
   would be refused on most normal pages. The script and markup score therefore says little about real traffic.
4. **An inline scan breaks the speed budget for large results.** A 16 KiB result takes about 16 ms (p50) whichever check is on. The gateway's budget is
   10 ms p50 for everything it adds.

And one matter of principle: a script inside a tool answer cannot run in the model. It is dangerous only if something later renders it in a browser.
So the one check close to passing is also the one where refusing the call helps least, while the check where blocking would matter most (hidden
instructions) is furthest away. At a 7% false alarm rate, an agent reading 50 documents a day would have about 3 or 4 of them refused every day.

## 3. Approach
**Build the gate and start collecting real-traffic evidence. Do not build the block path.** The gateway's enforcement path is the most sensitive code
we have, and adding block logic that no check can use is risk with no benefit (and is speculative code, CLAUDE.md 6.1).

### M4.6a: the gate (no database change, no behaviour change)
A pure function in `agentwall/src/bench/gate.py` decides, per check, from the frozen records. All of these must hold:

| # | Rule | Why |
|---|---|---|
| G1 | Evidence comes from a frozen blind round by an author who is not the rule writer, scored once. Development and our own held-out samples never count. | Our held-out set is not independent (plan section 12). |
| G2 | The round was scored on these exact rules. Each round stores a fingerprint of the rules (a hash of `radar.py`'s parsed code, so comments do not matter). Any change to the rules makes every check "needs re-measuring". | Today a rule edit would silently keep old numbers. |
| G3 | False alarms: 95% upper bound at most 3%, at least 40 hard samples. In practice at least 125 harmless samples. | Corrected 11.2. |
| G4 | Detection: the **lower** end of the 95% range at least 50%. | 11.2 used the point estimate. Stricter, and it changes no result today. |
| G5 (new) | At least 40 of the harmless samples are real-format and at least 2 KiB: full web pages, HTML email, API answers, long documents. | Finding 3 above. |

Output: `--format gate` on the bench, a `block_gate` block in `coverage.json` (a test fails if it differs from a fresh run), and a "Ready to block?"
section on the Coverage page: pass or fail per rule, per check, and what is missing, in plain words.
Safeguard: a constant `BLOCK_ELIGIBLE = frozenset()` must equal the computed result, so a check becoming eligible fails a test and needs a human's
deliberate commit. The test also pins the three existing refusals.
Wording fix: "would have been blocked" becomes "strong findings" and "would be blocked" becomes "strong finding" on the Radar page. Nothing can block,
and the three non-script checks are not near eligibility. The `would_block` API field keeps its name and meaning.

Rounds 2 and 3 get the current fingerprint, with a disclosed note: `radar.py` changed after round 2 by one table row only (`RAD-INJ-012`, commit
`329de7c`), which does not touch the output rules, and it has not changed since. The new real-format count is 0 for rounds 1 and 2 (nothing that long
exists in those samples) and is counted from the record for round 3.

### M4.6b: evidence from real traffic (migration, gateway, core, dashboard)
- **Count what was scanned.** The worker counts, per organization and day: results scanned and dropped per kind, and flagged results per rule, before any
  throttle, and sends totals to core once a minute (`POST /internal/v1/radar/scan-counts`, service token, through the existing `ReportDispatcher`). Numbers
  only: no text, tool name or agent. Sent with the rules fingerprint; if it cannot be computed, the value is `unknown` and that organization is never ready.
- **Readiness, per check, computed in core.** All must hold over the last 7 full days on the current rules: the check stayed on Watch the whole time; at
  least 200 results scanned; every strong finding reviewed; no silence active for that check; no findings lost to the daily cap; under 1% of scans
  dropped; and the false alarm rate has a 95% upper bound of at most 3% (the same test as G3, on the customer's own traffic: at 200 results, at most 1).
- **Counted the hard way.** Findings are grouped, so if even one finding of a rule was marked a false alarm, every result that rule flagged in the window
  counts as a false alarm. A silence cannot hide evidence, because counts are taken in the gateway, before suppressions apply.
- **Radar page: a panel per check** with both halves (our evidence, your traffic), plus the real figure nobody has yet: *flagged results out of results
  scanned on your traffic*. There is no enable button. The API and SQL still refuse block.

### Alternatives considered
1. *Build the block path now behind the gate* (the milestone as first written): rejected. Nothing can use it (section 2), it adds risk to the enforcement
   path, and it would fail the speed budget.
2. *Enable block for script and markup only:* rejected. It fails G3 and G5, and it has the least benefit.
3. *Put the agent in Safe Mode automatically on a finding* (reusing Phase 2): rejected. At 7% false alarms an agent trips after about 15 harmless documents.
4. *Keep the 100-sample number as approved:* rejected. It does not meet its own 3% limit.
5. *Lean on more rules to raise detection:* out of scope. It needs a new blind round to measure.

## 4. Changes
- **M4.6a:** `agentwall/src/bench/gate.py` (new), `report.py` (`BlindRow` real-format count, `BlindRound` fingerprint, `block_gate` in the UI JSON),
  `__main__.py`, regenerated `coverage.json` and `coverage-matrix.md`, `apps/redhand-ui/src/app/coverage/page.tsx`, `src/lib/coverage.ts`, wording in
  `src/app/radar/page.tsx`, tests, ADR 0016 (the gate), update to plan 11.2, `docs/runbooks/bench.md`, changelog.
- **M4.6b:** migration `radar_scan_counts` and `record_radar_scan_counts`, `radar_scan.py` and `settings.py`, `routers/radar.py` and `radar/models.py`, a pure
  `radar/readiness.py`, Radar page panel, OpenAPI regenerated, SQL and unit tests, runbook, threat model, changelog.

## 5. Security impact
- **M4.6a:** none at runtime. Static data; the three refusals stay and are now pinned by a test. No sample text is published, only counts.
- **M4.6b:** one new internal route, service token only, schema-validated, values capped, organization taken from the gateway context and checked in SQL.
  The new table has RLS, is scoped by organization, and holds counts and rule ids only.
- **Abuse:** a hostile tool can raise flagged counts, which only makes that organization look less ready, the safe direction. Faking "ready" needs the
  service token or an admin who marks every finding as real; every review is already audited, and block stays impossible either way.
- **Failure behaviour:** counter or core failure loses or delays counts and never touches a call. Missing or unknown data reads as "not ready" (fail closed).
  Readiness is display only and grants nothing.

## 6. Data and migrations
M4.6a: none. M4.6b: one additive migration, with rollback and SQL tests. Retention 90 days through the existing purge; removed with the tenant. Deploy order
is migration, core, gateway (an older gateway simply sends no counts). No change to the context, so no change to the enforcement path.

## 7. Tests
- **M4.6a:** gate boundaries (124 and 125 samples, 184 and 185 with one false alarm, the 50% lower bound, 39 and 40 hard and real-format); each rule failing alone;
  a changed fingerprint gives "needs re-measuring", and a comment-only edit does not; `BLOCK_ELIGIBLE` matches; our own held-out data never counts; JSON equals a fresh run;
  block still refused by SQL, API and gateway context; `tsc`, build, UI tests, browser check. Mutation checks on every gate rule.
- **M4.6b:** counts accurate and taken before the throttle; a counter error never touches a call; SQL tenant isolation, caps, retention, rollback; readiness cases, each failing alone:
  198 and 200 results, 6 days, one open finding, an active silence, capped findings, a mode change inside the window, a new fingerprint, `unknown`; worst-case counting (one false alarm
  counts all that rule flagged); roles (viewer refused); e2e through gateway and core. A staging brief for Antigravity, bundled with the M4.5b brief as the owner asked.

## 8. Cost and performance
No LLM, no new service, no new dependency. Added call latency: zero (M4.6a has no runtime part; M4.6b adds a counter on the background worker). Storage: at most about 25 small rows per
organization per day, 90 days. Network: at most one small request per organization per minute, only when there is something to send. Per-agent cost: effectively nil.

## 9. Risks and open questions
**Owner decisions:**
- **D12:** correct the gate as in G1 to G5, including the arithmetic (recommended). It is stricter than what was approved.
- **D13:** do not build the block path in M4.6 (recommended). This changes the milestone as written. M4.6 ends with "not earned yet, and here is exactly why".
- **D14:** collect real-traffic counts (M4.6b) now (recommended), or ship M4.6a alone.

**Conditions for any future block path (M4.7, not scheduled):** a check passes G1 to G5 and an organization passes readiness; an inline scan fits the speed budget, measured; a scanner error
in block mode denies the call; a neutral error message (D5); a per-tool exemption; two admins to switch it on; a new ADR; false alarms measured separately for each language we sell in (Malay and
Indonesian are at about 6% on round 3); and at least one human review of the labels, since round 3's are unreviewed.

**Risks:** G5 needs new samples nobody has written, so script and markup cannot pass without a fresh round by an author who is not Gemini or Grok. Passing the gate would still not mean "safe": it means false alarms are low and detection is
above a floor. Real-traffic counts are only as good as the owner's reviewing. Staging traffic is small and test-like, so its figures will say little until real customers run.

**The better next step for hidden instructions is not blocking.** With detection near 4 in 10, the stronger defence is limiting what a hijacked agent can reach: the per-agent destination allowlist (D10, already approved as the first follow-up).
It does not depend on recognising the attack at all.

## 10. Built (2026-11-09): what changed from this plan
Approved as recommended (D12 to D14). Both pieces are built; nothing is committed or deployed. Differences, all recorded in ADR 0016:
1. **Fingerprint is a hash of the whole rules file** (even a comment edit makes evidence stale), not of the parsed code: a parsed hash differs between Python versions, so it could not be pinned.
2. **Reports carry an id and are counted once** (new table `radar_count_reports`): the gateway retries on a timeout, and a report core had already saved would otherwise be counted twice, which flatters the false alarm rate.
3. **The readiness window is the last 7 UTC days including today**, and "no findings lost to the daily cap" is a proxy (no agent produced 1,000 or more findings on one UTC day), because the cap is applied in SQL and not recorded.
4. **Two proof tools were added** at the owner's request ("a test that makes a good proof for real life usage"): `scripts/radar_real_life_proof.py` (staging, real third-party documents through the real gateway, exact count comparison)
   and `scripts/radar_real_documents.py` (local, real long documents). The local run found that all 10 real web pages raise a script flag and that strangers' READMEs trip the hidden-instruction check 12% of the time
   (`docs/security/real-document-replay.md`); a line about it was added to the Coverage page's known gaps.
5. **G5 is measured by length** (2 KiB or more) as the mechanical stand-in for "real format"; whether a long sample is realistic remains a human judgement made when the round is recorded.
Not built (as planned): any block path (M4.7, not scheduled), a rule change, a new blind round, the destination allowlist (D10).
