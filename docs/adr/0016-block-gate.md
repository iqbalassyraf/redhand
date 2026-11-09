# ADR 0016: The block gate (measured evidence before block mode)

**Status:** Accepted (2026-11-09). Phase 4 M4.6. Plan: `docs/plans/phase4-m4-6-block-gate.md`. Corrects the gate in `docs/plans/phase4-m4-plan.md` 11.2
(it is not rewritten; this ADR supersedes the numbers there). Builds on ADR 0015 (the Radar is observe only).

## Context
Plan 11.2 said a check is block-eligible when the 95% upper bound of its false alarm rate is at most 3%, and that 100 harmless samples with zero or one false
alarm reach that. On the interval the product uses (Wilson) they do not: 100 with none gives 3.7%, with one 5.5%. The bound needs 125 with none, 185 with one.
Measured on the frozen independent rounds, no check passes (hidden instructions: 36% found, false alarms up to 12%; script: 92% found but 0 of 120 gives 3.1%; addresses and
paths: false alarms up to 7% and 10%). The harmless samples are all short (longest 824 characters), so none says how a check behaves on a web page or a long document.

## Decision
1. **Build the gate and the evidence, not the block path.** Nothing could use a block path today, it would add risk to the enforcement path, and an inline scan of 16 KiB costs
   about 16 ms against a 10 ms budget. Block mode stays refused in SQL, core and the gateway context; tests pin all three.
2. **The gate** (`agentwall/src/bench/gate.py`) has five rules, all required, per check: G1 independent frozen round (not used to improve the rules); G2 scored on exactly the rules that
   run now (fingerprint, helper model off); G3 false alarm 95% upper bound at most 3% with at least 40 hard harmless samples; G4 detection 95% **lower** bound at least 50%; G5 at least 40
   harmless samples of 2 KiB or more. It reads only the frozen blind rounds, never our own held-out or development samples.
3. **Fingerprint** = SHA-256 of `agentwall/src/firewall/radar.py` (line endings normalised). Any edit, even a comment, makes earlier rounds stale. This is blunt on purpose: a person must
   re-record the evidence, and the hash is the same on every Python version (an AST or token hash is not). The plan said comments would not matter; that was dropped for these reasons.
   Rounds 2 and 3 carry the current fingerprint: round 2 was scored one table row earlier (`RAD-INJ-012`, used only by the helper model), verified with `git diff 52fdfeb HEAD`.
4. **`BLOCK_ELIGIBLE` is an empty constant** that a test compares with the computed result, so a check becoming eligible fails the build until a person edits the line on purpose.
5. **The page says so.** The Coverage page shows the gate per check with plain reasons. The Radar page calls what `would_block` counts "strong findings" (not low confidence); nothing is blocked.

## Alternatives considered
Build the block path behind the gate now (rejected: nothing can use it, risk, speed). Block script and markup first (rejected: fails G3 and G5, and a script cannot run inside the model, so refusing helps
least). Put the agent in Safe Mode on a finding (rejected: at 7% false alarms an agent trips after about 15 harmless documents). An AST fingerprint (rejected: differs across Python versions).

## Consequences
- Editing the rules file invalidates the evidence and regenerates `coverage.json` and the matrix (tests fail until it is regenerated), which is the point.
- G5 cannot pass until someone writes long, realistic harmless samples (a new blind round by an author who is not Gemini or Grok). Passing the gate would still only make a check a candidate.
- Per-organization readiness from real traffic (M4.6b) is display only and grants nothing.

## M4.6b: evidence from real traffic (added 2026-11-09)
The gate above says whether OUR evidence could ever allow blocking. M4.6b adds the other half, which nobody had: a measured false alarm picture on an organization's own traffic.
- **Counts, taken before anything can hide a result.** The gateway counts per organization and check how many results it scanned, lost (queue full, scan error) and flagged (any confidence)
  and flagged strongly, and per rule how many results it flagged, BEFORE its 30-second repeat limit and before core applies suppressions (`agentwall/src/gateway/radar_scan.py`, `ScanCounters`).
  Totals go to core about once a minute (`POST /internal/v1/radar/scan-counts`, service token). Numbers and rule ids only: no text, tool name or agent. Counting is wrapped so a bug in it
  changes no call and loses no finding.
- **When counts are sent.** A timer sends them about once a minute, and they are also sent whenever a finding is reported (so a stored finding is never far ahead of its count) and
  whenever a scan finds a flush overdue. The extra triggers exist because the Cloud Run services are deployed with the default CPU setting, which pauses background timers while no request is
  running (found while building the staging proof: a silent wait could read the metrics before the report was ever sent). The last counts before an idle period can still wait until the next request
  or a clean shutdown (a final flush runs then). Not changed here: switching the services to always-on CPU is a monthly cost and the owner's decision.
- **Each report has an id and is counted once** (`radar_count_reports`, kept 7 days): the gateway retries a report on a timeout, and without an id a report core had already saved would be counted
  twice, which flatters the false alarm rate. An undeliverable report is put back and sent again under a new id.
- **Readiness is judged in core** (`radar/readiness.py`, pure, display only; `GET /v1/radar/readiness`, security operator or above). Over the last 7 UTC days (today included) a check is a *candidate* only if:
  R1 on Watch the whole window; R2 at least 200 results scanned; R3 every strong finding reviewed; R4 no silence was live at any time in the window (a silence hides findings, so even a revoked one counts);
  R5 counts complete (under 1% of results lost, no agent near the daily findings cap, and never more findings stored than the gateway counted for a rule: a gap means counts were lost);
  R6 the same rules ran the whole window (not "unknown", helper model off); R7 false alarms **counted the hard way** have a 95% upper bound of at most 3%.
  "The hard way": if even one strong finding of a rule was marked a false alarm, every result that rule flagged strongly in the window counts as a false alarm. A real attack caught by the same rule
  is counted against it too, so the figure is pessimistic on purpose. Missing or odd data reads as "not ready" (fail closed); unreadable inputs are an error, never a verdict.
- **It grants nothing.** Block mode is still refused by SQL, core and the gateway context; a "candidate" check says only that a person could consider it. The dashboard refuses a readiness answer
  that claims blocking is available.
- **Differences from the plan, decided while building:** (1) the window is the last 7 UTC days including today, not 7 full days; (2) "no findings lost to the daily cap" is a proxy (no agent produced
  1,000 or more findings on one UTC day; the cap is 2,000 per 24 hours), because the cap is applied in SQL and not recorded; (3) the rules fingerprint is a hash of the whole file, so even a comment
  edit makes evidence stale (the plan said comments would not matter); (4) reports carry an id and are de-duplicated (not in the plan).
- **Residual risks:** the final counts before an idle period are delayed until the next request or a clean shutdown (default Cloud Run CPU); counts lost in transit make the rate optimistic, which the R5 gap check catches only when findings arrived but counts did not; the gateway does not count more than 5,000 organizations
  per minute; the per-organization minute limits elsewhere are per core instance. An admin who marks every finding "real" can make R7 look better; every review is audited and nothing is unlocked by it.

## Amendment, 2026-11-09 (M4.7a): the false alarm figure is capped at the strong results

Found on staging in the M4.6 run (`docs/testing/results/2026-11-09-m4-6-block-gate-and-real-life-proof.md`): 36 of 100 results had a strong injection finding, yet the panel said 81 false alarms.
Each rule's own count includes every result that rule flagged, so a document hit by two reviewed rules was in both counts and the sum counted it twice; a check whose review predated per-rule counts added
all of the check's strong results on top.

- **Change:** "counted the hard way" is now `min(sum over reviewed rules, results with a strong finding, results scanned)`. A result is one false alarm however many rules flagged it, so the figure can never
  exceed the results with a strong finding. Nothing else about R7 changes: still a 95% Wilson upper bound of at most 3%.
- **Why this is still safe:** it is still an upper bound on the true number of false alarms, never lower than it. The cap removes only impossible double counting, so it can make R7 easier to pass only
  where the old figure was wrong. The gateway counts `strong` once per result per check (before the repeat limit and suppressions), which is what makes the cap valid.
- **Effect on the staging run:** injection 81 becomes 36 (upper bound 45.8%, not 87.5%); output 6 stays 6. Both are still far above the 3% limit, so no conclusion about blocking changes.
- **Display only, as before.** Nothing is unlocked by this figure.
