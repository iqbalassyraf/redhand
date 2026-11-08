# Plan: Phase 4 M4.5, coverage page, self-test and language badges

Status: PROPOSED (2026-11-08), waiting for the owner's approval. Part of `docs/plans/phase4-m4-plan.md` (section 11, A6 to A8). Split into
two releasable pieces (M4.5a, M4.5b) so each can be reviewed and tested on its own.

## 1. Goal
An owner can see, inside the dashboard, exactly how well the Radar and the other detectors work (including where they do not), and can
press one button to prove the deployed gateway's Radar still behaves as measured. Phase 4 "done" test served: the owner sees honest,
measured detection numbers and a live self-test result, not marketing.

## 2. Current state
- The coverage matrix exists as generated Markdown (`docs/security/coverage-matrix.md`, from `python -m agentwall.src.bench --format markdown`):
  dev results, held-out results, frozen blind rounds 1 and 2, per-language tables, status rules fixed in advance, 95% intervals. A test
  fails if the file differs from a fresh run. It is not in the dashboard. Blind round 3 (Grok, scored 2026-11-08, `docs/security/blind-round-3.md`)
  is not in it yet.
- The gateway image already contains `agentwall/bench/corpus` (the Dockerfile copies the whole `agentwall/` directory, 824 KB), so the
  gateway can run the Radar over the bundled samples without any new packaging.
- Core already calls the gateway for the MCP live scan (`routers/mcp_scan.py`, `GATEWAY_URL`, service token).
- There is no Indonesian or Chinese rule or sample set. Indonesian samples exist only as part of the Malay set (`lang=ms`, `indonesian` in
  the family name). Round 3: Malay and Indonesian injection detection found 4 of 25 (16%).

## 3. Approach
### M4.5a: coverage page and language badges (A7, A8). No backend change.
- `python -m agentwall.src.bench --format ui-json` writes `apps/redhand-ui/public/coverage.json` from the same evaluation that produces the
  Markdown, so the page and the matrix cannot disagree. Frozen blind-round tables move into one data structure in `report.py` (rounds 1, 2
  and now 3) and feed both outputs. A test fails if the committed JSON differs from a fresh run (same pattern as the matrix).
- New page `/coverage` in the dashboard (header link): held-out results first, then dev, then the three frozen blind rounds, each with
  95% intervals, false alarms and the status label, and the families we miss. A plain-language "how to read this" and the limits
  (small, written by us or one outside author, not native-reviewed) sit at the top.
- Language badges: English, Bahasa Malaysia, Indonesian, Simplified Chinese. Each shows **native-reviewed: no** (nobody has reviewed),
  and the measured per-language numbers where samples exist. English and Malay come from the corpus; Indonesian only from blind round 3
  (the samples marked Indonesian in the family name) if they can be separated honestly, else it says "measured together with Malay";
  Chinese says **not covered: no rules, no samples**. No new rules are written for Indonesian or Chinese in this milestone (see section 9).
### M4.5b: security self-test (A6).
- Gateway: `POST /internal/v1/radar/self-test` (service token). Runs the Radar (rules only, as the gateway runs it) over a fixed bundled
  sample set (the held-out injection and output samples, about 160 texts), on a worker thread, and returns counts per category
  (found, false alarms, intervals) plus the ids of misses, never any sample text. Takes no user input at all.
- Core: `POST /v1/radar/self-test` for security operators and above; one run per organization per minute (429 otherwise); calls the gateway
  with the service token and a short timeout, passes the result through, fails with a clear message if the gateway does not answer
  (never a fake result). Audit is not needed: it changes nothing.
- Dashboard: a **Run self-test** button on the Radar page showing the result next to the organization's current switches, with the
  wording: "this proves the Radar code running in the gateway behaves as measured on our samples; it does not prove that your agents'
  traffic goes through the gateway".

Alternatives considered. (1) Running the self-test in core by importing the Radar: rejected, core and gateway are separate services and the
Radar belongs to the gateway; two copies could differ. (2) A "paste your own text to test" box: rejected (plan section 11: free-text
testing is an abuse and cost surface). (3) Rendering the Markdown matrix in the page: rejected, it needs a Markdown library (new dependency)
and cannot be filtered or badged.

## 4. Changes
- `agentwall/src/bench/report.py` (blind-round data structure incl. round 3, `ui-json` renderer), `agentwall/src/bench/__main__.py`
  (new format), `docs/security/coverage-matrix.md` and `agentwall/bench/baseline.json` regenerated, `apps/redhand-ui/public/coverage.json`,
  `apps/redhand-ui/src/app/coverage/page.tsx`, header link on each page, tests.
- M4.5b: `agentwall/src/gateway/selftest.py` and its route in `agentwall/src/main.py`, `services/redhand-core/src/redhand_core/routers/radar.py`
  (one route), `apps/redhand-ui` (button and result), OpenAPI spec regenerated, tests, runbook, threat-model row, changelog.

## 5. Security impact
- M4.5a: none at runtime (static data in the dashboard bundle). The numbers are public-safe: no sample text, only counts and family names.
- M4.5b: a new internal gateway route that runs bounded CPU work. Guards: service token only (like `/metrics`), fixed input, one run per
  organization per minute in core, global concurrency of one in the gateway (a second call while one runs gets 429), at most about 1 s of
  CPU per run, results contain no text. The core route needs a security operator; viewers and other tenants are refused; the result is the
  same for every tenant (it describes code, not data) so there is no cross-tenant leak. Failure never shows made-up numbers.
- Claims: the page and the result carry the limits above; "native-reviewed: no" is explicit for every language.

## 6. Data / migrations
None.

## 7. Tests
- M4.5a: bench tests (JSON equals a fresh run, round 3 numbers equal the frozen record, intervals correct), unit tests for any page helper
  (status labels, interval wording), `tsc`, `next build`, browser check on a local build (every table renders, nothing claims coverage for
  Chinese, a narrow screen works).
- M4.5b: gateway tests (needs the token, returns counts only and never text, concurrency limit, a crash gives an error not numbers), core
  tests (roles, 429 on the second run within a minute, gateway down gives 503 not a result, tenant independence), mutation checks on the
  limits and on "no text in the result", an e2e test through core and gateway, browser check, then a staging brief for Antigravity.

## 8. Cost and performance
No LLM and no new recurring cost. Self-test: about 160 texts at roughly 1 ms per KiB, so about 1 s of one CPU on the gateway, at most once
a minute per organization and one at a time overall. It never runs on the call path.

## 9. Risks and open questions
- **Deviation from the approved scope (D9):** the plan approved on 2026-11-08 said to add Indonesian and Simplified Chinese samples and rules
  as "unreviewed". Round 3 showed Malay and Indonesian injection detection at 16% even with rules written by us, and nobody on the team
  can review Chinese. This plan therefore shows honest badges and measured numbers now and proposes writing new Indonesian and Chinese
  rules only together with independently written blind samples and a native reviewer. **Owner decision needed:** accept this (recommended),
  or build unreviewed Indonesian and Chinese rules now.
- The round 3 record and scorer are uncommitted on branch `docs/blind-round-3`; the coverage page needs them in `main`, so the first commit
  of M4.5a carries them.
- The bundled self-test set is our own held-out set, so a pass shows "behaves as measured", not "catches new attacks".
- Rate limiting in core is in memory per instance (as the other limiters are); fine for one instance, to be revisited with scale-out.
