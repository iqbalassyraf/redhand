# Phase 4 M4 plan: Prompt Injection Radar and output checks

Status: **approved by the owner as recommended (2026-11-07), decisions D1 to D5 below**. Refines section 3 and 7 of
`docs/plans/phase4-plan.md`; where this file is more specific, it wins.

## 1. Goal
Tool results that carry an injection attack, or output that is dangerous to whatever renders or fetches it, are detected at
the gateway, recorded and alerted without ever storing the matched text, and can optionally be blocked.
Serves Phase 4 done tests **5** (Radar), **6** (output checks) and **10** (fail behaviour).

## 2. Current state
- The gateway already scans every `tools/call` result for honeytokens and redacts secrets (`agentwall/src/gateway/service.py`
  lines 294 to 340, `honeytokens.py`, `firewall/ast_guardrails.py`). There is no injection or output detection.
- Measured baseline (`docs/security/coverage-matrix.md`, `agentwall/bench/baseline.json`): indirect injection 0 of 28,
  output path 0 of 20, output XSS 0 of 20, output SSRF 7 of 20, with 0 false alarms. Only `tool_poisoning` has a held-out
  set. The injection and output categories have dev samples only (52, 40, 40 and 40 lines).
- Context from core is strict and fails closed on missing fields (`gateway/context.py`). Two background reporters exist
  (`trips.py`, `pins.py`), nearly identical.
- Org settings follow the `payload_capture_enabled` pattern: a column, a compare-and-set `control_*` SQL function,
  an audit action, `SecurityOperatorDep` / `AdminDep` in core.
- The Black Box event `reasons` field carries free-form strings for everything except honeytraps (known follow-up).

## 3. Approach
**Radar and output checks are deterministic rules in one pure module**, `agentwall/src/firewall/radar.py`: no I/O, no model,
bounded work (64 KiB, 1,000 values, depth 16, the same budget as the honeytoken scanner), Unicode-normalised (NFKC), compiled
regexes reviewed for backtracking.

- **Injection families (results):** instruction override, fake role or system markers, tool-call smuggling, exfiltration
  requests, concealment ("do not tell the user"), invisible or tag-character text, and encoded blocks (base64 or hex, decoded
  one level, each blob capped at 4 KiB, at most 8 blobs per result). English and Malay from the start.
- **Output families (results):** script tags and event-handler attributes, `javascript:` and `data:` URLs, image-based
  exfiltration (markdown or HTML images whose URL carries query data to an external host), private, loopback, link-local and
  cloud-metadata addresses, and sensitive path traversal.
- **Findings** carry a fixed rule id, family, severity and a coarse location from a fixed vocabulary. The matched text is
  never stored, logged, alerted or returned. Rules catch known patterns; a rephrased attack gets through, and the UI says so.
- **Modes per organization, per kind** (`injection` and `output`): `off`, `observe` (default for both), `block`. Two switches,
  because the two kinds will have different false alarm rates.
- **Block is only real for block-eligible families.** A family is block-eligible only if the committed benchmark shows at most
  1% false alarms on at least 50 benign samples, enforced by a test (decision P4-D3). In `block` mode every other family still
  behaves as `observe`. Block returns the same neutral policy-violation error as the honeytoken path, never the finding.
- **Fail behaviour:** a scanner error in `block` mode denies the result (fail closed); in `observe` it never changes the
  decision and is counted in a metric.
- **Reporting:** the gateway batches findings to core through the existing non-blocking pattern. Core coalesces them to one row
  per agent, rule and 5 minutes with a count, and sends one Telegram alert per agent per window with counts only.

**Alternatives considered**
1. *ONNX or other local classifier:* rejected (P4-D8): new dependency, latency, and an accuracy claim we cannot yet measure.
2. *LLM judge:* rejected: no LLM calls on the hot path, and per-event cost breaks the price model.
3. *Scan asynchronously, observe only:* rejected as the only path: it cannot block. Inline rules are cheap enough to measure.
4. *Detect in the SDK:* rejected: enforcement belongs in the gateway (principle 1).
5. *Third copy of the background reporter:* see decision D1.

## 4. Changes
| Area | Files |
|---|---|
| Rules | `agentwall/src/firewall/radar.py`, `agentwall/tests/test_radar.py` (new) |
| Benchmark | held-out files `*.holdout.jsonl` (ids from 100) for injection and output categories; `bench/detectors.py` (a `radar` detector; each rule family is credited only to its own category) |
| Database | `supabase/migrations/20261117000000_radar_findings.sql`: `security_findings`, org columns `radar_mode` and `output_check_mode`, `record_security_findings`, `control_radar_settings`, audit actions, retention purge, rollback and SQL tests |
| Core | `radar/` models and service, `routers/radar.py` (`GET/PUT /v1/radar/settings`, `GET /v1/findings`), internal `POST /internal/v1/findings`, gateway context fields |
| Gateway | `gateway/service.py` hook after the result is parsed, `gateway/findings.py` reporter, metrics, Black Box reason codes (`radar:<rule>`) |
| Dashboard | Scanner page: runtime findings table and Radar settings panel with the measured numbers and the limits |
| Docs | ADR 0015, threat model, runbook `radar.md`, API spec, changelog, regenerated coverage matrix, test briefs |

## 5. Security impact
- **New boundary:** gateway to core finding reports (service token, schema-validated, size-capped; organization and agent ids
  re-checked in SQL, never trusted from the report).
- **Untrusted text:** results may attack whoever reads findings. Findings contain no result text; the UI renders plain text;
  alerts carry counts and rule names only.
- **Denial of service:** bounded input, bounded decoding, reviewed rules, a timing test on adversarial strings (long repeated
  tokens, near-miss patterns, 64 KiB of invisible characters); findings coalesced and capped per agent so a flood cannot fill the
  table; reporter queue bounded like trips.
- **Tenant isolation:** `organization_id` comes from the gateway context, RLS on the table, included in tenant data deletion
  and export, 90 days retention with a purge.
- **Failure modes:** missing context fields deny; `block` fails closed; `observe` never alters a decision.
- **False assurance:** the dashboard and docs state that these are known-pattern rules, show the measured detection and false
  alarm rates, and never say "protected from prompt injection". "Mapped to OWASP LLM01 and LLM05", never "compliant".
- **Privacy:** the Black Box already stores redacted payloads only when capture is on; Radar adds no payload storage.

## 6. Data and migrations
Additive only, one migration, deployed in order **migration, core, gateway** (the gateway reads new context fields only the new
core sends, so a wrong order denies everything). Rollback file removes the table, columns, functions and audit actions;
tested in the SQL harness. Turning a check off and enabling block need confirmation; every settings change is audited.

## 7. Tests
- **Rules:** each rule has caught, benign and hard-benign samples; English, Malay, invisible text, encoded blocks.
- **Benchmark:** held-out written before any rule; rules tuned on dev only; the held-out numbers reported, and any rule change
  after seeing held-out results disclosed (as in M2). The matrix is regenerated, not hand-edited.
- **Gateway:** modes off, observe and block; `block` fails closed on a scanner error; `observe` never changes the decision;
  block-eligible versus other families; the neutral error never leaks a rule; honeytoken and secret redaction unchanged.
- **Core and SQL:** roles (viewer, operator, admin), wrong tenant, forged report claims, coalescing and caps, audit rows,
  confirmation required, retention, tenant deletion.
- **End to end:** done tests 5, 6 and 10 in-process (`tests/e2e/test_phase4_radar.py`), and a staging brief for Antigravity.
- **Mutation checks** on each gate, as before. The existing suite must stay green; no existing test is changed without being
  called out.

## 8. Cost and performance
Budget: at most 10 ms p50 and 50 ms p99 added (CLAUDE.md section 8). The first estimate (under 2 ms at 64 KiB) was **wrong**: measured
in M4.1 it is about 0.8 ms per KiB (see section 12), so the scan budget is 16 KiB. Plan: record the gateway overhead histogram (`/metrics`,
`redhand_gateway_overhead_ms`) on staging before M4.3 and again after; add a local timing test with a loose bound. Context
grows by two small fields. Storage: coalesced rows, 90 days. No LLM calls, no new services, no new dependencies. Per-agent
running cost is expected to be negligible; Telegram alerts are rate limited.

## 9. Milestones (one PR each; a staging test per the cadence in `docs/testing/README.md`)
| | Work | Staging test |
|---|---|---|
| M4.0 | Held-out samples for injection and output categories (plus the helpdesk attack tickets, converted by Antigravity); staging latency baseline | no |
| M4.1 | `radar.py`, unit tests, bench detector, measured numbers (no gateway change) | no |
| M4.2 | Migration, core endpoints, SQL tests | no (deployed with M4.3) |
| M4.3 | Gateway integration, reporter, metrics, e2e tests; deploy migration, core, gateway | **yes** (brief 1) |
| M4.4 | Dashboard findings and settings, ADR, runbook, threat model | **yes** (brief 2) |

## 10. Risks and open questions
- Held-out quality: it is only worth as much as its independence. The helpdesk tickets help because Antigravity wrote them
  without seeing the rules.
- Malay rules still need a native speaker's review (P4-D7).
- Observe mode can create alert noise; coalescing and per-window alerts limit it, and thresholds are tunable.
- Results can be large or streamed; non-text content (images, blobs) is skipped, and the skip is counted and shown.
- Honest ceiling: the benchmark may show "partial" for injection even after M4. That is a result, not a failure to hide.

## Decisions (owner approved as recommended, 2026-11-07)
D1 extract one shared background reporter first. D2 two switches. D3 use the helpdesk attack tickets as held-out samples.
D4 Scanner page. D5 neutral block message. The options considered:

- **D1 reporters:** first extract one shared background reporter from `trips.py` and `pins.py` (a pure refactor, existing tests
  unchanged, recommended), or add a third copy now and refactor later.
- **D2 switches:** two (injection and output, recommended) or one.
- **D3 helpdesk samples:** use the 8 helpdesk attack tickets as extra held-out samples (needs Antigravity to export them as plain
  JSONL; recommended).
- **D4 UI home:** Radar settings and findings on the Scanner page (recommended) or a new page.
- **D5 block message:** neutral policy-violation error (recommended) or a message naming the finding family.

## 11. MVP ambition amendment (owner approved D6 to D10 as recommended, 2026-11-08)

**Owner direction:** the MVP should be advanced enough to impress, built around the idea of honest, measured, explainable
detection. "Impressive" here means things a buyer can check, not bigger claims. We still never say "protected from prompt
injection". This section adds to sections 3 to 9; where it conflicts with them (the block gate, the milestone table, the corpus),
this section wins once approved.

### 11.1 What makes it advanced (and credible)
| # | Capability | Why it impresses, and why it stays honest | Cost |
|---|---|---|---|
| A1 | **Layered normalisation and decoding** before any rule: NFKC, zero-width and bidi stripping, Unicode tag characters, homoglyph folding, leetspeak folding, and one bounded level of base64, hex, URL and HTML-entity decoding | Beats the cheap evasions most keyword filters miss; each step's gain is measured on the benchmark and reported | small, bounded |
| A2 | **Context-aware scoring.** A result that tells the agent to call a tool the agent actually holds (names from the passport already in the gateway context), or names a destination, raises confidence; a result that only mentions the idea in prose (an article about prompt injection) does not | Deterministic and cheap, uses data we already have, and attacks the main weakness of pattern filters, false alarms on security documentation | small |
| A3 | **Finding explanations:** rule family, severity, confidence, a plain reason, and what to do next, never the matched text; later also the ATLAS and ATT&CK technique each rule maps to (CTI piece A, `docs/plans/phase4.5-build-plan.md` Part 3) | Operators trust what they can understand | small |
| A4 | **Would-block counters in observe mode:** every finding records whether block mode would have stopped it | Gives each organization its own false alarm evidence before it enables block | small |
| A5 | **"Mark as false alarm" feedback and an expiring suppression** (per agent and rule, admin only, confirmed, audited, never for honeytokens, never for block-eligible families without a second admin) | The product learns from its owners, and the reviewed false alarms become candidate benign samples | medium |
| A6 | **Security self-test:** one button replays a bundled safe sample set through the organization's live settings and shows detection and false alarm rates with confidence intervals and the known misses | A live, repeatable demonstration that cannot be faked; also catches a misconfigured gateway | medium |
| A7 | **Detection coverage page:** the coverage matrix (held-out first, with intervals, per language and per family) generated from the committed baseline | Few vendors publish measured gaps; this is a trust signal and a sales asset | small |
| A8 | **Language coverage badges:** English, Malay, and (new) Indonesian and Simplified Chinese, each marked "native-reviewed: yes or no" | Fits the Southeast Asian market and says plainly what has been reviewed | medium |
| A9 | **Pluggable detector interface** so a measured classifier can be added later without touching the gateway flow | Keeps the door open for 4.5 without building it now (P4-D8 stands) | small |

**Deliberately not in the MVP:** a local ML classifier (P4-D8), an LLM judge (no LLM on the hot path), a free-text "test this
string" box (it would let anyone with access tune an evasion against the live rules; the self-test uses bundled samples only),
and a per-agent destination allowlist for arguments. The allowlist is the strongest defence against exfiltration, but it is a
separate control with its own settings and false alarm profile, so it is recommended as the first follow-up after M4.

### 11.2 The block gate, corrected (replaces "at most 1% false alarms on at least 50 benign samples")
With 50 benign samples and zero false alarms, the true rate could still be 7%; 1% needs about 380 clean benign samples. The new
gate has two parts, both required:
1. **Global:** a rule family is block-eligible only if, on the held-out benign set, its false alarm rate has a 95% upper bound of
   at most 3% (needs at least 100 benign held-out samples, at least 40 of them hard or realistic, with zero or one false alarm) and its detection
   rate on held-out attacks is at least 50%. A test enforces it from the committed baseline.
2. **Per organization:** block can be switched on only after the organization has run observe for at least 7 days or 200 results,
   whichever is later, with every would-block finding reviewed (confirmed or marked false alarm). The settings page shows the
   would-block count and the reviewed false alarm rate.
The stricter 1% upper bound stays the target for calling a family "covered".

### 11.3 Corpus growth plan (replaces nothing; adds M4.0b)
| Source | What it adds | Rule |
|---|---|---|
| Antigravity writes blind samples | Independent authorship (a different model, no sight of the rules): 100 attack and 150 benign samples per category from a brief that contains no rule text | Held-out only; Claude does not read or edit them |
| The 20 helpdesk tickets | Realistic customer text | Already in the M4.0 brief |
| RedHand's own docs and runbooks | Realistic hard benign (security text that quotes attacks) | We own the text |
| Reviewed false alarms from observe mode (A5) | Real-world benign, per organization, opt-in and redacted | Admin review, no matched text stored; only text an owner chooses to contribute |
| Public datasets | Breadth | Only after a licence check (P4-D10); no share-alike or non-commercial licences in the shipped corpus |
| New languages | Indonesian and Simplified Chinese attack and benign sets | Marked "not native-reviewed" until a native speaker checks them |
Targets before block mode is offered for any family: at least 100 benign held-out samples (the 3% upper bound) and a reviewed
plan for reaching about 380 (the 1% bound). Attack coverage is reported as measured, whatever it turns out to be.

### 11.4 Security impact of the additions
- **Suppression weakens a control:** admin only, confirmation, reason, scoped to one agent and one rule, expires (default 30 days),
  audited, listed on the settings page, and cannot target honeytoken checks.
- **Feedback and contributed samples are untrusted input:** schema-validated, size-capped, organization-scoped, rate limited; a
  contributed sample is never added to the shipped corpus without a human review in the repo.
- **Self-test:** admin only, rate limited, bundled samples only, no custom text, results are counts and rule names.
- **Context-aware scoring** reads the tool names already in the gateway context; it adds no new data flow and no new trust.
- **Decoding** is bounded (one level, at most 8 blobs of 4 KiB per result) and timing-tested.

### 11.5 Cost and performance
Added work per result stays inside the plan's budget (target under 2 ms at 64 KiB for the whole Radar, measured before and after).
Decoding is the main extra cost and is capped. Self-test and coverage page are on demand. Storage grows with feedback rows only
(capped per organization). No new services or dependencies.

### 11.6 Revised milestones (each a PR; staging tests per the cadence)
| | Work | Staging test |
|---|---|---|
| M4.0 | Held-out samples (built, PR 36) | latency baseline and helpdesk export (brief written) |
| M4.0b | Blind samples from Antigravity (100 attack, 150 benign per category) and the shared-reporter refactor (D1) | no |
| M4.1 | `radar.py`: rules, A1 normalisation and decoding, A2 context scoring, A3 explanations, A9 interface; measured on dev, reported on held-out | no |
| M4.2 | Migration and core: findings, settings, would-block flag, feedback and suppression, audit actions, SQL tests | with M4.3 |
| M4.3 | Gateway integration, reporter, metrics, e2e | **yes** |
| M4.4 | Dashboard: findings with explanations, settings with would-block evidence, false alarm marking and suppression list | **yes** |
| M4.5 | A6 self-test and A7 coverage page, A8 language badges, Indonesian and Chinese samples and rules (unreviewed badges) | **yes** |
| M4.6 | Block gate (11.2) enforced in code and UI, ADR 0015, runbook, threat model | **yes** |
The owner can stop after M4.4 and still have a working, honest Radar; M4.5 and M4.6 are what make it stand out.

### 11.7 Risks
- More scope means a longer M4. Mitigation: the milestones are independent and each is releasable.
- Rules for Indonesian and Chinese written without a native speaker may be weak; the badge says "not native-reviewed" and the
  benchmark shows the real numbers.
- Sophisticated, adaptive attacks will still get through. The coverage page lists the families we miss.
- Suppression and feedback can be misused by a compromised admin; they are audited, expiring and visible.

### 11.8 Decisions (approved as recommended, 2026-11-08)
- **D6 scope:** include A1 to A9 as above (recommended), or a smaller set.
- **D7 block gate:** the two-part gate in 11.2 (recommended), or a stricter 1% upper bound before any block.
- **D8 corpus:** have Antigravity write the blind samples (recommended), and use only our own docs and licence-checked data.
- **D9 languages:** add Indonesian and Simplified Chinese as unreviewed in M4.5 (recommended), or keep English and Malay only.
- **D10 follow-up:** schedule the per-agent destination allowlist right after M4 (recommended).

## 12. M4.1 results (2026-11-08): the rules module, `agentwall/src/firewall/radar.py`
**What exists:** injection rules (override, persona, fake markers, exfiltration, tool-call smuggling, concealment, disclosure,
authority and urgency, hidden tag characters, encoded blocks, direction controls), output rules (script and handlers, script URLs,
active markup, image exfiltration, internal and metadata addresses, risky schemes and collector services, sensitive paths),
normalisation (NFKC, invisible and lookalike characters, leetspeak digits, one level of base64 and hex, entity and percent decoding),
context-aware confidence (tools the agent holds), fixed-wording findings that never contain the text, and a pluggable
`Detector` interface. No gateway, database or UI change yet (M4.2 to M4.4).

**Held-out results, first run (before any change made after seeing held-out results):** indirect injection 17/20 detected and
1/20 false alarm; path traversal 19/20 and 0/20; SSRF 20/20 and 0/20; XSS 20/20 and 0/20.
**Disclosed change after that run:** the negation guard ("do not ...", "never ...") was not applied to the disclosure, exfiltration
and tool-call rules, so "Do not share your password with anyone, including IT" was flagged. It is now applied. Result after the change:
injection 17/20 and **0/20** false alarms; the others unchanged. Later changes (leetspeak folds digits only, because it was
treating email addresses as leetspeak; a tool shown as `name(args)` is documentation, not a request; the scan budget; speed) came from
this module's own tests and measurements, not from held-out samples.
**Known misses, left as they are (not tuned to):** an instruction to render an image whose address carries data, phrased as an
instruction; "the correct next action is shell_exec with command ..." (no call verb); the Malay inflected verb "memanggil"; the
double-encoded path `..%c0%af..%c0%afetc/shadow`. These are the kind of gap the benchmark exists to show.

**Read these numbers with care.** I wrote the dev samples, the held-out samples and the rules, and I had seen the held-out samples
when I wrote the rules, so the held-out set is **not independent**. With 20 samples per side, a clean result only shows false alarms
below about 16%. The independent evidence will be Antigravity's blind samples (M4.0b) and the helpdesk tickets (M4.0 brief): report
them first, as they arrive, before quoting anything above.

**Measured speed (local, pure Python, one core):**
| Input | Time |
|---|---|
| ordinary prose, 1 KiB / 4 KiB / 16 KiB | p50 0.8 ms / 3.3 ms / 13 ms (p99 1.2 / 4.4 / 15 ms) |
| worst adversarial 16 KiB inputs (unclosed tags, leetspeak, repeated verbs, URL floods) | 12 to 25 ms |
| the same inputs at 64 KiB before the budget cut and the optimisation | up to 380 ms |
**Decision:** a scan reads at most 16 KiB per result (both ends of a larger value, so an appended attack is still seen; an attack
buried in the middle of a larger value is not, and the result says it was truncated). The gateway cost is still to be measured
on staging with the real overhead histogram (M4.3), including the honeytoken and secret scans already on the same path.
