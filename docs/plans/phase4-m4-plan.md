# Phase 4 M4 plan: Prompt Injection Radar and output checks

Status: **proposed, awaiting owner approval** (2026-11-07). Refines section 3 and 7 of `docs/plans/phase4-plan.md`; where this
file is more specific, it wins once approved. No code is written until the owner says "approved".

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
Budget: at most 10 ms p50 and 50 ms p99 added (CLAUDE.md section 8). Expected cost is about the honeytoken scanner (under
2 ms at 64 KiB), **an estimate until measured**. Plan: record the gateway overhead histogram (`/metrics`,
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

## Decisions needed from the owner
- **D1 reporters:** first extract one shared background reporter from `trips.py` and `pins.py` (a pure refactor, existing tests
  unchanged, recommended), or add a third copy now and refactor later.
- **D2 switches:** two (injection and output, recommended) or one.
- **D3 helpdesk samples:** use the 8 helpdesk attack tickets as extra held-out samples (needs Antigravity to export them as plain
  JSONL; recommended).
- **D4 UI home:** Radar settings and findings on the Scanner page (recommended) or a new page.
- **D5 block message:** neutral policy-violation error (recommended) or a message naming the finding family.
