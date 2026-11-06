# Phase 4 plan: "Check inputs"

**Status:** Draft for approval (2026-11-06). No code until approved. Supersedes the one-line roadmap
entry in `docs/briefing.md`. The model proxy that several of these items *could* build on is
deliberately **not** here — it is a separate go/no-go in `docs/plans/phase4.5-model-proxy.md`,
because it changes RedHand's latency, cost and uptime profile in a way the rest of Phase 4 does not.

**Goal:** before an agent acts on something — a tool it is about to install, a tool result it is
about to read, a document about to enter its memory — RedHand checks that input against deterministic
rules and tells the owner what it found, at a cost that stays a small fraction of the per-agent price
(CLAUDE.md §1).

**Product truth (unchanged):** RedHand only checks what flows through the RedHand gateway (and what
an owner submits to a RedHand scanner). It does not see inputs an agent reads outside the gateway.
Every claim in UI, docs and copy says so.

**Cost discipline (the line that shapes this whole phase):** Phase 4 ships **deterministic** checks
— signatures, AST analysis, lookups, allowlists, static scanning. Nothing in Phase 4 calls an
external LLM API on the hot path. One optional **local** classifier tier (an ONNX model, bounded CPU,
no network) is allowed only behind a flag, off by default, with a measured latency/cost budget and
explicit approval (§1). Anything that needs an external model — classifying *user inputs*, scoring
ambiguous prompts with an LLM judge — is deferred to Phase 4.5, gated on the model-proxy decision.

---

## 1. Done tests

Each is measured against the OWASP-mapped test set built in M1, reporting block rate and
false-positive rate per category (not just "it runs").

1. **Measured coverage exists.** `redhand bench` runs the OWASP LLM Top-10 test set (benign +
   malicious per category) and prints block rate and false-positive rate per category; the published
   coverage matrix (covered / partial / not covered) is generated from that run, not hand-written.
2. **Output handling.** A tool result carrying an HTML/JS payload, a private/link-local/metadata URL,
   or a `../` path-traversal string is flagged and redacted/blocked before it reaches the agent; a
   benign result with a normal URL passes. (Extends the existing egress guardrail.)
3. **MCP Scanner.** Submitting a poisoned MCP server manifest (exfiltration in a tool description,
   overbroad tool, missing schema) returns findings with severities; a clean manifest passes. Remote
   manifest URLs are fetched SSRF-safe (scheme allowlist, no private IPs, capped redirects/size).
4. **Supply-chain allowlist.** A `tools/call` naming a model/provider not on the organization's
   approved list is refused and logged; an approved one passes.
5. **Injection Radar (indirect).** A tool result or a document at RAG ingest containing a known
   injection pattern ("ignore previous instructions", tool-call smuggling, invisible-unicode
   directives) raises a `prompt_injection_indirect` finding in the Black Box; a benign document does
   not. Deterministic tier only for the "done" bar; the local-model tier is a measured add-on.
6. **System-prompt canary.** A unique marker planted in an agent's system prompt that later appears
   in a tool argument or result trips exactly like a honeytoken (alert + Black Box event). *(Depends
   on Phase 3 M3 honeytokens shipping first.)*
7. **Secret in prompt/config.** `redhand scan` flags a credential embedded in a system prompt or
   agent config, with file and line, in its SARIF output; a clean config passes.
8. **RAG protection.** A retrieval tool call that would return a document the current principal may
   not read is refused; ingest of a document is scanned before it is stored.
9. **Loop / rate.** An agent calling the same tool in a tight loop past a per-tool-per-window
   threshold is throttled and the owner is alerted; per-user limits apply when a trusted end-user
   identity is present (see §10 open question).

## 2. Current state (what Phase 4 builds on — all already in the repo)

| Capability | Where it is today | What Phase 4 adds |
|---|---|---|
| MCP manifest vetting | `agentwall/src/firewall/mcp_vetting.py` (`MCPServerAuditor.audit_manifest`, `POST /v1/mcp/vet`) — flags exec/filesystem/DB tools, missing schema, permissive `additionalProperties`, unbounded strings | Remote SSRF-safe fetch; skills + package manifests; severity → policy; dashboard surface |
| Output/egress redaction | `agentwall/src/firewall/ast_guardrails.py` `EgressTaintGuardrail` — redacts API keys, private keys, `169.254.169.254`, exfil webhooks | Add HTML/JS (XSS), URL allowlist (SSRF), path-traversal patterns; same recursive scan |
| Argument guardrails | `FirewallPolicyEngine.inspect_arguments` (SQL AST, shell AST, schema) | Injection-pattern signatures as a new guardrail; reuse for RAG ingest text |
| Static scanner | `packages/redhand-sdk/src/redhand_sdk/scanner/` (`ast_checker.py`, `fuzzer.py`, `sarif.py`) — `redhand scan`, SARIF output | Secret-in-prompt rules; prompt/config file types; `redhand bench` for the OWASP set |
| Injection taxonomy | `security_events` enum already has `prompt_injection_direct`, `prompt_injection_indirect`; `detector_tier` documents `tier0_ast`, `tier1_onnx_deberta` | tier0 deterministic detector (ship); tier1 local ONNX (optional, measured) |
| Honeytoken system | **Phase 3 M3 (not yet built)** — generator, per-org digests in gateway context, scanner, trip → alert/freeze | System-prompt canaries are a *second kind of marker* reusing the same scan + trip path |
| Per-agent rate limiting | Budget Guard (Phase 2) — in-gateway counter, daily caps, alerts | Short-window loop detection; per-tool and (conditionally) per-user windows |
| Black Box | Phase 3 — records every decision, reason codes, tamper-evident | New reason codes (`injection`, `output_unsafe`, `provider_denied`, `canary`, `loop`) flow in unchanged |

## 3. Approach (deterministic first; one optional local model; nothing external)

- **M1 — Measurement before features.** Build `redhand bench`: a labelled corpus of benign and
  malicious examples per OWASP LLM Top-10 category, run every Phase 4 check over it, print per-category
  block rate and false-positive rate, and generate the public coverage matrix from the result. This
  lands first so every later milestone reports a real number and we never claim 100%. Doubles as sales
  material and Phase 5 compliance evidence.
- **M2 — Output handling checks.** Extend `EgressTaintGuardrail` with three deterministic detectors:
  HTML/script tags and event-handler attributes (XSS), URLs resolved-then-checked against the same
  private/link-local/metadata rules the upstream forwarder already uses (SSRF), and `../`/absolute
  path-traversal strings. Redact or block per policy; record a reason code. No schema change.
- **M3 — MCP Scanner expansion.** Fetch remote manifests SSRF-safe (reuse the forwarder's destination
  check: scheme allowlist, resolve-then-check, cap redirects and body size). Extend the auditor to
  skills and package manifests. Add a per-organization **approved model/provider allowlist**
  (deterministic check on `tools/call` naming a provider). Dashboard: paste/submit a manifest, see
  findings.
- **M4 — Prompt Injection Radar.** Deterministic **tier0** signature/heuristic detector over tool
  results and RAG-ingest text (reuses the egress scan traversal): known jailbreak phrases, tool-call
  smuggling, invisible/bidi unicode, oversized instruction blocks. Emits `prompt_injection_indirect`
  into the Black Box. **tier1** = an optional local ONNX classifier (the `tier1_onnx_deberta` the
  schema already names): no network, bounded CPU, behind a flag, off by default, shipped only with a
  measured p50/p99 latency and a per-agent cost estimate (§1). *User-input* coverage is **not** here —
  it needs the proxy (Phase 4.5).
- **M5 — Canaries + secret scanning.** System-prompt canaries: plant a unique marker per agent's
  system prompt; reuse the Phase 3 honeytoken digest-in-context + gateway scanner + trip path, with a
  distinct reason code `canary`. Extend `redhand scan` with secret-in-prompt/config rules (SARIF out).
  *(M5 is sequenced after Phase 3 M3 ships, since it reuses that machinery.)*
- **M6 — RAG protection + loop/rate.** Scan documents before ingest (reuse M4 detector); check the
  principal's read access on retrieval tool calls. Extend Budget Guard with a short-window loop
  detector (same tool, same args hash, N in T seconds) and per-tool windows; per-user windows only
  where a trusted end-user identity is available (§10).

### 3.1 Alternatives considered

| Option | Why not (for now) |
|---|---|
| LLM judge for injection on every call | External LLM API per event breaks §1 cost discipline and §4.6 lean hot path. Deterministic tier0 + optional local tier1 first; LLM tier is a Phase 4.5 proxy decision. |
| Classify user inputs in Phase 4 | RedHand does not see user inputs unless it sits in front of the model. That is the proxy. Deferred to 4.5. |
| Build a brand-new scanner service | `redhand scan`/SARIF and `MCPServerAuditor` already exist; extend them. |
| Trust `X-User-*` headers for per-user limits | §5.3: delegated identity headers are untrusted unless cryptographically bound. Per-user limits ship only with a trusted identity path (§10). |
| Hand-write the coverage matrix | Claims discipline (§1): publish measured numbers, generated from `redhand bench`, admitting gaps. |

## 4. Changes (per milestone; each its own PR with tests + staging check)

- **Gateway** (`agentwall/src/firewall/`): new detectors in `ast_guardrails.py` (output handling,
  injection tier0); `mcp_vetting.py` remote fetch + skill/package support; provider allowlist check in
  `gateway/service.py`; optional `injection_onnx.py` (local model, flag-gated); canary scan reuses the
  honeytoken scanner from Phase 3 M3.
- **Core** (`services/redhand-core/`): `routers/mcp_scan.py` (submit/fetch manifests), provider
  allowlist storage + `control_*` function, canary registration reusing honeytoken tables, retrieval
  access check; new reason codes pass through the existing Black Box ingest unchanged.
- **SDK** (`packages/redhand-sdk/`): `redhand bench` command + corpus; secret-in-prompt rules in the
  scanner; SARIF output extended.
- **Dashboard** (`apps/redhand-ui/`): MCP Scanner page, provider allowlist editor, coverage-matrix
  view, canary management, loop/rate settings.
- **Migrations:** approved providers table; canary rows (or extend honeytokens); no change to Black
  Box schema. Each with rollback + SQL tests.
- **Docs:** ADR 0013 (MCP Scanner scope), ADR 0014 (Injection Radar tiers + the local-model cost
  decision), threat model boundaries, runbooks, the public coverage matrix, API spec, changelog.

## 5. Security impact (summary; full section per milestone PR)

New trust boundaries: remote manifest fetch (SSRF-safe, same rules as the upstream forwarder);
RAG-ingest scanning (untrusted document text — size/time bounded, never executed). Fail closed on the
enforcement path (a scanner error denies); fail open for observe-only findings (recorded, never block
silently). Canary and provider-allowlist data are per-tenant, scoped in SQL. The optional local model
runs in-process with no network egress, so it adds no new external dependency or data-exfil path.
Claims discipline: the coverage matrix states what is *not* covered.

## 6. Cost and performance

Deterministic checks are regex/AST/lookup — microseconds to low-ms, within the ≤10 ms p50 budget;
each milestone benchmarks before/after. The optional ONNX tier is the only item with a real compute
cost: it ships only with a measured per-agent cost estimate and stays off by default. No external LLM
API calls, so no per-token cost and no new uptime dependency — that is exactly what Phase 4.5 weighs
separately.

## 7. Milestones

| | Milestone | Done tests | Notes |
|---|---|---|---|
| M1 | OWASP test harness + coverage matrix | 1 | Lands first; measurement before features |
| M2 | Output handling checks | 2 | Extends egress guardrail; no schema change |
| M3 | MCP Scanner expansion + provider allowlist | 3, 4 | SSRF-safe remote fetch |
| M4 | Prompt Injection Radar (tier0; tier1 optional) | 5 | Deterministic ships; local model measured + flag-gated |
| M5 | System-prompt canaries + secret scanning | 6, 7 | **Sequenced after Phase 3 M3 (honeytokens)** |
| M6 | RAG protection + loop/rate limits | 8, 9 | Extends Budget Guard; per-user gated on §10 |

## 8. Risks and open questions

- **D1 — tier1 local model.** Ship the ONNX injection classifier in Phase 4 (flag-gated, measured), or
  hold it entirely for 4.5 alongside the external-model tier? Recommendation: build the tier0
  deterministic detector in Phase 4; prototype tier1 behind a flag and decide on the measured numbers.
- **D2 — per-user rate limits need a trusted end-user identity.** The gateway authenticates the
  *agent*, not the end-user, and `X-User-*` headers are untrusted (§5.3). Options: (a) per-agent and
  per-tool only in Phase 4, defer per-user; (b) add a signed end-user assertion via the SDK. Rec: (a)
  now, (b) with the proxy work in 4.5.
- **D3 — ordering vs Phase 3.** M5 depends on Phase 3 M3 honeytokens. Rec: finish Phase 3 (M2c, M3,
  M4) before starting Phase 4 M5; M1–M4 of Phase 4 have no such dependency and could overlap.
- **D4 — RAG ingest integration.** RedHand sees RAG ingest only if ingest runs through a RedHand path
  (an SDK hook or an ingest-scan endpoint). Which integration point ships first is a customer-shaped
  question; flag for the 5–10 SME validation already open in the briefing.
- **D5 — scope size.** Phase 4 as written is six milestones. If you want it leaner for a first
  sellable cut, M1+M2+M3 (measurement, output handling, MCP Scanner) is a coherent, fully-deterministic
  release; M4–M6 can be Phase 4b.
