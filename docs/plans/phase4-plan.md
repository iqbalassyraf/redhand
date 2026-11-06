# Phase 4 plan: "Check inputs"

**Status:** Approved by the owner as recommended (2026-11-06), with the model-proxy work (Phase 4.5) planned
separately. Supersedes the draft written by a cloud session earlier the same day (see the table in section 2).

**Goal:** before an agent trusts a tool or a tool's output, RedHand checks it with deterministic rules, tells the
owner what it found, and publishes measured detection and false-alarm rates, at almost no cost per agent.

**Product truth (shown in the UI and docs):** RedHand only checks what flows through the RedHand gateway, or what
an owner submits to the scanner. It does not see user prompts, or anything the agent reads elsewhere.

## 1. Done tests
1. **Measured coverage:** `redhand bench` prints detection and false-alarm rates per category; the coverage table
   is generated from that run, not written by hand.
2. **Scanner:** a poisoned manifest (hidden instructions in a description, exfiltration text, shell execution, a
   missing schema) returns findings with severities. A clean manifest passes.
3. **Live server scan:** an admin scans a registered server from the dashboard. Addresses that fail the gateway's
   destination check are refused.
4. **Tool pinning:** when a server changes an approved tool's description, the owner is alerted. In enforce mode the
   tool is hidden and refused until re-approved.
5. **Radar:** a tool result with an injection (English or Malay, or hidden in invisible Unicode) is recorded and
   alerted. In block mode it never reaches the agent. A benign result passes.
6. **Output checks:** script tags, image-based data exfiltration and private or metadata addresses in a result are
   flagged. A normal URL is not.
7. **Canary:** a marker in a system prompt that later appears in a tool call or result trips an alert.
8. **Secrets in prompts:** `redhand scan` reports a credential in a prompt or config file, with file and line in
   SARIF, without printing the value.
9. **Loop detection:** an agent repeating the same call past the limit is flagged or throttled, and the owner is
   alerted.
10. **Fail behaviour:** in block mode a scanner error denies. In observe mode it never changes the decision, and the
    error is counted.

## 2. Current state, and where this differs from the cloud draft

| What | Where | Gap |
|---|---|---|
| Manifest audit | `agentwall/src/firewall/mcp_vetting.py`, `POST /v1/mcp/vet` | Flags risky tools and schemas; does not check descriptions for hidden instructions; fetches nothing |
| Egress redaction | `EgressTaintGuardrail` in `ast_guardrails.py` | Secrets and one metadata URL only |
| `tools/list` and result hooks | `gateway/service.py` | Descriptions pass through unchecked |
| Destination check | `check_destination` in `gateway/upstream.py` | Reusable for live scans |
| Trips and alerts | `gateway/trips.py`, `honeytokens/service.py` | Reusable pattern for findings |
| SDK firewall | `redhand_sdk/firewall/engine.py` | Tier 1 "ONNX" silently falls back to a lexical stub that reported itself as the model (fixed in M0) |
| `redhand scan` / `fuzz` | SDK | Python code only; fuzz is a synthetic benchmark, not a labelled set |

| The cloud draft said | Problem | This plan |
|---|---|---|
| Honeytokens are not built, so canaries wait | They are live | Canaries are a small add-on (M5) |
| Refuse calls naming an unapproved model | `tools/call` carries no model name; trivially bypassed, and it would claim more than it does | Deferred to the proxy decision |
| Refuse documents the principal cannot read | The gateway does not know the end user or document permissions | Deferred |
| Resolve URLs in results, then check them | A DNS lookup on the decision path breaks the lean hot path | IP literals and known hosts only |
| Redact or block on matches by default | Docs and logs legitimately contain `../` and HTML | Observe by default; block is opt-in |
| Reuse `security_events` | Old table with unredacted payload columns | New table, same event names |
| Ship a local ONNX model | Model size and CPU on scale-to-zero Cloud Run are unmeasured | Deferred |
| (not covered) | A tool changing after approval ("rug pull") | Tool pinning (M3) |
| (not covered) | The market is Malaysia; English-only rules miss Malay attacks | Malay rules from M1 |

## 3. Approach
- **M0 Foundations.** Land these plans; make the SDK report its stub honestly; scan tool NAMES and argument KEYS
  for honeytokens and keep bait out of events, logs and trip reports.
- **M1 Measurement first.** A labelled corpus (English and Malay; benign samples include hard cases such as articles
  about prompt injection) and `redhand bench` with per-category detection and false-alarm rates and a generated
  coverage table with a "not covered" column. CI fails if a rule change makes results worse. A rule set is offered for
  block mode only at 1% false alarms or lower on the benign set. A corpus we wrote ourselves flatters us; the output
  says so.
- **M2 MCP Scanner.** Description rules (hidden instructions, "do not tell the user", cross-tool references,
  exfiltration wording, invisible characters, oversized text). Live scan of REGISTERED servers only, run by the
  gateway through its existing destination check. Dashboard page; scanned text renders as plain text. (Rejected:
  scanning any URL from the public endpoint: an open fetcher.)
- **M3 Tool pinning.** The gateway hashes each tool's name, description and schema on `tools/list` and compares to
  the approved hashes in its context; new or changed tools are reported to core, and the owner approves or rejects
  them. Per server: off, alert (default), enforce (hide and refuse). Fires only when an agent lists tools; cannot see a
  tool that behaves differently under an unchanged description.
- **M4 Radar and output checks.** `agentwall/src/firewall/radar.py`: pure, no I/O, bounded (64 KiB, 1,000 values,
  depth 16), Unicode-normalised. Injection rules (override, fake role markers, tool-call smuggling, exfiltration
  requests, invisible text, encoded blocks) and output rules (script tags and handlers, `javascript:` links,
  image-based exfiltration, private and metadata addresses, sensitive path traversal). Modes per organization: off,
  observe (default), block; never redaction. Findings carry a fixed rule id; matched text is never stored or alerted.
  Rules catch known patterns; a rephrased attack gets through, and the UI says so.
- **M5 Canaries and secret scanning.** A `canary` honeytoken kind with a dashboard preset; `redhand scan` reads
  prompt and config files and reports file, line and type, never the value.
- **M6 Loop detection.** A bounded in-memory counter per gateway instance (same agent, tool and arguments, N times
  in T seconds); observe or throttle; approximate with several instances (like Budget Guard).
- **Deferred:** model and provider allowlist, document permission checks, RAG ingest endpoint, ONNX classifier,
  per-user limits, scheduled re-scans, the model proxy (Phase 4.5).

## 4. Security impact
New boundaries: gateway to registered servers for live scans; internal gateway-to-core finding and pin reports
(service token, validated, size-capped, every claim re-checked in SQL). Tool descriptions and results are untrusted
and may attack whoever reads them: they render as plain text, never enter alerts, and are size-capped. Regex denial
of service is handled by bounded input, reviewed rules and timing tests on adversarial strings. Block mode fails
closed on a scanner error; observe mode never changes the decision. Missing context fields deny. "Mapped to OWASP",
never "compliant".

## 5. Data and migrations
Additive, each with a rollback and SQL tests: `security_findings` (no matched text; 90 days), `mcp_tool_pins`
(capped), settings columns and audited control functions, the `canary` kind, new audit actions. Deploy order:
migration, core, gateway.

## 6. Cost and performance
Budget: at most 10 ms p50 added, measured before and after. Radar is expected to cost about the honeytoken scanner
(under 2 ms at 64 KiB; an estimate until measured). Context growth of up to about 13 KB for a 200-tool server is a
risk to measure. No LLM calls, no new services, no new dependencies.

## 7. Milestones
| | Milestone | Done tests |
|---|---|---|
| M0 | Foundations | n/a |
| M1 | Measurement | 1 |
| M2 | MCP Scanner | 2, 3 |
| M3 | Tool pinning | 4 |
| M4 | Radar and output checks | 5, 6, 10 |
| M5 | Canary and secret scanning | 7, 8 |
| M6 | Loop detection | 9 |

M0 to M4 are a coherent first release. Each milestone is its own PR with tests and a staging check.

## 8. Decisions (owner approved as recommended, 2026-11-06)
P4-D1 scope M0 to M6, allowlist and permission checks deferred. P4-D2 first release after M4. P4-D3 block mode only at
1% false alarms or lower. P4-D4 Radar default observe. P4-D5 pinning default alert. P4-D6 roles: findings viewable by
security operators; mode changes, approvals and live scans by admins; turning a check off needs confirmation. P4-D7 Malay
rules from M1 (a native speaker should review). P4-D8 no local ONNX model in Phase 4. P4-D9 model proxy stays a
separate plan. P4-D10 write our own corpus first; check licences before adding public datasets.
