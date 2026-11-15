# Plan: Phase 4 M7, per-agent destination allowlist

**Status:** DRAFT, awaiting the owner's approval (2026-11-13). Part of `docs/plans/phase4-finish-plan.md` (milestone M7, new done test 11, decisions F-D2 and D10). **Built on top of the M6 branch** (both replace the audit action list and `record_security_findings`); see `docs/plans/phase4-batch-build.md`.

## 1. Goal
An owner can list the hosts an agent may send data to. A tool call whose arguments contain a web address or email address outside that list is recorded (observe) or refused (enforce). The Radar can only watch; this is the one Phase 4 control that can **prevent** data leaving. Serves new done test 11.

## 2. Current state (checked 2026-11-13)
- Nothing inspects destinations in tool-call arguments. Existing guardrails (`agentwall/src/firewall/`) cover SQL, shell and schema. The upstream forwarder's SSRF protection (`DestinationBlockedError`) protects the **gateway's own** requests to the registered MCP server; it does not look at what an agent puts inside arguments.
- The gateway already walks arguments with a bounded scanner (`gateway/honeytokens.py`: 64 KiB of text, 1,000 values, depth 16). This plan uses the same limits.
- Findings, suppressions and the audit list are as in the M6 plan (this plan builds on its widened checks). Findings have no field for a host.
- The agent's passport is the natural owner of the list (`agents` table; scopes are already per agent), and passport control actions are admin only and audited.

## 3. Approach

### 3.1 Extraction (gateway, pure, no I/O, no DNS)
New `agentwall/src/firewall/destinations.py`. For each string in the arguments (values **and** object keys):
- **URLs:** `scheme://authority` for `http`, `https`, `ftp`, `ftps`, `ws`, `wss`, `sftp`; **email addresses** (`local@host`, and `mailto:`).
- **Parser differences are an attack surface**, so one URL yields a *set* of candidate hosts and **every candidate must be allowed**. The authority is read two ways: ending at the first of `/ ? #` (RFC 3986) and also at a backslash (as browsers do). Candidates are the host after the last `@` and after the first `@`, under both readings. `http://good.com\@evil.com` and `http://good.com@evil.com` and `http://evil.com#@good.com` all produce `evil.com` and are flagged.
- **Normalization** (so look-alikes and number tricks cannot slip past): one round of percent-decoding, NFKC, lower case, trailing dots removed, then IDNA to ASCII (stdlib `idna` codec; a host that fails to encode is flagged as unparseable, never allowed); a homograph such as a Cyrillic "o" becomes an `xn--` name and does not match. IPv4 in decimal, hex, octal and short forms (`2130706433`, `0x7f.1`, `0177.0.0.1`) is parsed by our own small function (not the operating system's, which differs by platform) to dotted form; IPv6 is canonicalized with `ipaddress`, and IPv4-mapped IPv6 is folded to IPv4. Ports, schemes, paths and queries are **ignored** (a stated limit: `http` and `https` are the same destination).
- **Bounds:** at most 50 candidate destinations per call; a call with more, or whose arguments exceed the scan budget, is **untracked**: counted in observe, **refused in enforce** (we cannot say it is clean).
- **Not found, and the UI says so:** a destination written as a plain word with no scheme (`evil.com`), one that is encoded (base64), split across fields, built from pieces by the tool, or an address the tool derives itself. The check looks at what the agent wrote in the call, not at what the tool then does.

### 3.2 Matching
- An allowlist entry is one **exact normalized host** (a name or a canonical IP). No wildcards in v1: without a public-suffix list a `*.co.uk` or `*.github.io` entry would allow strangers, and a new dependency needs separate approval (open question 2). Up to **100 entries per agent**.
- A call is allowed only when every candidate host is on the list. Mode `off` (default) does nothing; an empty list in observe flags every destination (useful to learn what an agent talks to), and **enforce needs a non-empty list** (core refuses it), because an empty list would refuse every URL.

### 3.3 Gateway wiring
- Placed after guardrails and before the M6 loop check and Budget Guard, so a refused call consumes nothing.
- **Observe:** a finding (`RAD-DST-001`), the call continues; an extraction error is counted and never changes the decision.
- **Enforce:** refuse with `-32000`, reason `destination_not_allowed`, message "PolicyViolation: this call contains a destination that is not on this agent's allowed list." (no echo of the host, which is attacker-controlled text); BLOCK in the Black Box. **Any unexpected error in enforce denies** (`destination_check_error`). Context missing or malformed denies, as for every context field.
- Finding report: through the M6 `report_finding()` path. The item carries only the **registrable-looking part** of the host (its last two labels, at most 64 characters: a subdomain can carry the stolen data, so it is never stored; for `a.b.co.uk` this keeps `co.uk`, less than ideal but safe) and the count.
- Metrics: `destination_checks_total{outcome=ok|flagged|refused|untracked|error}`, stage timer `destination_check`.

### 3.4 Core
- **Migration** `supabase/migrations/20261121000000_destination_allowlist.sql` (+ rollback):
  - `agents.destination_mode` (`off`, `observe`, `enforce`; default `off`), `destination_mode_changed_at`, `destination_last_alert_at` (own alert cooldown, as in M6).
  - Table `agent_destinations(id, organization_id, agent_id, host, created_by, created_at)`, unique `(agent_id, host)`, host check (lowercase ASCII, 1 to 253 characters, charset), row level security on, service role only, foreign keys cascading from the agent. The 100-entry cap and tenant match are enforced **in the function**, not only in code.
  - `security_findings` and `radar_suppressions`: rule `RAD-(INJ|OUT|LOOP|DST)-nnn`, kind adds `destination`; `security_findings.detail` (nullable, at most 64 characters, the coarse host).
  - Functions (compare and set, idempotent, audited, service role only): `control_destination_add()`, `control_destination_remove()`, `control_destination_mode()`; audit actions `passport.destination_added`, `passport.destination_removed`, `passport.destination_mode_changed`; the audit list widened in full (M6's actions kept).
  - `record_security_findings` replaced again so `destination` honors the agent's mode and its own cooldown.
- **API (new, additive):** `GET /v1/passports/{id}/destinations` (security operator or higher), `POST /v1/passports/{id}/destinations` (admin, `confirm: true` required, because adding a host widens what the agent may reach), `DELETE /v1/passports/{id}/destinations/{entry_id}` (admin, no confirmation: it only narrows), `PUT /v1/passports/{id}/destination-mode` (admin; `enforce` needs `confirm: true`, a non-empty list and the mode the caller saw). Hosts are validated and normalized **in core** before they are stored, with the same rules the gateway applies to a call. Core must not import the gateway (as the SDK must not, for M5b), so the normalizer is a small pure module kept in both places, and a shared vector file is run against both (the same approach as `test_sdk_secret_patterns_in_sync.py`), so a stored host and a host found in a call can never be normalized differently.
- **Context endpoint:** new required fields `destination_mode` and `allowed_destinations` (a list of at most 100 hosts; sent only when the mode is not `off`).
- **Alert text:** "agent X put an address outside its allowed list in a call to tool Y" with the coarse host, and "the call was refused" in enforce mode.
- In-memory twin updated.

### 3.5 Dashboard
Passports detail: an "Allowed destinations" section with the list, an add box with the confirmation tick, remove buttons, and the mode selector (Off, Observe, Enforce) with the plain-words limits from 3.1. Findings from this rule show the coarse host and "add to the allowed list" is **not** offered in v1 (follow-up).

### Alternatives considered
1. *One list per organization.* One agent's needs would widen every agent (finish plan). Rejected.
2. *Wildcard and registrable-domain matching with a public-suffix list.* More convenient, but needs a dependency and invites mistakes with shared hosting suffixes. Deferred.
3. *Resolve DNS and compare IPs.* Slow, an outbound call on the hot path, and rebinding makes it unreliable. Rejected (CLAUDE.md section 4.6).
4. *Use an existing URL library for parsing.* Libraries disagree with each other (that is the attack). The set-of-candidates approach is deliberately stricter than any single parser.
5. *Allow by default when parsing fails.* Rejected; unparseable is flagged and, in enforce, refused.

## 4. Changes
- New: `agentwall/src/firewall/destinations.py`, `services/redhand-core/src/redhand_core/destinations/` (normalizer, models, service), `supabase/migrations/20261121000000_destination_allowlist.sql`, its rollback, `supabase/tests/destination_allowlist_test.sql`, a shared vector file for the two normalizers, `docs/adr/0018-destination-allowlist.md`, `docs/runbooks/destination-allowlist.md`.
- Modified: `gateway/service.py`, `gateway/context.py`, `gateway/metrics.py`, core `routers/agent_auth.py` and a new router, `services/local_rpc.py`, `services/local_store.py`, `apps/redhand-ui` Passports page and `api.ts`, `scripts/latency_baseline.py`, threat model, OpenAPI, coverage text if a row applies, `CHANGELOG.md`, `docs/handoff.md`.
- **No change** to authentication, scopes or the upstream forwarder's own SSRF protection.

## 5. Security impact
- **A new refusal path** (enforce), off by default, per agent. Errors in enforce deny; in observe they only count.
- **Bypass classes handled by tests:** look-alike hosts (`good.com.evil.com`, `evilgood.com`), userinfo, backslash, fragment and percent tricks, trailing dots, case, homographs, IP number forms, IPv6 and mapped forms, scheme case, nested arguments and keys. **Not handled, stated:** bare words, encodings, split values, tool-built destinations, and everything past the scan budget (refused in enforce).
- **Who edits the list:** admin only, confirmation to add, audited with the host and the actor. A hijacked agent cannot reach core. A compromised admin can widen a list; that is visible in the audit log and the dashboard.
- **Data:** hosts are customer data of low sensitivity but real; the allowlist is tenant scoped with row level security and a function-level tenant check; findings keep only a coarse host. The refusal message echoes nothing from the call. Tenant isolation tests: another organization's agent id is refused on every endpoint.
- **Abuse:** regex work is linear and bounded by the same limits as the honeytoken scan; a test sends 64 KiB of near-matches and 1 MiB arguments inside a time limit. Rate limits: the existing core limits apply to the new control endpoints.
- **Threat model:** rows for "exfiltration to an attacker host through tool arguments", "allowlist widened by an insider", "parser differential".

## 6. Data and migrations
Additive, core first then gateway. Rollback deletes the allowlist rows and destination findings and suppressions, drops the new columns and table, and restores the M6 checks and functions. Tested apply, rollback and re-apply.

## 7. Tests (written first)
- **Extractor and matcher (pure, table driven, with a shared vector file also run against core's normalizer):** allowed and refused for every bypass class above; every parser-difference URL; email and `mailto`; IPv4 forms (decimal, hex, octal, short) and IPv6 forms; ports and schemes ignored; unparseable flagged; 51 destinations untracked; oversized arguments untracked; keys scanned; deterministic fuzz with a seeded generator for crashes and runtime.
- **Gateway:** mode off does nothing (a spy); observe records and continues; enforce refuses and consumes no budget and no loop count; enforce with a raising extractor denies; observe with a raising extractor continues; a call with no destinations passes; a call to an allowed host passes; the refusal text contains no part of the host.
- **Core and SQL:** role matrix on every endpoint (viewer, security operator, admin, owner), wrong organization, wrong agent, missing confirmation, 101st entry refused, duplicate entry idempotent, enforce with an empty list refused, enforce conflict on a stale mode, audit rows, normalization of the stored host, rollback.
- **Context compatibility:** a payload without the new fields is refused and the call denied.
- **UI tests:** list, add with confirmation, remove, mode change, the limits wording, hostile host text rendered as text.
- **Mutation checks:** accept the first candidate only, ignore backslash, skip IDNA, skip trailing dot, treat parse failure as allowed, enforce error treated as allow, skip the 100 cap, skip the tenant check. Each must be caught.
- **Full suite, ruff, mypy strict on the new modules, `tsc`, `next build`.**

## 8. Cost and performance
- **Hot path:** mode off adds nothing; otherwise a bounded walk and a few regular expressions over at most 64 KiB, expected well under 1 ms for typical arguments; **measured** with the `destination_check` stage locally and on staging against the 10 ms p50 and 50 ms p99 budgets. No figure claimed until then.
- **Context size:** at most 100 short hosts per agent, sent only when the mode is not `off`.
- **Running cost:** no LLM, no new service, no new dependency (stdlib `idna` codec and `ipaddress`).

## 9. Risks and open questions
1. **Authoring a list blind is hard.** Observe mode shows the coarse host only. A follow-up could offer "add to the allowed list" from a finding with a fuller view; that needs a privacy decision (full hosts in findings) and is not in this plan.
2. **Wildcards and a public-suffix list** are deferred (a dependency needs approval). Without them an agent that uses many subdomains needs many entries (cap 100).
3. **URLs that are not destinations** (a search tool whose query contains a URL, a summarizer given a link to read) will be flagged, and refused in enforce. Hence observe first, and per agent.
4. **Scheme and port are ignored**, so an allowed host on another port or protocol is allowed.
5. The two normalizers (gateway and core) must stay identical; a shared vector test guards it.

## 10. Decisions requested
| | Question | Recommended |
|---|---|---|
| M7-D1 | Exact hosts only in v1, no wildcards, no new dependency | Yes |
| M7-D2 | Ignore scheme and port | Yes |
| M7-D3 | Enforce needs a non-empty list and a confirmation; adding a host needs a confirmation | Yes |
| M7-D4 | Findings keep only the last two labels of a host, in a new `detail` column | Yes |
| M7-D5 | Unparseable or over-budget arguments are refused in enforce | Yes |
| M7-D6 | New endpoints under `/v1/passports/{id}/` as in 3.4 | Yes |
