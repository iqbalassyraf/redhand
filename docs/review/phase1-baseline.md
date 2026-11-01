# Phase 1 baseline review

**Date:** 2026-11-01
**Scope:** Read-only review of the whole repo against the Phase 1 goal in `CLAUDE.md` §19. No product code was changed.
**Method:** Read the source, ran the existing checks, and ran small probe scripts against the in-process apps (FastAPI `TestClient`) to confirm behavior rather than infer it. The probe scripts live outside the repo.

---

## 1. Verdict in one paragraph

The repo has real, decent building blocks: a SQL/shell guardrail engine, a Supabase schema with organizations, row-level security and an `agents` table that is close to a passport, a HITL state machine and a dashboard. **None of them are connected into a working control point yet, and nothing authenticates its callers.** AgentWall trusts whatever agent ID and user roles the caller sends in headers. Core's control endpoints (quarantine, change allowed tools, approve HITL) are open to anyone and ignore tenancy. Quarantining an agent in core has no effect on AgentWall. Most credential brokering is simulated. Phase 1 is therefore mostly **wiring and hardening existing pieces**, not greenfield. However, the security gaps below must be closed first, because they defeat every Phase 1 "done" test.

---

## 2. Baseline health (commands run)

| Check | Result |
|---|---|
| `uv sync` | OK |
| `uv run pytest -q` | **67 passed**, 1 deprecation warning, 3.5 s |
| `uvx ruff check --isolated --select E9,F .` | 41 findings (34 unused imports, 7 empty f-strings), all auto-fixable. The repo has no explicit ruff rule set, so the "zero new warnings" bar in CLAUDE.md has no defined baseline yet |
| Type-checker (mypy/pyright) | **Not run.** Neither is installed or configured in the repo |
| `apps/redhand-ui`: `npm ci`, `tsc --noEmit`, `npm run build` | All pass |
| `npm run lint` | Not run |

**Not verified:** the Supabase migration was not applied to a real Postgres. Nothing was tested against real AWS/GCP/Azure/Slack. The sidecar, SDK adapters and battleground were skimmed, not exercised.

---

## 3. Critical findings (fix before building Phase 1)

Each one is confirmed by a probe unless marked otherwise.

### C1. AgentWall has no authentication; identity and roles are self-asserted (confirmed)
`agentwall/src/main.py:95-120`: `X-Agent-ID`, `X-Caller-Identity`, `X-User-ID` and `X-User-Roles` are plain request headers with defaults. Nothing proves who is calling.
- **Probe:** a `tools/call` to `execute_sql` with no roles was **blocked**. The same call with the header `X-User-Roles: admin` was **allowed**.
- This is exactly the "delegated identity headers" critical issue that CLAUDE.md §5.3 tells us to report.

### C2. AgentWall returns a fake success when the upstream tool fails (confirmed)
`agentwall/src/proxy/handler.py:241-254`: any exception reaching the upstream returns `{"content": "Successfully simulated execution ...", "simulated": true}` with status 200.
- **Probe:** with no upstream running, an allowed call returned a simulated success.
- This is fail-open and fabricates results to the agent. It also breaks the "claims discipline" rule.

### C3. Core's control and HITL endpoints are unauthenticated and not tenant-scoped (confirmed)
`services/redhand-core/src/redhand_core/routers/state.py` and `routers/hitl.py`.
- **Probe:** an anonymous caller could read the full snapshot (all agents, traces, events, HITL queue) and could `PATCH` an agent's posture to `allowed_tools: ["*"]` (HTTP 200).
- The snapshot query has no `organization_id` filter, so with a real Supabase backend it would return every tenant's data. Core uses the service-role key, which **bypasses** the row-level security defined in the migration.

### C4. Four-eyes approval can be satisfied by one anonymous caller (confirmed)
`routers/hitl.py`: the reviewer's identity is the `reviewer_user_id` field in the request body.
- **Probe:** posting two approvals with two made-up UUIDs moved the pending intervention past its two-signature requirement. The resume webhook then fired; it failed only because nothing was listening.
- The Slack interactivity endpoint (`/v1/hitl/slack/interactivity`) does not verify Slack's request signature (no signing-secret check found in `services/notifications/slack.py`). Not probed.

### C5. Other secrets and defaults worth noting (from reading, not probed)
- `agentwall/src/broker/providers/local_mock.py`: a hardcoded HMAC signing secret (a default string in the source). Anyone with the repo can forge `local_sts` tokens.
- `services/redhand-core/src/redhand_core/services/local_store.py`: a seeded dev API key (`DEFAULT_DEV_API_KEY`) is active whenever Supabase is not configured. Core silently falls into this mode when `SUPABASE_URL` is the placeholder, which is the default.
- AgentWall uses CORS `allow_origins=["*"]` together with `allow_credentials=True` (`agentwall/src/main.py:47-53`).
- `GET /v1/policies` and `GET /v1/audit/logs` on AgentWall are unauthenticated (confirmed, both 200). The audit log stores the **raw tool arguments** under a field named `sanitized_arguments` (confirmed). Nothing is sanitized.
- `FAIL_MODE` is a setting that is logged but never read (`agentwall/config/settings.py:46`). Fail-closed behavior isn't actually configurable, and the upstream path is fail-open (C2).

---

## 4. Component-by-component status

Legend: **Working** = real logic that does what it says. **Partial** = real logic with significant gaps. **Simulated** = returns plausible fake output. **Unused** = present but not wired in.

| Component | Status | Notes |
|---|---|---|
| **AgentWall: guardrails** (`src/firewall/engine.py`, `ast_guardrails.py`, `schema_validator.py`) | **Working** | Per-tool allowlist, SQL AST checks (statements, columns, row limit), shell allowlist, schema validation, egress redaction. Well tested. This is the strongest asset. |
| **AgentWall: MCP proxy** (`src/proxy/handler.py`, `mcp_parser.py`) | **Partial, not a real MCP proxy** | Only `tools/call` is evaluated and forwarded. `initialize`, `tools/list` and every other method get a canned `{"status":"ok"}` reply and are **not forwarded** (confirmed). Forwarded payloads aren't valid JSON-RPC (no `jsonrpc` or `id` fields). No MCP Streamable HTTP or SSE transport, no sessions. A real MCP client (Claude, n8n) could not use it as-is. |
| **AgentWall: policy model** (`config/policies.yaml`) | **Partial** | Policies are **global**: one tool list for all agents. `agent_id` is only logged and never used in decisions. No per-agent scopes, no tenants. Policy load failures default to an empty policy (which denies everything, so it is effectively fail-closed). |
| **AgentWall: STS broker** (`src/broker/`) | **Simulated** | All six providers (AWS, Azure, GCP, SaaS, Vault, local) fabricate token-shaped strings locally. None calls a real service. The minted token is sent upstream as `Bearer`, but no upstream can validate it. |
| **AgentWall: audit ledger** (`src/telemetry/audit_logger.py`) | **Partial** | The hash chain is real, but it lives **in memory only** and is lost on restart. Optional file output is off by default. `/v1/audit/verify` only proves integrity within the current process. |
| **AgentWall: MCP vetting** (`src/firewall/mcp_vetting.py`, `POST /v1/mcp/vet`) | **Partial** | Keyword and schema heuristics on a manifest JSON the caller pastes in: shell launchers, secrets in env vars, broad tools, loose schemas. It does **not** detect hidden instructions in tool descriptions or phone-home behavior, and it doesn't fetch anything (so no SSRF risk today). A reasonable seed for the Phase 4 scanner, not yet a credible "safety score". |
| **redhand-core: data layer** (`supabase/migrations/…_schema.sql`, `services/local_store.py`) | **Partial** | The schema is good: `organizations`, `organization_members`, hashed `sdk_api_keys`, `agents` (status enum, `allowed_tools`, framework), traces, events, HITL, and row-level security policies. But core bypasses RLS with the service role (C3). Default mode is an in-memory/JSON fake of Supabase with seeded demo data. |
| **redhand-core: SDK API key auth** (`routers/telemetry.py:266`) | **Working** | Hashed key lookup with active and expiry checks, returns the org. Only the telemetry and IAM-broker routers use it. |
| **redhand-core: state/posture** (`routers/state.py`) | **Partial, not enforced** | The `agents.status` and `allowed_tools` fields exist and can be changed, but **AgentWall never reads them** (no reference anywhere in `agentwall/`). Quarantining an agent in the dashboard does not stop anything. The SSE stream always reads the local store, even when Supabase is configured. |
| **redhand-core: HITL** (`routers/hitl.py`) | **Partial** | The state machine, state-checksum check and resume webhook are real. Reviewer identity is not authenticated (C4). |
| **redhand-core: GCP / AWS downscopers** (`services/sts_downscoper.py`, `aws_sts_downscoper.py`) | **Real with silent mock fallback** | Real calls to Google STS and AWS `AssumeRole` when credentials exist. **Silently fall back to fake tokens** when credentials are missing, which can hide misconfiguration in production. |
| **redhand-core: WORM S3/GCS logger** (`services/worm_audit_logger.py`) | **Unused** | Only referenced by tests. Not wired into any request path. |
| **redhand-core: SCIM** (`routers/scim.py`) | **Partial** | Endpoints exist. No bearer-token check was found on them (not probed). Enterprise feature; gate by tier. |
| **redhand-ui** (`apps/redhand-ui/`) | **Partial** | Builds clean. Talks to core (`/v1/state/*`, HITL) and calls AgentWall `/v1/mcp/vet` directly. **No login at all.** Falls back to `lib/mock-telemetry.ts` data when core is unreachable, so a demo can look live while disconnected. |
| **Root `src/` Next.js app** | **Duplicate** | Byte-identical to `apps/redhand-ui/src` (`diff -rq` shows no differences). The root `package.json` and Next config build this copy. One of the two should be removed. |
| **redhand-sdk** (`packages/redhand-sdk/`) | **Partial** | `@guard` decorator, framework adapters, fuzzer, `redhand scan`. Defaults to **fail-open** for read-only tools (`decorators.py:244,296`). It also relies on an ONNX prompt-injection classifier, which matters for the cost model. Voluntary enforcement by design. |
| **redhand-sidecar** (`packages/redhand-sidecar/`) | **Simulated** | The MCP proxy route forwards to a `dummy_upstream` function (`proxy.py:92`). |
| **battleground / examples** | Demo only | As intended. |
| **Claims** | **Unbacked** | README claims "sub-millisecond" and "<0.2ms" guardrails and multi-cloud/SaaS brokering. No benchmark exists in the repo, and most brokering is simulated (see above). |

---

## 5. Answers to the open questions in CLAUDE.md

| Question | Answer from the code |
|---|---|
| How do agents authenticate to AgentWall? | **They don't.** Identity comes from headers (C1). |
| Production database? | Supabase Postgres is designed and has a migration, but core runs on a local in-memory fake by default. The AgentWall ledger has no database at all. |
| Tenancy model? | `organizations` + `organization_members` + RLS exists **in the schema only**. AgentWall has no tenant concept. Core endpoints ignore tenancy (C3). |
| Are delegated identity headers trusted safely? | **No.** They're trusted unauthenticated. This is a critical finding. |
| Which STS providers are real? | In core: GCP and AWS are real when credentials exist (with silent fake fallback). In AgentWall: **none**, all simulated. |
| How do operators log in to the UI/core? | **They don't.** There is no operator authentication. |
| Hosting target? | Hints only: the `.env.example` mentions Cloud Run for core, there's a `vercel.json` for the UI and a Helm chart for the sidecar. No decision is recorded. |

---

## 6. Gap analysis against the Phase 1 "done" tests

| Done test | What exists | What's missing |
|---|---|---|
| **1. Register agent → passport visible with owner, scopes, expiry** | `agents` table (org, name, framework, status, `allowed_tools`); dashboard renders agents | Owner and backup owner, `expires_at`, `version`, read/write scopes per server/tool, `frozen`/`revoked`/`expired` statuses (the current enum is `active / suspended / quarantined / decommissioned`), a registration API, and per-agent credentials |
| **2. In-scope MCP call succeeds; out-of-scope denied and logged** | Guardrail engine, deny of unknown tools, block audit records | Agent authentication; AgentWall reading the agent's passport and scopes instead of a global YAML; a real MCP proxy (forward all methods, proper JSON-RPC, Streamable HTTP); persistent audit; and fail-closed upstream errors (C2) |
| **3. Revoke one agent → next call fails within 5 s** | A status field that can be changed | Any link from status to AgentWall; cache with invalidation; revoking the agent's credential; authenticated control action |
| **4. Freeze all → every agent denied; audit records it** | Nothing | A freeze-all action, a tenant-wide status flip in one transaction, an audit entry with the actor, and operator authentication and roles |

---

## 7. Recommended order for the next steps

1. **Security fixes first** (each a small plan → change):
   - Authenticate agents to AgentWall. Remove trust in `X-User-*` headers until they can be cryptographically bound (C1).
   - Make upstream failures fail closed; remove the simulated success (C2).
   - Add operator authentication (Supabase Auth fits the existing schema) and tenant-scoped access to core. Stop using the service role for user-facing reads (C3).
   - Bind HITL reviewer identity to the authenticated operator; verify Slack signatures (C4).
   - Remove the hardcoded HMAC secret and the always-on dev key outside development; lock down CORS and AgentWall's read endpoints (C5).
2. **Decisions for you (ADRs):**
   - Extend the existing `agents` table into the passport rather than creating a new entity (recommended).
   - Postgres via Supabase as the single source of truth for passport status.
   - How AgentWall reads status: direct database read with a short cache plus invalidation on change, to meet the 5-second SLO.
   - Make AgentWall a real MCP Streamable HTTP proxy for remote servers.
   - Starter-tier gating of SCIM, multi-cloud STS, Helm and OCSF.
3. **Then the Phase 1 slices** from the earlier plan: tenancy wiring → passport fields → agent credentials → passport check in AgentWall → freeze/revoke/freeze-all → dashboard → end-to-end tests and latency benchmark.

**Housekeeping (separate small changes):** delete the duplicate root Next.js app; add explicit ruff rules and a type-checker so "zero new warnings" has a baseline; label simulated providers and mock fallbacks in code and UI; persist the AgentWall ledger.
