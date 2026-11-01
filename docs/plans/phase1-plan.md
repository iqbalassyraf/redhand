# Phase 1 implementation plan

**Status:** Approved 2026-11-01 and implemented (M1–M6). Deviations and follow-ups in §9.
**Based on:** `docs/review/phase1-baseline.md`
**Goal:** RedHand can identify every agent, control what it touches and stop it instantly. That means passing the four Phase 1 "done" tests in `CLAUDE.md` §19 and closing critical findings C1–C5 from the baseline review.

---

## 1. Design overview

```
Operator (browser)                         Agent (Claude, n8n, custom)
      |  operator JWT (Supabase Auth)            |  1. agent key  --> core: exchange for 10-min access token
      v                                          |  2. MCP over HTTP + Bearer access token
redhand-core (:8000)  <---- passport status ---- AgentWall (:8080) ----> customer's MCP server
  - passports, keys, freeze/revoke         (service token,   - verify token signature locally
  - control audit log (append-only)         2 s cache)       - check passport status + scope
  - operator auth + tenant scoping                           - existing SQL/shell guardrails
  - signs agent access tokens (Ed25519)                      - fail closed on any error
```

### Key choices

1. **The passport is the existing `agents` table, extended.** A migration adds owner, backup owner, expiry, scopes, version and the new statuses. Rejected alternative: a new `passports` table, which would duplicate the agent identity the dashboard and telemetry already use.

2. **Agent authentication is two-step.**
   - Each agent gets a long-lived **agent key** (`rh_agent_…`, 256-bit random, stored as a SHA-256 hash, shown once).
   - The agent exchanges that key at core for a **10-minute access token**: a JWT signed with Ed25519, carrying the agent ID, tenant and passport version.
   - Core refuses the exchange unless the passport is `active` and not expired.
   - AgentWall holds only the **public** key, so it can verify tokens but never mint them.
   - Rejected alternative: AgentWall checks the agent key directly against the database on every call. Simpler, but it puts a secret lookup on the hot path and gives no short-lived credential.

3. **Revocation is checked on every call, not just at token refresh.**
   - AgentWall asks core for the passport's status through an internal endpoint authenticated with a service token, and caches the answer for at most 2 seconds.
   - A freeze or revoke therefore takes effect within 2 seconds, inside the 5-second SLO, even while a stolen access token is still valid.
   - If core is unreachable, AgentWall denies.
   - Rejected alternative: core pushes invalidation messages to AgentWall. Faster, but it needs a message bus. The pull-with-short-cache approach meets the SLO with nothing new to run.

4. **Operator authentication uses Supabase Auth JWTs**, verified in core. Roles come from the existing `organization_members` table (`owner`, `admin`, `security_operator`, `viewer`).
   - The tenant is always taken from the verified membership, never from the request.
   - In local development only (`ENVIRONMENT=development` and no Supabase configured), a dev login endpoint issues operator tokens so the dashboard works without Supabase. It is disabled in every other environment, and tests prove that.

5. **AgentWall becomes a real MCP proxy for remote servers.**
   - Each tenant registers its MCP servers (name and URL).
   - An agent connects to `https://<gateway>/mcp/<server-slug>` with its access token.
   - AgentWall forwards **all** MCP methods (`initialize`, `tools/list`, `tools/call`, and so on) as proper JSON-RPC over Streamable HTTP, handling JSON and server-sent-event (SSE) responses with size and time limits.
   - `tools/list` responses are filtered to the tools the passport allows.
   - `tools/call` is checked against the passport scopes, then against the existing SQL/shell guardrails when a guardrail policy exists for that tool.
   - Upstream errors return an error. The simulated-success path is removed.

6. **Scopes:** a list of `{server, tool (name or "*"), access: read | write}`.
   - In Phase 1 the gateway enforces **server and tool**.
   - `access` is stored and shown, but **not enforced**, because MCP servers' own read-only hints can't be trusted. A trusted read/write classification arrives with Safe Mode in Phase 2. The product copy will say so.

7. **Control actions** (freeze, unfreeze, revoke, freeze-all, rotate key):
   - All idempotent and authenticated, restricted to `owner`, `admin` or `security_operator` (freeze-all: `owner` or `admin`).
   - Each writes an append-only `control_audit_log` row recording actor, action, target, reason and time.
   - Freeze-all is a single tenant-scoped `UPDATE`, so it is atomic.
   - Unfreeze is per agent and requires an explicit `confirm: true`.
   - Revoke is permanent: the passport can't be reactivated and its keys are deactivated.

8. **Audit:**
   - Control actions go in core's append-only table, protected by a database trigger that blocks updates and deletes.
   - AgentWall's per-call ledger keeps its hash chain and gains optional append-only file persistence, on by default outside tests.
   - Raw tool arguments are no longer stored, only argument key names and a hash. Moving the ledger into the database is deferred to Phase 3 (Black Box Recorder).

---

## 2. Milestones (one commit each, tests with each)

| # | Milestone | Closes |
|---|---|---|
| M1 | **Quick hardening:**<br>• Remove simulated upstream success; fail closed<br>• HMAC/test secrets from environment<br>• Dev API key only in development<br>• Fix AgentWall CORS<br>• Slack request-signature verification<br>• Remove unused `FAIL_MODE` fail-open option<br>• Stop logging raw arguments | C2, C5, part of C4 |
| M2 | **Operator authentication + tenant scoping in core:** auth dependency, role checks, every query scoped by `organization_id`, HITL reviewer taken from the authenticated operator (four-eyes = two distinct authenticated users), SCIM behind a bearer token | C3, C4 |
| M3 | **Passport + agent credentials + control actions:**<br>• Migration<br>• Register / list / get APIs<br>• Agent keys<br>• Token exchange<br>• Freeze / unfreeze / revoke / freeze-all<br>• Control audit log<br>• Internal status endpoint for the gateway | Done tests 1, 3, 4 (backend) |
| M4 | **AgentWall enforcement:**<br>• Token verification<br>• Passport status cache<br>• Per-server MCP forwarding<br>• Scope check<br>• `tools/list` filtering<br>• Remove header-trusted identity and roles (the `required_user_roles` check stays off until delegated identity can be signed, a later ADR)<br>• Legacy REST endpoint put behind the same auth | C1, done test 2 |
| M5 | **Dashboard:**<br>• Login<br>• Passports page (register, view, scopes, expiry, status)<br>• Freeze / revoke / unfreeze / freeze-all buttons<br>• Control audit view<br>• Delete the duplicate root Next.js app<br>• Label mock data clearly | Done test 1 (UI) |
| M6 | **End-to-end tests for all four done tests, a gateway latency benchmark, and docs:**<br>• ADRs 0001–0005<br>• Threat model<br>• OpenAPI spec<br>• Runbooks<br>• README claims corrected | Phase 1 done |

---

## 3. Security impact

- **New trust boundaries:**
  - Agent → AgentWall (Ed25519 access token)
  - AgentWall → core (service token, constant-time comparison)
  - Operator → core (Supabase JWT, algorithm allowlist, audience/issuer/expiry checks)
- **Secrets handled:**
  - Agent keys: stored only as hashes and shown once.
  - Ed25519 private key: core only, from the environment.
  - Service token and Supabase JWT secret: from the environment.
  - None of these are logged.
- **Fail-closed paths:** an invalid, expired or tampered token, unknown agent, non-active passport, core unreachable or timing out, upstream error, oversized response or unknown server all mean **deny**.
- **Tenant isolation:**
  - Every core query is filtered by the authenticated organization.
  - The gateway resolves the server only within the token's tenant.
  - Supabase row-level security stays as defense in depth.
- **Removed:** trust in `X-Agent-ID`, `X-User-ID` and `X-User-Roles` headers; simulated success; wildcard CORS with credentials; the hardcoded signing secret.
- **Server-side request forgery (SSRF):** registering an MCP server URL means AgentWall makes outbound requests. URLs must be `https`, private, link-local and cloud-metadata IP ranges are blocked by resolving the host and then checking it, and redirects are not followed. A development flag allows `http://localhost` for local testing only.

## 4. Data and migrations

- **New migration `20261101000000_phase1_passport.sql`:**
  - `agent_status` enum: add `frozen`, `revoked`, `expired`; map `suspended`/`quarantined` → `frozen` and `decommissioned` → `revoked`.
  - `agents`: add `owner_id`, `backup_owner_id`, `scopes` (JSONB), `expires_at`, `version`, `last_seen_at`.
  - New tables:
    - `agent_keys` (hashed)
    - `mcp_servers` (per tenant)
    - `control_audit_log` (append-only trigger, row-level security)
- **Rollback:** a down migration is provided. The enum value mapping is lossy (`suspended` and `quarantined` both become `frozen`), which is acceptable pre-launch with no production data. The local store is updated to match.

## 5. Tests

For each milestone: allowed and denied cases (wrong tenant, wrong scope, frozen, revoked, expired, missing, malformed or tampered token, wrong algorithm), failure modes (core down, timeout, upstream down, oversized response) asserting deny, and the revocation SLO checked with a fake clock. M6 adds end-to-end tests that run core, AgentWall and a stub MCP server in-process.

## 6. Cost and performance

- **Hot path:** local signature check (around 0.1 ms) plus a cached status lookup.
- **Cache misses:** at most one internal HTTP call per agent every 2 seconds.
- **LLM calls:** none.
- **Per-agent running cost:** negligible compute; storage is a few rows per agent plus audit rows.
- **Latency:** will be measured against the ≤10 ms p50 budget in M6.

## 7. Dependencies

- `pyjwt[crypto]` becomes a direct dependency of `redhand-core` and `agentwall`. It is already in `uv.lock` (2.15.1, pulled in by `supabase-auth`, with `cryptography` 50.0.2), so nothing new is downloaded.
- No new frontend dependencies (`@supabase/ssr` and `@supabase/supabase-js` are already declared).

## 8. Risks and open questions

- **Size:** this is a large change (likely several thousand lines including tests). Each milestone is committed and pushed separately so it can be reviewed and reverted on its own.
- **Untested against real Supabase:** the migration and operator auth are tested against the local store and unit tests only. A real Supabase project is needed to verify them for real.
- **Local servers out of scope:** MCP servers that run locally over stdio stay out of scope for Phase 1, and the product copy will say so.
- **Delegated per-user roles are disabled** in the gateway until they can be cryptographically bound. Tools that relied on `required_user_roles` will be governed by passport scopes instead.

---

## 9. Outcome

All four "done" tests pass end to end (`tests/e2e/test_phase1_done.py`). Measured gateway overhead
and revocation delay are in the README (§4).

### Deviations from this plan
- **Legacy REST endpoint removed instead of put behind auth (M4).** `/v1/tools/execute`, `/mcp` and
  `/mcp/rpc` trusted identity headers and had no tenant or upstream model; v1 is MCP-only. Their
  guardrail scenarios are now tested against the engine directly.
- **Gateway audit file is opt-in, not on by default (M4).** The gateway logs a warning outside
  development when `AGENTWALL_AUDIT_LOG_FILE` is unset, rather than writing to an implicit path.
- **Upstream credentials:** agents may pass the MCP server's own credential in
  `X-RedHand-Upstream-Authorization`. This was implied by "customers keep their own keys in v1"
  but not spelled out.

### Follow-ups (not done in Phase 1)
1. Make each control action and its audit row a single SQL transaction (today: two statements; a
   failed audit write returns 500 after the action applied).
2. Pin the upstream connection to the address that passed the destination check (DNS rebinding).
3. Supabase asymmetric JWT signing keys (JWKS) for operator tokens.
4. Signing-key rotation with overlapping keys in the JWKS.
5. Idempotency-Key support for `POST /v1/passports` (other control actions are naturally
   idempotent).
6. Shared stores for the in-process pieces when core runs more than one instance: SSE stream
   tickets, token-exchange rate limiter, and the live event stream (which today reads only the
   local store, so it is empty in Supabase mode).
7. Move the gateway ledger into the database (Phase 3, Black Box Recorder).
8. Dashboard session in httpOnly cookies instead of sessionStorage.
9. Step-up authentication for unfreeze, scope expansion and freeze-all.
10. core `/metrics` is unauthenticated (pre-existing); restrict at the network or add a token.
11. Explicit ruff rule set and a type-checker (mypy/pyright) in the repo and CI, so "zero new
    warnings" has a baseline. ESLint is not configured for the dashboard.
12. Add a `LICENSE` file (README previously claimed Apache 2.0).
13. Drop the superseded `agents.allowed_tools` column in a later contract migration.
14. Local stdio MCP servers (needs a local shim) and resources/prompts scopes.
