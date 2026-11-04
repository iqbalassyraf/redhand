# Threat model: Phases 1 and 2 (Identity and control; Stop things)

**Last updated:** 2026-11-03. Update this file whenever a trust boundary changes (CLAUDE.md §5.1).

## 1. Components and trust boundaries

```
 Operator browser ──(1) Supabase JWT──▶ redhand-core ◀──(3) service token── AgentWall gateway
                                         │  ▲                                  │      ▲
                                         │  └──(2) agent key → access token ───┘      │
                                         ▼                                            │
                                  Postgres (Supabase)              Agent ──(4) access token
                                                                                      │
                                                     customer MCP server ◀──(5) HTTPS─┘
```

| # | Boundary | Authentication | Notes |
|---|---|---|---|
| 1 | Operator → core | Supabase access token (ES256/RS256 via JWKS, or HS256 with a shared secret; `aud=authenticated`), tenant and role from `organization_members` | All control actions authorized server-side |
| 2 | Agent → core (token exchange) | Agent key (256-bit, stored hashed) | Refused unless passport active; rate-limited per key |
| 3 | Gateway → core (`/internal`) | Shared service token, constant-time compare | Missing token means every agent call is denied |
| 4 | Agent → gateway | Ed25519 access token, 10 min, verified with public key | Plus per-call passport status check (≤ 2 s cache) |
| 5 | Gateway → MCP server | Optional upstream credential supplied by the agent | Destination check per request: https, public IPs, no redirects |
| 6 | Telegram → core webhook | Secret header (constant-time compare), then the chat must be linked to an operator whose role is re-read on every command | Public endpoint by necessity; private chats only; stop-only commands (ADR 0008) |

## 2. Threats and mitigations

| Threat | Mitigation | Residual risk / follow-up |
|---|---|---|
| Hijacked or prompt-injected agent calls tools outside its job | Passport scopes enforced per `tools/call`; `tools/list` filtered; SQL/shell guardrails; resources/prompts methods refused | Read vs write is enforced only in Safe Mode, and only as declared by the operator (ADR 0009) |
| Stolen agent access token | 10-minute lifetime; freeze/revoke denies within ≤ 2 s via status lookup | Token usable until revoked if theft is undetected |
| Stolen agent key | Revoke or rotate deactivates it immediately; only hash stored | No anomaly detection on key use yet |
| Agent bypasses the gateway with raw upstream credentials | Out of scope by design; product copy states the limit | Credential broker (Phase 1.5) closes this |
| Malicious or compromised MCP server | Response size and time limits, no redirects, secrets redacted from tool results, unsupported methods refused | Poisoned tool descriptions not yet scanned (Phase 4) |
| SSRF through registered MCP server URLs | Registration: https and public host; per request: resolve then require public addresses | DNS rebinding between check and connect (pin connection to checked IP) |
| Cross-tenant access | Tenant from verified membership; every core query filtered by organization; gateway context bound to token's tenant; SSE stream filtered | core uses service role, so isolation relies on core's queries (RLS is defense in depth) |
| Forged operator identity / spoofed headers | No identity headers are trusted; reviewer is the authenticated operator; operator tokens are verified as ES256/RS256 against the project's JWKS (or HS256 with a shared secret), never both; HS256 is rejected in JWKS mode (no algorithm confusion); issuer, audience and expiry are checked (ADR 0007) | A signed-out operator's token stays valid until it expires; shorten the Supabase access-token lifetime |
| Insider or compromised admin abuses control actions | Role requirements (revoke, freeze-all, scope expansion need admin), explicit confirmation, append-only audit with actor and reason | No step-up authentication yet |
| Audit tampering | `control_audit_log` blocked from UPDATE/DELETE by trigger; gateway ledger hash-chained | Gateway ledger is per process (file optional); move to database in Phase 3 |
| Audit gap after a control action | Each action and its audit row commit in one database transaction (`control_*` functions); a failed audit write rolls the action back. See ADR 0006 | A network timeout after commit leaves the outcome unknown to the caller (the API says to reload; actions are safe to repeat) |
| Stolen or lost phone with the panic command | Stop-only commands: it cannot unfreeze, revoke or widen scopes; admins can unlink a chat in the dashboard; every action is audited with `via Telegram` | The holder can freeze every agent (a denial of service, by design); no PIN on top of Telegram's own lock |
| Forged Telegram webhook calls | Secret header compared in constant time; a wrong secret does nothing and returns 401; unlinked chats get no information beyond "not linked" | Anyone who learns the webhook secret can send updates, but still needs a linked chat id to act |
| Attacker links their own chat | Link codes are created only by a signed-in admin or owner, are single use, expire in 10 minutes, stored hashed, with about 49 bits of entropy and 5 attempts per minute per chat | A code shown on screen can be shoulder-surfed within its 10 minutes |
| Replay of an old command | Update ids are claimed once in the database; the secret header is required | Freeze commands are idempotent anyway |
| Bot token leaks through logs | httpx request logging disabled in the Telegram module; errors logged by class only; tests assert the token is absent | A future logging change elsewhere could reintroduce it: the test covers the module only |
| Removed or demoted operator still has a linked phone | Role and membership are re-read per command; unlink revokes the link | None known |
| Agent keeps writing during an incident | Safe Mode (agent or organization): the gateway allows only read-declared scopes; on within about 2 s; audited; ON from a phone, OFF only by an admin in the dashboard (ADR 0009) | RedHand cannot verify a tool is read-only: the declaration is the operator's. A `*` scope declared read covers the whole server. |
| Safe Mode silently skipped after a version mismatch | The gateway requires `safe_mode` to be a real boolean from core; otherwise it denies. Core reads anything but a stored `false` as ON | An old gateway ignores the flag: deploy core first and enable only after both are updated |
| Runaway or hijacked agent does unbounded work | Budget Guard: a daily cap on forwarded tool calls enforced in the gateway with no I/O on the decision path; alerts at 80% and 100%; optional auto-freeze (ADR 0010) | Counts calls, not cost or LLM spend. Agents with no limit are never stopped. With several gateway instances the cap can be exceeded briefly (bounded and documented). |
| Limits relaxed without authority | Raising or removing a limit, or turning auto-freeze off, needs an admin and confirmation; the change is compare-and-set against the state the decision was made on | None known |
| Forged or inflated usage reports | `/internal/v1/usage` needs the internal service token; the organization comes from the agents table; counts are monotonic and bounded; at most 1,000 items per report | A compromised service token could inflate counts and block an agent for the day (raise its limit to recover) |
| Budget silently skipped after a version mismatch | The gateway requires a strictly typed `budget` from core and denies otherwise; a malformed stored limit reads as 0 | An old gateway ignores the field: deploy core first |
| Core outage | Gateway fails closed (denies) | Availability target 99.9 %; no multi-region yet |
| Signing key compromise | Ed25519 private key only in core; gateway holds public key | Signing-key rotation not automated |
| Development shortcuts reach production | core refuses the in-memory store and `/v1/dev/login` outside development; signing key required outside dev/test; no hardcoded secrets | Deployment checklist must set all required secrets |
| Supply chain | Locked dependencies (`uv.lock`, `package-lock.json`); no new packages added in Phase 1 (pyjwt was already locked) | No automated vulnerability scan in CI yet |

## 3. Out of scope so far
Local stdio MCP servers, non-MCP REST APIs, LLM API spend (Budget Guard, Phase 2), recording of
payloads (Black Box, Phase 3), MCP server reputation (Phase 4).
