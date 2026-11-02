# Threat model: Phase 1 (Identity and control)

**Last updated:** 2026-11-01. Update this file whenever a trust boundary changes (CLAUDE.md §5.1).

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

## 2. Threats and mitigations

| Threat | Mitigation | Residual risk / follow-up |
|---|---|---|
| Hijacked or prompt-injected agent calls tools outside its job | Passport scopes enforced per `tools/call`; `tools/list` filtered; SQL/shell guardrails; resources/prompts methods refused | Read vs write not enforced until Safe Mode (Phase 2) |
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
| Core outage | Gateway fails closed (denies) | Availability target 99.9 %; no multi-region yet |
| Signing key compromise | Ed25519 private key only in core; gateway holds public key | Signing-key rotation not automated |
| Development shortcuts reach production | core refuses the in-memory store and `/v1/dev/login` outside development; signing key required outside dev/test; no hardcoded secrets | Deployment checklist must set all required secrets |
| Supply chain | Locked dependencies (`uv.lock`, `package-lock.json`); no new packages added in Phase 1 (pyjwt was already locked) | No automated vulnerability scan in CI yet |

## 3. Out of scope for Phase 1
Local stdio MCP servers, non-MCP REST APIs, LLM API spend (Budget Guard, Phase 2), recording of
payloads (Black Box, Phase 3), MCP server reputation (Phase 4).
