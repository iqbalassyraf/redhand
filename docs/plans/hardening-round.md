# Plan: hardening round H1 to H4

**Status:** approved by the owner 2026-11-14. ADR: `docs/adr/0021-hardening-round.md`.

## Context
An audit of the code against CLAUDE.md section 5 (security) and section 9 (reliability) found concrete gaps. I verified the three most serious claims myself:
- **Budget day ignores the organization's timezone.** The context query in `agent_auth.py` does not select `utc_offset_minutes`, but line 471 reads it, so production always uses the default UTC+8. The in-memory test store hides it.
- **The token `ver` claim is parsed but never compared** with the passport version (`identity.py:127`).
- **Tool pinning in enforce mode** judges a tool this gateway process never saw listed by name alone (`service.py` `_pin_allows`), and Cloud Run instances start empty.

The owner approved everything, including the changes CLAUDE.md puts behind explicit approval (token logic, enforcement behaviour, CI, deploy settings), and wants them done one at a time in the right order. Staging can only be tested at night, so each PR carries a night-test part and is verified locally now.

## Order, and why
Safest and highest value first; the changes that alter behaviour for agents last, so they can be tested on their own.

### H1: correctness and secrets (no behaviour change for agents)
1. **Budget timezone bug:** select `utc_offset_minutes` in the context query. Add a test that fails when the column is missing from the select (the twin must stop hiding it: make `LocalTableQueryBuilder.select()` honor the column list, in the twin only, and fix whatever then breaks).
2. **No secrets in logs:** stop logging webhook URLs (`slack.py:117`, `hitl.py`); log the host only. A test greps captured logs for a fake token placed in a URL's query string.
3. **Gateway audit log memory:** bound `_records` in `audit_logger.py` (ring buffer with a count and a stated limit; the chain head and hash stay verifiable for the retained window). The WORM-ledger claim stays accurate by stating the retained window in the verify output. Move the optional file append off the event loop.
4. **Risk scoring off the Black Box ingest path:** `routers/events.py` replies first and evaluates in a background task with a bounded queue; one `agent_risk_signals` call for all agents in the batch instead of one per agent; the same for the B2 trigger's row lock (aggregate per batch in SQL only if measurement shows contention; otherwise leave and document).
5. **Core context endpoint tail:** run the destination lookup, `usage_by_others` and the `last_seen` update concurrently where independent; select only the columns used. Measure round trips before and after with the local harness.
6. **Gateway DNS:** resolve once per forwarded message, not twice (reuse the checked address for the call, see H2).

### H2: SSRF and edge limits (new refusals, no change for valid use)
1. **Webhook SSRF guard in core:** one shared `validate_outbound_url` (https only, no credentials, public addresses only, resolve then check, no redirects, size and time caps) reused by `resume_webhook_url`, `notification_webhook_url` and the organization's `siem_webhook_url`. Reuse the gateway's checks in `agentwall/src/gateway/upstream.py` and core's `validate_mcp_server_url` rather than a third copy: extract one tested function. Existing stored URLs that fail are refused at send time with a metric and a log line (never a crash).
2. **Pin the connection to the checked address** for MCP upstreams (closes DNS rebinding that `upstream.py` itself notes): connect to the resolved IP with the original Host and SNI.
3. **Body size limits:** a global request body cap in core (ASGI middleware, streaming-safe, 413) with per-route overrides for ingest; fix the gateway's `_read_json_body` to enforce the cap while reading chunked bodies.
4. **Whole-call upstream deadline** at the gateway (not only per-read timeout), so a slow-drip server cannot hold a call open.
5. **Insecure-flags guard:** refuse to start if `ALLOW_INSECURE_*` flags are on while the environment name is `production` or `staging`; the environment becomes an enum.

### H3: security headers, rate limits, supply chain
1. **Dashboard headers** in `next.config.mjs`: CSP (no inline script; connect-src limited to core, gateway and Supabase), `frame-ancestors 'none'`, HSTS, `nosniff`, Referrer-Policy, Permissions-Policy. Verified with a production build and a browser run (no console CSP violations on every page, all roles, 1280 and 375 px).
2. **Core and gateway response headers** (`nosniff`, `Cache-Control: no-store` on authenticated and token responses, `Strict-Transport-Security`).
3. **Rate limits that match the deployment:** token exchange gets a per-source and global limit as well as the per-key one; the limiter evicts idle keys (bounded memory); the live scan limit becomes per tenant; ingest and telegram checks move before the database write. Limits live behind one `RateLimiter` interface with an in-memory implementation now and the instance count documented (limits are per instance while `--max-instances 1`).
4. **Cloud Run trusted-proxy setting** (approved): set `FORWARDED_ALLOW_IPS` in `deploy.sh` so per-IP limits see the caller; restrict HS256 operator tokens to development and require the issuer when they are allowed.
5. **CI supply chain** (approved): add `pip-audit` and `npm audit --audit-level=high` (fail on known high/critical) and `.github/dependabot.yml` (weekly, grouped). Pin third-party actions by commit SHA. These are new CI steps: they may fail on an existing finding; if so I report it and propose the fix as part of the same PR rather than ignoring it.

### H4: enforcement tightening (approved; behaviour change, so last and alone)
1. **Token version check:** the gateway refuses a token whose `ver` differs from the passport's current version (fail closed, a clear refusal reason `token_stale`). The agent SDK and `staging_agent.py` fetch a fresh token on that refusal once. Ordering and clock-skew tested; the revocation SLO test is extended to cover "unfreeze does not revive an old token".
2. **Strict pinning in enforce mode:** a tool with no checked digest in this process is refused until a `tools/list` has been checked; the gateway fetches and checks the list itself on first use (bounded, cached per instance, counted in a metric) so a cold start costs one extra upstream call, not a failed call.
3. **Upstream error bodies:** redact secrets and scan for honeytokens in JSON-RPC `error` messages and data, not only `result`.
4. Each of these ships behind its own kill switch environment variable (default on), documented in the runbook, so a bad night test can be reverted without a deploy.

## For each PR (the same checklist)
- Plan section kept short in the PR body; ADR 0021 (hardening round) written once, amended per PR.
- **Tests first** where a bug is fixed (the failing test is shown); negative and abuse cases for every new refusal; seeded property tests where they apply.
- **Deliberate-breakage checks** on every new safeguard (the standing method).
- Full Python suite, ruff 0.17.3 and mypy 2.4.1 as CI, SQL script when SQL changes, dashboard tests, `tsc` and `next build`, a local browser run when the UI is touched, and a local benchmark (the fixed `scripts/benchmark_gateway.py`) before and after for any hot-path change. Targets: gateway p50 at most 10 ms and p99 at most 50 ms added (budget in CLAUDE.md section 8), no regression.
- A night-test part appended to the night brief (Part J for H1, K for H2, L for H3, M for H4) with exact commands and expected text, guarded by the same string test, plus a line in the master checklist.
- Threat model rows, CHANGELOG, handoff entry; CLAUDE.md changes are proposed in the handoff, never applied.

## Branches and merging
- One branch per round from the B2 branch tip: `fix/h1-correctness-and-secrets`, `feat/h2-ssrf-and-limits`, `feat/h3-headers-limits-supply-chain`, `feat/h4-enforcement-tightening`. Each PR is stacked on the previous one; the owner merges after PRs 57 to 68, in order.
- I commit and push after every item so nothing is lost if the container is reclaimed. I never merge, deploy or change staging.

## Security impact
Net positive and each item is itself a security change: closes SSRF through core webhooks and DNS rebinding at the gateway, adds browser security headers, removes secret-bearing log lines, bounds memory and request sizes, blocks stale tokens, closes the rug-pull gap on cold instances, and redacts upstream errors. New failure modes are refusals (fail closed) with metrics and runbook entries. H4 changes what agents experience (a stale token is refused once and must be refreshed; a cold instance may spend one extra upstream call), so it is last, behind kill switches, with its own night test.

## Verification
Local: all gates above on each PR. Not verifiable until night: Cloud Run behaviour (trusted-proxy setting, cold-start pinning, real DNS), Supabase, Telegram, Vercel headers in production. Each is a numbered step in its night part.

## Risks and open questions (my recommendation)
1. H3 CI audit may fail on an existing dependency finding [fix or pin in the same PR and say so].
2. A strict CSP can break Next.js inline bootstrap scripts [use the nonce-based CSP supported by Next 15 middleware, tested in a browser before commit].
3. Audit-log ring buffer changes what `/v1/audit/verify` can prove [state the retained window in its output and the docs; the durable record is the core Black Box, which keeps the full hash chain].
4. Connection pinning for upstreams touches TLS/SNI handling [covered by tests against a local TLS server; kill switch available].
5. Size: large. Four PRs, each independently reviewable.
