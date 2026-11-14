# ADR 0021: Hardening round (H1 to H4)

**Status:** Proposed (2026-11-14), amended by each H PR. Owner approval 2026-11-14 for all four rounds, including the changes CLAUDE.md puts
behind explicit approval (token logic, enforcement behaviour, CI, deploy settings). Plan: `docs/plans/hardening-round.md`.

## Context
An audit of the code against CLAUDE.md sections 5 (security) and 9 (reliability) found concrete gaps. This ADR records what each round changes
and why, so a reviewer can follow the intent across the four PRs.

## H1: correctness and secrets (no behaviour change for agents)
- **Budget day.** The gateway-context query never selected `organizations.utc_offset_minutes`, so production always used the default UTC+8 day
  boundary. The in-memory twin returned every column regardless of the select list, which hid it; it now returns only the selected columns,
  like PostgREST. The test asserts the reset moment (05:00 UTC at UTC-5), which holds at any time of day.
- **No webhook URLs in logs.** A Slack webhook URL is the secret itself, a resume URL can carry a token, and httpx repeats the URL in its own
  error text. All five log sites now log the host, and the error's type and HTTP status only (`services/safe_log.py`); a static test fails if
  any log call in core mentions a `*webhook_url` unreduced.
- **Bounded gateway audit chain.** The in-memory chain grew without limit. It keeps the most recent 10,000 records; the hash of the record that
  falls out anchors the retained window, so tampering inside it is still detected. `/v1/audit/verify` states what it covers (records verified,
  dropped from memory, total) and that the complete record is the Black Box in redhand-core. The optional audit file is written by a writer
  thread, not on the request's thread, and a failing disk is counted, never raised.
- **Ingest replies before risk scoring.** Scoring ran inside the Black Box ingest request (up to 5 s) while the gateway's report timeout is
  5 s, so a slow database could make the gateway resend a stored batch. It now runs after the reply; at most 8 evaluations run at once (a
  skipped one is counted and picked up by the next report); a batch naming four or more agents reads signals in one query.
- **Context lookups run together.** After the first parallel batch, the destination list, the usage by other instances and the last-seen
  write are independent and run together; the agent query selects its nine columns instead of every column. The last-seen write is
  best-effort now (dashboard-only data must not deny an authorization lookup); the decisions still fail closed.
- **Folded into H2.2:** the gateway resolves an upstream's DNS twice per message (once to check it, once inside httpx). The only safe fix
  is to connect to the address that was checked (connection pinning), not to cache DNS, which would weaken the per-request check.

## H2: SSRF and edge limits (new refusals; no change for valid use)
- **One outbound rule set for webhooks (core).** `net/outbound.py` is the only way core calls a customer-supplied URL (Slack, the SIEM export,
  the resume webhook). In order: static checks (https, no credentials, no local or internal name, a literal address must be public); one DNS
  lookup, every answer must be public (IPv4-mapped IPv6 is judged as the IPv4 address, one private answer refuses the name); the request goes
  to a checked address with the original `Host` and TLS name (httpx `sni_hostname`, proven with a real local TLS server: a certificate for
  another name is still refused); no redirects; one total deadline; a response size cap; error text that never contains the URL. A refused URL
  is permanent: no retry, `redhand_outbound_blocked_total{purpose}`, host-only log. `resume_webhook_url` and `notification_webhook_url` are
  also refused at ingest (static checks; the address is checked again at send time). Development flag `ALLOW_INSECURE_WEBHOOK_URLS`.
- **The gateway connects to the address it checked (closes DNS rebinding).** `resolve_destination` resolves once, applies the same rules and
  returns the ways to connect: a checked address (IPv4 first, at most 3) with the original Host and TLS name. A connection that cannot be
  opened moves to the next checked address; any other failure ends the call (a request that may have been delivered is never repeated).
  `UPSTREAM_PIN_ENABLED=false` is a kill switch: the same check, then connect by name. This also removes the second DNS lookup per message
  (H1.6).
- **One deadline for a whole upstream call.** The lookup, every connection attempt and the whole body share `UPSTREAM_TIMEOUT_SECONDS`; before,
  only each read had a timeout, so a server answering one byte at a time could hold a call open.
- **Body caps.** Core had none (only Telegram checked its own). A pure ASGI middleware answers 413 above `MAX_REQUEST_BYTES` (1 MiB), counting
  the bytes as they arrive; `/internal/v1/events` and `/v1/telemetry` get `MAX_INGEST_REQUEST_BYTES` (16 MiB: 500 events or 250 spans a call).
  The gateway's reader counted only after `request.body()` had buffered everything; it now stops at the limit.
- **Development flags cannot run in a shared environment.** Core refuses to start with `ALLOW_INSECURE_MCP_URLS` or
  `ALLOW_INSECURE_WEBHOOK_URLS` unless `ENVIRONMENT` is development or test. The gateway's environment name is a free string, so only
  `development`, `dev`, `test` or `local` is trusted for `ALLOW_INSECURE_UPSTREAMS`; a typo such as "prod" fails closed.
- **Kept in step.** Core and the gateway have separate copies of the URL rules (separate processes, no shared package); one vector file
  (`agentwall/tests/data/outbound_url_vectors.json`, 31 static and 9 resolved cases) is run through both.

## H3: browser headers, rate limits that match the deployment, supply chain
- **Dashboard policy.** Every page response carries a nonce-based Content-Security-Policy set by middleware (`src/middleware.ts`, builder in
  `src/lib/csp.ts`): scripts only with the per-response nonce plus `'strict-dynamic'` (no `'unsafe-inline'`, no eval in production), no framing,
  `connect-src` limited to this site, core, the gateway and Supabase, styles keep `'unsafe-inline'` (React inline styles and the flow-diagram
  library need it; a style cannot run code). Pages are rendered per request so Next.js can stamp the nonce. Plus `nosniff`, referrer policy,
  HSTS, permissions policy and `X-Frame-Options` (`security-headers.mjs`, plain JavaScript because `next.config.mjs` loads before TypeScript).
  Proven in a real browser over every page, three roles and two widths (172 checks, 0 failures), including that an injected inline handler and a
  request to a foreign origin are blocked; removing the per-request rendering makes it fail.
- **API answer headers.** Core and the gateway add `nosniff`, HSTS and `Cache-Control: no-store` (unless the route chose its own) from a pure ASGI
  middleware outside the body limit, so a 413 carries them too.
- **Bounded limiter.** The two limiters grew a dict entry per distinct key and never shrank, so a caller sending a new well-formed agent key each
  time grew core's memory. One class per service now sweeps expired keys and drops the least recently used when full (10,000 keys). Per instance
  while `--max-instances 1` (stated in the module).
- **Token exchange per source.** Limited per source address (300 a minute by default) before any hashing or database read, as well as per key.
  **Deviation from the plan:** no global limit. A global cap on exchanges would let one caller use up everyone's budget (an availability lever)
  and protect nothing the per-source limit does not.
- **Source address from the right, not uvicorn's `*`.** The plan said to set `FORWARDED_ALLOW_IPS`. uvicorn with `*` takes the **leftmost**
  `X-Forwarded-For` entry, which the caller wrote. Core and the gateway instead read the header themselves, counted from the right by
  `TRUSTED_PROXY_HOPS` (0 ignores it; Cloud Run: 1, set by `deploy.sh`). Fewer or unreadable entries fall back to the socket peer (one shared
  bucket: over-limits, never evades). A test fails if the deploy script ever uses `forwarded-allow-ips`.
- **Other limit placement.** Telegram's per-chat limit is checked before the update claim write; the live scan is limited per organization (core
  sends `X-RedHand-Organization`, a header so an old gateway ignores it during the deploy window; missing or malformed shares one fixed bucket);
  the vet endpoint per real caller instead of per Google front end. Not changed: the Black Box ingest has no limiter (service token only; the
  gateway batches).
- **HS256 operator secret outside development is refused.** A shared secret both verifies and mints operator tokens. **This supersedes the
  "legacy Supabase secret" mode in ADR 0007.** A deployment still on a legacy HS256 project must enable asymmetric signing keys and use
  `OPERATOR_JWKS_URL`. Staging already does. Not done: requiring an issuer for development HS256 tokens (a random per-process secret, test churn,
  no security value).
- **Supply chain.** `pip-audit` (pinned, locked versions) and `npm audit --audit-level=high` fail CI; weekly grouped Dependabot for uv, npm and
  workflows. The first audit found a real high finding: Next 15 pins postcss 8.4.31 (four advisories). The offered fix is Next 16 (a breaking
  major); an npm override points Next at the dashboard's own patched postcss instead (build, type-check, tests and the browser pass confirmed).
  **Not done:** pinning actions by commit SHA: the SHAs could not be resolved from this session (the repository scope blocks reading other
  repositories). Dependabot keeps the tags current; the SHA pin is an owner follow-up.

## H4: enforcement tightening (behaviour changes for agents; each has a kill switch)
- **Stale tokens are refused (H4.1).** A token carries the passport version it was issued at; the version rises with every change of status,
  scopes or expiry (database trigger). The gateway parsed `ver` and never compared it, so a token issued before a freeze worked again after the
  unfreeze. A token **older** than the passport is refused (HTTP 401, reason `token_stale`, recorded in the Black Box) after the status check, so
  a frozen agent is still reported as frozen. A **newer** token is accepted: that only means the gateway's cached context lags a change by at
  most its TTL, which already bounds every other decision. No new lookup (the version is in the context the gateway has). The agent exchanges
  its key again. `scripts/staging_agent.py` does so once and retries; the agent SDK has no token exchange, so a customer's client must treat
  this 401 as "exchange the key again". Plan said "differs"; "older than" is deliberate (see above).
- **Strict pinning on first use (H4.2).** In Enforce mode a call to a tool this process has no checked version of was judged by its approved
  name alone, so a rug-pulled tool passed on any instance that started empty (Cloud Run starts them at zero) or whose agent never re-listed. The
  gateway now fetches the server's tool list itself (`pin_check.py`: the scan module's `list_tools` with the agent's own upstream credentials),
  records every version it sees in the same memory a normal listing fills (and reports new ones to core), and judges the tool's current version.
  If that cannot be done the call is refused. Bounded: one check per (organization, server) at a time (simultaneous callers share it; a caller
  that disconnects does not cancel it), 50 at once, a 10 s deadline, the scan caps (5 pages, 500 tools); after a failure the same server is
  refused quickly for 10 s instead of being asked again on every call. Cost: one extra initialize, initialized and tools/list (about a second)
  on the first call per server per instance, only in Enforce mode.
- **Upstream errors are treated like results (H4.3).** A JSON-RPC `error` from the server was passed through untouched while results were
  redacted and bait-checked. An error now gets the same secret redaction (all methods) and honeytoken redaction and trip (`tools/call`); a
  scanner failure denies, as for results. Nothing the server says is added or kept.
- **Kill switches** (all default on; set to `false` on the gateway, no deploy of code needed): `AGENTWALL_TOKEN_VERSION_CHECK_ENABLED`,
  `AGENTWALL_STRICT_PINNING_ENABLED`, `AGENTWALL_REDACT_UPSTREAM_ERRORS_ENABLED`.

## Alternatives considered
- **Cache DNS answers at the gateway** to save a lookup: rejected, it would widen the DNS-rebinding window.
- **Drop the in-memory audit chain** entirely and rely on the Black Box: rejected, the gateway's chain is a second, independent record.
- **A message queue for scoring:** rejected for now; a bounded in-process cap and background task are enough, and nothing is lost (the signals
  are stored).

## Consequences
- `/v1/audit/verify` now proves the retained window, not "all records since start"; its answer says so.
- A failed last-seen write is logged and the lookup succeeds.
- Scoring after a Black Box batch can be skipped under load (counted); the next report catches up.
- H2: a webhook or upstream URL that used to work only because a check was missing (an internal address, plain http, a name that resolves to a
  private address) is now refused. Pinning means the gateway's call goes to an IP: an upstream that cannot be reached by its first checked
  addresses fails as "unreachable" (kill switch: `AGENTWALL_UPSTREAM_PIN_ENABLED=false`).
- H2: a request body over 1 MiB (16 MiB on the two ingest routes) is refused with 413 on core.
- H3: a deployment on the HS256 shared operator secret outside development no longer starts. The dashboard needs per-request rendering (no static
  pages). Token exchange has a per-address limit (300 a minute by default); many agents behind one egress address share it.
- H4: a token issued before a freeze, unfreeze, scope change or expiry change is refused once; the agent must exchange its key again. In Enforce
  mode the first call per server per instance costs about one extra second. An upstream error that contained a secret now reaches the agent redacted.
