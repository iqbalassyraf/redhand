# Environment variables

Every setting of the three services, so the person deploying production knows what exists. **The tables are generated from the code** (`redhand_core/config.py`, `agentwall/config/settings.py`),
and `services/redhand-core/tests/test_launch_docs.py` fails when a setting is missing here, so this page cannot go stale unnoticed. Defaults shown are the code's, not production's.
Secrets go in the platform's secrets manager (Cloud Run: Secret Manager through `--set-secrets`), never in `.env` files or the repository, and never in this page.

## What a production deployment must set (the rest can stay at their defaults)

**redhand-core**
| Variable | Why | Where `deploy/cloudrun/deploy.sh` gets it |
|---|---|---|
| `ENVIRONMENT` | `development` turns on the dev login and the in-memory store; production must not use it | script (`staging` today: use `production` once the production hosting decision is made, ADR 0028) |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` (secret) | the database | environment and Secret Manager |
| `OPERATOR_JWKS_URL`, `OPERATOR_JWT_ISSUER` | how dashboard sign-ins are verified (Supabase Auth); without them no operator can sign in | derived from `SUPABASE_URL` |
| `INTERNAL_SERVICE_TOKEN` (secret) | core and gateway trust each other with it; also guards `/metrics`, `/internal/*` and the sign-up code route | Secret Manager |
| `AGENT_TOKEN_SIGNING_KEY` (secret) | signs the short-lived agent credentials | Secret Manager |
| `CORS_ALLOWED_ORIGINS` | the dashboard's origin, exactly (never `*`) | script |
| `TRUSTED_PROXY_HOPS` | how many proxies sit in front (Cloud Run: 1) so rate limits see the real client address | script |
| `DASHBOARD_URL` | https address used in Telegram links | script |
| `SIGNUP_MODE` | `invite` (default: sign-up codes) or `closed` | not set by the script: the default is right for launch |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET` (secrets), `TELEGRAM_BOT_USERNAME` | only if the panic command is offered | Secret Manager |

**AgentWall gateway** (all with the `AGENTWALL_` prefix): `ENVIRONMENT`, `CORE_URL`, `CORE_SERVICE_TOKEN` (secret, the same value as core's `INTERNAL_SERVICE_TOKEN`), `CONTEXT_CACHE_TTL_SECONDS` (2; capped at 2.5, see
`docs/security/measurements/2026-11-17-revocation-drill-after-lookup-timeout.md`), `TRUSTED_PROXY_HOPS`, `CORS_ALLOWED_ORIGINS`. The kill switches `AGENTWALL_*_ENABLED` stay **unset** unless you mean to turn a check off.

**Dashboard (Vercel)**: `NEXT_PUBLIC_REDHAND_CORE_URL`, `NEXT_PUBLIC_REDHAND_GATEWAY_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (the anon key is public by design; row-level security is what protects the data).
These are baked in at build time, so changing one needs a redeploy.

## redhand-core (`services/redhand-core`)
| Variable | Default | Secret | What it does |
|---|---|---|---|
| `APP_NAME` | 'RedHand Core Control Plane' |  |  |
| `APP_VERSION` | '0.1.0' |  |  |
| `ENVIRONMENT` | 'development' |  |  |
| `HOST` | '0.0.0.0' |  | Bind address for Uvicorn worker. |
| `PORT` | 8000 |  | HTTP listen port (Cloud Run). |
| `LOG_LEVEL` | 'INFO' |  |  |
| `CORS_ALLOWED_ORIGINS` | ['http://localhost:3000', 'http://127.0.0.1:3000'] |  | Allowed origins for the Next.js RedHand Command Center. |
| `SUPABASE_URL` | 'https://placeholder-project.supabase.co' |  | Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY` | (set) | yes | Service Role JWT used by redhand-core to bypass RLS during batch writes. |
| `GCP_PROJECT_ID` | 'redhand-security-sandbox' |  | Target Google Cloud Project ID for STS and Cloud Run telemetry. |
| `GOOGLE_APPLICATION_CREDENTIALS` | None |  | Optional path to base Service Account JSON for STS downscoping. |
| `REDHAND_ONNX_MODEL_PATH` | PosixPath('/root/.cache/redhand/deberta-v3-prompt-injecti... |  | Filesystem path to INT8-quantized ONNX prompt injection classifier. |
| `HITL_WEBHOOK_TIMEOUT_SECONDS` | 10.0 |  | HTTP timeout when firing resume webhooks to wake suspended agents. |
| `DEFAULT_HITL_TTL_SECONDS` | 3600 |  | Default expiration window for pending HITL circuit breaker checkpoints. |
| `SLACK_SIGNING_SECRET` | none | yes | Slack app signing secret. When unset, the Slack interactivity endpoint rejects every request (fail closed). |
| `OPERATOR_JWT_SECRET` | none | yes | HS256 mode: the shared secret that signs operator access tokens. Local development and tests only: any other ENVIRONMENT refuses to start with it set. In development/test a random per-process secret is generated when unset. Mutually exclusive with OPERATOR_JWKS_URL. |
| `OPERATOR_JWKS_URL` | None |  | JWKS mode: URL of the public keys that verify operator tokens, e.g. https://<ref>.supabase.co/auth/v1/.well-known/jwks.json (Supabase projects using asymmetric signing keys). Accepts ES256 and RS256 only. When set, HS256 tokens are rejected and OPERATOR_JWT_SECRET is ignored. |
| `OPERATOR_JWT_ISSUER` | None |  | Required with OPERATOR_JWKS_URL: the `iss` claim operator tokens must carry, e.g. https://<ref>.supabase.co/auth/v1. |
| `SLACK_ORGANIZATION_ID` | None |  | Organization whose HITL interventions the configured Slack app may resolve. |
| `SCIM_BEARER_TOKEN` | none | yes | Bearer token required on /scim/v2 endpoints. Unset disables SCIM. |
| `AGENT_TOKEN_SIGNING_KEY` | none | yes | Ed25519 private key (PEM) that signs agent access tokens. Required outside development/test; a random per-process key is used there when unset. |
| `SIGNUP_MODE` | 'invite' |  | Who may create an organization: 'invite' needs a single-use sign-up code the platform owner issued (default); 'closed' refuses everyone. Open self-serve sign-up is deliberately not offered yet. |
| `SIGNUPS_PER_HOUR_PER_USER` | 10 |  | Attempts to create an organization or accept an invite per user per hour. |
| `SIGNUPS_PER_HOUR_PER_SOURCE` | 30 |  | The same per source address (a stranger guessing codes). |
| `AGENT_TOKEN_TTL_SECONDS` | (set) | yes |  |
| `AGENT_TOKEN_EXCHANGES_PER_MINUTE` | (set) | yes |  |
| `AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE` | (set) | yes | Token exchanges one source address may attempt per minute, whatever keys it presents. Checked before any database read. |
| `TRUSTED_PROXY_HOPS` | 0 |  | How many proxies core runs behind (Cloud Run: 1). The source address is then the entry that many places from the right of X-Forwarded-For; 0 ignores the header. Never set higher than the real number: a caller controls everything to the left. |
| `INTERNAL_SERVICE_TOKEN` | none | yes | Shared secret the gateway (AgentWall) presents on /internal endpoints. When unset, those endpoints reject every call, so the gateway denies all traffic. |
| `GATEWAY_URL` | None |  | Base URL of the AgentWall gateway (for example https://redhand-gateway-xxxx.a.run.app). Used only for the MCP Scanner's live scan of registered servers; when unset that scan answers 503 and nothing else changes. |
| `TELEGRAM_BOT_TOKEN` | none | yes | Bot token from @BotFather. Never logged. Unset disables the Telegram feature. |
| `TELEGRAM_WEBHOOK_SECRET` | none | yes | Secret Telegram sends in X-Telegram-Bot-Api-Secret-Token on every webhook call (32-256 characters: letters, digits, '_' or '-'). Unset disables the webhook. |
| `TELEGRAM_BOT_USERNAME` | None |  | The bot's @username without the @; used to build the one-tap link. |
| `TELEGRAM_COMMANDS_PER_MINUTE` | 20 |  |  |
| `MAX_REQUEST_BYTES` | 1048576 |  | Largest request body core reads on any route, counted as the bytes arrive. Larger is answered 413. |
| `MAX_INGEST_REQUEST_BYTES` | 16777216 |  | The larger cap for the batched ingest routes (gateway event reports, trace ingest): up to 500 events or 250 spans a call. |
| `DASHBOARD_URL` | None |  | The dashboard's address, e.g. https://redhand.example.com. When set, Telegram alerts about one agent end with a link to that agent's incident view. https only outside development; no credentials, query or fragment. |
| `ALLOW_INSECURE_MCP_URLS` | False |  | Development only: allow http:// and localhost MCP server URLs. |
| `ALLOW_INSECURE_WEBHOOK_URLS` | False |  | Development only: allow http:// and localhost webhook URLs (resume, Slack, SIEM). Never set this on staging or production. |

## AgentWall gateway (`agentwall`, every name takes the `AGENTWALL_` prefix)
| Variable | Default | Secret | What it does |
|---|---|---|---|
| `AGENTWALL_HOST` | '0.0.0.0' |  | Bind address for the proxy server |
| `AGENTWALL_PORT` | 8080 |  | Listening port for AgentWall |
| `AGENTWALL_ENVIRONMENT` | 'development' |  | Runtime environment |
| `AGENTWALL_POLICY_FILE_PATH` | '/home/user/redhand/agentwall/config/policies.yaml' |  | Path to YAML policy definitions |
| `AGENTWALL_DEFAULT_IAM_PROVIDER` | 'local_sts' |  | Default provider for minting ephemeral tokens |
| `AGENTWALL_DEFAULT_TOKEN_TTL_SECONDS` | (set) | yes | Default JIT ephemeral token lifetime in seconds |
| `AGENTWALL_MAX_TOKEN_TTL_SECONDS` | (set) | yes | Hard upper bound for JIT ephemeral token lifetimes |
| `AGENTWALL_CORS_ALLOWED_ORIGINS` | ['http://localhost:3000', 'http://127.0.0.1:3000'] |  | Browser origins allowed to call the gateway (the dashboard). |
| `AGENTWALL_LOCAL_STS_SIGNING_SECRET` | none | yes | HMAC secret for the local development token provider. When unset, a random per-process secret is generated, so tokens never verify across restarts. |
| `AGENTWALL_CORE_URL` | 'http://localhost:8000' |  | Base URL of redhand-core (internal network). |
| `AGENTWALL_CORE_SERVICE_TOKEN` | none | yes | Must equal redhand-core's INTERNAL_SERVICE_TOKEN. Without it every agent call is denied because passports cannot be checked. |
| `AGENTWALL_AGENT_TOKEN_PUBLIC_KEY` | none | yes | Ed25519 public key (PEM) for agent access tokens. When unset, keys are fetched from core's /v1/agent-auth/jwks. |
| `AGENTWALL_CONTEXT_CACHE_TTL_SECONDS` | 2.0 |  | How long a passport lookup is reused. Capped so that, with a hanging core, the first refusal still comes within 4.5 s (revocation promise: 5 s). |
| `AGENTWALL_BUDGET_FLUSH_INTERVAL_SECONDS` | 5.0 |  | How often call counts are reported to core while there are unreported calls. |
| `AGENTWALL_BUDGET_MAX_TRACKED_KEYS` | (set) | yes | Most (agent, day) counters held in memory. A limited agent that cannot be tracked is refused. |
| `AGENTWALL_RECORDER_FLUSH_INTERVAL_SECONDS` | 2.0 |  | How often buffered Black Box events are reported to core (Phase 3 M1). |
| `AGENTWALL_RECORDER_MAX_BUFFERED_EVENTS` | 10000 |  | Most events held in memory before new ones are dropped (and counted) instead of blocking calls. |
| `AGENTWALL_RECORDER_MAX_BATCH_SIZE` | 500 |  | Most events sent to core in one report call. Must not exceed core's own per-batch limit. |
| `AGENTWALL_LOOP_DETECTION_ENABLED` | True |  | Kill switch for loop detection (Phase 4 M6). False skips the meter entirely, whatever the organization's mode says. |
| `AGENTWALL_DESTINATION_CHECK_ENABLED` | True |  | Kill switch for the destination allowlist (Phase 4 M7). False skips the check entirely, whatever an agent's mode says. |
| `AGENTWALL_TOKEN_VERSION_CHECK_ENABLED` | (set) | yes | Kill switch for the stale-token check (H4.1). False accepts a token issued for an older passport version again (a token from before an unfreeze, or before a scope or expiry change). Status and scopes still decide every call. |
| `AGENTWALL_STRICT_PINNING_ENABLED` | True |  | Kill switch for strict tool pinning (H4.2). False judges a tool this gateway process has not seen listed by its approved name alone again; True fetches the server's tool list on first use and judges the tool's current version (refusing when that cannot be done). |
| `AGENTWALL_REDACT_UPSTREAM_ERRORS_ENABLED` | True |  | Kill switch for redacting and bait-checking JSON-RPC errors from an MCP server (H4.3). False passes an upstream error through untouched again, as before; a secret or a bait value in its message or data then reaches the agent. |
| `AGENTWALL_RADAR_MODEL_ENABLED` | False |  | Also run the second-stage injection model in the Radar's background scan (about 8 ms more CPU per large result, never inline). |
| `AGENTWALL_ALLOW_INSECURE_UPSTREAMS` | False |  | Development only: allow http:// and private-network MCP server URLs. |
| `AGENTWALL_TRUSTED_PROXY_HOPS` | 0 |  | How many proxies the gateway runs behind (Cloud Run: 1). The caller's address is then the X-Forwarded-For entry that many places from the right; 0 ignores the header. Never set higher than the real number: a caller controls everything to the left. |
| `AGENTWALL_UPSTREAM_PIN_ENABLED` | True |  | Connect to the address the destination check approved (closes DNS rebinding). False connects by name again after the same check: a kill switch for a deployment where pinning misbehaves, not a setting to leave off. |
| `AGENTWALL_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | 5.0 |  |  |
| `AGENTWALL_UPSTREAM_TIMEOUT_SECONDS` | 30.0 |  |  |
| `AGENTWALL_MAX_UPSTREAM_RESPONSE_BYTES` | 5242880 |  |  |
| `AGENTWALL_MAX_REQUEST_BYTES` | 1048576 |  |  |
| `AGENTWALL_LOG_LEVEL` | 'INFO' |  | Structured logging level |
| `AGENTWALL_OTEL_SERVICE_NAME` | 'agentwall-proxy' |  | OpenTelemetry service name |
| `AGENTWALL_MODEL_PROXY_ENABLED` | False |  | PROTOTYPE (Phase 4.5 B5, ADR 0025). True mounts POST /v1/model/anthropic/v1/messages. Off by default: the route does not exist. Prototype only (ADR 0025): refuses to start outside development, dev, test, local and staging. |
| `AGENTWALL_MODEL_PROXY_ANTHROPIC_URL` | 'https://api.anthropic.com' |  | Provider base URL for the model proxy prototype. Prototype only (ADR 0025): refuses to start outside development, dev, test, local and staging. |
| `AGENTWALL_MODEL_PROXY_ANTHROPIC_KEY` | none | yes | The deployment's own provider key, held only in this process and sent only to the provider. Without it the proxy refuses every call. Prototype only (ADR 0025): refuses to start outside development, dev, test, local and staging. |
| `AGENTWALL_MODEL_PROXY_ALLOWED_MODELS` | '' |  | Comma-separated model ids allowed for the whole deployment; empty means the passport scopes alone decide. Prototype only (ADR 0025): refuses to start outside development, dev, test, local and staging. |
| `AGENTWALL_MODEL_PROXY_MAX_TOKENS_CAP` | 32000 |  | Largest max_tokens a proxied request may ask for. Prototype only (ADR 0025): refuses to start outside development, dev, test, local and staging. |
| `AGENTWALL_MODEL_USAGE_FLUSH_INTERVAL_SECONDS` | 5.0 |  | How often the model proxy reports the usage the provider counted to core (B5b). A daily dollar limit sees new spend only after this, plus core's processing and the passport cache lifetime, so a shorter interval means less overshoot and more calls to core. Prototype only (ADR 0025): refuses to start outside development, dev, test, local and staging. |
