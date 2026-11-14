# Runbook: browser headers, rate limits, trusted proxy hops and dependency audits (hardening round H3)

**Product truth:** these are defences in depth. The dashboard is never a security boundary: core and the gateway authorize every action.

## What you may see
| Symptom | Cause | What to do |
|---|---|---|
| A dashboard page is blank or a feature stops; the browser console says "Refused to ... Content Security Policy" | A script, style, image or address the policy does not allow | Read the directive in the message. A new address the dashboard must call goes in `NEXT_PUBLIC_REDHAND_CORE_URL`, `..._GATEWAY_URL` or `..._SUPABASE_URL` (the policy reads them); do not add `'unsafe-inline'` for scripts |
| Dashboard pages are slow to first byte | Every page is rendered per request (needed for the nonce) | Expected; pages are small client apps |
| `HTTP 429` "Too many token requests from this address." | One source address made more than `AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE` (300) attempts in a minute | Agents behind one egress address share it: raise the setting with evidence. Not an attack by itself; look at the 401 rate |
| Per-address limits seem to count everyone together | `TRUSTED_PROXY_HOPS` is 0 behind a proxy, so the proxy is the "address" | Cloud Run: it must be `1` (core) and `AGENTWALL_TRUSTED_PROXY_HOPS=1` (gateway); `deploy.sh` sets both |
| Per-address limits can be stepped round with forged headers | The hop count is higher than the real number of proxies | Set it to the real number. Never use uvicorn `--forwarded-allow-ips '*'` |
| Core will not start; log says `OPERATOR_JWT_SECRET ... only allowed when ENVIRONMENT is 'development' or 'test'` | A shared operator secret in a shared environment | Remove it; set `OPERATOR_JWKS_URL` and `OPERATOR_JWT_ISSUER` (Supabase: enable JWT signing keys) |
| CI fails at "Dependency audit" | A new advisory for a locked dependency | Upgrade the package (Dependabot may already have a pull request) or, if it cannot affect us, record why in the pull request. Never add `continue-on-error` |

## Numbers
- The dashboard policy and headers: `curl -sI https://<dashboard>/login`.
- Answer headers: `curl -sI <core-or-gateway>/health` (`nosniff`, `no-store`, HSTS).

## Limits
- Rate limits are per instance (single instance today); with N instances the effective limit is up to N times higher.
- Styles allow inline; the operator token is in sessionStorage, readable by any script that does run (tracked follow-up: httpOnly cookies).
- GitHub Actions are pinned by tag, not commit SHA.
