# AgentWall: the RedHand MCP gateway

AgentWall sits between AI agents and their MCP tool servers and enforces each agent's
**Agent Passport** on every message. It is the Phase 1 control point (see
[`docs/adr/0001-gateway-as-control-point.md`](../docs/adr/0001-gateway-as-control-point.md)).

## What it does per message (`POST /mcp/{server}`)

1. Verifies the agent's access token (Ed25519 JWT from redhand-core: issuer, audience, expiry).
2. Loads the passport context from redhand-core: status, scopes and the tenant's upstream URL for
   `{server}`. Cached for at most 2 seconds so freezes and revocations land within the 5-second SLO.
3. Denies unless the passport is `active` and the server is registered for the tenant.
4. Allows only `initialize`, `ping`, `tools/list`, `tools/call` and the initialized/cancelled
   notifications. For `tools/call`, the tool must match a passport scope and pass the optional
   argument guardrails in `config/policies.yaml` (SQL AST checks, shell allowlist, schema).
5. Forwards to the MCP server (Streamable HTTP; JSON or SSE responses; no redirects; size and time
   limits; destination must be https and public unless insecure upstreams are allowed for
   development), filters `tools/list` to permitted tools, redacts secrets from tool results.
6. Records the decision in the hash-chained audit log and Prometheus metrics.

Every failure denies: missing or invalid token → 401, inactive passport → 403, core unreachable →
503, upstream failure → 502. There is no fail-open mode.

## Other endpoints

| Endpoint | Access |
|---|---|
| `POST /v1/mcp/vet` | Public, rate-limited. Heuristic static vetting of a pasted MCP manifest; fetches nothing |
| `GET /v1/policies`, `GET /metrics` | Service token (`AGENTWALL_CORE_SERVICE_TOKEN`) |
| `GET /health` (also `/healthz`) | Public. Use `/health` on Cloud Run, which can intercept `/healthz` |

## Configuration

All settings use the `AGENTWALL_` prefix; see the repository's [`.env.example`](../.env.example).
The important ones:

- `AGENTWALL_CORE_URL` and `AGENTWALL_CORE_SERVICE_TOKEN` (must equal core's
  `INTERNAL_SERVICE_TOKEN`; without it every call is denied).
- `AGENTWALL_AGENT_TOKEN_PUBLIC_KEY` (optional; otherwise core's JWKS is used).
- `AGENTWALL_CONTEXT_CACHE_TTL_SECONDS` (default 2, max 2.5).

## Run

From the repository root:

```bash
AGENTWALL_CORE_SERVICE_TOKEN=<token> uv run uvicorn agentwall.src.main:app --port 8080
```

## Tests

```bash
uv run pytest -q agentwall
```

## Not used by the Phase 1 gateway

`src/broker/` contains token providers for AWS, Azure, GCP, SaaS and Vault. They are **simulated**
(they generate token-shaped strings locally) and are kept for the enterprise credential-broker
track. Delegated per-user roles (`required_user_roles` in the policy file) are evaluated by the
engine but are not used on the gateway path until delegated identity can be cryptographically
bound to the caller.
