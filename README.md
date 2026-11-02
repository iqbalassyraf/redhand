# RedHand

RedHand is a security and control layer for AI agents. It gives every agent a **passport**
(who owns it, which tools it may use, until when), puts a **gateway** between agents and their
MCP tool servers, and lets you **freeze or revoke** one agent, or all of them, in seconds.

> **What RedHand can and cannot stop:** RedHand controls agents that connect through the RedHand
> gateway. Agents that hold raw API keys or reach tools directly, outside the gateway, are not
> covered.

Product scope and the phase plan live in [`docs/briefing.md`](docs/briefing.md). Working rules for
contributors (and Claude Code) are in [`CLAUDE.md`](CLAUDE.md).

---

## 1. How Phase 1 works

```
 Operator ──login──▶ Dashboard (apps/redhand-ui) ──▶ redhand-core (:8000)
                                                      passports, keys, freeze / revoke,
                                                      audit log, operator auth, tenants
                                                          ▲            ▲
                         agent key → 10-min access token  │            │ passport status + scopes
                                                          │            │ (cached ≤ 2 s)
 Agent (Claude, n8n, custom) ──── MCP + access token ──▶ AgentWall gateway (:8080) ──▶ your MCP server
                                                          checks passport on every call,
                                                          denies on any error
```

1. An operator registers an agent in the dashboard. RedHand creates its passport and shows an
   **agent key** once.
2. The agent exchanges the key at `POST /v1/agent-auth/token` for a **10-minute access token**.
3. The agent talks MCP to `https://<gateway>/mcp/<server>` with that token. For each message the
   gateway verifies the token, checks the passport is active and that the tool is in its scopes,
   applies argument guardrails, forwards to the customer's MCP server, filters `tools/list`, and
   redacts secrets from results.
4. **Freeze**, **revoke** or **freeze all** in the dashboard. The gateway denies the agent's next
   call within about 2 seconds (always under the 5-second target), even if its token is still valid.

Design decisions are recorded in [`docs/adr/`](docs/adr), threats in
[`docs/security/threat-model.md`](docs/security/threat-model.md), API contracts in
[`docs/api/`](docs/api), and operational procedures in [`docs/runbooks/`](docs/runbooks).

---

## 2. What is in the repository

| Component | Path | Status |
|---|---|---|
| **redhand-core**: FastAPI control plane: passports, agent keys and tokens, control actions, audit log, operator auth, HITL approvals | `services/redhand-core/` | Working. Runs on Supabase Postgres, or an in-memory store in development |
| **AgentWall**: MCP gateway with passport enforcement, SQL/shell guardrails, secret redaction | `agentwall/` | Working |
| **Dashboard**: Next.js login, Passports page, command center | `apps/redhand-ui/` | Passports page is live. The command center's canvas, traces and simulations are **sample data** (labelled in the UI) |
| **MCP manifest vetting** (`POST /v1/mcp/vet`) | `agentwall/src/firewall/mcp_vetting.py` | Keyword and schema heuristics on a pasted manifest. A seed for the Phase 4 scanner, not a safety guarantee |
| **Database schema and migrations** | `supabase/migrations/`, `supabase/rollbacks/` | Phase 1 migration tested on PostgreSQL 16 (up, rollback, re-apply) |
| **Python SDK** (`@guard`, `redhand scan`, `redhand fuzz`) | `packages/redhand-sdk/` | Working, but enforcement in the SDK is voluntary; the gateway is the control point |
| AgentWall cloud token providers (AWS, Azure, GCP, SaaS, Vault) | `agentwall/src/broker/` | **Simulated**: generate token-shaped strings locally; not used by the Phase 1 gateway |
| core GCP/AWS credential downscoping | `services/redhand-core/src/redhand_core/services/` | Real API calls when cloud credentials exist; **falls back to simulated tokens** without them |
| SCIM 2.0 | `services/redhand-core/src/redhand_core/routers/scim.py` | Enterprise feature, disabled unless `SCIM_BEARER_TOKEN` is set; in-memory demo storage |
| In-VPC sidecar and Helm chart | `packages/redhand-sidecar/`, `deploy/` | Enterprise / self-host track; the sidecar's MCP route uses a dummy upstream |
| Attack battleground | `battleground/` | Demo only |

---

## 3. Local quickstart (development)

Prerequisites: Python 3.11+, [uv](https://github.com/astral-sh/uv), Node.js 18+.

```bash
uv sync
```

```bash
npm --prefix apps/redhand-ui install
```

Pick a shared service token for core and the gateway (any long random string):

```bash
export RH_SERVICE_TOKEN=$(openssl rand -base64 32)
```

**Terminal 1: redhand-core** (development mode uses an in-memory store with demo operators):

```bash
cd services/redhand-core && ENVIRONMENT=development ALLOW_INSECURE_MCP_URLS=true INTERNAL_SERVICE_TOKEN=$RH_SERVICE_TOKEN uv run uvicorn redhand_core.main:app --port 8000
```

**Terminal 2: AgentWall gateway:**

```bash
AGENTWALL_CORE_SERVICE_TOKEN=$RH_SERVICE_TOKEN AGENTWALL_ALLOW_INSECURE_UPSTREAMS=true uv run uvicorn agentwall.src.main:app --port 8080
```

**Terminal 3: a demo MCP server** (canned invoice tools):

```bash
uv run uvicorn examples.demo_mcp_server:app --port 9100
```

**Terminal 4: dashboard:**

```bash
npm run dev
```

Then open `http://localhost:3000`, choose **Continue as Owner**, and on the Passports page:

1. Register an MCP server: slug `xero`, URL `http://localhost:9100/mcp`.
2. Register an agent with scope `xero` / `list_invoices`. Copy the agent key.

Call a tool as the agent:

```bash
TOKEN=$(curl -s -X POST localhost:8000/v1/agent-auth/token -H "Authorization: Bearer <agent key>" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

```bash
curl -s localhost:8080/mcp/xero -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{}}}'
```

`delete_invoice` is refused because it is not in the passport's scopes. Freeze the agent in the
dashboard and the same call returns HTTP 403 within about 2 seconds.

Never use `ENVIRONMENT=development`, `ALLOW_INSECURE_MCP_URLS` or
`AGENTWALL_ALLOW_INSECURE_UPSTREAMS` in production. All settings are listed in
[`.env.example`](.env.example).

### Connecting an MCP client

Point the client at the gateway URL for the server and send the agent's access token:

```json
{
  "mcpServers": {
    "xero-via-redhand": {
      "url": "https://<gateway>/mcp/xero",
      "headers": { "Authorization": "Bearer <agent access token>" }
    }
  }
}
```

If the MCP server needs its own credential, send it as `X-RedHand-Upstream-Authorization`; the
gateway forwards it as `Authorization` and never logs it. Access tokens last 10 minutes; agents
renew them with their agent key.

Phase 1 forwards `initialize`, `ping`, `tools/list`, `tools/call` and the initialized/cancelled
notifications. Resources and prompts are refused until passport scopes cover them. Only remote
(HTTP) MCP servers are supported; local stdio servers are not.

---

## 4. Verification

```bash
uv run pytest -q
```

```bash
uvx ruff@0.17.3 check --config pyproject.toml .
```

```bash
uv run --with mypy==2.4.1 mypy
```

CI (`.github/workflows/ci.yml`) runs the same checks plus the dashboard type-check and build on
every push. The strict type-check covers the modules listed under `[tool.mypy]` in
`pyproject.toml`; older modules are added as they are brought up to standard.

```bash
npm --prefix apps/redhand-ui run typecheck
```

```bash
npm --prefix apps/redhand-ui run build
```

- `tests/e2e/test_phase1_done.py` runs the four Phase 1 "done" tests end to end (core, gateway
  and the demo MCP server wired together in-process).
- Gateway overhead benchmark, in-process (excludes network and upstream time):

```bash
PYTHONPATH=. uv run python scripts/benchmark_gateway.py
```

  Last run on a development container (2026-11-01): p50 0.57 ms, p99 1.11 ms with the passport
  cached; p50 0.90 ms, p99 1.74 ms with a lookup on every call; revocation reached the gateway
  after 2.02 s. Budgets: p50 ≤ 10 ms, p99 ≤ 50 ms, revocation ≤ 5 s.

---

## 5. Other demos

- **Attack battleground** (sample data):

```bash
uv run python battleground/run_battle.py
```

- **SDK demo:**

```bash
uv run redhand demo
```

- **MCP manifest vetting:** `POST` a manifest to `http://localhost:8080/v1/mcp/vet`. Results are
  heuristic; a `PASS` is not a guarantee that a server is safe.

---

## 6. License

The previous README stated Apache License 2.0, but no `LICENSE` file is present in the repository.
Add one before distributing.
