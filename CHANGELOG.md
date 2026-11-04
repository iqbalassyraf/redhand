# Changelog

## Unreleased: Phase 2 (Stop things), in progress

### Added
- Budget Guard (M3): a daily cap on the tool calls an agent makes through the gateway. Set it per agent in
  the dashboard (**Limit**); over the cap the gateway refuses further calls, linked Telegram chats are alerted
  at 80% and 100%, and the agent can optionally be frozen automatically (recorded as "RedHand Budget Guard").
  `/usage` on Telegram and a **Calls today** column show usage. Counts calls, not money or LLM tokens. New
  migration `20261105000000_budget_guard.sql`. **Deploy order: migration, core, then the gateway**: the gateway
  now requires core to send `budget` and denies every call otherwise (`docs/runbooks/budget-guard.md`,
  ADR 0010). Raising or removing a limit needs an admin and a confirmation.
- Safe Mode (M2): put one agent, or all agents, into read-only mode. The gateway then allows only
  tools declared `read` in the agent's scopes and hides the rest from `tools/list`. Turn it on from the
  dashboard or with `/safemode on [agent]` in Telegram; turning it off needs an admin in the dashboard.
  New migration `20261104000000_safe_mode.sql`. **Deploy core before the gateway**: the gateway now
  requires core to send `safe_mode` and denies every call otherwise (`docs/runbooks/safe-mode.md`,
  ADR 0009). RedHand cannot verify a tool is read-only; the operator declares it. New scopes in the
  dashboard default to `write`.
- Telegram panic command (M1): linked admins and owners can `/freeze_all`, `/freeze <name>` and
  `/status` from a phone; unfreeze and revoke stay in the dashboard. Linked chats are also alerted
  about freezes, unfreezes, revokes and freeze-all done in the dashboard. Needs a bot token and the
  new migration `20261103000000_telegram_panic.sql`; set up with `deploy/cloudrun/deploy.sh telegram`
  and `scripts/telegram_webhook.py` (`docs/runbooks/telegram-panic-command.md`, ADR 0008).
- Dashboard: "Telegram panic command" panel to link a phone and unlink lost ones.
- New control audit actions `telegram.linked` and `telegram.unlinked`.

## Phase 1 (Identity and control)

### Added (deployment)
- `scripts/staging_agent.py`: a stand-in agent (standard library only) that runs the Phase 1 checks
  against a deployed stack and a real MCP server, and shows freeze / revoke / freeze-all taking
  effect live (`docs/runbooks/staging-agent-test.md`).
- Cloud Run staging deployment: Dockerfiles for core and the gateway, a Cloud Build config, `deploy.sh`
  (secrets in Secret Manager, per-service identities) and `smoke.sh` (`deploy/cloudrun/`).

### Changed (hardening)
- Core's `/metrics` now needs the service token (`INTERNAL_SERVICE_TOKEN`), like the gateway's. Without
  a configured token it answers 503. Anything that scrapes core's metrics must send
  `Authorization: Bearer <token>`.
- Dashboard: edit an agent's scopes after registration, a warning when registering or saving an agent
  with no scopes, and MCP server names (not just "mcp_server") in the control audit log.
- Operator login also works with Supabase projects that use asymmetric signing keys: core verifies
  ES256/RS256 tokens against the project's JWKS (HS256 shared-secret mode remains for local
  development). Core refuses to start outside development unless exactly one mode is configured.
- Every control action and its audit entry now commit in one database transaction. A failed audit
  write rolls the action back instead of leaving an unrecorded change. Concurrent changes to the
  same passport are detected and retried once, then answered with 409.
- Database function hardening from Supabase's security advisor: pinned `search_path` on the trigger
  functions and no `anon` access to `get_user_organization_ids()`.
- GitHub Actions CI (ruff, strict mypy on the Phase 1 modules, pytest, dashboard type-check and
  build) runs on every push.


### Added
- Agent Passports: owner, backup owner, scopes per MCP server and tool, expiry, status
  (active / frozen / revoked / expired) and version.
- Control actions with an append-only audit log: freeze, unfreeze (confirmed), revoke (permanent),
  freeze all agents, scope changes, renewal and key rotation.
- Agent keys exchanged for 10-minute signed access tokens.
- AgentWall MCP gateway at `/mcp/{server}` that enforces passports on every message and fails
  closed.
- Operator login (Supabase Auth, or a development login) with roles and tenant isolation.
- Dashboard Passports page with the "Freeze all agents" kill switch.
- Demo MCP server (`examples/demo_mcp_server.py`), end-to-end tests and a gateway benchmark.

### Changed
- Every core endpoint except health, agent token exchange and the public JWKS requires
  authentication; HITL approvals use the authenticated operator as reviewer.
- Upstream failures return errors instead of a simulated success.
- Audit records store argument names and a digest instead of raw tool arguments.
- The dashboard lives only in `apps/redhand-ui` (the duplicate root app was removed).

### Removed
- AgentWall `/mcp`, `/mcp/rpc` and `/v1/tools/execute`, which trusted `X-Agent-ID` and
  `X-User-Roles` headers.
- `PATCH /v1/state/agents/{id}/posture` (replaced by passport control actions).
