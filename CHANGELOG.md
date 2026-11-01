# Changelog

## Unreleased: Phase 1 (Identity and control)

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
