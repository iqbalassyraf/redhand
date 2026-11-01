# ADR 0001: The MCP gateway is the control point

- **Status:** Accepted (2026-11-01)
- **Phase:** 1

## Context
RedHand must be able to stop an agent, not just observe it. Three options were considered: an
in-path gateway, a credential broker, and an SDK inside the agent's code.

## Decision
Agents reach their tools through AgentWall, an MCP Streamable HTTP gateway (`POST /mcp/{server}`).
The gateway checks the Agent Passport on every message and denies on any error. MCP is the only
protocol in v1.

## Alternatives
- **SDK only** (`redhand-sdk` `@guard`): easiest to adopt, but enforcement is voluntary; a hijacked
  agent can skip it. Kept for telemetry and developer ergonomics, not enforcement.
- **Credential broker first:** strongest (holds even if the gateway is bypassed) but requires
  customers to hand RedHand their upstream credentials. Planned as Phase 1.5.
- **Also proxy REST APIs:** roughly doubles the work; deferred. The header-trusting legacy REST
  endpoint was removed.

## Consequences
- RedHand only controls traffic that flows through the gateway. Product copy must say so.
- MCP servers that run locally over stdio are not covered in v1 (a local shim would be needed).
- Resources and prompts methods are refused until passport scopes describe them.
- We run the traffic: latency and availability budgets in CLAUDE.md §8 apply.
