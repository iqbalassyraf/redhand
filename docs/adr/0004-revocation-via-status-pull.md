# ADR 0004: Revocation via per-call status lookup with a 2-second cache

- **Status:** Accepted (2026-11-01)
- **Phase:** 1

## Context
The revocation SLO is 5 seconds worst case (CLAUDE.md §4.5), even while a stolen access token is
still valid.

## Decision
For every message, the gateway asks core's internal endpoint
`GET /internal/v1/gateway-context` (service-token authenticated) for the passport's status,
version, scopes and the tenant's MCP server URL. Answers are cached per (agent, tenant, server)
for at most 2 seconds by default; configuration cannot exceed 4 seconds. Failures are never cached
and always deny.

Measured: a revocation reached the gateway after 2.02 s (scripts/benchmark_gateway.py).

## Alternatives
- **Push invalidation from core (pub/sub):** faster, but needs a message bus to operate.
- **Rely on token expiry only:** would leave a 10-minute window.

## Consequences
- Core availability is on the enforcement path: if core is down, agents are denied (fail closed).
- At most one internal lookup per agent and server every 2 seconds.
