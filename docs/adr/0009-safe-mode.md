# ADR 0009: Safe Mode (read-only enforcement)

- **Status:** Accepted (2026-11-03)
- **Phase:** 2 (M2)
- **Plan:** `docs/plans/phase2-m2-safe-mode.md`

## Context
Scopes have recorded an `access` of read or write since Phase 1, but the gateway ignored it. Phase 2
asks for a way to put agents into a mode where they can look but not change things, quickly, during an
incident or while an agent is being trusted with a new task.

## Decision
- Two flags: `agents.safe_mode` and `organizations.safe_mode`. Safe Mode is in effect when either is on.
- While in effect, the gateway allows a `tools/call` only if a scope with access `read` covers the tool.
  A tool covered only by `write` scopes is refused, with its own reason (`safe_mode`) in the audit
  record and metrics. `tools/list` is filtered by the same rule.
- Core tells the gateway the effective flag in `/internal/v1/gateway-context`. The gateway's lookup
  requires it to be a real boolean: a core that does not send it, or sends anything else, makes the
  lookup fail and the call is denied (fail closed). Core itself reads anything other than a stored
  `false` as ON.
- Control actions (`control_agent_safe_mode`, `control_org_safe_mode`) are single database transactions
  with an audit row, idempotent, tenant-scoped, service-role only (same pattern as ADR 0006).
- Turning ON needs a security operator or higher, like freeze. Turning OFF needs an admin or owner and an
  explicit confirmation, like unfreeze. Telegram can turn it ON (`/safemode on [agent]`) but never OFF.
- The dashboard form defaults new scopes to **write**, so an undeclared tool is suspended by Safe Mode.

## What it does not do (stated in the dashboard, docs and code)
RedHand cannot verify that a tool really is read-only. The operator declares it when granting the scope,
and a `*` scope declared read means every tool on that server is declared read. MCP servers' own
read-only hints are self-declared by the server and are not trusted. Safe Mode is only as accurate as
the declarations.

## Alternatives
- **Infer read or write from tool names or server hints:** guesswork; a wrong guess silently allows writes.
- **A separate tool classification table:** more to maintain; deferred until customers need it.
- **Only an organization-wide switch:** too blunt for "this one agent is acting strangely".

## Consequences
- Deploy order: core first, then the gateway. A new gateway talking to an old core denies everything (it
  needs the flag), which is visible, not silent. An old gateway ignores the flag, so do not turn Safe Mode
  on until both are updated.
- Rolling back the migration drops the flags: agents return to normal enforcement.
- The cache window (2 s) bounds how long a change takes to reach the gateway, within the 5 s SLO.
