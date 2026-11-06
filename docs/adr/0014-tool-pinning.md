# ADR 0014: Tool pinning

**Status:** Accepted (2026-11-07). Phase 4 M3. Plan: `docs/plans/phase4-plan.md`. Builds on ADR 0013 (MCP Scanner).

## Context
A tool description is read by the agent, and an MCP server can change it after the owner approved it (a "rug pull"): the
tool that was harmless on Monday carries a hidden instruction on Friday. A one-off scan cannot see that, because it
only looks at one moment.

## Decision
- **A tool version is the SHA-256 of its canonical name, description and input schema.** The gateway computes it whenever a
  server's `tools/list` passes through it (`agentwall/src/gateway/pins.py`).
- **Reporting never blocks.** Versions the process has not reported before are sent to core in the background
  (`POST /internal/v1/tool-observations`, service token): non-blocking, retried, 4xx dropped, at most 20 in flight; a
  report that fails is forgotten so the next listing sends it again. Memory is bounded (20,000 entries).
- **Core stores each new version as PENDING** (`mcp_tool_pins`), with the description and schema capped at 2,000 and 8,000
  characters, only so the owner can review what changed. The text came from a server and is untrusted: it is shown as plain
  text and never put in an alert. Alerts carry counts and the server slug, at most one per server per ten minutes.
- **The owner decides.** An admin approves or rejects a pending version (compare-and-set, audited). Approving a version
  supersedes that tool's previous approved version, so one version per tool is approved. "Approve all pending" is for the
  first baseline and needs confirmation. Limits: 500 tools per server, 20 versions per tool.
- **Per-server mode:** `off`, `alert` (default: report only; agents see and call everything) or `enforce`. In enforce mode the
  gateway shows an agent only tools whose current version is approved, and refuses calls to a tool whose name is not approved
  or whose last-seen version is not the approved one. Every mode change needs an admin and confirmation and is audited.
- **Context stays small:** core sends the approved list only in enforce mode; the gateway requires `pin_mode` and
  `approved_tools` in the server context and denies if they are missing (an older core), like the earlier required fields.
  **Deploy core before the gateway.**
- **Fails closed in enforce mode:** a failure checking the list shows no tools (not unchecked ones), and a core that cannot
  read the approved list answers 503 so the gateway denies. In alert mode pinning is a side effect: a failure only counts.

## Alternatives considered
- **Trust on first use (auto-approve the first sighting):** an attacker who poisons a tool before the first listing would be
  trusted forever. Rejected: the owner approves the baseline.
- **Re-scan on a schedule:** misses changes between scans and adds a poller. Deferred.
- **Pin the whole server manifest:** coarser, so every harmless change alerts. Rejected: per-tool versions.
- **Block in the gateway without core's list (hash allowlist in a file):** no owner workflow, no audit. Rejected.

## Consequences and limits
- It fires only when an agent lists tools through this gateway (also when an agent would read a changed description).
- It cannot see a tool that behaves differently under an unchanged description.
- In enforce mode, a tool never listed through the current gateway process is judged by name alone until it is listed.
- A change takes effect at the next context refresh (a few seconds); gateways keep their own memory per process.
- Turning enforce on before approving the baseline hides every tool; the dashboard says so and asks for confirmation.
