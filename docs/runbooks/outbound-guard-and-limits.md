# Runbook: outbound webhook guard, pinned upstream connections and request limits (hardening round H2)

**Product truth:** these checks stop RedHand being used to call internal addresses and stop one request from using unbounded memory. They do
not make a customer's own webhook or MCP server trustworthy.

## What refuses what
| What you see | Where | Cause | What to do |
|---|---|---|---|
| `HTTP 413` with `{"detail":"Request body too large."}` | core or gateway | Body over 1 MiB (core: 16 MiB on `/internal/v1/events` and `/v1/telemetry`; gateway: `MAX_REQUEST_BYTES`) | A legitimate client sends less. If a real report batch is refused, check `RECORDER_MAX_BATCH_SIZE` (500) and raise `MAX_INGEST_REQUEST_BYTES` only with the evidence |
| A resume or notification webhook rejected at submission (HTTP 422 naming the field) | core ingest | The URL is not https, has credentials, names a local or internal host, or is a non-public address | Use a public https URL. The address is checked again when the webhook is called |
| A Slack or SIEM alert never arrives and `redhand_outbound_blocked_total{purpose}` rises | core | The stored URL fails the guard (for example plain http, or a name that now resolves to a private address). It is refused every time: no retry | Log shows the host only. Fix the URL in the organization settings |
| Calls to an MCP server fail with "Upstream resolves to a non-public address." | gateway | One of the addresses the name resolves to is private | Correct the DNS record; do not turn the check off |
| Calls fail with "Upstream MCP server is unreachable." right after a deploy | gateway | The connection to the pinned address failed (certificate name, routing) | Check the server from outside. Emergency only: set `AGENTWALL_UPSTREAM_PIN_ENABLED=false` (same check, connects by name); open an issue, because the DNS-rebinding window returns while it is off |
| Calls fail with "Upstream MCP server did not answer in time." | gateway | The whole call (lookup, connections, body) took longer than `UPSTREAM_TIMEOUT_SECONDS` (30 s) | Look at the upstream; raise the limit only if the tool is legitimately slow |
| A service will not start; the log says `ALLOW_INSECURE_...` may only be set when ENVIRONMENT is development or test | core or gateway | A development-only flag is set in a shared environment, or the gateway's `AGENTWALL_ENVIRONMENT` is not a known local name | Remove the flag. Never set `ENVIRONMENT=development` on a shared deployment to get round this |

## Numbers
- `redhand_outbound_blocked_total{purpose}` (core): `resume`, `slack`, `siem`.
- Gateway logs `Upstream MCP server unreachable` (error type only) and `Upstream MCP server did not finish in time`.

## Limits
- Only webhooks core calls and MCP upstreams the gateway calls. Core's MCP-server registration (`validate_mcp_server_url`) is a separate copy of
  the same rules.
- Body limits are per request. Many requests are a rate-limit question.
- Pinning picks the first checked addresses (IPv4 first, at most 3). A host whose first three addresses are all down is reported unreachable.
