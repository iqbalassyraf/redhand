# Runbook: stale tokens, strict tool pinning and upstream errors (hardening round H4)

**Product truth:** these checks apply to what flows through the RedHand gateway. They do not protect agents or credentials outside it.

## What you may see
| Symptom | Cause | What to do |
|---|---|---|
| An agent gets HTTP 401 "Agent access token is out of date. Request a new one." | The passport changed (freeze, unfreeze, scope or expiry edit) after the token was issued | Expected once: the client exchanges its agent key again (`POST /v1/agent-auth/token`). A client that never refreshes must be fixed. Metric: `redhand_gateway_decisions_total{reason="token_stale"}` |
| Agents get `token_stale` constantly | A client keeps using one token across changes, or something keeps editing the passport | Check the audit log for repeated passport changes; fix the client |
| In Enforce mode a call is refused "is not approved" for a tool that was approved | The server's current version of the tool differs from the approved one, or the first-use lookup failed | The Tools card on Radar shows the current version waiting for approval. For a failed lookup see `redhand_gateway_pin_events_total{event="first_use_failed"}` and the log line "Tool pin first-use check could not list the server's tools" |
| First call per server after a cold start is slower (about 1 s) in Enforce mode | The gateway fetched the server's tool list (initialize, initialized, tools/list) | Expected; `first_use_check` counts it |
| `first_use_skipped` rises | A server failed its check and is paused for 10 s so it is not asked on every call | Fix the server or its credentials; it recovers by itself |
| `first_use_busy` rises | More than 50 servers were being checked at once | Look for an unusual number of distinct servers or a slow upstream |
| An error message from a tool shows `[REDACTED...]` | The server put a secret in its error | Fix the server; the redaction is working |

## Kill switches (gateway environment variables; each `false` turns that one change off, nothing else)
| Variable | Off means |
|---|---|
| `AGENTWALL_TOKEN_VERSION_CHECK_ENABLED` | A token older than the passport is accepted again (status and scopes still decide) |
| `AGENTWALL_STRICT_PINNING_ENABLED` | An unseen tool in Enforce mode is judged by its approved name alone again |
| `AGENTWALL_REDACT_UPSTREAM_ERRORS_ENABLED` | A server's JSON-RPC error passes through untouched again |

Use one only to restore service, tell the owner, and put it back: each switch removes a protection. `deploy.sh` replaces environment values, so
setting one by hand is lost at the next deploy unless it is also passed to the script.

## Limits
- A token issued at the current version works until it expires or the passport changes: it is still a bearer credential.
- A tool change made after the first lookup is caught at the next listing or the next cold instance, not in the middle of a session.
- Redaction uses the egress guard's patterns: a secret in a format they do not know passes.
