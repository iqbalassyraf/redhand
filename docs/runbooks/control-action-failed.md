# Runbook: "The action could not be completed. Reload to see the current state."

**Meaning:** a control action (freeze, revoke, key rotation, and so on) failed inside the
database. Each action and its audit row run in one transaction, so **a failed action changes
nothing**: the passport, its keys and the audit log are exactly as before.

The one case where the outcome is unknown is a network timeout after the database committed but
before core received the answer. That is why the message says to reload.

1. Reload the Passports page (or `GET /v1/passports/{id}`) to see the real state.
2. If the action did not apply, repeat it. Freeze, unfreeze, revoke and the other actions are
   safe to repeat: they report `changed: false` when the state already matches.
3. If it keeps failing, find the log line in core:
   `Control action failed and was rolled back: function=control_... sqlstate=...`.
   The SQLSTATE says why; the database message is deliberately not logged because it can echo
   submitted values.
4. Check database health. If the database is unavailable the gateway is already denying agent
   calls (fail closed), so agents are not running unchecked while you fix it.

**If you need an agent stopped and freezing fails:** use *Freeze all agents*, which is the same
database path. If the database itself is down, stop the agent's access at the source (revoke the
credential at the MCP server); RedHand cannot act on traffic it cannot check.
