# Runbook: MCP Scanner

Checks a tool server before agents use it. **Product truth:** RedHand only covers agents that connect through the RedHand
gateway, and a pass is not a guarantee: the rules catch known patterns and miss rephrased attacks.

## Use it
Dashboard -> **MCP Scanner**.
- **Scan a registered server (admin):** click Scan next to a server. The gateway asks the server for its tool list the way an
  agent would, through the gateway's safety checks (public addresses only), and audits it. Results are shown, not stored.
- **Check a pasted manifest (anyone signed in):** paste the manifest JSON and click Check. Nothing is fetched or stored. Do
  not paste real credentials.
Read the verdict (PASS, WARN, FAIL), then each finding: severity, tool, rule id, what to do. Text that came from the server is
shown as plain text and findings never quote it.

## Tool pinning (notice when a server changes a tool)
Dashboard -> **MCP Scanner** -> **Tool pins** on a server. When an agent lists the server's tools through the gateway, each
tool version appears as **pending**. Review the description and schema (plain text), then Approve or Reject, or **Approve
all pending** for the first baseline once you have reviewed them. If the server later changes a tool you approved, the new
version appears as pending ("changed since you approved it"), with the approved text beside it, and you get one Telegram
alert per server per ten minutes (counts only, never the tool text).
- **Mode:** `off` (no checks), `alert` (default; report only), `enforce` (agents see and can call only tools whose current
  version you approved; a changed or new tool is hidden and refused until you approve it). Changing the mode needs an admin
  and a confirmation. **Approve the current tools before turning enforce on**, or agents lose them.
- Rejecting a version keeps it out; in enforce mode a rejected change stays hidden. Approving supersedes the old version.
- Limits: it only sees tools when an agent lists them through the gateway; it cannot see a tool that behaves differently under
  an unchanged description; a tool never listed through the running gateway is judged by name alone in enforce mode.
- Deploy order: migration, **core**, then gateway (the gateway requires fields only the new core sends).

## Finding ids
MCP-SEC-001 to 009: shell or interpreter launch, secrets in environment variables, exec, filesystem, database and network
tools, missing or loose schemas. MCP-DESC-001 to 009: description rules (hide from the user, override instructions,
hidden-instruction markers, read sensitive data, send data outside, call other tools first, invisible characters, length or
tool-choice manipulation, run commands without approval).

## Set up live scans (deploy)
Core needs the gateway's address: set `GATEWAY_URL` on `redhand-core` (and `INTERNAL_SERVICE_TOKEN`, already set). Without it
the scan button answers "Live scanning is not configured" (503) and nothing else is affected. `deploy/cloudrun/deploy.sh` replaces
all environment variables on deploy, so the value must be passed by the script (see the open PR for that change) or set again
after each core deploy:
```
gcloud run services update redhand-core --region asia-southeast1 --update-env-vars GATEWAY_URL=<gateway url>
```

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| 503 "not configured" | `GATEWAY_URL` is not set on core |
| 503 "misconfigured" | the gateway rejected core's service token (the two tokens differ) |
| 502 "did not return a tool list" | the server needs credentials to list its tools, or is not an MCP server |
| 502 "non-public address" or "must use https" | the registered URL fails the destination check (as it would for agents) |
| 429 | more than 20 scans a minute across the gateway; wait |
| Agents lost a tool after enforce | its current version is not approved: approve it in Tool pins, or set the mode back to alert |
| A harmless tool is flagged | report it: add it to the benchmark corpus as a benign sample, then change the rule |

## Limits
Static, text-only: cannot see what a tool does when called. A description over 8 KiB is flagged for length and only its first
8 KiB is read for phrases. Pattern rules are not a substitute for reviewing a server you do not trust.
