# Runbook: a frozen or revoked agent is still being served

**Expected behaviour:** a freeze or revoke takes effect within the context cache TTL (default 2 s,
max 4 s) and always within 5 s.

1. Confirm the passport status in the dashboard (Passports page) or `GET /v1/passports/{id}`.
2. Confirm the agent is calling through the RedHand gateway (`/mcp/<server>`). RedHand cannot stop
   calls made directly to the MCP server with the customer's own credentials.
3. Check `AGENTWALL_CONTEXT_CACHE_TTL_SECONDS` (values above 2.5 are refused at startup; the gateway also clamps to 2.5).
4. Check the gateway's audit log (`GET /v1/audit/logs` with the service token) for the agent's
   recent decisions and `passport_frozen` / `passport_revoked` reasons.
5. If calls still succeed after 5 s, freeze the whole tenant (Freeze all agents) and escalate:
   this is an SLO breach.
