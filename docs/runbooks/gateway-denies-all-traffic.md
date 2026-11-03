# Runbook: the gateway denies every agent call

**Symptom:** agents get HTTP 503 with JSON-RPC error `-32003` ("Passport service unavailable") or
`/metrics` shows `reason="context_unavailable"` or `reason="keys_unavailable"` rising.

This is the fail-closed design working: the gateway could not confirm passports, so it refused.

1. Check core health: `curl https://<core>/health` (on Google Cloud Run use `/health`; the platform can intercept `/healthz`).
2. Check the gateway has the service token: `AGENTWALL_CORE_SERVICE_TOKEN` must equal core's
   `INTERNAL_SERVICE_TOKEN`. On startup the gateway logs an error when it is unset.
3. Check gateway → core reachability from the gateway host: `AGENTWALL_CORE_URL`.
4. If `keys_unavailable`: core's `/v1/agent-auth/jwks` must be reachable, or set
   `AGENTWALL_AGENT_TOKEN_PUBLIC_KEY` to the PEM public key of `AGENT_TOKEN_SIGNING_KEY`.
5. Do **not** add a bypass or switch to fail-open. Restore core instead.
