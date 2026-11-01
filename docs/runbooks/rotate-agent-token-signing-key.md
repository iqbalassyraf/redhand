# Runbook: provisioning or rotating the agent token signing key

`AGENT_TOKEN_SIGNING_KEY` (redhand-core) signs every agent access token. It is required outside
development and test.

Generate a key:
```bash
openssl genpkey -algorithm ed25519 -out agent-token-signing.pem
```
Public key for the gateway (optional; otherwise it reads core's JWKS):
```bash
openssl pkey -in agent-token-signing.pem -pubout
```

Rotation today is a hard cut-over: deploy the new key to core, then update
`AGENTWALL_AGENT_TOKEN_PUBLIC_KEY` (or let the gateway refetch JWKS). Tokens signed with the old
key fail verification and agents re-exchange their agent keys (seconds of errors). Publishing two
keys in the JWKS for an overlap window is a follow-up.
