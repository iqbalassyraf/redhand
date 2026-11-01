# ADR 0003: Agent keys exchanged for short-lived Ed25519 access tokens

- **Status:** Accepted (2026-11-01)
- **Phase:** 1

## Decision
- Each agent gets an **agent key** (`rh_agent_` + 256 random bits), shown once and stored only as a
  SHA-256 hash. (A slow password hash is unnecessary for a 256-bit random secret.)
- The agent exchanges it at `POST /v1/agent-auth/token` for a **10-minute access token**: an
  Ed25519-signed JWT with `iss=redhand-core`, `aud=redhand-gateway`, `sub` (agent), `org`, `ver`
  (passport version), `jti`, `iat`, `nbf`, `exp`. Exchange is refused unless the passport is active
  and is rate-limited per key.
- The gateway verifies tokens with the public key only (configured PEM or core's JWKS), so a
  compromised gateway cannot mint tokens.
- Revocation does not depend on token expiry: the gateway also checks passport status (ADR 0004).

## Alternatives
- **Gateway looks up the agent key on every call:** simpler, but puts a secret lookup on the hot
  path and gives no short-lived credential.
- **HS256 shared secret:** the gateway could forge tokens.

## Consequences
- Key rotation and revocation deactivate keys immediately.
- `AGENT_TOKEN_SIGNING_KEY` must be provisioned outside development; key rotation of the signing
  key itself (multiple `kid`s) is supported by the JWKS format but not yet automated.
