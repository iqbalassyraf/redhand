# Runbook: operators get "Invalid or expired operator token" (401)

1. **Right mode?** Staging and production use JWKS mode for Supabase projects with asymmetric
   signing keys: `OPERATOR_JWKS_URL=https://<ref>.supabase.co/auth/v1/.well-known/jwks.json` and
   `OPERATOR_JWT_ISSUER=https://<ref>.supabase.co/auth/v1`. Core refuses to start with both modes
   or neither configured.
2. **Is the issuer exact?** The `iss` claim of a token must equal `OPERATOR_JWT_ISSUER`
   character for character (no trailing slash). Decode a failing token's payload (it is not secret
   data, but never paste tokens into chats or tickets) and compare `iss`.
3. **Can core reach the JWKS URL?** Look for `Operator JWKS refresh failed` in core's logs. With no
   cached keys every login is denied; after the first successful fetch, outages of up to one hour
   are tolerated. Retrying a failed fetch happens at most every 30 seconds.
4. **Key rotation:** if Supabase rotated the signing key, new tokens carry a new `kid`; core
   picks it up within about 30 seconds of the first request that uses it.
5. **Token lifetime:** a clock that is far off makes `exp`/`iat` checks fail (30 s leeway).
6. Do **not** switch to HS256 or disable verification as a workaround.
