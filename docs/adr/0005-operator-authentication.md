# ADR 0005: Operator authentication with Supabase Auth; tenant from membership

- **Status:** Accepted (2026-11-01)
- **Phase:** 1

## Decision
- Operators sign in with Supabase Auth. redhand-core verifies the access token locally (HS256 only,
  `aud=authenticated`, required `exp`/`sub`) using the project JWT secret (`OPERATOR_JWT_SECRET`).
- The tenant and role come from `organization_members`; a requested organization (`X-RedHand-Org`)
  is honoured only if the user is a member. Roles: viewer < security_operator < admin < owner.
- Every core query is filtered by the operator's organization; another tenant's object returns 404.
- HITL reviewers are the authenticated operator; the request body cannot name one.
- In development only (ENVIRONMENT=development and no Supabase), `/v1/dev/login` issues tokens for
  seeded dev operators. It is not registered in any other configuration.

## Consequences
- Supabase projects that use asymmetric JWT signing keys need JWKS support in core (follow-up).
- core uses the Supabase service role, so isolation is enforced in core's queries; Supabase row
  level security remains as defense in depth for direct client access.
