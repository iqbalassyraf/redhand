# ADR 0026: Onboarding: sign-up by single-use code, member invites by link, member management (Phase 4.5 D1)

**Status:** Proposed (2026-11-17), with the pull request. Owner decisions the same day: new organizations by **invite code** (open self-serve later), member invites as a **copy-link**
(no e-mail service), and two role tightenings from the route sweep (registering an agent and rotating its key are admin actions; a viewer's state snapshot carries no reasoning or tool-argument text).

## Context
Until now RedHand had no way in: every organization and every member was added by hand in SQL, so nobody outside the team could become a customer. A published product needs a person to
sign up, create an organization, invite colleagues and manage who may do what, without giving a stranger the ability to create unlimited tenants (running cost) or to join one uninvited.

## Decision
- **Identity stays with Supabase Auth** (e-mail and password, reset by e-mail: already built). A person with a valid token and no membership has no tenant; `get_operator` answers 403 "not a member" for them, and
  a new dependency (`get_authenticated_user`: a verified token and nothing else) serves only the two routes such a person needs.
- **Creating an organization needs a single-use sign-up code** (`rh_inv_` + 192 random bits, stored as SHA-256, 1 to 90 days, shown once). The **platform owner** issues them with the internal service token
  (`scripts/issue_signup_code.py`; deliberately no dashboard for it). `SIGNUP_MODE` is `invite` (default) or `closed`; open sign-up is not offered until abuse limits and e-mail verification are designed.
  The database function `control_org_create` consumes the code, creates the organization and its owner membership and writes the audit row in one transaction. Unknown, used and expired codes get one answer.
- **Joining needs an invite token** (`rh_join_` + 192 bits, SHA-256 only, 1 to 30 days, default 7, shown once with a link path the admin sends by any channel). An admin or owner issues invites up to their own role,
  never owner; at most 20 pending; revocable; the inviter must still be an admin when the invite is used (a demoted admin's old invites die with the demotion).
- **One organization per person** through these functions (a person in an organization can neither create nor join another). Multi-organization membership exists in the schema and in `X-RedHand-Org`, but no product flow creates it.
- **Members:** admins list members with their e-mail (`list_organization_members`, since `auth.users` is not reachable through the API), change roles and remove members. Nobody grants a role above their own, nobody touches
  someone above them, **only an owner makes an owner (with confirmation)**, and **the last owner can never be removed or demoted**.
- **Abuse limits:** both attempt routes are limited per person (10 an hour) and per source address (30 an hour) before any lookup.
- **All rules live in the database functions** (service role only, row-level security closed on the two new tables, audit in the same transaction, never a code or token in an audit row); core generates, hashes, limits and maps errors.
- **Role tightenings (owner):** `POST /v1/passports` and `rotate-key` need admin (they hand out a working credential; freeze, unfreeze and investigation stay with security operators); `GET /v1/state/snapshot` removes `thought_content`,
  `observation_payload`, `tool_arguments` (and the proposed arguments of review items) for viewers.

## Alternatives considered
- **Open self-serve sign-up.** Fastest growth, but tenant creation costs money and invites abuse from day one. Rejected for now; the mode setting leaves room.
- **E-mail invites through Supabase Auth.** Needs SMTP on the Supabase project and ties an invite to an address. Rejected for now (copy-link works today); can be added on top without changing the tables.
- **Owner creates every organization by script.** Safest, but nobody can start without the owner. The code flow gives the same control (the owner decides who gets a code) with the person doing the typing.
- **Role checks only in core.** Cheaper to write, but one missed check lets a role escalate. Rejected: the database functions enforce them and core repeats them for good messages.

## Consequences
- The route table grows by 9 routes, each in the route sweep's reviewed role matrix and other-tenant seeds.
- A person with a token and no organization can call two routes; both are rate-limited and answer identically for every kind of wrong code.
- Operators lose the right to register agents and rotate keys: anyone relying on that must be made an admin.
- Not built: e-mail invites, open sign-up, several organizations per person, transferring ownership by invite, SSO. Deleting an organization and exporting its data are D1 PR 3.
