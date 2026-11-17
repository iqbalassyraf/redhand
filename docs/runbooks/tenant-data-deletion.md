# Runbook: exporting and deleting a tenant

Applies from migration `20261130000000_tenant_lifecycle` (ADR 0027). The old manual procedure (disable the append-only triggers by hand) is replaced by `control_org_purge`, which does the
same steps inside one transaction and proves the result.

## What the owner can do (dashboard page **Organization**, or the API; owner role)
- **Export:** `GET /v1/organization/export` returns every table of the organization as JSON (key hashes, token hashes, webhook URLs left out; members with their e-mail). One export per organization per hour; each is audited (counts only).
- **Request deletion:** `POST /v1/organization/delete-request` with `{"confirm_slug": "<the organization's address name>"}`. This freezes every agent, switches SDK keys off, revokes pending invites and starts a **7-day grace period**.
  Until it ends the organization answers 403 to everything except status, export, a repeated request and cancel.
- **Cancel:** `POST /v1/organization/delete-request/cancel`. Agents stay frozen (unfreeze each deliberately) and SDK keys have to be created again.

## What the platform operator does when a deletion request arrives
1. Check the request really is from the organization's owner (the audit log shows `organization.deletion_requested` with the owner's user id). If in doubt, contact the owner by a channel you already trust; cancelling is always safe.
2. Offer the export if they have not taken one. Confirm the retention policy that applies (PDPA, contract terms) and that no legal hold exists.
3. After the grace period (`organizations.deletion_purge_after` in the past), as the **database owner** from a trusted shell:
   ```bash
   PURGE_DATABASE_URL='<owner connection string, from the secrets manager>' scripts/purge_tenant.sh <organization-uuid>
   ```
   It shows the rows that will be deleted, makes you type the organization's address name, then runs `control_org_purge`. The purge refuses before the grace period, rolls back by itself if any table still holds a row for the tenant,
   and leaves a counts-only record in `public.tenant_deletions`.
4. Afterwards: record the purge in the operations log (organization id and date; the record in `tenant_deletions` is the evidence).

## What the purge does not reach (do these separately, and tell the customer)
- **Supabase Auth accounts** of the members (`auth.users`): the purge removes memberships, not people, because a person may be invited elsewhere. On request, delete them in the Supabase dashboard (Authentication, Users).
- **Database backups** keep the data until they age out under the provider's retention; say so in the reply.
- **Logs** (Cloud Run and Vercel) may hold request metadata (no payloads, no keys by design) until they expire.
- **Telegram:** messages the bot sent stay in the customer's chat; the link is removed with the tenant.
- **The gateway's in-memory ledger** is per process and disappears with a restart; it holds no tenant data across restarts.
- **Any export file** the owner downloaded is theirs.

## If the purge fails
It rolls back completely (the tenant is untouched, both append-only triggers are back on). The message names the cause: grace period not ended, deletion not requested, or rows left behind
(which means a table was added without a foreign key that cascades: stop, and report it, because the SQL test should have caught it). Do not disable triggers by hand.

## Recovering from a mistaken request
Before the purge: the owner cancels. After the purge there is no recovery except a database backup restore, which would resurrect every tenant's data at that time: do not do that for one tenant without a written plan.
