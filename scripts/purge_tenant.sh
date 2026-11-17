#!/usr/bin/env bash
# Deletes one organization's data after its 7-day grace period (docs/runbooks/tenant-data-deletion.md, ADR 0027).
#
# Run it as the database OWNER (the role that owns the tables), from a trusted shell. The purge function is not callable through the API or by the service role.
#   PURGE_DATABASE_URL='postgresql://...' scripts/purge_tenant.sh <organization-uuid>
# The connection string is read from the environment, never from an argument, and is never printed. It shows what will be deleted, makes you type the
# organization's address name, then runs control_org_purge() in one transaction (it rolls back by itself if any table still holds a row for the tenant).
set -euo pipefail

org="${1:-}"
if [[ ! "$org" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "usage: PURGE_DATABASE_URL=... $0 <organization-uuid>" >&2
  exit 2
fi
if [[ -z "${PURGE_DATABASE_URL:-}" ]]; then
  echo "PURGE_DATABASE_URL is not set" >&2
  exit 2
fi
# The query goes in on stdin: psql expands :'org' there, not in -c, so the id is a quoted literal and never pasted into the SQL text.
sql() { psql "$PURGE_DATABASE_URL" -X -v ON_ERROR_STOP=1 -At -v org="$org"; }

state="$(sql <<<"SELECT slug, coalesce(deletion_requested_at::text, 'NOT REQUESTED'), coalesce(deletion_purge_after::text, '-') FROM public.organizations WHERE id = :'org'")"
if [[ -z "$state" ]]; then echo "no such organization (already purged?)"; exit 1; fi
IFS='|' read -r slug requested purge_after <<<"$state"
echo "organization:  $slug"
echo "requested at:  $requested"
echo "purge after:   $purge_after"
if [[ "$requested" == "NOT REQUESTED" ]]; then echo "refusing: the owner has not requested deletion"; exit 1; fi
if [[ "$(sql <<<"SELECT deletion_purge_after > now() FROM public.organizations WHERE id = :'org'")" == "t" ]]; then echo "refusing: the grace period has not ended"; exit 1; fi

echo
echo "rows that will be deleted:"
sql <<<"SELECT key || ': ' || value FROM jsonb_each_text(public.tenant_row_counts(:'org')) WHERE value::bigint > 0 ORDER BY key"
echo
read -r -p "Type the organization's address name ($slug) to delete everything: " typed
if [[ "$typed" != "$slug" ]]; then echo "does not match; nothing deleted"; exit 1; fi

sql <<<"SELECT public.control_org_purge(:'org')" >/dev/null
echo "purged. The record is in public.tenant_deletions. Remember the steps after the purge in the runbook (auth users, backups, logs)."
