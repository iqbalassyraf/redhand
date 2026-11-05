-- Rollback for 20261110000100_blackbox_hash_search_path.sql: restores the previous search_path of the
-- hash helper. On Supabase that path cannot resolve pgcrypto's digest(), so rolling back this migration
-- alone leaves the Black Box unable to record events; roll back 20261110000000_blackbox.sql too, or
-- re-apply this migration.

BEGIN;

ALTER FUNCTION public._blackbox_event_hash(
    text, uuid, uuid, bigint, timestamptz, text, text, text, text, text,
    text[], integer, numeric, text[], text, integer, integer, text
) SET search_path = public, pg_temp;

COMMIT;

NOTIFY pgrst, 'reload schema';
