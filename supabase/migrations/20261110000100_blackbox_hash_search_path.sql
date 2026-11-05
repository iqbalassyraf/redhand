-- =============================================================================
-- Black Box: let the event hash helper find pgcrypto's digest() on Supabase.
-- Rollback: supabase/rollbacks/20261110000100_blackbox_hash_search_path.down.sql
--
-- 20261110000000_blackbox.sql pinned _blackbox_event_hash to "search_path = public, pg_temp" (the
-- function_search_path_mutable advisor fix). Supabase installs pgcrypto in the "extensions" schema,
-- so digest() could no longer be resolved: every call raised "function digest(text, unknown) does not
-- exist", record_events() swallowed the error per item and counted the event as rejected, and no
-- event was ever stored. The search_path stays pinned (the advisor is satisfied) but now includes
-- "extensions". This is a forward fix: the applied migration is not edited again.
-- =============================================================================

BEGIN;

ALTER FUNCTION public._blackbox_event_hash(
    text, uuid, uuid, bigint, timestamptz, text, text, text, text, text,
    text[], integer, numeric, text[], text, integer, integer, text
) SET search_path = public, extensions, pg_temp;

COMMIT;

NOTIFY pgrst, 'reload schema';
