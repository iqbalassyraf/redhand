-- Rollback for 20261110000000_blackbox.sql
-- Drops the Black Box Recorder tables, functions and trigger, and the organization columns.
-- Every recorded event and chain is lost.

BEGIN;

DROP TRIGGER IF EXISTS trg_agent_events_append_only ON public.agent_events;
DROP FUNCTION IF EXISTS public._forbid_event_mutation();

DROP FUNCTION IF EXISTS public.verify_events(uuid, bigint, bigint);
DROP FUNCTION IF EXISTS public.record_events(text, uuid, uuid, jsonb);
DROP FUNCTION IF EXISTS public._blackbox_event_hash(text, uuid, uuid, bigint, timestamptz, text, text, text, text, text, text[], integer, numeric, text[], text, integer, integer, text);

DROP TABLE IF EXISTS public.event_batches;
DROP TABLE IF EXISTS public.agent_events;
DROP TABLE IF EXISTS public.event_chain_heads;

ALTER TABLE public.organizations
    DROP COLUMN payload_retention_days,
    DROP COLUMN payload_capture_enabled,
    DROP COLUMN blackbox_retention_days;

COMMIT;

NOTIFY pgrst, 'reload schema';
