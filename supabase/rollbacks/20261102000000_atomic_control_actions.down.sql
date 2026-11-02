-- Rollback for 20261102000000_atomic_control_actions.sql
-- Drops the four control functions. redhand-core versions that call them must be rolled back
-- first; the previous core code applies actions with plain table writes and still works.

BEGIN;

DROP FUNCTION IF EXISTS public.control_agent_change(uuid, uuid, uuid, text, text, jsonb, boolean, jsonb, text, jsonb);
DROP FUNCTION IF EXISTS public.control_freeze_all(uuid, uuid, text);
DROP FUNCTION IF EXISTS public.control_create_passport(uuid, uuid, jsonb, jsonb, jsonb);
DROP FUNCTION IF EXISTS public.control_mcp_server(uuid, uuid, text, jsonb, uuid);

COMMIT;

NOTIFY pgrst, 'reload schema';
