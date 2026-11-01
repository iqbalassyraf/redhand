-- =============================================================================
-- Rollback for 20261101000000_phase1_passport.sql
-- Lossy: 'frozen' and 'expired' both become 'suspended'; 'revoked' becomes
-- 'decommissioned'. Agent keys, MCP servers and the control audit log are dropped.
-- Kept outside supabase/migrations/ so the Supabase CLI never applies it automatically.
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS public.control_audit_log;
DROP FUNCTION IF EXISTS public.trigger_control_audit_append_only();
DROP TABLE IF EXISTS public.mcp_servers;
DROP TABLE IF EXISTS public.agent_keys;

DROP TRIGGER IF EXISTS agents_passport_rules ON public.agents;
DROP FUNCTION IF EXISTS public.trigger_agents_passport_rules();

ALTER TABLE public.agents
    DROP CONSTRAINT IF EXISTS agents_scopes_is_array,
    DROP CONSTRAINT IF EXISTS agents_version_positive,
    DROP CONSTRAINT IF EXISTS agents_status_reason_length,
    DROP COLUMN IF EXISTS owner_id,
    DROP COLUMN IF EXISTS backup_owner_id,
    DROP COLUMN IF EXISTS scopes,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS status_reason,
    DROP COLUMN IF EXISTS status_changed_at,
    DROP COLUMN IF EXISTS last_seen_at;

DROP INDEX IF EXISTS public.idx_agents_org_status;
CREATE TYPE agent_status_v1 AS ENUM ('active', 'suspended', 'quarantined', 'decommissioned');
ALTER TABLE public.agents ALTER COLUMN status DROP DEFAULT;
ALTER TABLE public.agents
    ALTER COLUMN status TYPE agent_status_v1
    USING (
        CASE status::text
            WHEN 'active' THEN 'active'
            WHEN 'frozen' THEN 'suspended'
            WHEN 'expired' THEN 'suspended'
            WHEN 'revoked' THEN 'decommissioned'
        END
    )::agent_status_v1;
DROP TYPE agent_status;
ALTER TYPE agent_status_v1 RENAME TO agent_status;
ALTER TABLE public.agents ALTER COLUMN status SET DEFAULT 'active';
CREATE INDEX idx_agents_org_status ON public.agents(organization_id, status);

COMMIT;
