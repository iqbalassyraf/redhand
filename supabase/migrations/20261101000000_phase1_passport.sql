-- =============================================================================
-- Phase 1: Agent Passport, agent keys, MCP servers and control audit log
-- Rollback: supabase/rollbacks/20261101000000_phase1_passport.down.sql
--
-- The Agent Passport is the existing public.agents row, extended (ADR 0002).
-- Status mapping from the previous enum (lossy, accepted pre-launch):
--   active -> active, suspended -> frozen, quarantined -> frozen,
--   decommissioned -> revoked
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Passport status enum
-- -----------------------------------------------------------------------------
CREATE TYPE agent_status_v2 AS ENUM ('active', 'frozen', 'revoked', 'expired');

DROP INDEX IF EXISTS public.idx_agents_org_status;

ALTER TABLE public.agents ALTER COLUMN status DROP DEFAULT;
ALTER TABLE public.agents
    ALTER COLUMN status TYPE agent_status_v2
    USING (
        CASE status::text
            WHEN 'active' THEN 'active'
            WHEN 'suspended' THEN 'frozen'
            WHEN 'quarantined' THEN 'frozen'
            WHEN 'decommissioned' THEN 'revoked'
        END
    )::agent_status_v2;

DROP TYPE agent_status;
ALTER TYPE agent_status_v2 RENAME TO agent_status;
ALTER TABLE public.agents ALTER COLUMN status SET DEFAULT 'active';

CREATE INDEX idx_agents_org_status ON public.agents(organization_id, status);

-- -----------------------------------------------------------------------------
-- 2. Passport fields
-- -----------------------------------------------------------------------------
ALTER TABLE public.agents
    ADD COLUMN owner_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    ADD COLUMN backup_owner_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    -- [{"server": "<mcp server slug>", "tool": "<name>|*", "access": "read"|"write"}]
    ADD COLUMN scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '90 days'),
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN status_reason TEXT,
    ADD COLUMN status_changed_at TIMESTAMPTZ,
    ADD COLUMN last_seen_at TIMESTAMPTZ;

ALTER TABLE public.agents
    ADD CONSTRAINT agents_scopes_is_array CHECK (jsonb_typeof(scopes) = 'array'),
    ADD CONSTRAINT agents_version_positive CHECK (version >= 1),
    ADD CONSTRAINT agents_status_reason_length CHECK (char_length(status_reason) <= 500);

-- Revocation is permanent, and any change to status or scopes bumps the passport
-- version so the gateway can detect stale cached decisions.
CREATE OR REPLACE FUNCTION public.trigger_agents_passport_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'Agent passport % is revoked and cannot be reactivated', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status OR NEW.scopes IS DISTINCT FROM OLD.scopes
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        NEW.version = OLD.version + 1;
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.status_changed_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agents_passport_rules
    BEFORE UPDATE ON public.agents
    FOR EACH ROW EXECUTE FUNCTION public.trigger_agents_passport_rules();

-- -----------------------------------------------------------------------------
-- 3. Agent keys (long-lived secret, exchanged for short-lived access tokens)
-- -----------------------------------------------------------------------------
CREATE TABLE public.agent_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,              -- first characters, for display only
    key_hash TEXT NOT NULL UNIQUE,         -- SHA-256 of the full key; the key itself is never stored
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_agent_keys_agent ON public.agent_keys(organization_id, agent_id) WHERE is_active;

-- -----------------------------------------------------------------------------
-- 4. MCP servers registered per tenant (gateway upstreams)
-- -----------------------------------------------------------------------------
CREATE TABLE public.mcp_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    url TEXT NOT NULL CHECK (char_length(url) <= 2048),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, slug)
);

CREATE TRIGGER set_mcp_servers_updated_at
    BEFORE UPDATE ON public.mcp_servers
    FOR EACH ROW EXECUTE FUNCTION public.trigger_set_updated_at();

-- -----------------------------------------------------------------------------
-- 5. Control audit log (append-only)
-- -----------------------------------------------------------------------------
CREATE TABLE public.control_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    actor_user_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
        'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
        'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
        'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated'
    )),
    target_type TEXT NOT NULL CHECK (target_type IN ('agent', 'organization', 'mcp_server')),
    target_id UUID NOT NULL,
    reason TEXT CHECK (char_length(reason) <= 500),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_control_audit_org_time ON public.control_audit_log(organization_id, created_at DESC);

CREATE OR REPLACE FUNCTION public.trigger_control_audit_append_only()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'control_audit_log is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER control_audit_log_no_update
    BEFORE UPDATE OR DELETE ON public.control_audit_log
    FOR EACH ROW EXECUTE FUNCTION public.trigger_control_audit_append_only();

-- -----------------------------------------------------------------------------
-- 6. Row level security (defense in depth; redhand-core also scopes every query)
-- -----------------------------------------------------------------------------
ALTER TABLE public.agent_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.control_audit_log ENABLE ROW LEVEL SECURITY;

-- Agent key hashes are never readable by dashboard users; only redhand-core
-- (service role) reads them. No policies are defined, so RLS denies all.

CREATE POLICY "Users can view MCP servers in their organizations"
    ON public.mcp_servers FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Users can view control audit log in their organizations"
    ON public.control_audit_log FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

COMMIT;
