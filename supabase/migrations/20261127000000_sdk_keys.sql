-- =============================================================================
-- Phase 4.5 C1a: SDK keys an admin can issue and revoke (docs/plans/phase45-c1-sdk-keys.md, ADR 0024).
-- Rollback: supabase/rollbacks/20261127000000_sdk_keys.down.sql
--
-- Until now an organization SDK key could only be made with raw SQL. Keys are now created and revoked only through two audited functions that
-- redhand-core calls for an admin; the plaintext key is generated in core, shown once and never stored (only its SHA-256 hash and a short prefix).
-- New: sdk_api_keys.created_by / revoked_at / revoked_by, an organization index, control_sdk_key_create(), control_sdk_key_revoke(),
-- sdk_key_touch() (last_used_at, at most once a minute). Changed: the audit action list (every earlier action kept); the old "Admins can manage SDK
-- keys" row-level policy is dropped, so nobody can write the table directly any more (writes go through the audited functions).
-- =============================================================================

BEGIN;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed',
    'organization.blackbox_retention_changed', 'organization.blackbox_purged',
    'organization.payload_capture_changed',
    'organization.blackbox_payload_viewed', 'organization.blackbox_exported',
    'organization.blackbox_payloads_cleared',
    'honeytoken.created', 'honeytoken.retired', 'honeytoken.tripped',
    'honey_tool.created', 'honey_tool.retired', 'honey_tool.tripped',
    'tool_pin.pending', 'tool_pin.approved', 'tool_pin.rejected', 'tool_pin.approved_all',
    'mcp_server.pin_mode_changed',
    'organization.radar_settings_changed', 'radar_finding.reviewed',
    'radar_suppression.created', 'radar_suppression.revoked',
    'organization.loop_settings_changed',
    'passport.destination_added', 'passport.destination_removed', 'passport.destination_mode_changed',
    'organization.risk_ladder_changed',
    'passport.timeline_exported',
    'passport.spend_limit_changed',
    'organization.approved_models_changed',
    'sdk_key.created', 'sdk_key.revoked'
));
ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_target_type_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_target_type_check
    CHECK (target_type IN ('agent', 'organization', 'mcp_server', 'telegram_link', 'sdk_key'));

ALTER TABLE public.sdk_api_keys
    ADD COLUMN created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD COLUMN revoked_by UUID REFERENCES auth.users(id) ON DELETE SET NULL;
CREATE INDEX idx_sdk_api_keys_org ON public.sdk_api_keys(organization_id);
DROP POLICY IF EXISTS "Admins can manage SDK keys" ON public.sdk_api_keys;

-- -----------------------------------------------------------------------------
-- control_sdk_key_create(): stores a key core generated (hash and display prefix only) with the audit row, in one transaction. At most 10 usable keys
-- (active and not expired) per organization: an eleventh returns {limit: true} and stores nothing. Expiry between 1 hour and 366 days from now.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_sdk_key_create(
    p_org uuid, p_actor uuid, p_name text, p_key_hash text, p_key_prefix text, p_expires_at timestamptz
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id uuid;
    v_name text := btrim(coalesce(p_name, ''));
BEGIN
    IF char_length(v_name) NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'a name of 1 to 100 characters is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_key_hash IS NULL OR p_key_hash !~ '^[0-9a-f]{64}$' OR p_key_prefix IS NULL OR p_key_prefix !~ '^rh_live_[A-Za-z0-9_-]{4}$' THEN
        RAISE EXCEPTION 'malformed key hash or prefix' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at < now() + interval '1 hour' OR p_expires_at > now() + interval '366 days' THEN
        RAISE EXCEPTION 'the expiry must be between 1 hour and 366 days from now' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.organizations WHERE id = p_org FOR UPDATE;  -- serialises creates per organization, so the limit holds under races
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF (SELECT count(*) FROM public.sdk_api_keys
        WHERE organization_id = p_org AND is_active AND (expires_at IS NULL OR expires_at > now())) >= 10 THEN
        RETURN jsonb_build_object('created', false, 'limit', true);
    END IF;
    INSERT INTO public.sdk_api_keys (organization_id, name, key_prefix, key_hash, is_active, expires_at, created_by)
    VALUES (p_org, v_name, p_key_prefix, p_key_hash, true, p_expires_at, p_actor)
    RETURNING id INTO v_id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'sdk_key.created', 'sdk_key', v_id, NULL,
            jsonb_build_object('name', v_name, 'prefix', p_key_prefix, 'expires_at', p_expires_at));
    RETURN jsonb_build_object('created', true, 'id', v_id, 'expires_at', p_expires_at);
END $$;

-- -----------------------------------------------------------------------------
-- control_sdk_key_revoke(): idempotent; another organization's key reads as not found.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_sdk_key_revoke(p_org uuid, p_actor uuid, p_key_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_key public.sdk_api_keys%ROWTYPE;
BEGIN
    SELECT * INTO v_key FROM public.sdk_api_keys WHERE id = p_key_id AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'key not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF NOT v_key.is_active THEN
        RETURN jsonb_build_object('changed', false, 'id', v_key.id);
    END IF;
    UPDATE public.sdk_api_keys SET is_active = false, revoked_at = now(), revoked_by = p_actor WHERE id = v_key.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'sdk_key.revoked', 'sdk_key', v_key.id, p_reason, jsonb_build_object('name', v_key.name, 'prefix', v_key.key_prefix));
    RETURN jsonb_build_object('changed', true, 'id', v_key.id);
END $$;

-- -----------------------------------------------------------------------------
-- sdk_key_touch(): records that a key was used, at most once a minute, so a busy key does not write on every batch.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.sdk_key_touch(p_key_id uuid) RETURNS void
LANGUAGE sql
SET search_path = public, pg_temp
AS $$
    UPDATE public.sdk_api_keys SET last_used_at = now()
     WHERE id = p_key_id AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')
$$;

REVOKE EXECUTE ON FUNCTION public.control_sdk_key_create(uuid, uuid, text, text, text, timestamptz) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_sdk_key_revoke(uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.sdk_key_touch(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.control_sdk_key_create(uuid, uuid, text, text, text, timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_sdk_key_revoke(uuid, uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.sdk_key_touch(uuid) TO service_role;

COMMIT;
