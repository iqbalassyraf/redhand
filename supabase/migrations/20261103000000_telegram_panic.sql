-- =============================================================================
-- Telegram panic command (Phase 2, M1): links between operators and Telegram chats.
-- Rollback: supabase/rollbacks/20261103000000_telegram_panic.down.sql
-- Plan: docs/plans/phase2-plan.md   ADR: docs/adr/0008-telegram-panic-command.md
--
-- Tables (all RLS-enabled with NO policies: only redhand-core, via the service role, reads
-- or writes them; dashboard users and anon get nothing):
--   telegram_link_codes  one-time codes an admin/owner generates in the dashboard (hash only)
--   telegram_links       a Telegram chat bound to one operator in one organization
--   telegram_updates     Telegram update ids already handled (replay protection)
--
-- Functions are SECURITY INVOKER, fixed search_path, executable only by service_role.
--
-- Retention: telegram_updates rows are only needed while Telegram may still redeliver an
-- update (hours). purge_telegram_updates() deletes rows older than 7 days; schedule it daily
-- (docs/runbooks/telegram-panic-command.md). Link codes are single-use and expire after 10
-- minutes; used or expired codes are removed by the same function. Links are kept (with
-- revoked_at) as evidence of who could stop agents; they are deleted with the organization.
-- =============================================================================

BEGIN;

CREATE TABLE public.telegram_link_codes (
    code_hash TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE public.telegram_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

-- A chat can be bound to at most one operator at a time.
CREATE UNIQUE INDEX idx_telegram_links_active_chat ON public.telegram_links(chat_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_telegram_links_org ON public.telegram_links(organization_id) WHERE revoked_at IS NULL;

CREATE TABLE public.telegram_updates (
    update_id BIGINT PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.telegram_link_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telegram_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telegram_updates ENABLE ROW LEVEL SECURITY;

-- The audit log needs to be able to name these events.
ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked'
));
ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_target_type_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_target_type_check
    CHECK (target_type IN ('agent', 'organization', 'mcp_server', 'telegram_link'));

-- -----------------------------------------------------------------------------
-- Consume a link code and bind the chat, atomically. Raises:
--   P0002  code unknown, used or expired
--   42501  the code's operator is no longer an admin/owner of the organization
-- Nothing is consumed when it raises.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.telegram_link_chat(p_code_hash text, p_chat_id bigint)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_code public.telegram_link_codes%ROWTYPE;
    v_role text;
    v_link_id uuid;
BEGIN
    SELECT * INTO v_code FROM public.telegram_link_codes WHERE code_hash = p_code_hash FOR UPDATE;
    IF NOT FOUND OR v_code.used_at IS NOT NULL OR v_code.expires_at <= NOW() THEN
        RAISE EXCEPTION 'link code is invalid or expired' USING ERRCODE = 'no_data_found';
    END IF;

    SELECT role INTO v_role FROM public.organization_members
    WHERE organization_id = v_code.organization_id AND user_id = v_code.user_id;
    IF v_role IS NULL OR v_role NOT IN ('admin', 'owner') THEN
        RAISE EXCEPTION 'operator may not use the panic command' USING ERRCODE = 'insufficient_privilege';
    END IF;

    UPDATE public.telegram_links SET revoked_at = NOW() WHERE chat_id = p_chat_id AND revoked_at IS NULL;
    UPDATE public.telegram_link_codes SET used_at = NOW() WHERE code_hash = p_code_hash;
    INSERT INTO public.telegram_links (organization_id, user_id, chat_id)
    VALUES (v_code.organization_id, v_code.user_id, p_chat_id)
    RETURNING id INTO v_link_id;

    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, details)
    VALUES (v_code.organization_id, v_code.user_id, 'telegram.linked', 'telegram_link', v_link_id,
            jsonb_build_object('channel', 'telegram'));

    RETURN jsonb_build_object(
        'link_id', v_link_id, 'organization_id', v_code.organization_id,
        'user_id', v_code.user_id, 'role', v_role
    );
END;
$$;

-- -----------------------------------------------------------------------------
-- Unlink a chat (lost phone, left the company). Idempotent; scoped to the organization.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.telegram_unlink(p_org uuid, p_actor uuid, p_link_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_link public.telegram_links%ROWTYPE;
BEGIN
    SELECT * INTO v_link FROM public.telegram_links
    WHERE id = p_link_id AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'telegram link not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_link.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('link_id', v_link.id, 'changed', false);
    END IF;

    UPDATE public.telegram_links SET revoked_at = NOW() WHERE id = v_link.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, details)
    VALUES (p_org, p_actor, 'telegram.unlinked', 'telegram_link', v_link.id,
            jsonb_build_object('linked_user_id', v_link.user_id));
    RETURN jsonb_build_object('link_id', v_link.id, 'changed', true);
END;
$$;

-- -----------------------------------------------------------------------------
-- Replay guard: true the first time an update id is seen, false afterwards.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.telegram_claim_update(p_update_id bigint)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_inserted integer;
BEGIN
    INSERT INTO public.telegram_updates (update_id) VALUES (p_update_id) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    RETURN v_inserted = 1;
END;
$$;

-- -----------------------------------------------------------------------------
-- Retention: run daily.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.purge_telegram_updates()
RETURNS integer
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_updates integer;
    v_codes integer;
BEGIN
    DELETE FROM public.telegram_updates WHERE received_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS v_updates = ROW_COUNT;
    DELETE FROM public.telegram_link_codes WHERE used_at IS NOT NULL OR expires_at < NOW() - INTERVAL '1 day';
    GET DIAGNOSTICS v_codes = ROW_COUNT;
    RETURN v_updates + v_codes;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.telegram_link_chat(text, bigint) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.telegram_unlink(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.telegram_claim_update(bigint) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_telegram_updates() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.telegram_link_chat(text, bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public.telegram_unlink(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.telegram_claim_update(bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_telegram_updates() TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
