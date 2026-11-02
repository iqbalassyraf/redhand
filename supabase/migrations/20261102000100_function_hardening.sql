-- =============================================================================
-- Function hardening, from the Supabase security advisor run on staging (2026-11-02).
-- Rollback: supabase/rollbacks/20261102000100_function_hardening.down.sql
--
-- 1. Three trigger functions had no fixed search_path ("function_search_path_mutable").
--    Pinning it stops a caller-controlled search_path from changing what they resolve.
-- 2. get_user_organization_ids() is SECURITY DEFINER and was executable by `anon` through
--    /rest/v1/rpc. `anon` has no row-level-security policies that need it. `authenticated`
--    keeps EXECUTE because the row-level-security policies call it as the signed-in user; it
--    only returns the caller's own organization ids (it filters on auth.uid()).
-- =============================================================================

BEGIN;

ALTER FUNCTION public.trigger_set_updated_at() SET search_path = public, pg_temp;
ALTER FUNCTION public.trigger_agents_passport_rules() SET search_path = public, pg_temp;
ALTER FUNCTION public.trigger_control_audit_append_only() SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.get_user_organization_ids() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_user_organization_ids() TO authenticated, service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
