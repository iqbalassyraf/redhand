-- Rollback for 20261102000100_function_hardening.sql
-- Restores the previous (less strict) settings: unpinned search_path on the three trigger
-- functions and EXECUTE for anon on get_user_organization_ids().

BEGIN;

ALTER FUNCTION public.trigger_set_updated_at() RESET search_path;
ALTER FUNCTION public.trigger_agents_passport_rules() RESET search_path;
ALTER FUNCTION public.trigger_control_audit_append_only() RESET search_path;

GRANT EXECUTE ON FUNCTION public.get_user_organization_ids() TO anon;

COMMIT;

NOTIFY pgrst, 'reload schema';
