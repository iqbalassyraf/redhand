-- Rollback for 20261118000000_radar_scan_counts.sql: removes the count tables (and their data) and the three new functions, and
-- restores purge_findings() to the body it had in 20261117000000_radar_findings.sql.

BEGIN;

DROP FUNCTION IF EXISTS public.radar_readiness_inputs(uuid);
DROP FUNCTION IF EXISTS public.record_radar_scan_counts(uuid, text, jsonb);
DROP FUNCTION IF EXISTS public.radar_count_of(text, bigint);
DROP TABLE IF EXISTS public.radar_count_reports;
DROP TABLE IF EXISTS public.radar_rule_counts;
DROP TABLE IF EXISTS public.radar_scan_counts;

CREATE OR REPLACE FUNCTION public.purge_findings()
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_findings bigint;
    v_suppressions bigint;
BEGIN
    DELETE FROM public.security_findings WHERE last_seen_at < now() - interval '90 days';
    GET DIAGNOSTICS v_findings = ROW_COUNT;
    DELETE FROM public.radar_suppressions
    WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '90 days') OR (revoked_at IS NULL AND expires_at < now() - interval '90 days');
    GET DIAGNOSTICS v_suppressions = ROW_COUNT;
    RETURN jsonb_build_object('findings', v_findings, 'suppressions', v_suppressions);
END;
$$;

COMMIT;

NOTIFY pgrst, 'reload schema';
