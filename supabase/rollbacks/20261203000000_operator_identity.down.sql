-- Rolls back 20261203000000_operator_identity.sql. Refuses while any operator exists only through Clerk: their member rows, invites and audit
-- references would have no auth.users row to point at. Remove or re-invite those people first.
BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.operators o WHERE NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = o.id)) THEN
        RAISE EXCEPTION 'rollback refused: operators exist that have no auth.users row (Clerk-only people)';
    END IF;
END $$;

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.conname, c.conrelid::regclass AS tbl, a.attname AS col,
               CASE c.confdeltype WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'r' THEN 'RESTRICT' ELSE 'NO ACTION' END AS on_delete
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
        WHERE c.contype = 'f' AND c.confrelid = 'public.operators'::regclass AND c.conrelid <> 'public.operator_identities'::regclass
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', r.tbl, r.conname);
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES auth.users(id) ON DELETE %s', r.tbl, r.conname, r.col, r.on_delete);
    END LOOP;
END $$;

DROP TRIGGER IF EXISTS trg_auth_users_operator ON auth.users;
DROP FUNCTION IF EXISTS public.sync_supabase_operator();
DROP FUNCTION IF EXISTS public.operator_resolve(text, text, text);

CREATE OR REPLACE FUNCTION public.list_organization_members(p_org uuid)
RETURNS TABLE (user_id uuid, email text, role text, joined_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT m.user_id, u.email::text, m.role, m.created_at
      FROM public.organization_members m JOIN auth.users u ON u.id = m.user_id
     WHERE m.organization_id = p_org
     ORDER BY public.role_rank(m.role) DESC, m.created_at
$$;

CREATE OR REPLACE FUNCTION public.tenant_table_rows(p_entry jsonb, p_org uuid, p_limit integer)
RETURNS jsonb
LANGUAGE plpgsql STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
    v_table text := p_entry ->> 'table';
    v_scope text := p_entry ->> 'scope';
    v_exclude text[] := ARRAY(SELECT jsonb_array_elements_text(p_entry -> 'exclude'));
    v_where text;
    v_rows jsonb;
    v_count bigint;
BEGIN
    IF v_scope = 'members' THEN
        SELECT count(*) INTO v_count FROM public.organization_members WHERE organization_id = p_org;
        SELECT COALESCE(jsonb_agg(row), '[]'::jsonb) INTO v_rows FROM (
            SELECT to_jsonb(m) || jsonb_build_object('email', u.email) AS row
            FROM public.organization_members m LEFT JOIN auth.users u ON u.id = m.user_id
            WHERE m.organization_id = p_org LIMIT p_limit) q;
    ELSE
        v_where := CASE v_scope
            WHEN 'org' THEN 'organization_id = $1'
            WHEN 'agent' THEN 'agent_id IN (SELECT id FROM public.agents WHERE organization_id = $1)'
            WHEN 'self' THEN 'id = $1'
        END;
        IF v_where IS NULL THEN RAISE EXCEPTION 'unknown manifest scope %', v_scope; END IF;
        EXECUTE format('SELECT count(*) FROM public.%I WHERE %s', v_table, v_where) INTO v_count USING p_org;
        EXECUTE format('SELECT COALESCE(jsonb_agg(to_jsonb(t) - $2), ''[]''::jsonb) FROM (SELECT * FROM public.%I WHERE %s LIMIT $3) t', v_table, v_where)
            INTO v_rows USING p_org, v_exclude, p_limit;
    END IF;
    RETURN jsonb_build_object('count', v_count, 'truncated', v_count > p_limit, 'rows', v_rows);
END $$;

DROP TABLE public.operator_identities;
DROP TABLE public.operators;

COMMIT;
