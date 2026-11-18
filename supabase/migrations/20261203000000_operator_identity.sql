-- =============================================================================
-- Operator identity (ADR 0032, Clerk slice C1): RedHand owns one UUID per person (`operators`), and maps each identity provider's subject to
-- it (`operator_identities`). Every foreign key that pointed at Supabase's auth.users(id) now points at operators(id), so a person who signs in
-- through Clerk (whose subjects are strings, not UUIDs) gets the same kind of id and every existing table, function and test keeps working.
--
-- Rules:
--   - Existing Supabase users are backfilled (same UUID, provider 'supabase'); a trigger on auth.users keeps new Supabase sign-ups in step, so
--     the Supabase sign-in mode works unchanged.
--   - operator_resolve() creates a Clerk operator on first use and NEVER matches an existing account by e-mail (owner decision: no account
--     takeover by claiming an address). It is callable by service_role only; core calls it after verifying the Clerk token.
--   - Members' e-mails now come from operators (a Clerk user has no auth.users row).
-- =============================================================================

BEGIN;

CREATE TABLE public.operators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT CHECK (email IS NULL OR char_length(email) <= 320),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.operator_identities (
    provider TEXT NOT NULL CHECK (provider IN ('supabase', 'clerk')),
    subject TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    operator_id UUID NOT NULL REFERENCES public.operators(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, subject)
);
CREATE INDEX idx_operator_identities_operator ON public.operator_identities (operator_id);

-- Platform tables, not tenant data: no client may read them directly.
ALTER TABLE public.operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operator_identities ENABLE ROW LEVEL SECURITY;

-- Backfill every existing Supabase user with the same UUID.
INSERT INTO public.operators (id, email, created_at) SELECT u.id, u.email::text, NOW() FROM auth.users u ON CONFLICT (id) DO NOTHING;
INSERT INTO public.operator_identities (provider, subject, operator_id) SELECT 'supabase', u.id::text, u.id FROM auth.users u ON CONFLICT DO NOTHING;

-- Keep Supabase sign-ups (and e-mail changes) in step while the Supabase mode exists.
CREATE OR REPLACE FUNCTION public.sync_supabase_operator() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO public.operators (id, email) VALUES (NEW.id, NEW.email::text)
        ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;
    INSERT INTO public.operator_identities (provider, subject, operator_id) VALUES ('supabase', NEW.id::text, NEW.id) ON CONFLICT DO NOTHING;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.sync_supabase_operator() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER trg_auth_users_operator AFTER INSERT OR UPDATE OF email ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.sync_supabase_operator();

-- Re-point every foreign key that references auth.users(id) to operators(id), keeping its name, column and ON DELETE action.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.conname, c.conrelid::regclass AS tbl, a.attname AS col,
               CASE c.confdeltype WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'r' THEN 'RESTRICT' ELSE 'NO ACTION' END AS on_delete
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
        WHERE c.contype = 'f' AND c.confrelid = 'auth.users'::regclass AND c.connamespace = 'public'::regnamespace
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', r.tbl, r.conname);
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES public.operators(id) ON DELETE %s', r.tbl, r.conname, r.col, r.on_delete);
    END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- operator_resolve(): the operator for a verified identity. Clerk only (Supabase subjects are already our UUIDs). Creates the operator on first
-- use; the e-mail is stored for display and refreshed when it changes, but is never used to find an existing account.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.operator_resolve(p_provider text, p_subject text, p_email text)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id uuid;
BEGIN
    IF p_provider IS DISTINCT FROM 'clerk' THEN
        RAISE EXCEPTION 'operator_resolve is for clerk identities only' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'subject is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_email IS NOT NULL AND char_length(p_email) > 320 THEN
        RAISE EXCEPTION 'e-mail too long' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT operator_id INTO v_id FROM public.operator_identities WHERE provider = 'clerk' AND subject = p_subject;
    IF v_id IS NULL THEN
        INSERT INTO public.operators (email) VALUES (p_email) RETURNING id INTO v_id;
        BEGIN
            INSERT INTO public.operator_identities (provider, subject, operator_id) VALUES ('clerk', p_subject, v_id);
        EXCEPTION WHEN unique_violation THEN
            -- Two first requests raced: keep the winner's operator, drop ours.
            DELETE FROM public.operators WHERE id = v_id;
            SELECT operator_id INTO v_id FROM public.operator_identities WHERE provider = 'clerk' AND subject = p_subject;
        END;
    ELSIF p_email IS NOT NULL THEN
        UPDATE public.operators SET email = p_email WHERE id = v_id AND email IS DISTINCT FROM p_email;
    END IF;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.operator_resolve(text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.operator_resolve(text, text, text) TO service_role;

-- Members' e-mails come from operators now (same output as before for Supabase users).
CREATE OR REPLACE FUNCTION public.list_organization_members(p_org uuid)
RETURNS TABLE (user_id uuid, email text, role text, joined_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT m.user_id, o.email, m.role, m.created_at
      FROM public.organization_members m JOIN public.operators o ON o.id = m.user_id
     WHERE m.organization_id = p_org
     ORDER BY public.role_rank(m.role) DESC, m.created_at
$$;
REVOKE EXECUTE ON FUNCTION public.list_organization_members(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.list_organization_members(uuid) TO service_role;

-- The tenant export lists members with the e-mail from operators (a Clerk user has no auth.users row). Otherwise identical to 20261130.
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
            FROM public.organization_members m LEFT JOIN public.operators u ON u.id = m.user_id
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
REVOKE EXECUTE ON FUNCTION public.tenant_table_rows(jsonb, uuid, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.tenant_table_rows(jsonb, uuid, integer) TO service_role;

COMMIT;
