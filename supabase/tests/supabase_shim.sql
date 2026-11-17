-- Minimal stand-in for the parts of Supabase the migrations depend on, so they can be
-- tested on plain PostgreSQL. Never applied to a real Supabase project.
-- Supabase installs pgcrypto in the "extensions" schema, not "public". Mirror that so a function whose
-- pinned search_path leaves it out fails here as it does in production (the Black Box hash helper did).
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY, email TEXT);  -- email exists on the real table (D1 lists members with it)
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
-- Supabase grants EXECUTE on new public functions to these roles by default; mirror that so
-- the tests prove the migration's explicit REVOKE is what protects the control functions.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;
CREATE PUBLICATION supabase_realtime;
