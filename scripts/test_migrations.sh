#!/usr/bin/env bash
# Applies every migration to a throwaway database on plain PostgreSQL (with a minimal
# Supabase shim), runs the SQL tests, then proves the newest rollback and re-apply work.
#
# Usage: PGHOST=... PGPORT=... PGUSER=... scripts/test_migrations.sh
# Needs a PostgreSQL server you can create databases on. Never point it at a real project.
set -euo pipefail
cd "$(dirname "$0")/.."

DB="rh_migration_test_$$"
psql_admin() { psql -v ON_ERROR_STOP=1 -q -d postgres "$@"; }
psql_db() { psql -v ON_ERROR_STOP=1 -q -d "$DB" "$@"; }

psql_admin -c "CREATE DATABASE $DB"
trap 'psql_admin -c "DROP DATABASE IF EXISTS $DB" >/dev/null' EXIT

psql_db -f supabase/tests/supabase_shim.sql >/dev/null 2>&1
for migration in supabase/migrations/*.sql; do
  echo "applying $migration"
  psql_db -f "$migration" >/dev/null
done

for test in supabase/tests/*_test.sql; do
  echo "running $test"
  psql_db -f "$test" 2>&1 | grep -E "NOTICE:  ok|ALL SQL TESTS PASSED|ERROR|CHECK FAILED" | sed -E 's/^.*NOTICE:  //'
  test "${PIPESTATUS[0]}" -eq 0
done

latest_rollback=$(ls supabase/rollbacks/*.down.sql | sort | tail -1)
latest_migration=$(ls supabase/migrations/*.sql | sort | tail -1)
echo "rollback: $latest_rollback"
psql_db -f "$latest_rollback" >/dev/null
echo "re-apply: $latest_migration"
psql_db -f "$latest_migration" >/dev/null
echo "MIGRATIONS OK"
