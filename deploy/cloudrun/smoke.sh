#!/usr/bin/env bash
# Checks a deployed RedHand stack from the outside, without any credentials.
#
#   deploy/cloudrun/smoke.sh <core-url> <gateway-url>
#
# Every check is a request that must be REFUSED (or a public health page that must answer),
# so a pass means the services are up, protected, and able to reach their database.
set -uo pipefail

CORE="${1:?usage: smoke.sh <core-url> <gateway-url>}"
GATEWAY="${2:?usage: smoke.sh <core-url> <gateway-url>}"
CORE="${CORE%/}"; GATEWAY="${GATEWAY%/}"
FAILED=0
# A well-formed agent key that does not exist: core must look it up in the database and say 401.
BOGUS_KEY="rh_agent_$(printf 'A%.0s' $(seq 1 43))"

status() { curl -s -o /dev/null -m 40 -w '%{http_code}' "$@" 2>/dev/null || echo "000"; }

check() { # check "<what>" <expected> <actual> [hint]
  if [ "$3" = "$2" ]; then
    printf 'PASS  %s (HTTP %s)\n' "$1" "$3"
  else
    printf 'FAIL  %s: expected HTTP %s, got %s\n' "$1" "$2" "$3"
    [ -n "${4:-}" ] && printf '      hint: %s\n' "$4"
    FAILED=1
  fi
}

# The first request after an idle period can take several seconds while Cloud Run starts the service.
echo "Waking the services (first request after idle can be slow)..."
status "$CORE/health" >/dev/null; status "$GATEWAY/health" >/dev/null

ENVIRONMENT="$(curl -s -m 40 "$CORE/health" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("environment",""))' 2>/dev/null || true)"
echo "Core reports environment: ${ENVIRONMENT:-unknown}"
echo

check "core /health is up" 200 "$(status "$CORE/health")" "check the service logs in Cloud Run (Cloud Run itself reserves /healthz, so this check uses /health)"
check "gateway /health is up" 200 "$(status "$GATEWAY/health")" "check the service logs in Cloud Run (Cloud Run itself reserves /healthz, so this check uses /health)"

check "core refuses requests without an operator login" 401 "$(status "$CORE/v1/passports")"
check "core refuses a fake operator token" 401 "$(status -H 'Authorization: Bearer not-a-real-token' "$CORE/v1/passports")"
check "core publishes the agent-token public key" 200 "$(status "$CORE/v1/agent-auth/jwks")" \
  "AGENT_TOKEN_SIGNING_KEY secret missing or unreadable by the core service account"
check "core internal API refuses callers without the service token" 401 "$(status "$CORE/internal/v1/gateway-context?agent_id=00000000-0000-0000-0000-000000000000&organization_id=00000000-0000-0000-0000-000000000000&server=x")" \
  "503 means INTERNAL_SERVICE_TOKEN did not reach core (secret missing, or not readable by the core service account)"
check "core database is reachable and accepts our key (unknown agent key -> 401)" 401 \
  "$(status -X POST -H "Authorization: Bearer $BOGUS_KEY" "$CORE/v1/agent-auth/token")" \
  "500 here usually means the Supabase secret key was rejected: try the legacy service_role key (see docs/runbooks/cloud-run-staging.md)"
if [ "$ENVIRONMENT" != "development" ]; then
  check "core has no development login" 404 "$(status -X POST -H 'Content-Type: application/json' -d '{"user":"owner"}' "$CORE/v1/dev/login")"
fi

check "gateway refuses MCP calls without an agent token" 401 \
  "$(status -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$GATEWAY/mcp/example")"
check "gateway refuses a fake agent token" 401 \
  "$(status -X POST -H 'Authorization: Bearer not-a-token' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$GATEWAY/mcp/example")"
check "gateway audit log needs the service token" 401 "$(status "$GATEWAY/v1/audit/logs")"
check "gateway metrics need the service token" 401 "$(status "$GATEWAY/metrics")"

echo
metrics="$(status "$CORE/metrics")"
if [ "$metrics" = "200" ]; then
  echo "NOTE  core /metrics is publicly readable (HTTP 200). Known open item: restrict it (docs/plans/phase1-plan.md follow-up 10)."
fi

echo
if [ "$FAILED" = "0" ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$FAILED"
