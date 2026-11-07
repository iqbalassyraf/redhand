#!/usr/bin/env bash
# Browser allow-list for the dashboard, shared by deploy.sh and its tests (sourced, never run).
#
# DASHBOARD_ORIGIN holds one or more https origins separated by commas, for example
#   https://redhand.archtificial.com,https://redhand-dashboard.vercel.app
# The list becomes CORS_ALLOWED_ORIGINS on core and AGENTWALL_CORS_ALLOWED_ORIGINS on the gateway. Both are
# credentialed (cookies / bearer tokens), so an over-broad origin is a security hole, not a convenience:
# every entry must be a bare https origin (scheme + host + optional port). No wildcards, paths, queries,
# user info, quotes or spaces, so nothing can break out of the JSON the list is printed into.
# http://localhost:3000 is always added for local development.

MAX_DASHBOARD_ORIGINS=5
_ORIGIN_PATTERN='^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$'

# Prints the cleaned origins, one per line, in the order given, without duplicates.
# Returns 1 (and prints why on stderr) for anything that is not a bare https origin.
clean_dashboard_origins() {
  local raw="${1:-}" entry seen=" " count=0
  [ -n "$raw" ] || return 0
  local IFS=','
  # shellcheck disable=SC2086  # splitting on commas is the point
  set -f
  for entry in $raw; do
    set +f
    entry="${entry#"${entry%%[![:space:]]*}"}"   # trim leading whitespace
    entry="${entry%"${entry##*[![:space:]]}"}"   # trim trailing whitespace
    entry="${entry%/}"                           # one trailing slash is a common typo; paths are rejected below
    entry="$(printf '%s' "$entry" | tr '[:upper:]' '[:lower:]')"
    [ "$entry" != "http://localhost:3000" ] || continue  # always added by dashboard_cors_json
    if ! [[ "$entry" =~ $_ORIGIN_PATTERN ]]; then
      echo "error: '$entry' is not an allowed dashboard origin (use bare https origins such as https://app.example.com, separated by commas; no wildcards, paths or http)" >&2
      return 1
    fi
    case "$seen" in *" $entry "*) continue;; esac
    seen="$seen$entry "
    count=$((count + 1))
    if [ "$count" -gt "$MAX_DASHBOARD_ORIGINS" ]; then
      echo "error: more than $MAX_DASHBOARD_ORIGINS dashboard origins; each one widens who can call the API from a browser" >&2
      return 1
    fi
    printf '%s\n' "$entry"
  done
  set +f
}

# Prints the JSON list for the two CORS settings; localhost first, then the cleaned origins.
dashboard_cors_json() {
  local cleaned origin json='"http://localhost:3000"'
  cleaned="$(clean_dashboard_origins "${1:-}")" || return 1
  while IFS= read -r origin; do
    [ -n "$origin" ] || continue
    json="$json,\"$origin\""
  done <<< "$cleaned"
  printf '[%s]' "$json"
}
