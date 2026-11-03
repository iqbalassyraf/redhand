#!/usr/bin/env bash
# Deploys redhand-core and the AgentWall gateway to Google Cloud Run (staging).
#
#   deploy/cloudrun/deploy.sh [all|secrets|core|gateway|cors|telegram]
#
#   all      secrets + core + gateway (default)
#   secrets  create the three secrets in Secret Manager and the per-service identities
#   core     build and deploy redhand-core
#   gateway  build and deploy the gateway (needs core deployed first: it needs core's URL)
#   cors     point both services at the dashboard origin (set DASHBOARD_ORIGIN)
#   telegram store the Telegram bot token (hidden prompt) and a generated webhook secret in
#            Secret Manager and give them to redhand-core (set TELEGRAM_BOT_USERNAME, without @).
#            Then run scripts/telegram_webhook.py to point Telegram at core.
#
# Configuration comes from environment variables (defaults in brackets):
#   PROJECT_ID          [gcloud's current project]
#   REGION              [asia-southeast1]
#   SUPABASE_URL        [required: https://<project-ref>.supabase.co]
#   DASHBOARD_ORIGIN    [empty: browsers on http://localhost:3000 only]
#
# Secrets are never printed. The Supabase secret key is read with hidden input, the internal
# service token and the agent-token signing key are generated here and sent straight to
# Secret Manager. Re-running keeps existing secrets (set ROTATE=1 to replace the generated ones).
set -euo pipefail
cd "$(dirname "$0")/../.."

COMMAND="${1:-all}"
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-asia-southeast1}"
REPO="${REPO:-redhand}"
SUPABASE_URL="${SUPABASE_URL:-}"
DASHBOARD_ORIGIN="${DASHBOARD_ORIGIN:-}"
TAG="${TAG:-$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"

SECRET_SUPABASE="redhand-supabase-secret-key"
SECRET_INTERNAL="redhand-internal-service-token"
SECRET_SIGNING="redhand-agent-token-signing-key"
CORE_SA="redhand-core-sa"
GATEWAY_SA="redhand-gateway-sa"
SECRET_TG_TOKEN="redhand-telegram-bot-token"
SECRET_TG_WEBHOOK="redhand-telegram-webhook-secret"
TELEGRAM_BOT_USERNAME="${TELEGRAM_BOT_USERNAME:-}"

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

preflight() {
  command -v gcloud >/dev/null || die "gcloud is not installed"
  command -v openssl >/dev/null || die "openssl is not installed"
  [ -n "$PROJECT_ID" ] || die "no project: run 'gcloud config set project <id>' or set PROJECT_ID"
  gcloud auth list --filter=status:ACTIVE --format='value(account)' | grep -q . \
    || die "not logged in: run 'gcloud auth login'"
  case "$COMMAND" in
    all|core|gateway|cors) [ -n "$SUPABASE_URL" ] || die "set SUPABASE_URL (https://<project-ref>.supabase.co)";;
  esac
  case "$SUPABASE_URL" in ""|https://*.supabase.co) ;; *) die "SUPABASE_URL must look like https://<ref>.supabase.co";; esac
  echo "Account : $(gcloud auth list --filter=status:ACTIVE --format='value(account)')"
  echo "Project : $PROJECT_ID"
  echo "Region  : $REGION"
  echo "Command : $COMMAND"
  [ "${YES:-}" = "1" ] || { read -r -p "Continue? [y/N] " answer; [ "$answer" = "y" ] || die "cancelled"; }
}

# Core's --set-secrets / --set-env-vars REPLACE the previous lists, so a plain 'core' deploy must
# re-state the Telegram settings or it would silently switch the panic command off.
telegram_secret_args() {
  if secret_exists "$SECRET_TG_TOKEN" && secret_exists "$SECRET_TG_WEBHOOK"; then
    printf ',TELEGRAM_BOT_TOKEN=%s:latest,TELEGRAM_WEBHOOK_SECRET=%s:latest' "$SECRET_TG_TOKEN" "$SECRET_TG_WEBHOOK"
  fi
}
telegram_env_args() {
  if [ -n "$TELEGRAM_BOT_USERNAME" ]; then printf '@TELEGRAM_BOT_USERNAME=%s' "$TELEGRAM_BOT_USERNAME"; fi
}

cors_json() {
  if [ -n "$DASHBOARD_ORIGIN" ]; then
    printf '["http://localhost:3000","%s"]' "${DASHBOARD_ORIGIN%/}"
  else
    printf '["http://localhost:3000"]'
  fi
}

sa_email() { echo "$1@${PROJECT_ID}.iam.gserviceaccount.com"; }

ensure_foundation() {
  say "Enabling the Google Cloud services this needs (safe to repeat)"
  gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
    cloudbuild.googleapis.com secretmanager.googleapis.com --project "$PROJECT_ID"

  say "Artifact Registry repository '$REPO' in $REGION"
  gcloud artifacts repositories describe "$REPO" --location "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1 \
    || gcloud artifacts repositories create "$REPO" --repository-format=docker --location "$REGION" \
         --description "RedHand container images" --project "$PROJECT_ID"

  for sa in "$CORE_SA" "$GATEWAY_SA"; do
    say "Service account $sa"
    gcloud iam service-accounts describe "$(sa_email "$sa")" --project "$PROJECT_ID" >/dev/null 2>&1 \
      || gcloud iam service-accounts create "$sa" --display-name "RedHand ${sa%-sa}" --project "$PROJECT_ID"
  done
}

secret_exists() { gcloud secrets describe "$1" --project "$PROJECT_ID" >/dev/null 2>&1; }

# put_secret NAME  (value on stdin; never echoed)
put_secret() {
  local name="$1"
  if secret_exists "$name"; then
    gcloud secrets versions add "$name" --data-file=- --project "$PROJECT_ID" >/dev/null
  else
    gcloud secrets create "$name" --replication-policy=automatic --data-file=- --project "$PROJECT_ID" >/dev/null
  fi
}

allow_secret() { # allow_secret SECRET SERVICE_ACCOUNT
  gcloud secrets add-iam-policy-binding "$1" --project "$PROJECT_ID" \
    --member "serviceAccount:$(sa_email "$2")" --role roles/secretmanager.secretAccessor >/dev/null
}

# Prints a new Ed25519 private key (PEM). macOS's built-in openssl (LibreSSL) may not support
# Ed25519, so try Homebrew's OpenSSL 3 and then Python's cryptography package.
generate_signing_key() {
  local candidate
  for candidate in openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" genpkey -algorithm ed25519 2>/dev/null; then
      return 0
    fi
  done
  if command -v python3 >/dev/null 2>&1; then
    python3 - 2>/dev/null <<'PY' && return 0
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
print(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode(), end="")
PY
  fi
  return 1
}

ensure_secrets() {
  if ! secret_exists "$SECRET_INTERNAL" || [ "${ROTATE:-}" = "1" ]; then
    say "Generating the internal service token (stored in Secret Manager only)"
    openssl rand -base64 32 | tr -d '\n' | put_secret "$SECRET_INTERNAL"
  else
    say "Keeping existing secret $SECRET_INTERNAL"
  fi

  if ! secret_exists "$SECRET_SIGNING" || [ "${ROTATE:-}" = "1" ]; then
    say "Generating the agent-token signing key (Ed25519; stored in Secret Manager only)"
    signing_key="$(generate_signing_key)" || die "could not generate an Ed25519 key: install OpenSSL 3 ('brew install openssl') or Python's 'cryptography' package, then re-run"
    case "$signing_key" in "-----BEGIN PRIVATE KEY-----"*) ;; *) die "generated key has an unexpected format; nothing was stored";; esac
    printf '%s\n' "$signing_key" | put_secret "$SECRET_SIGNING"
    unset signing_key
  else
    say "Keeping existing secret $SECRET_SIGNING"
  fi

  if ! secret_exists "$SECRET_SUPABASE"; then
    say "The Supabase SECRET key is needed once (Project Settings > API Keys > Secret keys)."
    read -r -s -p "Paste it now (input is hidden): " supabase_key; echo
    [ -n "$supabase_key" ] || die "no key entered"
    printf %s "$supabase_key" | put_secret "$SECRET_SUPABASE"
    unset supabase_key
  else
    say "Keeping existing secret $SECRET_SUPABASE (add a new version in the console to change it)"
  fi

  say "Granting each service access only to the secrets it needs"
  allow_secret "$SECRET_SUPABASE" "$CORE_SA"
  allow_secret "$SECRET_INTERNAL" "$CORE_SA"
  allow_secret "$SECRET_SIGNING" "$CORE_SA"
  allow_secret "$SECRET_INTERNAL" "$GATEWAY_SA"
}

build_image() { # build_image NAME DOCKERFILE -> sets IMAGE
  IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/$1:${TAG}"
  say "Building $IMAGE with Cloud Build (a few minutes)"
  gcloud builds submit --config deploy/cloudrun/cloudbuild.yaml \
    --substitutions "_DOCKERFILE=$2,_IMAGE=${IMAGE}" --project "$PROJECT_ID" .
}

service_url() { gcloud run services describe "$1" --region "$REGION" --project "$PROJECT_ID" --format='value(status.url)'; }

deploy_core() {
  build_image redhand-core deploy/cloudrun/Dockerfile.core
  say "Deploying redhand-core"
  # ^@^ makes '@' the separator so the JSON list in CORS_ALLOWED_ORIGINS can contain commas.
  gcloud run deploy redhand-core --image "$IMAGE" --region "$REGION" --project "$PROJECT_ID" \
    --service-account "$(sa_email "$CORE_SA")" \
    --allow-unauthenticated --min-instances 0 --max-instances 1 --cpu 1 --memory 512Mi --timeout 300 \
    --set-env-vars "^@^ENVIRONMENT=staging@LOG_LEVEL=INFO@SUPABASE_URL=${SUPABASE_URL}@OPERATOR_JWKS_URL=${SUPABASE_URL}/auth/v1/.well-known/jwks.json@OPERATOR_JWT_ISSUER=${SUPABASE_URL}/auth/v1@CORS_ALLOWED_ORIGINS=$(cors_json)$(telegram_env_args)" \
    --set-secrets "SUPABASE_SERVICE_ROLE_KEY=${SECRET_SUPABASE}:latest,INTERNAL_SERVICE_TOKEN=${SECRET_INTERNAL}:latest,AGENT_TOKEN_SIGNING_KEY=${SECRET_SIGNING}:latest$(telegram_secret_args)"
  say "redhand-core: $(service_url redhand-core)"
  if secret_exists "$SECRET_TG_TOKEN" && [ -z "$TELEGRAM_BOT_USERNAME" ]; then
    echo "note: TELEGRAM_BOT_USERNAME is not set, so the dashboard's one-tap Telegram link is off until you re-run with it." >&2
  fi
}

deploy_gateway() {
  local core_url
  core_url="$(service_url redhand-core)" || die "deploy redhand-core first"
  build_image redhand-gateway deploy/cloudrun/Dockerfile.gateway
  say "Deploying the gateway (talks to core at $core_url)"
  gcloud run deploy redhand-gateway --image "$IMAGE" --region "$REGION" --project "$PROJECT_ID" \
    --service-account "$(sa_email "$GATEWAY_SA")" \
    --allow-unauthenticated --min-instances 0 --max-instances 1 --cpu 1 --memory 512Mi --timeout 300 \
    --set-env-vars "^@^AGENTWALL_ENVIRONMENT=staging@AGENTWALL_CORE_URL=${core_url}@AGENTWALL_CONTEXT_CACHE_TTL_SECONDS=2@AGENTWALL_CORS_ALLOWED_ORIGINS=$(cors_json)" \
    --set-secrets "AGENTWALL_CORE_SERVICE_TOKEN=${SECRET_INTERNAL}:latest"
  say "gateway: $(service_url redhand-gateway)"
}

setup_telegram() {
  [ -n "$TELEGRAM_BOT_USERNAME" ] || die "set TELEGRAM_BOT_USERNAME (the bot's @name without the @)"
  case "$TELEGRAM_BOT_USERNAME" in *[!A-Za-z0-9_]*) die "TELEGRAM_BOT_USERNAME may only contain letters, digits and _";; esac
  ensure_foundation
  if ! secret_exists "$SECRET_TG_TOKEN"; then
    say "The Telegram bot token is needed once (from @BotFather)."
    read -r -s -p "Paste it now (input is hidden): " bot_token; echo
    case "$bot_token" in [0-9]*:?*) ;; *) die "that does not look like a bot token (expected 123456789:AA...); nothing was stored";; esac
    printf %s "$bot_token" | put_secret "$SECRET_TG_TOKEN"
    unset bot_token
  else
    say "Keeping existing secret $SECRET_TG_TOKEN"
  fi
  if ! secret_exists "$SECRET_TG_WEBHOOK" || [ "${ROTATE:-}" = "1" ]; then
    say "Generating the Telegram webhook secret (stored in Secret Manager only)"
    openssl rand -hex 32 | tr -d '\n' | put_secret "$SECRET_TG_WEBHOOK"
  else
    say "Keeping existing secret $SECRET_TG_WEBHOOK"
  fi
  allow_secret "$SECRET_TG_TOKEN" "$CORE_SA"
  allow_secret "$SECRET_TG_WEBHOOK" "$CORE_SA"
  say "Giving redhand-core the Telegram settings"
  gcloud run services update redhand-core --region "$REGION" --project "$PROJECT_ID" \
    --update-secrets "TELEGRAM_BOT_TOKEN=${SECRET_TG_TOKEN}:latest,TELEGRAM_WEBHOOK_SECRET=${SECRET_TG_WEBHOOK}:latest" \
    --update-env-vars "TELEGRAM_BOT_USERNAME=${TELEGRAM_BOT_USERNAME}"
  echo
  echo "Done. Now point Telegram at core:"
  echo "  python3 scripts/telegram_webhook.py set --project ${PROJECT_ID} --core-url \"$(gcloud run services describe redhand-core --region ${REGION} --format='value(status.url)')\""
}

update_cors() {
  [ -n "$DASHBOARD_ORIGIN" ] || die "set DASHBOARD_ORIGIN (for example https://your-dashboard.vercel.app)"
  say "Allowing the dashboard origin $DASHBOARD_ORIGIN"
  gcloud run services update redhand-core --region "$REGION" --project "$PROJECT_ID" \
    --update-env-vars "^@^CORS_ALLOWED_ORIGINS=$(cors_json)"
  gcloud run services update redhand-gateway --region "$REGION" --project "$PROJECT_ID" \
    --update-env-vars "^@^AGENTWALL_CORS_ALLOWED_ORIGINS=$(cors_json)"
}

summary() {
  echo
  echo "Done. Next:"
  echo "  1. Open https://console.cloud.google.com/run?project=${PROJECT_ID} and check both services show a green tick."
  echo "  2. Run the smoke test:"
  echo "       deploy/cloudrun/smoke.sh \"\$(gcloud run services describe redhand-core --region ${REGION} --format='value(status.url)')\" \\"
  echo "                                \"\$(gcloud run services describe redhand-gateway --region ${REGION} --format='value(status.url)')\""
}

preflight
case "$COMMAND" in
  secrets) ensure_foundation; ensure_secrets;;
  core) ensure_foundation; deploy_core; summary;;
  gateway) ensure_foundation; deploy_gateway; summary;;
  cors) update_cors;;
  telegram) setup_telegram;;
  all) ensure_foundation; ensure_secrets; deploy_core; deploy_gateway; summary;;
  *) die "unknown command '$COMMAND' (use all, secrets, core, gateway, cors or telegram)";;
esac
