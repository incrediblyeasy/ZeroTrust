#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

WAIT_FOR_HEALTH=1
[[ "${1:-}" == "--no-wait" ]] && WAIT_FOR_HEALTH=0

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

say "Checking prerequisites"
command -v docker  >/dev/null 2>&1 || die "docker is not installed or not on PATH."
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin ('docker compose') is required."
command -v openssl >/dev/null 2>&1 || die "openssl is required to generate the mTLS certificates."
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon — is it running and do you have permission?"
echo "    docker, compose, openssl present; daemon reachable."

set_env_var() {
  # Replace KEY=... in .env (key is assumed to already exist from .env.example).
  local key="$1" value="$2"
  if grep -q "^${key}=" .env; then
    # Use a sed delimiter unlikely to appear in a hex secret.
    sed -i.bak "s|^${key}=.*|${key}=${value}|" .env && rm -f .env.bak
  else
    printf '%s=%s\n' "${key}" "${value}" >> .env
  fi
}

if [[ -f .env ]]; then
  say ".env already present — leaving it untouched"
else
  say "Creating .env from .env.example with freshly generated secrets"
  cp .env.example .env

  # Replace every placeholder secret with a strong random value so no two
  # deployments share credentials and nothing weak ever reaches production.
  set_env_var KEYCLOAK_ADMIN_PASSWORD "$(openssl rand -hex 24)"
  set_env_var INTERNAL_GATEWAY_SECRET "$(openssl rand -hex 32)"
  set_env_var AUDIT_HMAC_KEY "$(openssl rand -hex 32)"
  set_env_var LOGSTASH_INGEST_TOKEN "$(openssl rand -hex 32)"
  echo "    Generated random KEYCLOAK_ADMIN_PASSWORD, INTERNAL_GATEWAY_SECRET, AUDIT_HMAC_KEY, LOGSTASH_INGEST_TOKEN."
  echo "    (Keycloak admin password is stored in .env — never committed.)"
fi

say "Generating mTLS certificates (idempotent)"
bash "${SCRIPT_DIR}/generate-certs.sh"

say "Building images and starting the stack"
docker compose up -d --build

if [[ "${WAIT_FOR_HEALTH}" -eq 0 ]]; then
  say "Stack started (--no-wait); current status:"
  docker compose ps
  exit 0
fi

say "Waiting for services to become healthy (up to 5 minutes)"
deadline=$(( $(date +%s) + 300 ))
while :; do
  not_ready=$(docker compose ps --format '{{.Name}} {{.Status}}' \
    | grep -Ev 'healthy|Up ' || true)
  unhealthy=$(docker compose ps --format '{{.Name}} {{.Status}}' \
    | grep -E 'unhealthy|starting' || true)
  if [[ -z "${unhealthy}" && -z "${not_ready}" ]]; then
    break
  fi
  if [[ "$(date +%s)" -ge "${deadline}" ]]; then
    say "Timed out waiting for health; current status:"
    docker compose ps
    die "one or more services did not become healthy in time. Check 'docker compose logs'."
  fi
  sleep 5
done

say "All services are up. Current status:"
docker compose ps
cat <<'EOF'

ZTAC is ready.
  - Envoy ingress (data plane):   http://localhost:8080
  - Keycloak:                     http://localhost:8180  (admin user: see KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD in .env)
  - Kibana:                       http://localhost:5601
  - API gateway health:           http://localhost:8001/health

Get an analyst token and call a protected endpoint:
  TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztac/protocol/openid-connect/token \
    -d grant_type=password -d client_id=ztac-cli -d username=bob -d password=bob123 \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  curl -s -H "Authorization: Bearer $TOKEN" -H "x-device-trust: managed" \
    http://localhost:8080/api/data/reports
EOF
