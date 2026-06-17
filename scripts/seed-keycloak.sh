#!/usr/bin/env bash
# scripts/seed-keycloak.sh
# Imports the ZTAC realm into a running Keycloak instance.
# Usage: ./scripts/seed-keycloak.sh

set -euo pipefail

# Load env vars
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

KEYCLOAK_URL="http://localhost:${KEYCLOAK_HTTP_PORT:-8180}"
REALM="${KEYCLOAK_REALM:-ztac}"

echo "==> Waiting for Keycloak to be ready..."
until curl -sf "${KEYCLOAK_URL}/health/ready" > /dev/null 2>&1; do
  sleep 2
done
echo "==> Keycloak is ready."

# Get admin access token
echo "==> Authenticating as admin..."
ADMIN_TOKEN=$(curl -sf -X POST \
  "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=${KEYCLOAK_ADMIN}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
  echo "ERROR: Failed to get admin token."
  exit 1
fi

# Check if realm already exists
REALM_EXISTS=$(curl -sf -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/${REALM}")

if [ "$REALM_EXISTS" = "200" ]; then
  echo "==> Realm '${REALM}' already exists. Skipping import."
  echo "    To re-import, delete the realm first:"
  echo "    curl -X DELETE -H 'Authorization: Bearer <token>' ${KEYCLOAK_URL}/admin/realms/${REALM}"
else
  echo "==> Importing realm '${REALM}' from realm-export.json..."
  HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST \
    "${KEYCLOAK_URL}/admin/realms" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d @keycloak/realm-export.json)

  if [ "$HTTP_CODE" = "201" ]; then
    echo "==> Realm imported successfully."
  else
    echo "ERROR: Realm import failed with HTTP ${HTTP_CODE}."
    exit 1
  fi
fi

# Verify: get a token for each test user
echo ""
echo "==> Verifying token issuance for test users..."
for USER_VAR in "TEST_USER_ADMIN:TEST_USER_ADMIN_PASSWORD:admin" \
                "TEST_USER_ANALYST:TEST_USER_ANALYST_PASSWORD:analyst" \
                "TEST_USER_VIEWER:TEST_USER_VIEWER_PASSWORD:viewer"; do
  IFS=':' read -r USER_KEY PASS_KEY EXPECTED_ROLE <<< "$USER_VAR"
  USERNAME="${!USER_KEY}"
  PASSWORD="${!PASS_KEY}"

  TOKEN=$(curl -sf -X POST \
    "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=ztac-cli&username=${USERNAME}&password=${PASSWORD}" \
    | jq -r '.access_token')

  if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "    FAIL: ${USERNAME} — could not obtain token"
  else
    ROLES=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.realm_access.roles[]' 2>/dev/null)
    if echo "$ROLES" | grep -q "$EXPECTED_ROLE"; then
      echo "    OK: ${USERNAME} — token issued, role '${EXPECTED_ROLE}' present"
    else
      echo "    WARN: ${USERNAME} — token issued but role '${EXPECTED_ROLE}' not found in: ${ROLES}"
    fi
  fi
done

echo ""
echo "==> Seed complete."
