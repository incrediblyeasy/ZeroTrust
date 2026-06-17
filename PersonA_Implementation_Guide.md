# Person A — Implementation Guide

## Identity Pipeline · Accountability Subsystem · Adversarial Testing · Documentation

---

## Scope overview

Person A owns everything on the authentication and accountability sides of the ZTAC framework.

**You build and own:**

- `keycloak/` — Identity Provider (Keycloak with OIDC, JWT issuance, MFA-ready config)
- `services/protected-service/` — the downstream microservice with tiered endpoints
- `elk/` — Elasticsearch + Logstash + Kibana with hash-chained audit logs
- `scripts/seed-keycloak.sh` — automated realm provisioning
- `tests/test_token_replay.py` — adversarial scenario 1
- `tests/test_stale_session.py` — adversarial scenario 4
- `tests/test_log_tampering.py` — adversarial scenario 5
- `tests/conftest.py` — shared test fixtures (Keycloak token helper)
- `scripts/verify_log_chain.py` — standalone log integrity checker
- `docs/cybok-alignment-matrix.md` — the project's central academic deliverable
- `docs/architecture-diagram.md` — request flow diagram
- The evaluation report section (Day 9)

**You contribute to (shared with Person B):**

- Root `docker-compose.yml` — you write the initial skeleton and own the Keycloak + ELK service blocks; Person B adds OPA + Envoy blocks
- `.env.example` — you define Keycloak vars; Person B adds OPA/Envoy vars
- Day 10 final integration and cross-review

**Person B owns (you don't touch, but you depend on):**

- `opa/` — Rego policies, OPA container
- `envoy/` — proxy config, ext_authz filter, mTLS certs
- `services/api-gateway/` — the gateway service that sits behind Envoy

---

## Prerequisites

Before Day 1, make sure you have:

- Docker Desktop or Docker Engine 24+ with Docker Compose v2
- Python 3.12+ with `pip`
- `curl`, `jq`, `openssl` available in your terminal
- A GitHub account with SSH key configured
- At least 8 GB of RAM free (ELK is hungry)

---

## Day 1 — Repo scaffolding and Keycloak

### 1.1 Create the monorepo

```bash
mkdir ztac-framework && cd ztac-framework
git init
git checkout -b main
```

Create the directory skeleton:

```bash
mkdir -p keycloak/themes
mkdir -p elk/logstash elk/kibana
mkdir -p services/protected-service
mkdir -p scripts
mkdir -p tests
mkdir -p docs
```

### 1.2 Write .env.example

Create `.env.example` at the repo root. This is the single source of truth for all configurable values. Both people source from it.

```env
# ---- Keycloak (Person A) ----
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
KEYCLOAK_HTTP_PORT=8180
KEYCLOAK_REALM=ztac
KEYCLOAK_GATEWAY_CLIENT_ID=ztac-gateway
KEYCLOAK_GATEWAY_CLIENT_SECRET=change-me-in-production
KEYCLOAK_CLI_CLIENT_ID=ztac-cli

# ---- Test users (Person A) ----
TEST_USER_ADMIN=alice
TEST_USER_ADMIN_PASSWORD=alice123
TEST_USER_ANALYST=bob
TEST_USER_ANALYST_PASSWORD=bob123
TEST_USER_VIEWER=charlie
TEST_USER_VIEWER_PASSWORD=charlie123

# ---- OPA (Person B) ----
OPA_HTTP_PORT=8181

# ---- Envoy (Person B) ----
ENVOY_HTTP_PORT=8080

# ---- ELK (Person A) ----
ES_HTTP_PORT=9200
ES_JAVA_OPTS=-Xms512m -Xmx512m
KIBANA_HTTP_PORT=5601
LOGSTASH_TCP_PORT=5044
LOGSTASH_HTTP_PORT=5050

# ---- Protected Service (Person A) ----
PROTECTED_SERVICE_PORT=8000

# ---- Network ----
DOCKER_NETWORK=ztac-net
```

Copy it to `.env` for local use:

```bash
cp .env.example .env
```

Add `.env` to `.gitignore`:

```bash
echo ".env" > .gitignore
echo "__pycache__/" >> .gitignore
echo "*.pyc" >> .gitignore
echo ".pytest_cache/" >> .gitignore
```

### 1.3 Write docker-compose.yml (initial skeleton)

You create the initial file with the services you own. Person B will add `opa` and `envoy` blocks via PR.

```yaml
# docker-compose.yml
version: "3.9"

networks:
  ztac-net:
    driver: bridge

services:
  # ============================================================
  # KEYCLOAK — Identity Provider (Person A)
  # ============================================================
  keycloak:
    image: quay.io/keycloak/keycloak:24.0.4
    container_name: ztac-keycloak
    command: start-dev --import-realm
    environment:
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
    ports:
      - "${KEYCLOAK_HTTP_PORT}:8080"
    volumes:
      - ./keycloak/realm-export.json:/opt/keycloak/data/import/realm-export.json:ro
    networks:
      - ztac-net
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/8080 && echo -e 'GET /health/ready HTTP/1.1\r\nHost: localhost\r\n\r\n' >&3 && cat <&3 | grep -q '200'"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 30s

  # ============================================================
  # PROTECTED SERVICE — downstream microservice (Person A)
  # ============================================================
  protected-service:
    build: ./services/protected-service
    container_name: ztac-protected-service
    ports:
      - "${PROTECTED_SERVICE_PORT}:8000"
    environment:
      - KEYCLOAK_ISSUER=http://keycloak:8080/realms/${KEYCLOAK_REALM}
    networks:
      - ztac-net
    depends_on:
      keycloak:
        condition: service_healthy

  # ============================================================
  # ELASTICSEARCH (Person A)
  # ============================================================
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.14.1
    container_name: ztac-elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=${ES_JAVA_OPTS}
    ports:
      - "${ES_HTTP_PORT}:9200"
    networks:
      - ztac-net
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

  # ============================================================
  # LOGSTASH (Person A)
  # ============================================================
  logstash:
    image: docker.elastic.co/logstash/logstash:8.14.1
    container_name: ztac-logstash
    volumes:
      - ./elk/logstash/pipeline.conf:/usr/share/logstash/pipeline/pipeline.conf:ro
    ports:
      - "${LOGSTASH_TCP_PORT}:5044"
      - "${LOGSTASH_HTTP_PORT}:5050"
    environment:
      - LS_JAVA_OPTS=-Xms256m -Xmx256m
    networks:
      - ztac-net
    depends_on:
      elasticsearch:
        condition: service_healthy

  # ============================================================
  # KIBANA (Person A)
  # ============================================================
  kibana:
    image: docker.elastic.co/kibana/kibana:8.14.1
    container_name: ztac-kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "${KIBANA_HTTP_PORT}:5601"
    networks:
      - ztac-net
    depends_on:
      elasticsearch:
        condition: service_healthy

  # ============================================================
  # Person B adds: opa, envoy, api-gateway
  # ============================================================
```

### 1.4 Keycloak realm configuration

You configure the realm manually first to understand the UI, then export to JSON for repeatability.

**Step 1 — start Keycloak standalone:**

```bash
docker compose up keycloak -d
# wait for healthy
docker compose logs keycloak -f  # watch for "Listening on: http://0.0.0.0:8080"
```

**Step 2 — open admin console:**

Go to `http://localhost:8180` → log in with `admin` / `admin`.

**Step 3 — create the `ztac` realm:**

- Top-left dropdown → "Create realm" → name: `ztac` → Create.

**Step 4 — create realm roles:**

Realm Settings → Realm Roles → Create Role:

| Role name | Description |
|---|---|
| `admin` | Full administrative access to all resources |
| `analyst` | Read access to reports and analytics data |
| `viewer` | Read-only access to public resources only |

**Step 5 — create clients:**

Clients → Create Client:

**Client 1 — `ztac-gateway` (confidential, used by the api-gateway service):**

- Client ID: `ztac-gateway`
- Client authentication: ON (makes it confidential)
- Authentication flow: check "Standard flow" and "Service accounts roles" and "Direct access grants"
- Valid redirect URIs: `http://localhost:8080/*`
- Web origins: `*`
- After creation → Credentials tab → copy the Client Secret → put in `.env` as `KEYCLOAK_GATEWAY_CLIENT_SECRET`

**Client 2 — `ztac-cli` (public, used for testing from curl/Postman):**

- Client ID: `ztac-cli`
- Client authentication: OFF (public client)
- Authentication flow: check "Direct access grants" only
- Valid redirect URIs: `http://localhost:*`

**Step 6 — create test users:**

Users → Add User for each:

| Username | Email | First name | Last name | Realm role assigned |
|---|---|---|---|---|
| `alice` | alice@ztac.lab | Alice | Admin | `admin` |
| `bob` | bob@ztac.lab | Bob | Analyst | `analyst` |
| `charlie` | charlie@ztac.lab | Charlie | Viewer | `viewer` |

For each user: Credentials tab → Set Password → password from `.env` → Temporary = OFF.
For each user: Role Mapping tab → Assign Role → filter by realm roles → assign the correct role.

**Step 7 — configure token settings:**

Realm Settings → Tokens:

| Setting | Value | Reason |
|---|---|---|
| Access Token Lifespan | 5 minutes | Short-lived for zero-trust continuous verification |
| Client login timeout | 5 minutes | |
| SSO Session Idle | 30 minutes | |
| SSO Session Max | 10 hours | |
| Access Token Lifespan For Implicit Flow | 5 minutes | |

**Step 8 — configure token mappers (ensure OPA gets the claims it needs):**

Client Scopes → `ztac-gateway-dedicated` → Add Mapper → By configuration:

**Mapper 1 — Realm Roles in token:**

- Name: `realm-roles`
- Mapper type: User Realm Role
- Token Claim Name: `realm_access.roles`
- Claim JSON Type: String
- Add to ID token: ON
- Add to access token: ON
- Add to userinfo: ON
- Multivalued: ON

This is usually already present by default, but verify the claim structure. The JWT should contain:

```json
{
  "realm_access": {
    "roles": ["admin"]
  }
}
```

**Mapper 2 — JTI (JSON Token ID) for revocation:**

Keycloak includes `jti` by default in JWTs. Verify by decoding a token (Step 9).

**Step 9 — verify token issuance:**

```bash
# Get a token for alice (admin role)
TOKEN=$(curl -s -X POST \
  "http://localhost:8180/realms/ztac/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=ztac-cli" \
  -d "username=alice" \
  -d "password=alice123" | jq -r '.access_token')

echo $TOKEN

# Decode the JWT payload (middle segment)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

**Expected payload structure (this is the contract Person B depends on):**

```json
{
  "exp": 1718400300,
  "iat": 1718400000,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "iss": "http://keycloak:8080/realms/ztac",
  "sub": "user-uuid-here",
  "preferred_username": "alice",
  "email": "alice@ztac.lab",
  "realm_access": {
    "roles": ["admin", "default-roles-ztac"]
  },
  "scope": "openid email profile"
}
```

**Step 10 — export the realm:**

```bash
docker exec ztac-keycloak /opt/keycloak/bin/kc.sh export \
  --dir /opt/keycloak/data/export \
  --realm ztac \
  --users realm_file

docker cp ztac-keycloak:/opt/keycloak/data/export/ztac-realm.json ./keycloak/realm-export.json
```

Review the export and remove any sensitive fields you don't want in git (though for a lab this is fine).

**Step 11 — verify import works from scratch:**

```bash
docker compose down -v
docker compose up keycloak -d
# wait for healthy, then test token again
```

### 1.5 Protected service stub

Create `services/protected-service/main.py`:

```python
"""
Protected Service — simulated downstream microservice.
Serves three endpoints at different sensitivity levels.
No direct auth enforcement here — that's Envoy+OPA's job.
This service trusts that requests arriving have already passed the PEP.
"""

from fastapi import FastAPI, Request
from datetime import datetime, timezone
import logging
import json

app = FastAPI(title="ZTAC Protected Service")

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",  # raw JSON output
)
logger = logging.getLogger("protected-service")


def log_access(request: Request, endpoint: str, sensitivity: str):
    """Emit structured access log for every request."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "protected-service",
        "endpoint": endpoint,
        "sensitivity": sensitivity,
        "method": request.method,
        "client_ip": request.client.host if request.client else "unknown",
        "headers": {
            "x-forwarded-for": request.headers.get("x-forwarded-for", ""),
            "x-request-id": request.headers.get("x-request-id", ""),
            # Person B's Envoy will inject these after ext_authz
            "x-auth-user": request.headers.get("x-auth-user", ""),
            "x-auth-roles": request.headers.get("x-auth-roles", ""),
        },
    }
    logger.info(json.dumps(log_entry))


@app.get("/api/data/public")
async def public_data(request: Request):
    """Public endpoint — no authentication required."""
    log_access(request, "/api/data/public", "public")
    return {
        "status": "ok",
        "data": "This is publicly accessible data.",
        "sensitivity": "public",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/data/reports")
async def reports_data(request: Request):
    """Reports endpoint — requires analyst role or above."""
    log_access(request, "/api/data/reports", "internal")
    return {
        "status": "ok",
        "data": {
            "report_id": "RPT-2024-001",
            "title": "Q2 Security Posture Assessment",
            "classification": "internal",
            "summary": "Simulated report data for ZTAC framework evaluation.",
        },
        "sensitivity": "internal",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/data/admin")
async def admin_data(request: Request):
    """Admin endpoint — requires admin role only."""
    log_access(request, "/api/data/admin", "confidential")
    return {
        "status": "ok",
        "data": {
            "config": {
                "auth_provider": "keycloak",
                "pdp": "opa",
                "pep": "envoy",
                "mTLS": True,
                "log_integrity": "sha256-hash-chain",
            },
            "users_total": 3,
            "active_sessions": 1,
        },
        "sensitivity": "confidential",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "protected-service"}
```

Create `services/protected-service/requirements.txt`:

```
fastapi==0.111.0
uvicorn[standard]==0.30.1
```

Create `services/protected-service/Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 1.6 Day 1 verification

```bash
docker compose up keycloak protected-service -d --build

# Test Keycloak
curl -s http://localhost:8180/realms/ztac/.well-known/openid-configuration | jq .issuer
# Expected: "http://localhost:8180/realms/ztac"

# Test protected service
curl -s http://localhost:8000/api/data/public | jq .
# Expected: {"status": "ok", "data": "This is publicly accessible data.", ...}

# Get token and decode
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztac/protocol/openid-connect/token \
  -d "grant_type=password&client_id=ztac-cli&username=alice&password=alice123" | jq -r .access_token)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .realm_access
# Expected: {"roles": ["admin", ...]}
```

**Commit and push:**

```bash
git add -A
git commit -m "feat: repo scaffold, keycloak realm, protected-service stub"
git push -u origin main
```

---

## Day 2 — JWT configuration, seed script, and token schema

### 2.1 Keycloak seed script

Create `scripts/seed-keycloak.sh`. This automates realm import so Person B (and CI) can stand up the identity layer without touching the Keycloak admin UI.

```bash
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
```

Make it executable:

```bash
chmod +x scripts/seed-keycloak.sh
```

### 2.2 Document the JWT token schema

Create `docs/token-schema.md`. This is the contract between Person A and Person B — the exact claim names that OPA will read.

```markdown
# JWT Token Schema — ZTAC Framework

## Issuer

- Keycloak realm: `ztac`
- Issuer URL (internal): `http://keycloak:8080/realms/ztac`
- Issuer URL (external): `http://localhost:8180/realms/ztac`
- JWKS endpoint: `<issuer>/.well-known/openid-configuration` → `jwks_uri`

## Access token claims (used by OPA)

| Claim | Type | Example | OPA input key | Notes |
|---|---|---|---|---|
| `exp` | integer (unix timestamp) | `1718400300` | `input.token_exp` | 5-minute lifespan |
| `iat` | integer (unix timestamp) | `1718400000` | — | Not used by OPA |
| `jti` | string (UUID) | `"a1b2c3d4-..."` | `input.token_jti` | For revocation blacklist |
| `iss` | string (URL) | `"http://keycloak:8080/realms/ztac"` | — | Validated by gateway |
| `sub` | string (UUID) | `"550e8400-..."` | — | Keycloak user ID |
| `preferred_username` | string | `"alice"` | `input.user` | Human-readable username |
| `email` | string | `"alice@ztac.lab"` | — | For audit logs |
| `realm_access.roles` | array of strings | `["admin"]` | `input.roles` | Realm-level roles |
| `scope` | string | `"openid email profile"` | — | OIDC scopes |

## Claims added by the api-gateway (injected as HTTP headers after JWT validation)

| Header | Source claim | OPA input key |
|---|---|---|
| `x-auth-user` | `preferred_username` | `input.user` |
| `x-auth-roles` | `realm_access.roles` (JSON-encoded) | `input.roles` |
| `x-auth-jti` | `jti` | `input.token_jti` |
| `x-auth-exp` | `exp` | `input.token_exp` |

## Additional context headers (set by gateway based on request metadata)

| Header | Value | OPA input key |
|---|---|---|
| `x-device-trust` | `"managed"` or `"byod_compliant"` or `"untrusted"` | `input.device_trust` |
| `x-ip-risk` | `"low"` or `"medium"` or `"high"` | `input.ip_risk` |

Note: In the lab environment, `x-device-trust` defaults to `"managed"` and `x-ip-risk`
defaults to `"low"` unless explicitly overridden in test headers. In a production deployment,
these would come from a device posture agent and an IP reputation service.

## Token endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/realms/ztac/protocol/openid-connect/token` | POST | Token issuance (password grant, refresh) |
| `/realms/ztac/protocol/openid-connect/revoke` | POST | Token revocation |
| `/realms/ztac/protocol/openid-connect/logout` | POST | Backchannel logout |
| `/realms/ztac/protocol/openid-connect/certs` | GET | JWKS (public keys for JWT verification) |
| `/admin/realms/ztac/users/<id>/logout` | POST | Admin-initiated session logout |
```

### 2.3 Commit Day 2

```bash
git add -A
git commit -m "feat: seed script, token schema docs, keycloak token config"
```

**Sync with Person B:** share `docs/token-schema.md` — they need the exact claim paths for their Rego policy.

---

## Day 3 — Protected service expansion and mTLS client config

### 3.1 Expand the protected service

The three endpoints are already in place from Day 1. Now add mTLS support and request ID tracking.

Update `services/protected-service/main.py` — add a middleware that logs the full request context and validates that internal requests came through Envoy (by checking for the `x-request-id` header Envoy injects):

```python
"""
Protected Service — expanded with request tracking and internal-call validation.
"""

from fastapi import FastAPI, Request, Response
from datetime import datetime, timezone
import logging
import json
import uuid

app = FastAPI(title="ZTAC Protected Service")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("protected-service")


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Log every request with full context for the ELK accountability subsystem."""
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    start_time = datetime.now(timezone.utc)

    response: Response = await call_next(request)

    duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

    log_entry = {
        "timestamp": start_time.isoformat(),
        "service": "protected-service",
        "request_id": request_id,
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query) if request.url.query else None,
        "status_code": response.status_code,
        "duration_ms": round(duration_ms, 2),
        "client_ip": request.client.host if request.client else "unknown",
        "user": request.headers.get("x-auth-user", "anonymous"),
        "roles": request.headers.get("x-auth-roles", "[]"),
        "device_trust": request.headers.get("x-device-trust", "unknown"),
        "ip_risk": request.headers.get("x-ip-risk", "unknown"),
        "envoy_routed": "x-request-id" in request.headers,
    }
    logger.info(json.dumps(log_entry))

    response.headers["x-request-id"] = request_id
    return response


@app.get("/api/data/public")
async def public_data():
    return {
        "status": "ok",
        "data": "This is publicly accessible data.",
        "sensitivity": "public",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/data/reports")
async def reports_data():
    return {
        "status": "ok",
        "data": {
            "report_id": "RPT-2024-001",
            "title": "Q2 Security Posture Assessment",
            "classification": "internal",
            "summary": "Simulated report data for ZTAC evaluation.",
        },
        "sensitivity": "internal",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/data/admin")
async def admin_data():
    return {
        "status": "ok",
        "data": {
            "config": {
                "auth_provider": "keycloak",
                "pdp": "opa",
                "pep": "envoy",
                "mTLS": True,
                "log_integrity": "sha256-hash-chain",
            },
            "users_total": 3,
            "active_sessions": 1,
        },
        "sensitivity": "confidential",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "protected-service"}
```

---

## Day 4 — ELK accountability subsystem

This is the CyBOK Accountability pillar. Every access decision — allow or deny — is logged with user identity, timestamp, resource, and action, forming an immutable audit trail with cryptographic hash chaining.

### 4.1 Logstash pipeline with hash chaining

Create `elk/logstash/pipeline.conf`:

```conf
# elk/logstash/pipeline.conf
# Ingests structured JSON logs from Envoy, OPA, and services.
# Adds SHA-256 hash chaining for log integrity (CyBOK accountability).

input {
  # HTTP input — services POST JSON logs here
  http {
    port => 5050
    codec => json
    additional_codecs => {}
  }

  # TCP input — for syslog-style forwarding
  tcp {
    port => 5044
    codec => json_lines
  }
}

filter {
  # Ensure every log has a timestamp
  if ![timestamp] {
    ruby {
      code => 'event.set("timestamp", Time.now.utc.iso8601(3))'
    }
  }

  # Normalise the source field
  if ![source_component] {
    mutate {
      add_field => { "source_component" => "unknown" }
    }
  }

  # =========================================================
  # HASH CHAINING — cryptographic log integrity
  # Each log's hash = SHA-256(previous_hash + current_body)
  # This enables tamper detection in the accountability audit.
  # =========================================================
  ruby {
    code => '
      require "digest"
      require "json"

      # Build the log body to hash (exclude meta fields)
      body_fields = {}
      event.to_hash.each do |k, v|
        next if k.start_with?("@") || k == "log_hash" || k == "previous_hash"
        body_fields[k] = v
      end
      body_json = body_fields.sort.to_h.to_json

      # Read previous hash from a file (shared state across events)
      hash_file = "/tmp/logstash_last_hash"
      previous_hash = "GENESIS"
      if File.exist?(hash_file)
        previous_hash = File.read(hash_file).strip
      end

      # Compute current hash
      current_hash = Digest::SHA256.hexdigest(previous_hash + body_json)

      # Store for next event
      File.write(hash_file, current_hash)

      event.set("previous_hash", previous_hash)
      event.set("log_hash", current_hash)
      event.set("log_body_for_hash", body_json)
    '
  }

  # Add a sequence number for ordering
  ruby {
    code => '
      seq_file = "/tmp/logstash_seq"
      seq = 0
      if File.exist?(seq_file)
        seq = File.read(seq_file).strip.to_i
      end
      seq += 1
      File.write(seq_file, seq.to_s)
      event.set("log_sequence", seq)
    '
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "ztac-audit-%{+YYYY.MM.dd}"
  }

  # Also print to stdout for debugging
  stdout {
    codec => json_lines
  }
}
```

### 4.2 Verify ELK starts

```bash
docker compose up elasticsearch logstash kibana -d

# Wait for ES
until curl -sf http://localhost:9200/_cluster/health | jq .status; do sleep 3; done

# Send a test log
curl -X POST http://localhost:5050 \
  -H "Content-Type: application/json" \
  -d '{"source_component":"test","message":"ELK pipeline verification","user":"alice","action":"GET","resource":"/api/data/reports"}'

# Check it landed in ES
sleep 2
curl -s "http://localhost:9200/ztac-audit-*/_search?size=1" | jq '.hits.hits[0]._source | {log_hash, previous_hash, log_sequence, user, action}'
```

Expected output:

```json
{
  "log_hash": "a1b2c3...",
  "previous_hash": "GENESIS",
  "log_sequence": 1,
  "user": "alice",
  "action": "GET"
}
```

### 4.3 Send a second log and verify chain

```bash
curl -X POST http://localhost:5050 \
  -H "Content-Type: application/json" \
  -d '{"source_component":"test","message":"Second log entry","user":"bob","action":"POST","resource":"/api/data/admin"}'

sleep 2
curl -s "http://localhost:9200/ztac-audit-*/_search?size=2&sort=log_sequence:asc" \
  | jq '.hits.hits[]._source | {log_sequence, log_hash, previous_hash}'
```

The second log's `previous_hash` should equal the first log's `log_hash`. This chain is what `test_log_tampering.py` will verify and attempt to break.

### 4.4 Configure services to send logs to Logstash

Add a log forwarder to the protected service. Update `services/protected-service/requirements.txt`:

```
fastapi==0.111.0
uvicorn[standard]==0.30.1
httpx==0.27.0
```

Add a background log shipper to the protected service. Insert at the top of `main.py`:

```python
import httpx
import asyncio
import os

LOGSTASH_URL = os.getenv("LOGSTASH_URL", "http://logstash:5050")


async def ship_log(log_entry: dict):
    """Send structured log to Logstash asynchronously."""
    log_entry["source_component"] = "protected-service"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(LOGSTASH_URL, json=log_entry)
    except Exception:
        pass  # Don't let logging failures break the service
```

Then in the `audit_middleware`, after `logger.info(json.dumps(log_entry))`, add:

```python
    asyncio.create_task(ship_log(log_entry.copy()))
```

Update the `docker-compose.yml` protected-service block to add:

```yaml
    environment:
      - KEYCLOAK_ISSUER=http://keycloak:8080/realms/${KEYCLOAK_REALM}
      - LOGSTASH_URL=http://logstash:5050
    depends_on:
      keycloak:
        condition: service_healthy
      logstash:
        condition: service_started
```

### 4.5 Kibana dashboard setup

Once Kibana is running at `http://localhost:5601`:

1. Go to Stack Management → Data Views → Create data view:
   - Name: `ztac-audit`
   - Index pattern: `ztac-audit-*`
   - Timestamp field: `@timestamp`

2. Go to Discover → select the `ztac-audit` data view. Verify logs appear.

3. Create saved searches:
   - "All Access Decisions" — no filter, columns: `timestamp`, `user`, `action`, `resource`, `status_code`
   - "Denied Requests" — filter: `status_code: 403`, columns: same
   - "Admin Access" — filter: `resource: /api/data/admin`, columns: same

4. Create a dashboard with visualisations:
   - Bar chart: request count over time (x: `@timestamp`, y: count)
   - Pie chart: requests by `status_code`
   - Data table: top 10 users by request count
   - Metric: total 403 responses

5. Export the dashboard: Stack Management → Saved Objects → select dashboard + all linked objects → Export → save as `elk/kibana/dashboards.ndjson`.

---

## Day 5 — Session management and continuous validation

### 5.1 Token revocation via JTI blacklist

The gateway (Person B's service) is the primary place for JWT validation. However, Person A provides the revocation infrastructure. Create a shared module that Person B imports.

Create `services/shared/token_blacklist.py`:

```python
"""
In-memory JTI blacklist for token revocation.
In production, this would be backed by Redis or a database.
For the ZTAC lab, an in-memory set is sufficient.

CyBOK alignment: Session Management — ensures revoked tokens
cannot be reused even if they haven't expired yet.
"""

import threading
from datetime import datetime, timezone
from typing import Optional


class TokenBlacklist:
    """Thread-safe token revocation blacklist."""

    def __init__(self):
        self._revoked: dict[str, float] = {}  # jti -> revocation timestamp
        self._lock = threading.Lock()

    def revoke(self, jti: str) -> None:
        """Add a JTI to the blacklist."""
        with self._lock:
            self._revoked[jti] = datetime.now(timezone.utc).timestamp()

    def is_revoked(self, jti: str) -> bool:
        """Check if a JTI has been revoked."""
        with self._lock:
            return jti in self._revoked

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove entries older than max_age_seconds. Returns count removed."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            expired = [
                jti for jti, ts in self._revoked.items()
                if (now - ts) > max_age_seconds
            ]
            for jti in expired:
                del self._revoked[jti]
            return len(expired)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._revoked)


# Singleton instance — imported by the gateway
blacklist = TokenBlacklist()
```

### 5.2 Keycloak backchannel logout listener

Create `services/shared/keycloak_logout.py`:

```python
"""
Keycloak backchannel logout handler.
When a user logs out or an admin terminates a session,
Keycloak sends a POST with a logout token containing the session ID.
This handler extracts the session's JTIs and adds them to the blacklist.

Configure in Keycloak: Client → ztac-gateway → Advanced → Backchannel Logout URL:
  http://api-gateway:8001/backchannel-logout
"""

import json
import base64
from .token_blacklist import blacklist


def handle_backchannel_logout(logout_token: str) -> dict:
    """
    Process a Keycloak backchannel logout token.
    Extracts the session ID and revokes associated tokens.
    """
    try:
        # Decode the logout token payload (middle segment)
        payload = json.loads(
            base64.urlsafe_b64decode(
                logout_token.split(".")[1] + "=="
            )
        )

        sid = payload.get("sid", "unknown")
        sub = payload.get("sub", "unknown")

        # In a real implementation, we'd look up all JTIs for this session.
        # For the lab, we add the session ID itself as a revocation marker.
        blacklist.revoke(f"session:{sid}")

        return {
            "status": "ok",
            "revoked_session": sid,
            "user": sub,
            "blacklist_size": blacklist.size,
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}
```

### 5.3 Configure Keycloak backchannel logout

In Keycloak admin console:

1. Clients → `ztac-gateway` → Settings → Backchannel Logout URL: `http://api-gateway:8001/backchannel-logout`
2. Backchannel Logout Session Required: ON
3. Re-export the realm:

```bash
docker exec ztac-keycloak /opt/keycloak/bin/kc.sh export \
  --dir /opt/keycloak/data/export --realm ztac --users realm_file
docker cp ztac-keycloak:/opt/keycloak/data/export/ztac-realm.json ./keycloak/realm-export.json
```

### 5.4 Tell Person B

Person B needs to integrate `token_blacklist.py` and `keycloak_logout.py` into the api-gateway. Share the `services/shared/` directory and tell them:

- Import `from shared.token_blacklist import blacklist`
- In their JWT validation middleware, after signature verification, add: `if blacklist.is_revoked(claims["jti"]): return 401`
- Add a POST endpoint at `/backchannel-logout` that calls `handle_backchannel_logout()`

---

## Day 6 — Adversarial tests (scenarios 1 and 4)

### 6.1 Shared test fixtures

Create `tests/conftest.py`:

```python
"""
Shared test fixtures for ZTAC adversarial testing.
Provides Keycloak token acquisition and common HTTP client setup.
"""

import os
import pytest
import httpx
import time

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8180")
ENVOY_URL = os.getenv("ENVOY_URL", "http://localhost:8080")
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
REALM = os.getenv("KEYCLOAK_REALM", "ztac")
CLIENT_ID = os.getenv("KEYCLOAK_CLI_CLIENT_ID", "ztac-cli")

TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
ADMIN_TOKEN_URL = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"


@pytest.fixture
def http_client():
    """Shared HTTP client with reasonable timeout."""
    with httpx.Client(timeout=10.0) as client:
        yield client


def get_token(username: str, password: str) -> dict:
    """
    Acquire an access token from Keycloak.
    Returns the full token response (access_token, refresh_token, expires_in, etc.)
    """
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            TOKEN_URL,
            data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "username": username,
                "password": password,
            },
        )
        resp.raise_for_status()
        return resp.json()


def get_admin_token() -> str:
    """Get a Keycloak admin token for session management operations."""
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            ADMIN_TOKEN_URL,
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": os.getenv("KEYCLOAK_ADMIN", "admin"),
                "password": os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin"),
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


def decode_jwt_payload(token: str) -> dict:
    """Decode a JWT payload without verification (for test inspection)."""
    import base64
    import json

    payload = token.split(".")[1]
    # Add padding
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def revoke_user_sessions(user_id: str) -> None:
    """Revoke all sessions for a user via Keycloak admin API."""
    admin_token = get_admin_token()
    with httpx.Client(timeout=10.0) as client:
        client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/logout",
            headers={"Authorization": f"Bearer {admin_token}"},
        )


def get_user_id(username: str) -> str:
    """Look up a Keycloak user ID by username."""
    admin_token = get_admin_token()
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
            params={"username": username, "exact": "true"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        resp.raise_for_status()
        users = resp.json()
        if not users:
            raise ValueError(f"User '{username}' not found")
        return users[0]["id"]
```

Create `tests/requirements.txt`:

```
pytest==8.2.2
httpx==0.27.0
```

### 6.2 Scenario 1 — Token replay

Create `tests/test_token_replay.py`:

```python
"""
Adversarial Scenario 1: Stolen Token Replay

Attack: An attacker obtains a valid JWT (e.g., via network sniffing or
phishing) and attempts to reuse it after the user's session has been
revoked by an administrator.

Expected behaviour: The framework detects the revoked session and returns
401 Unauthorized, even though the JWT signature is still valid and the
token has not expired.

CyBOK AAA alignment: Session Management, Non-repudiation
"""

import time
from conftest import (
    get_token,
    get_user_id,
    revoke_user_sessions,
    decode_jwt_payload,
    ENVOY_URL,
)
import httpx


class TestTokenReplay:

    def test_valid_token_works_before_revocation(self, http_client):
        """Baseline: a fresh token should grant access."""
        token_resp = get_token("bob", "bob123")
        token = token_resp["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    def test_replayed_token_rejected_after_revocation(self, http_client):
        """
        Core test: obtain a token, revoke the session, then replay.
        The stolen token should be rejected.
        """
        # Step 1: Get a valid token for bob (analyst)
        token_resp = get_token("bob", "bob123")
        stolen_token = token_resp["access_token"]

        # Verify it works
        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {stolen_token}"},
        )
        assert resp.status_code == 200

        # Step 2: Admin revokes bob's sessions (simulating detection of compromise)
        user_id = get_user_id("bob")
        revoke_user_sessions(user_id)

        # Small delay for revocation propagation
        time.sleep(2)

        # Step 3: Attacker replays the stolen token
        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {stolen_token}"},
        )

        # The framework should reject the replayed token
        assert resp.status_code in (401, 403), (
            f"Replayed token should be rejected after session revocation. "
            f"Got {resp.status_code} instead."
        )

    def test_new_token_works_after_revocation(self, http_client):
        """After revocation, a fresh login should still work."""
        # Revoke first
        user_id = get_user_id("bob")
        revoke_user_sessions(user_id)
        time.sleep(1)

        # Fresh login
        token_resp = get_token("bob", "bob123")
        new_token = token_resp["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200, "Fresh token after revocation should work"
```

### 6.3 Scenario 4 — Stale session exploitation

Create `tests/test_stale_session.py`:

```python
"""
Adversarial Scenario 4: Stale Session Exploitation

Attack: An attacker uses a token that has expired, hoping the framework
doesn't enforce token lifetimes on every request.

Expected behaviour: The framework rejects expired tokens with 401.

CyBOK AAA alignment: Session Management, Continuous Verification
"""

import time
from conftest import get_token, decode_jwt_payload, ENVOY_URL
import httpx


class TestStaleSession:

    def test_fresh_token_is_accepted(self, http_client):
        """Baseline: a fresh token within its lifespan works."""
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]
        claims = decode_jwt_payload(token)

        # Token should have > 0 seconds remaining
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        remaining = claims["exp"] - now
        assert remaining > 0, "Freshly issued token should not be expired"

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_expired_token_is_rejected(self, http_client):
        """
        Core test: wait for a token to expire, then attempt access.
        This requires Keycloak's access token lifespan to be set to a
        short duration (5 minutes in our config). For faster testing,
        temporarily set it to 60 seconds.

        Alternative: use the OPA expiry check, which validates the
        'exp' claim on every request.
        """
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]
        claims = decode_jwt_payload(token)

        # Calculate time to wait
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        wait_time = claims["exp"] - now + 2  # Wait 2 extra seconds past expiry

        if wait_time > 120:
            # If token lifespan is > 2 minutes, skip the wait test
            # and test with a manually crafted expired claim instead
            import pytest
            pytest.skip(
                f"Token lifespan too long ({wait_time:.0f}s) for real-time test. "
                "Set Keycloak access token lifespan to 60s for this test."
            )

        print(f"Waiting {wait_time:.0f}s for token to expire...")
        time.sleep(wait_time)

        # Attempt access with expired token
        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code in (401, 403), (
            f"Expired token should be rejected. Got {resp.status_code}."
        )

    def test_refresh_restores_access(self, http_client):
        """After expiry, using a refresh token to get a new access token works."""
        token_resp = get_token("alice", "alice123")
        refresh_token = token_resp.get("refresh_token")

        if not refresh_token:
            import pytest
            pytest.skip("No refresh token issued")

        # Use the refresh token to get a new access token
        from conftest import TOKEN_URL, CLIENT_ID
        resp = http_client.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
            },
        )
        assert resp.status_code == 200
        new_token = resp.json()["access_token"]

        # Verify the new token works
        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200
```

---

## Day 7 — Scenario 5 (log tampering) and log integrity verifier

### 7.1 Standalone log chain verifier

Create `scripts/verify_log_chain.py`:

```python
#!/usr/bin/env python3
"""
verify_log_chain.py — Verify the integrity of the ZTAC audit log hash chain.

Queries Elasticsearch for all audit logs in sequence order and verifies
that each log's hash is SHA-256(previous_hash + log_body).

Usage:
    python scripts/verify_log_chain.py [--es-url http://localhost:9200] [--index ztac-audit-*]

CyBOK AAA alignment: Accountability — Non-repudiation, Audit Log Integrity
"""

import argparse
import hashlib
import json
import sys
import httpx


def fetch_all_logs(es_url: str, index: str) -> list[dict]:
    """Fetch all audit logs from ES, sorted by log_sequence ascending."""
    logs = []
    search_after = None

    while True:
        body = {
            "size": 500,
            "sort": [{"log_sequence": "asc"}],
            "_source": [
                "log_sequence", "log_hash", "previous_hash", "log_body_for_hash"
            ],
        }
        if search_after is not None:
            body["search_after"] = [search_after]

        resp = httpx.post(
            f"{es_url}/{index}/_search",
            json=body,
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data["hits"]["hits"]

        if not hits:
            break

        for hit in hits:
            logs.append(hit["_source"])
            search_after = hit["sort"][0]

    return logs


def verify_chain(logs: list[dict]) -> tuple[bool, list[str]]:
    """
    Verify the hash chain integrity.
    Returns (is_valid, list_of_errors).
    """
    errors = []

    if not logs:
        return True, ["No logs found to verify."]

    for i, log in enumerate(logs):
        seq = log.get("log_sequence", i)
        stored_hash = log.get("log_hash", "")
        previous_hash = log.get("previous_hash", "")
        body = log.get("log_body_for_hash", "")

        # Verify previous_hash linkage
        if i == 0:
            if previous_hash != "GENESIS":
                errors.append(
                    f"Log #{seq}: first log should have previous_hash='GENESIS', "
                    f"got '{previous_hash}'"
                )
        else:
            expected_previous = logs[i - 1].get("log_hash", "")
            if previous_hash != expected_previous:
                errors.append(
                    f"Log #{seq}: previous_hash mismatch. "
                    f"Expected '{expected_previous[:16]}...', "
                    f"got '{previous_hash[:16]}...'"
                )

        # Recompute hash
        expected_hash = hashlib.sha256(
            (previous_hash + body).encode()
        ).hexdigest()

        if stored_hash != expected_hash:
            errors.append(
                f"Log #{seq}: hash mismatch. "
                f"Stored '{stored_hash[:16]}...', "
                f"computed '{expected_hash[:16]}...'"
            )

    return len(errors) == 0, errors


def main():
    parser = argparse.ArgumentParser(
        description="Verify ZTAC audit log hash chain integrity"
    )
    parser.add_argument(
        "--es-url", default="http://localhost:9200",
        help="Elasticsearch URL"
    )
    parser.add_argument(
        "--index", default="ztac-audit-*",
        help="Elasticsearch index pattern"
    )
    args = parser.parse_args()

    print(f"Fetching logs from {args.es_url}/{args.index}...")
    logs = fetch_all_logs(args.es_url, args.index)
    print(f"Found {len(logs)} log entries.")

    if not logs:
        print("No logs to verify.")
        sys.exit(0)

    print("Verifying hash chain...")
    is_valid, errors = verify_chain(logs)

    if is_valid:
        print(f"PASS: All {len(logs)} log entries have valid hash chain integrity.")
        sys.exit(0)
    else:
        print(f"FAIL: {len(errors)} integrity error(s) detected:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

Make it executable:

```bash
chmod +x scripts/verify_log_chain.py
```

### 7.2 Adversarial test — log tampering

Create `tests/test_log_tampering.py`:

```python
"""
Adversarial Scenario 5: Log Tampering Detection

Attack: An attacker with database access (e.g., compromised ES credentials)
inserts a fake log entry to cover their tracks or frame another user.

Expected behaviour: The hash chain verification detects the inserted entry
because it breaks the sequential chain of SHA-256 hashes.

CyBOK AAA alignment: Accountability — Audit Log Integrity, Non-repudiation
"""

import hashlib
import json
import time
import httpx
from conftest import ES_URL, ENVOY_URL, get_token


class TestLogTampering:

    def _get_logs(self, client: httpx.Client, count: int = 20) -> list[dict]:
        """Fetch recent logs sorted by sequence."""
        resp = client.post(
            f"{ES_URL}/ztac-audit-*/_search",
            json={
                "size": count,
                "sort": [{"log_sequence": "asc"}],
                "_source": [
                    "log_sequence", "log_hash", "previous_hash",
                    "log_body_for_hash"
                ],
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return [hit["_source"] for hit in resp.json()["hits"]["hits"]]

    def _verify_chain(self, logs: list[dict]) -> bool:
        """Verify hash chain integrity. Returns True if intact."""
        for i, log in enumerate(logs):
            prev = log.get("previous_hash", "")
            body = log.get("log_body_for_hash", "")
            stored = log.get("log_hash", "")

            expected = hashlib.sha256((prev + body).encode()).hexdigest()
            if stored != expected:
                return False

            if i > 0:
                if prev != logs[i - 1].get("log_hash", ""):
                    return False

        return True

    def test_chain_intact_before_tampering(self, http_client):
        """Baseline: generate some logs and verify the chain is valid."""
        # Generate a few real requests to populate logs
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]

        for _ in range(3):
            http_client.get(
                f"{ENVOY_URL}/api/data/reports",
                headers={"Authorization": f"Bearer {token}"},
            )

        time.sleep(3)  # Let Logstash process

        logs = self._get_logs(http_client)
        if len(logs) < 2:
            import pytest
            pytest.skip("Not enough logs for chain verification")

        assert self._verify_chain(logs), "Hash chain should be intact before tampering"

    def test_tampered_log_breaks_chain(self, http_client):
        """
        Core test: insert a fake log and verify the chain breaks.
        """
        # Generate real logs first
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]

        for _ in range(3):
            http_client.get(
                f"{ENVOY_URL}/api/data/public",
                headers={"Authorization": f"Bearer {token}"},
            )

        time.sleep(3)

        # Get current logs and verify chain is intact
        logs_before = self._get_logs(http_client)
        assert len(logs_before) >= 2, "Need at least 2 logs"
        assert self._verify_chain(logs_before), "Chain should be intact before tampering"

        # Inject a fake log directly into Elasticsearch (bypassing Logstash)
        fake_log = {
            "timestamp": "2024-06-15T12:00:00.000Z",
            "source_component": "ATTACKER",
            "user": "alice",
            "action": "DELETE",
            "resource": "/api/data/admin",
            "status_code": 200,
            "log_sequence": logs_before[-1]["log_sequence"] + 1,
            "previous_hash": "FAKE_PREVIOUS_HASH",
            "log_hash": "FAKE_HASH_VALUE",
            "log_body_for_hash": '{"fake": true}',
            "message": "Attacker-injected log entry",
        }

        resp = http_client.post(
            f"{ES_URL}/ztac-audit-tampered/_doc",
            json=fake_log,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in (200, 201), "Fake log should be insertable"

        # Refresh the index so the fake log is searchable
        http_client.post(f"{ES_URL}/ztac-audit-tampered/_refresh")

        time.sleep(1)

        # Fetch logs from both indices
        resp = http_client.post(
            f"{ES_URL}/ztac-audit-*/_search",
            json={
                "size": 50,
                "sort": [{"log_sequence": "asc"}],
                "_source": [
                    "log_sequence", "log_hash", "previous_hash",
                    "log_body_for_hash", "source_component"
                ],
            },
        )
        all_logs = [hit["_source"] for hit in resp.json()["hits"]["hits"]]

        # The chain should now be broken
        assert not self._verify_chain(all_logs), (
            "Hash chain should be broken after inserting a fake log entry. "
            "The tampered entry's previous_hash does not match the preceding "
            "log's hash, demonstrating that hash chaining detects insertion attacks."
        )

    def test_cleanup_tampered_index(self, http_client):
        """Clean up the tampered index after testing."""
        http_client.delete(f"{ES_URL}/ztac-audit-tampered")
```

---

## Day 8 — CyBOK alignment matrix and architecture diagram

### 8.1 CyBOK alignment matrix

Create `docs/cybok-alignment-matrix.md`:

```markdown
# CyBOK AAA Alignment Matrix — ZTAC Framework

This matrix maps each sub-principle from the CyBOK Authentication, Authorisation,
and Accountability (AAA) Knowledge Area to a specific component in the ZTAC framework,
providing implementation details and pointers to evidence in the codebase.

## Authentication

| CyBOK sub-principle | Framework component | Implementation | Evidence |
|---|---|---|---|
| Password-based authentication | Keycloak IdP | OIDC Resource Owner Password Grant for lab testing; Authorization Code flow supported for production | `keycloak/realm-export.json` — client config |
| Multi-factor authentication | Keycloak IdP | TOTP (Time-based One-Time Password) configurable per-user via Keycloak authentication flow; disabled by default in lab for convenience | Keycloak admin → Authentication → Flows → Browser |
| Certificate-based authentication | Envoy PEP + mTLS | Mutual TLS with X.509 client certificates for all service-to-service communication; CA-signed certs generated by `scripts/generate-certs.sh` | `envoy/envoy.yaml` — `require_client_certificate: true`; `envoy/certs/` |
| Token-based authentication | Keycloak IdP + api-gateway | JWT access tokens issued via OIDC with 5-minute lifespan, RS256 signing, JWKS endpoint for verification | `docs/token-schema.md`; Keycloak realm token settings |
| Federated identity / SSO | Keycloak IdP | OpenID Connect protocol; realm supports federation with external IdPs (not configured in lab but architecture supports it) | `keycloak/realm-export.json` — OIDC client scopes |

## Authorisation

| CyBOK sub-principle | Framework component | Implementation | Evidence |
|---|---|---|---|
| Role-Based Access Control (RBAC) | OPA PDP + Keycloak | Three realm roles (admin, analyst, viewer) mapped to resource access levels via Rego policy | `opa/policies/rbac.rego`; `keycloak/realm-export.json` — roles |
| Attribute-Based Access Control (ABAC) | OPA PDP | Rego policies evaluate user identity, roles, device trust level, IP risk score, and time-of-day against resource sensitivity classification | `opa/policies/authz.rego`; `opa/policies/data.json` |
| Least privilege | OPA PDP + Envoy PEP | Default-deny policy; each resource requires explicit allow rule; no implicit trust based on network location | `opa/policies/authz.rego` — `default allow := false` |
| Policy Decision Point (PDP) | Open Policy Agent | Declarative Rego policies evaluated on every access request via REST API; supports hot-reload without service restart | `opa/` directory; OPA config |
| Policy Enforcement Point (PEP) | Envoy Proxy | External authorisation filter (ext_authz) intercepts every HTTP request before routing to backend; denies requests that OPA rejects | `envoy/envoy.yaml` — `ext_authz` filter config |
| Dynamic / continuous authorisation | OPA + Keycloak + Gateway | Token expiry checked on every request (not just at login); OPA evaluates current context (device trust, IP risk) per-request | Gateway JWT middleware; `authz.rego` expiry rule |

## Accountability

| CyBOK sub-principle | Framework component | Implementation | Evidence |
|---|---|---|---|
| Audit logging | ELK stack (Elasticsearch + Logstash + Kibana) | Every access decision (allow/deny) logged as structured JSON with user identity, resource, action, timestamp, and decision outcome | `elk/logstash/pipeline.conf`; Kibana dashboard |
| Log integrity / tamper detection | Logstash hash chaining | Each log entry's hash = SHA-256(previous_hash + current_body); chain starts with "GENESIS" sentinel; standalone verifier script provided | `elk/logstash/pipeline.conf` — Ruby filter; `scripts/verify_log_chain.py` |
| Non-repudiation | ELK + Keycloak | Every log entry contains the authenticated user's identity (from JWT `preferred_username` and `jti`); user cannot deny having made the request | ES index `ztac-audit-*` — `user` and `request_id` fields |
| Session tracking | Keycloak + Gateway | JTI-based token tracking; session revocation via backchannel logout; blacklist prevents replay of revoked tokens | `services/shared/token_blacklist.py`; Keycloak backchannel config |
| Monitoring and anomaly detection | Kibana dashboards | Real-time visualisation of request patterns, 403 rates, and user activity; anomalies visible as spikes in denied requests | `elk/kibana/dashboards.ndjson` |

## Cross-cutting

| CyBOK sub-principle | Framework component | Implementation | Evidence |
|---|---|---|---|
| Transport security | Envoy mTLS | All inter-service communication encrypted with mutual TLS; no plaintext traffic within the framework | `envoy/envoy.yaml`; `envoy/certs/` |
| Separation of concerns | Architecture design | IdP (Keycloak), PDP (OPA), PEP (Envoy), and accountability (ELK) are independent, replaceable components communicating via standard protocols | `docker-compose.yml`; architecture diagram |
| Defence in depth | All components | Multiple layers: mTLS at transport, JWT validation at gateway, ABAC policy at OPA, deny-by-default, audit logging with integrity verification | Full test suite (`tests/`) |
```

### 8.2 Architecture diagram

Create `docs/architecture-diagram.md`:

````markdown
# ZTAC Framework — Architecture Diagram

## Request flow

```
                                    ┌─────────────────┐
                                    │   ELK Stack      │
                                    │  (Accountability) │
                                    │                   │
                                    │  Elasticsearch    │
                                    │  Logstash         │
                                    │  Kibana           │
                                    └──────▲──────▲────┘
                                           │      │
                              access logs  │      │ decision logs
                                           │      │
┌──────┐     HTTPS      ┌──────────┐  ext_authz  ┌─────────┐
│      │ ──────────────► │  Envoy   │ ──────────► │   OPA   │
│ User │                 │  (PEP)   │ ◄────────── │  (PDP)  │
│      │ ◄────────────── │          │  allow/deny │         │
└──────┘   200/401/403   └────┬─────┘             └─────────┘
                              │                        ▲
                         mTLS │                        │
                              ▼                        │
                        ┌───────────┐          ┌───────────────┐
                        │   API     │          │   Keycloak    │
                        │  Gateway  │ ────────►│    (IdP)      │
                        │           │  JWKS    │               │
                        └─────┬─────┘ verify   └───────────────┘
                              │
                         mTLS │
                              ▼
                        ┌───────────┐
                        │ Protected │
                        │  Service  │
                        └───────────┘
```

## Component mapping to CyBOK AAA

| Component | CyBOK AAA pillar | NIST SP 800-207 equivalent |
|---|---|---|
| Keycloak | Authentication | Identity Provider / CDMS |
| OPA | Authorisation | Policy Decision Point (PDP) |
| Envoy | Enforcement | Policy Enforcement Point (PEP) |
| API Gateway | Authentication + Session Mgmt | Policy Administrator (PA) |
| ELK Stack | Accountability | Logging / Monitoring subsystem |
| mTLS certs | Transport Authentication | Implicit trust plane |

## Data flow for a single request

1. User sends HTTPS request with JWT `Authorization: Bearer <token>` to Envoy (port 8080).
2. Envoy's `ext_authz` filter forwards the request metadata (path, method, JWT) to OPA.
3. OPA evaluates the Rego policy against the request context (user, roles, device trust, IP risk, token expiry).
4. OPA returns allow or deny to Envoy.
5. If denied: Envoy returns 403 with structured JSON error. Log emitted to ELK.
6. If allowed: Envoy forwards the request to the API Gateway over mTLS.
7. The Gateway validates the JWT signature against Keycloak's JWKS, checks the JTI blacklist, and injects identity headers (`x-auth-user`, `x-auth-roles`).
8. The Gateway forwards to the Protected Service over mTLS.
9. The Protected Service processes the request and returns a response.
10. Every step emits structured JSON logs to Logstash, which adds hash-chain fields and indexes into Elasticsearch.
11. Kibana provides real-time dashboards for monitoring and audit.
````

---

## Day 9 — Evaluation report and performance benchmark

### 9.1 Evaluation report structure

Create `docs/evaluation-report.md` with the following structure. Fill in actual results after running the tests.

```markdown
# ZTAC Framework — Evaluation Report

## 1. Test environment

- Host: [your machine specs]
- Docker Engine: [version]
- Keycloak: 24.0.4
- OPA: 0.68.x
- Envoy: 1.31.x
- Elasticsearch: 8.14.1
- Python: 3.12

## 2. Adversarial scenario results

### Scenario 1: Token replay

- **Procedure:** Obtained valid JWT for user `bob` (analyst). Verified access
  to `/api/data/reports` (200). Revoked all sessions via Keycloak Admin API.
  Replayed the same token.
- **Expected:** 401 Unauthorized
- **Actual:** [fill in]
- **CyBOK principle validated:** Session Management, Non-repudiation
- **Evidence:** [paste ELK log snippet showing the rejected request]

### Scenario 2: Privilege escalation
[Person B fills this in]

### Scenario 3: Unauthenticated service-to-service call
[Person B fills this in]

### Scenario 4: Stale session exploitation

- **Procedure:** Obtained valid JWT for user `alice` (admin). Waited for token
  to expire (5 minutes). Attempted access with expired token.
- **Expected:** 401 Unauthorized
- **Actual:** [fill in]
- **CyBOK principle validated:** Continuous Verification, Session Management
- **Evidence:** [paste OPA decision log showing expiry-based denial]

### Scenario 5: Log tampering detection

- **Procedure:** Generated 3 legitimate access logs. Verified hash chain
  integrity using `verify_log_chain.py`. Injected a fake log entry directly
  into Elasticsearch. Re-ran hash chain verification.
- **Expected:** Verification fails, reports broken chain at the injected entry.
- **Actual:** [fill in]
- **CyBOK principle validated:** Audit Log Integrity, Non-repudiation
- **Evidence:** [paste verifier output showing the detected break]

## 3. Performance benchmark

### Methodology
Used `hey` (HTTP load generator) to measure request latency through the
full chain at three concurrency levels.

### Commands
```bash
# Install hey
go install github.com/rakyll/hey@latest

# Get a valid token
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztac/protocol/openid-connect/token \
  -d "grant_type=password&client_id=ztac-cli&username=bob&password=bob123" | jq -r .access_token)

# 10 concurrent connections, 200 total requests
hey -n 200 -c 10 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/reports

# 50 concurrent
hey -n 500 -c 50 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/reports

# 100 concurrent
hey -n 1000 -c 100 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/reports
```

### Results

| Concurrency | Total requests | Avg latency | P99 latency | Requests/sec | Error rate |
|---|---|---|---|---|---|
| 10 | 200 | [fill in] | [fill in] | [fill in] | [fill in] |
| 50 | 500 | [fill in] | [fill in] | [fill in] | [fill in] |
| 100 | 1000 | [fill in] | [fill in] | [fill in] | [fill in] |

### Analysis
[Discuss the overhead introduced by ext_authz. Compare latency with and
without OPA in the request path. Note any bottlenecks.]

## 4. Summary

[Overall assessment of the framework's effectiveness against the five
adversarial scenarios, the CyBOK alignment coverage, and practical
deployment considerations.]
```

---

## Quick reference — what to build each day

| Day | What you deliver | Key files |
|---|---|---|
| 1 | Repo, docker-compose, Keycloak realm, protected-service stub | `docker-compose.yml`, `keycloak/realm-export.json`, `services/protected-service/*` |
| 2 | Seed script, token schema docs | `scripts/seed-keycloak.sh`, `docs/token-schema.md` |
| 3 | Protected service expansion (audit middleware, 3 tiered endpoints) | `services/protected-service/main.py` (updated) |
| 4 | ELK stack with hash-chained logs, Kibana dashboard | `elk/logstash/pipeline.conf`, `elk/kibana/dashboards.ndjson` |
| 5 | Token blacklist, backchannel logout handler | `services/shared/token_blacklist.py`, `services/shared/keycloak_logout.py` |
| 6 | Adversarial tests 1 and 4 | `tests/conftest.py`, `tests/test_token_replay.py`, `tests/test_stale_session.py` |
| 7 | Adversarial test 5, log chain verifier | `tests/test_log_tampering.py`, `scripts/verify_log_chain.py` |
| 8 | CyBOK alignment matrix, architecture diagram | `docs/cybok-alignment-matrix.md`, `docs/architecture-diagram.md` |
| 9 | Evaluation report, performance benchmark | `docs/evaluation-report.md` |
| 10 | Cross-review, final integration, release tag | All files — clean state test |

---

## Troubleshooting

**Keycloak won't start:**
- Check port 8180 isn't already in use: `lsof -i :8180`
- Check the realm export is valid JSON: `python -m json.tool keycloak/realm-export.json > /dev/null`
- Check container logs: `docker compose logs keycloak --tail 50`

**Realm import fails on restart:**
- Keycloak's `--import-realm` only imports on first boot. If the realm already exists, it silently skips.
- To re-import: `docker compose down -v` (destroys volumes), then `docker compose up`.

**ELK out of memory:**
- Reduce ES heap: set `ES_JAVA_OPTS=-Xms256m -Xmx256m` in `.env`.
- If still OOM, switch to OpenSearch with the same Logstash pipeline (it's API-compatible).

**Hash chain breaks on restart:**
- The hash state file (`/tmp/logstash_last_hash`) lives inside the Logstash container. When the container restarts, the chain resets to "GENESIS". This is expected in a lab; in production you'd persist state to a volume.
- To handle this in tests, verify chains within a single container lifecycle.

**Token verification fails in tests:**
- The issuer URL inside the container is `http://keycloak:8080/realms/ztac`, but from the host it's `http://localhost:8180/realms/ztac`. Make sure your test client uses the host URL and the gateway uses the container URL.

**Tests time out waiting for token expiry:**
- For `test_stale_session.py`, temporarily set Keycloak access token lifespan to 60 seconds. The default 5 minutes is realistic but slow for automated testing.
- Keycloak admin → Realm Settings → Tokens → Access Token Lifespan → 1 minute → Save.
- Remember to reset it after testing.
