# ZTAC Framework — Complete Guide

**ZTAC** (Zero-Trust Access Control) is a self-hostable, open-source reference
implementation of a zero-trust architecture. Every request to a protected
resource is authenticated, authorised against a central policy engine, and
audited — *no request is trusted because of where it comes from*. This document
explains every component, how they fit together, and how to operate and extend
the framework.

> **Quick links to the focused companion docs**
> - [`architecture-diagram.md`](architecture-diagram.md) — the canonical diagram
> - [`token-schema.md`](token-schema.md) — the exact OPA input contract
> - [`cybok-alignment-matrix.md`](cybok-alignment-matrix.md) — CyBOK AAA mapping
> - [`comparative-analysis.md`](comparative-analysis.md) — NIST SP 800-207 & BeyondCorp comparison
> - [`evaluation-report.md`](evaluation-report.md) — test/evaluation results

---

## Table of contents

1. [What ZTAC is and the principles it implements](#1-what-ztac-is)
2. [Architecture and request flow](#2-architecture-and-request-flow)
3. [The components, one by one](#3-the-components-one-by-one)
4. [The authorization decision (the heart of the system)](#4-the-authorization-decision)
5. [Identity and token model](#5-identity-and-token-model)
6. [Getting started](#6-getting-started)
7. [Using the framework — recipes](#7-using-the-framework--recipes)
8. [Testing](#8-testing)
9. [Audit logging and tamper-evidence](#9-audit-logging-and-tamper-evidence)
10. [Configuration reference](#10-configuration-reference)
11. [Operations and troubleshooting](#11-operations-and-troubleshooting)
12. [Security model and known limitations](#12-security-model-and-known-limitations)
13. [Extending the framework](#13-extending-the-framework)
14. [Repository layout](#14-repository-layout)

---

## 1. What ZTAC is

ZTAC enforces the three pillars of access control — in CyBOK terms, the
**Authentication, Authorisation, Accountability (AAA)** Knowledge Area — and
maps cleanly onto the **NIST SP 800-207** logical zero-trust architecture:

| Zero-trust function | NIST SP 800-207 role | ZTAC component |
|---|---|---|
| Who are you? (**Authentication**) | Identity Provider | **Keycloak** (OIDC, RS256 JWTs) |
| Should you reach this, *right now*? (**Authorisation**) | Policy Decision Point (PDP) | **OPA** (Rego ABAC/RBAC) |
| Collect the verified identity and ask the PDP | Policy Administrator (PA) | **API Gateway** (FastAPI) |
| Let nothing through unless allowed (**Enforcement**) | Policy Enforcement Point (PEP) | **Envoy** proxy |
| What happened? (**Accountability**) | Continuous Diagnostics (CDM) | **ELK** with a keyed HMAC-SHA256 hash chain |
| Prove the request came through the chain | Trust plane | **Gateway-auth secret** (app-layer); **mTLS** PKI provisioned for the transport upgrade |

The defining zero-trust properties ZTAC realises:

- **Default deny.** The OPA policy is `default allow := false`; access exists
  only where a rule explicitly grants it.
- **Per-request, dynamic authorisation.** The PDP is consulted on *every*
  request, not once per session. Token expiry, device posture and IP risk are
  re-evaluated each time.
- **Fail closed.** If the PDP is unreachable, the gateway returns `503` and the
  request is denied — never "allow on error".
- **Tamper-evident accountability.** Audit logs are hash-chained, so any
  modification or deletion of a past record is detectable.

---

## 2. Architecture and request flow

```
                         ┌───────────────────────────────────┐
                         │        ELK (Accountability)        │
                         │  Logstash → Elasticsearch → Kibana │
                         └──────────────▲────────────▲────────┘
                       audit logs       │            │ access logs
                                        │            │
 ┌──────┐    HTTP    ┌──────────┐       │            │        ┌─────────┐
 │ User │ ─────────► │  Envoy   │ ──────┼────────────┘        │   OPA   │
 │      │ ◄───────── │  (PEP)   │       │                     │  (PDP)  │
 └──────┘ 200/401/   │ forward  │       │                     └────▲────┘
          403/503    └────┬─────┘       │                          │
                          │ (mTLS-ready)│            per-request    │
                          ▼             │     POST /v1/data/authz/allow
                    ┌───────────┐ ──────┘     {"input": {...}} ─────┘
                    │    API    │
                    │  Gateway  │ ──── JWKS verify ───► ┌───────────┐
                    │   (PA)    │ ◄─── backchannel ──── │  Keycloak │
                    └─────┬─────┘      logout           │   (IdP)   │
                          │ (mTLS-ready)                └───────────┘
                          ▼
                    ┌───────────┐
                    │ Protected │
                    │  Service  │
                    └───────────┘
```

**The happy path, step by step** (`Client → Envoy:8080 → Gateway:8001 → Protected:8000`):

1. **Client → Envoy (`:8080`).** Envoy is the data-plane PEP. It terminates the
   ingress connection and forwards the request to the gateway. Nothing reaches
   the protected service except through Envoy.
2. **Gateway authenticates.** It reads the `Authorization: Bearer <JWT>` header,
   validates the token against Keycloak's JWKS (RS256 only, correct issuer, not
   expired, signature valid).
3. **Gateway checks revocation.** The token's `jti` and session `sid` are
   checked against an in-memory blacklist populated by Keycloak backchannel
   logout. A revoked session is rejected even though the JWT is otherwise valid.
4. **Gateway asks the PDP.** It builds an `input` object (identity + device
   trust + IP risk + token expiry) and `POST`s it to OPA at
   `/v1/data/authz/allow`. OPA returns `{"result": true|false}`.
5. **Gateway enforces.** On `true`, it forwards to the protected service,
   injecting *verified* identity headers. On `false`, it returns `403`.
6. **Protected service responds.** It trusts the gateway-injected identity
   headers (it is only reachable behind the gateway).
7. **Everything is audited.** The gateway ships a structured audit record to
   Logstash, which hash-chains it into Elasticsearch; Envoy ships access logs.

**Why the gateway (not Envoy) calls OPA.** Vanilla OPA's REST Data API is *not*
an Envoy `ext_authz` server, and an `ext_authz` call would never carry the JWT
claims. The gateway is the only point in the flow where the decoded identity,
device and risk context exist, so it is the correct place to consult the PDP.
Envoy remains the enforcement boundary; the gateway is the decision requester.

---

## 3. The components, one by one

### 3.1 Keycloak — Identity Provider (Authentication)

- Image `quay.io/keycloak/keycloak:24.0.4`, run with `start-dev --import-realm`.
- Realm **`ztac`** is imported from `keycloak/realm-export.json`.
- Issues **RS256** JWTs. Roles are carried in the `realm_access.roles` claim.
- **Issuer is pinned** via `KC_HOSTNAME_URL=http://keycloak:8080`, so every
  token carries a stable issuer (`http://keycloak:8080/realms/ztac`) whether it
  was requested via the host port (`localhost:8180`) or the internal network.
  This is what lets host-issued test tokens validate inside the gateway.
- Host port: **`8180` → 8080**. Admin console at `http://localhost:8180`
  (`admin` / `admin`).

**Seeded principals** (realm export):

| User | Password | Realm role |
|---|---|---|
| `alice` | `alice123` | `admin` |
| `bob` | `bob123` | `analyst` |
| `charlie` | `charlie123` | `viewer` |

**Clients:**

| Client | Type | Purpose |
|---|---|---|
| `ztac-cli` | public, direct-access-grant | Used by tests and `curl` to get tokens via password grant. Has a backchannel-logout URL pointing at the gateway. |
| `ztac-gateway` | confidential | Represents the gateway as a relying party; also registered for backchannel logout. |

### 3.2 API Gateway — Policy Administrator (FastAPI)

The gateway (`services/api-gateway/main.py`) is the brain of the request path.
A single HTTP middleware enforces on **every** path except its own endpoints
(`/health`, `/verify`, `/token`, `/backchannel-logout`).

**Authentication (`validate_token`):**
- Rejects anything whose header `alg` is not in the allowed set (notably blocks
  `alg: none`).
- Looks up the signing key by `kid` in the cached JWKS.
- **JWKS auto-refresh on unknown `kid`** (`validate_token_refreshing`): Keycloak
  rotates realm signing keys (e.g. on restart). If a token's `kid` is not in the
  cache, the gateway refetches the JWKS once and retries, instead of rejecting
  every token until the periodic 5-minute refresh fires.
- Verifies signature and `iss`; rejects expired tokens.

**Session management:** the token's `jti` and `session:<sid>` are checked
against an in-memory blacklist. Keycloak posts a backchannel-logout token to
`POST /backchannel-logout` when a session ends; the handler adds
`session:<sid>` to the blacklist, so replayed tokens for a revoked session are
rejected.

**Authorization:** `build_opa_input` assembles the `input` object and
`opa_allows` posts it to OPA. A non-200 from OPA (or an unreachable PDP) raises
`OPAUnavailable` → the gateway returns `503` (fail closed).

**Forwarding (`forward_to_protected`):** on allow, the request is proxied to the
protected service with verified identity headers injected:

| Injected header | Meaning |
|---|---|
| `x-auth-user` | `preferred_username` from the validated token |
| `x-auth-roles` | JSON array of realm roles |
| `x-auth-jti` | token ID |
| `x-auth-exp` | token expiry (unix seconds) |
| `x-request-id` | correlation ID (also returned to the client) |

**Gateway-owned endpoints:**

| Method & path | Purpose |
|---|---|
| `GET /health` | Liveness — `{"status":"healthy","service":"api-gateway"}` |
| `GET /verify` | Dependency check — probes Keycloak, OPA and the protected service; reports JWKS key count |
| `POST /token` | Convenience proxy to Keycloak's password-grant token endpoint |
| `POST /backchannel-logout` | Receives Keycloak logout tokens and revokes the session |

Host port: **`8001` → 8001**.

### 3.3 OPA — Policy Decision Point

- `opa/policies/authz.rego` (package `authz`, Rego v1) is the authoritative
  policy. `opa/policies/rbac.rego` is a simplified role-only fallback.
- `opa/policies/data.json` is the data document: resource→role mapping, the
  trusted device levels, and the blocked IP-risk levels.
- The gateway queries `POST /v1/data/authz/allow` with `{"input": {...}}`.
- Decision logs are emitted to the console (`--set=decision_logs.console=true`).
- Host port: **`8181` → 8181**. Health at `/health`.

The policy and data are covered in detail in
[§4](#4-the-authorization-decision).

### 3.4 Envoy — Policy Enforcement Point

- `envoyproxy/envoy:v1.31-latest`, configured by `envoy/envoy.yaml`.
- Listener on **`8080`** (data plane); admin interface on `9901` (not published
  to the host).
- Routes all traffic to the `api_gateway_cluster`. JSON access logs go to both
  stdout and a file (tailed in production).
- **mTLS is provisioned but not active by default.** The CA and leaf certs are
  baked into the image; the `transport_socket` blocks in `envoy.yaml` are
  commented out so a production build can enable mutual TLS without changing the
  image. See [§3.7](#37-mtls-pki).

### 3.5 Protected Service

A minimal FastAPI app (`services/protected-service/main.py`) standing in for a
real microservice. It trusts the gateway-injected identity headers and exposes:

| Endpoint | Sensitivity | Who may reach it |
|---|---|---|
| `GET /api/data/public` | public | anyone (even unauthenticated) |
| `GET /api/data/reports` | internal | `analyst` or `admin`, trusted device, safe IP |
| `GET /api/data/admin` | confidential | `admin`, trusted device, safe IP |
| `GET /health` | — | liveness |

Host port: **`8000` → 8000** (exposed for the lab; see
[§12](#12-security-model-and-known-limitations)).

### 3.6 ELK — Accountability

- **Logstash** receives audit records on an HTTP input (host `5050`) and a Beats
  input (`5044`). Its filter computes a **keyed HMAC-SHA256 hash chain**:
  `log_hash = HMAC_SHA256(AUDIT_HMAC_KEY, previous_hash + body_json)`, seeded
  with `"GENESIS"`. Each document stores both `previous_hash` and `log_hash`.
  Because the key is secret, an attacker who can write to Elasticsearch cannot
  forge a self-consistent chain.
- **Elasticsearch** stores records in daily `ztac-audit-*` indices (host `9200`).
- **Kibana** (host `5601`) provides the audit dashboard.

Integrity is verifiable offline with `scripts/verify_log_chain.py`
(see [§9](#9-audit-logging-and-tamper-evidence)).

### 3.7 mTLS PKI

`scripts/generate-certs.sh` builds a complete X.509 trust chain with OpenSSL,
writing to `envoy/certs/`:

| File(s) | Subject | Role |
|---|---|---|
| `ca.pem` / `ca-key.pem` | the CA (10-yr) | signs everything below |
| `server.pem` / `server-key.pem` | CN=`envoy` (SAN: envoy, localhost, 127.0.0.1) | Envoy's server cert |
| `client.pem` / `client-key.pem` | CN=`api-gateway` | gateway client cert |
| `protected-client.pem` / `protected-client-key.pem` | CN=`protected-service` | service client cert |

The script is **idempotent** (regenerates only with `--force`). Keys are
git-ignored and never committed; an `envoy/certs/.gitkeep` keeps the directory
present so the Envoy image build succeeds on a fresh clone.

---

## 4. The authorization decision

This is where zero-trust lives. The gateway sends OPA an `input` object; OPA
returns a single boolean.

### 4.1 The input contract

(Authoritative copy in [`token-schema.md`](token-schema.md).)

| Field | Source | Example |
|---|---|---|
| `input.user` | JWT `preferred_username` | `"bob"` |
| `input.roles` | JWT `realm_access.roles` | `["analyst"]` |
| `input.action` | HTTP method | `"GET"` |
| `input.resource` | HTTP path | `"/api/data/reports"` |
| `input.token_exp` | JWT `exp` (unix seconds) | `1750000000` |
| `input.token_jti` | JWT `jti` | `"a1b2…"` |
| `input.device_trust` | header `x-device-trust` (default `managed`) | `"managed"` |
| `input.ip_risk` | header `x-ip-risk` (default `low`) | `"low"` |

### 4.2 The policy data (`data.json`)

```json
{
  "resource_roles": {
    "/api/data/public":  {"required_roles": [],                  "sensitivity": "public"},
    "/api/data/reports": {"required_roles": ["analyst","admin"], "sensitivity": "internal"},
    "/api/data/admin":   {"required_roles": ["admin"],           "sensitivity": "confidential"}
  },
  "trusted_device_levels": ["managed", "byod_compliant"],
  "blocked_ip_risk_levels": ["high"]
}
```

### 4.3 The rules (`authz.rego`)

```
default allow := false                       # least privilege

# RULE 1 — public resources (empty required_roles) are reachable by anyone
allow if { resource_roles[input.resource].required_roles == [] }

# RULE 2 — protected resources need ALL of:
allow if {
    token_valid        # input.token_exp > now           (not expired)
    role_sufficient    # a caller role ∈ required_roles   (RBAC)
    device_trusted     # device_trust ∈ trusted levels    (ABAC: posture)
    ip_safe            # ip_risk ∉ blocked levels          (ABAC: network risk)
}
```

The four checks are *independent and conjunctive* — a correct credential from a
high-risk network, or from an untrusted device, is still denied. That is the
zero-trust difference from plain RBAC.

### 4.4 Decision matrix (worked outcomes)

| Caller | Resource | Device | IP risk | Result | Why |
|---|---|---|---|---|---|
| anyone (no token) | `/api/data/public` | any | any | **200** | RULE 1 |
| `bob` (analyst) | `/api/data/reports` | managed | low | **200** | RULE 2 ✓ |
| `charlie` (viewer) | `/api/data/reports` | managed | low | **403** | role insufficient |
| `alice` (admin) | `/api/data/admin` | managed | low | **200** | RULE 2 ✓ |
| `bob` (analyst) | `/api/data/admin` | managed | low | **403** | role insufficient |
| `bob` (analyst) | `/api/data/reports` | **untrusted** | low | **403** | device not trusted |
| `bob` (analyst) | `/api/data/reports` | managed | **high** | **403** | IP blocked |
| (no token) | `/api/data/reports` | — | — | **401** | authentication required |
| any | any protected | — | — | **503** | OPA unreachable (fail closed) |

### 4.5 Status codes the client sees

| Code | Meaning |
|---|---|
| `200` | allowed and forwarded |
| `401` | missing / malformed / invalid / expired / revoked token |
| `403` | authenticated but policy denied |
| `503` | policy engine unavailable (fail closed) |
| `502` | (`/token` proxy only) Keycloak unreachable |

---

## 5. Identity and token model

- Tokens are **RS256** JWTs from the `ztac` realm; issuer
  `http://keycloak:8080/realms/ztac`.
- Relevant claims: `preferred_username`, `realm_access.roles`, `exp`, `jti`,
  `sid`.
- The gateway never trusts the `alg` header to pick an algorithm blindly — only
  RS256 is accepted, which defeats `alg:none` and HS256-confusion downgrades.
- **Context attributes** (`x-device-trust`, `x-ip-risk`) are *simulated* via
  request headers in the lab. In production these would come from a device
  posture agent and an IP-reputation feed (see [§13](#13-extending-the-framework)).
- Downstream, the protected service receives the gateway's **verified** identity
  headers (`x-auth-*`) and never re-parses the JWT.

---

## 6. Getting started

### Prerequisites
- Docker 24+ with the Compose plugin
- `bash` and `openssl`
- ~8 GB RAM (the ELK stack is memory-hungry)
- `python3` (only to run the test suite; an isolated venv is created for you)

### One command (fresh clone → running stack)

```bash
git clone <repo-url> ztac-framework && cd ztac-framework
./scripts/bootstrap.sh          # or:  make up
```

`bootstrap.sh` is idempotent and self-contained. It:
1. checks prerequisites and Docker daemon reachability,
2. creates `.env` from `.env.example` if missing,
3. generates the mTLS PKI if missing,
4. builds all images and starts the stack,
5. waits (up to 5 minutes) for every service to report healthy.

When it finishes you'll have:

| URL | What |
|---|---|
| `http://localhost:8080` | Envoy ingress (send your API calls here) |
| `http://localhost:8001/health` | gateway health |
| `http://localhost:8180` | Keycloak admin (`admin`/`admin`) |
| `http://localhost:5601` | Kibana |
| `http://localhost:9200` | Elasticsearch |

### Make targets

```
make help        # list everything
make up          # bootstrap + build + start, wait for health
make down        # stop & remove containers (keep images)
make restart     # recreate from current code (no full rebuild)
make build       # build all images
make certs       # (re)generate mTLS certs   (ARGS=--force to force)
make ps          # container status
make logs        # tail all logs
make test        # adversarial pytest suite + log-chain check (isolated venv)
make opa-test    # OPA Rego policy unit tests
make verify-logs # audit hash-chain integrity check
make clean       # down -v (drops volumes) + remove the test venv
```

---

## 7. Using the framework — recipes

All API calls go through **Envoy on `:8080`**.

### Get a token (analyst `bob`)

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztac/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ztac-cli \
  -d username=bob -d password=bob123 \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

(Or use the gateway's convenience proxy: `POST http://localhost:8001/token`
with the same form fields.)

### Call endpoints

```bash
# Public — no token needed
curl -s http://localhost:8080/api/data/public

# Reports — analyst on a managed device → 200
curl -s -H "Authorization: Bearer $TOKEN" -H "x-device-trust: managed" \
  http://localhost:8080/api/data/reports

# Reports from an untrusted device → 403 (policy denies on posture)
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" -H "x-device-trust: untrusted" \
  http://localhost:8080/api/data/reports

# Reports from a high-risk IP → 403
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" -H "x-ip-risk: high" \
  http://localhost:8080/api/data/reports

# Admin endpoint as an analyst → 403 (role insufficient)
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/admin
```

### Demonstrate session revocation (stolen-token replay)

```bash
# 1. token works
curl -s -o /dev/null -w 'before: %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" -H "x-device-trust: managed" \
  http://localhost:8080/api/data/reports        # 200

# 2. admin kills bob's sessions in Keycloak (backchannel logout fires to the gateway)
ADMIN=$(curl -s -X POST http://localhost:8180/realms/master/protocol/openid-connect/token \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
UID=$(curl -s -H "Authorization: Bearer $ADMIN" \
  "http://localhost:8180/admin/realms/ztac/users?username=bob" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
curl -s -X POST -H "Authorization: Bearer $ADMIN" \
  "http://localhost:8180/admin/realms/ztac/users/$UID/logout"

# 3. the SAME token is now rejected
curl -s -o /dev/null -w 'after:  %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" -H "x-device-trust: managed" \
  http://localhost:8080/api/data/reports        # 401
```

### Check the gateway's view of its dependencies

```bash
curl -s http://localhost:8001/verify | python3 -m json.tool
```

### A scripted end-to-end demo

`scripts/demo.sh` walks through token acquisition and each allow/deny case.

---

## 8. Testing

ZTAC ships two layers of automated tests.

### Policy unit tests (no running stack needed)

```bash
make opa-test           # → PASS: 13/13
```

13 Rego tests in `opa/tests/authz_test.rego` cover public access, each role
against each resource, device-trust and IP-risk denial, and expiry.

### Adversarial integration tests (stack must be up)

```bash
make test               # builds .venv-test, runs pytest, then verifies the log chain
```

`scripts/run-tests.sh` creates an isolated virtualenv (PEP-668 safe — never
touches system Python), installs `tests/requirements.txt`, runs the suite, and
verifies the audit hash chain. The suite (`tests/`) covers five attack classes:

| File | Adversarial scenario |
|---|---|
| `test_privilege_escalation.py` | viewer reaching admin; tampered-payload JWT; `alg:none` downgrade; token forged with the wrong key |
| `test_unauth_s2s.py` | unauthenticated access; empty/garbage bearer; direct-service bypass (documents the limitation) |
| `test_token_replay.py` | replaying a stolen token after the session is revoked |
| `test_stale_session.py` | fresh vs. expired token; refresh restores access |
| `test_log_tampering.py` | mutating a stored audit record breaks the hash chain |

Expected result: **17 passed, 1 skipped** (the skip avoids sleeping for a full
token lifetime to prove expiry).

### Verify audit integrity on its own

```bash
make verify-logs        # → PASS: All N log entries have valid hash chain integrity
```

---

## 9. Audit logging and tamper-evidence

Every gateway decision produces a structured audit record (user, roles,
resource, action, decision, deny reason, status, duration, `request_id`) shipped
to Logstash. Logstash computes, for each event:

```
log_hash = HMAC_SHA256(AUDIT_HMAC_KEY, previous_hash + canonical_body_json)   # seed: "GENESIS"
```

and stores `previous_hash` + `log_hash` alongside the record in
`ztac-audit-YYYY.MM.DD`. Because each hash binds the entire prior history,
**editing or deleting any past record invalidates every hash after it** —
exactly what `test_log_tampering.py` and `scripts/verify_log_chain.py`
demonstrate.

Explore the records visually in Kibana (`http://localhost:5601`); the dashboard
export lives under `elk/`.

---

## 10. Configuration reference

All configuration is environment-driven via `.env` (created from
`.env.example`). Key variables:

| Variable | Default | Used by |
|---|---|---|
| `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` | `admin` / `admin` | Keycloak |
| `KEYCLOAK_HTTP_PORT` | `8180` | host port → Keycloak |
| `KEYCLOAK_REALM` | `ztac` | all |
| `OPA_HTTP_PORT` | `8181` | host port → OPA |
| `ENVOY_HTTP_PORT` | `8080` | host port → Envoy ingress |
| `PROTECTED_SERVICE_PORT` | `8000` | host port → protected service |
| `ES_HTTP_PORT` / `KIBANA_HTTP_PORT` | `9200` / `5601` | host ports → ELK |
| `LOGSTASH_TCP_PORT` / `LOGSTASH_HTTP_PORT` | `5044` / `5050` | host ports → Logstash |
| `ES_JAVA_OPTS` | `-Xms512m -Xmx512m` | Elasticsearch heap |

Gateway-internal settings (set in `docker-compose.yml`, not usually changed):
`KEYCLOAK_ISSUER=http://keycloak:8080/realms/ztac`,
`OPA_URL=http://opa:8181`, `PROTECTED_SERVICE_URL=http://protected-service:8000`,
`LOGSTASH_URL=http://logstash:5050`.

**Internal service addresses** (inside the `ztac-net` bridge) use service names:
`keycloak:8080`, `opa:8181`, `api-gateway:8001`, `protected-service:8000`,
`logstash:5050`, `elasticsearch:9200`.

The authorization data (resources, roles, device/IP rules) lives in
`opa/policies/data.json`; the seeded users/roles/clients live in
`keycloak/realm-export.json`.

---

## 11. Operations and troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `bootstrap.sh` says the daemon is unreachable | Docker isn't running, or your user lacks socket access. |
| A service never becomes healthy | `make logs` (or `docker compose logs <svc>`). ELK needs RAM — check `ES_JAVA_OPTS` and host memory. |
| Valid token gets `401 unknown_signing_key` | Keycloak rotated keys; the gateway auto-refetches JWKS and retries — if it persists, restart the gateway (`docker compose restart api-gateway`). |
| Valid token gets `401 Invalid issuer` | Token issuer ≠ `http://keycloak:8080/realms/ztac`. Ensure `KC_HOSTNAME_URL` is set (it is, in `docker-compose.yml`) and the realm was re-imported. |
| Everything returns `503` | OPA is down or unreachable — by design the gateway fails closed. Check `docker compose ps opa` and `curl localhost:8181/health`. |
| Build fails on `COPY certs/` | Only on a checkout missing `envoy/certs/.gitkeep`; run `make certs` then rebuild. |
| Realm changes not taking effect | `start-dev` uses an ephemeral DB; recreate Keycloak (`docker compose up -d --force-recreate keycloak`) to re-import `realm-export.json`. |

Common lifecycle commands: `make ps`, `make logs`, `make restart`, `make down`,
`make clean` (the last drops volumes — audit history and ES data — and the test
venv).

---

## 12. Security model and known limitations

This is a **reference/lab** implementation. Understand these boundaries before
treating it as production-ready:

- **Direct access to the protected service is now refused.** The service fails
  closed: every request must carry the gateway-injected `INTERNAL_GATEWAY_SECRET`
  (constant-time compared), so a host-local call on `:8000` that bypasses
  Envoy/OPA gets `403`. The host port is also bound to loopback. This is
  enforced and regression-tested
  (`test_unauth_s2s.py::test_direct_service_access_bypassing_envoy` and
  `test_offline_security.py`).
- **mTLS is provisioned as a production upgrade, not enforced by default.** The
  app-layer gateway-auth above is the active service-to-service control. Certs
  are generated and baked in; enabling the `transport_socket` blocks in
  `envoy.yaml` (and the gateway/service ends) adds transport-layer mutual TLS on
  top.
- **Device posture and IP risk are simulated** via the `x-device-trust` /
  `x-ip-risk` request headers. A real deployment must source these from trusted
  signals the client cannot forge. Note: identity headers (`x-auth-*`) and the
  internal-auth secret header **are** stripped at Envoy ingress, so a client
  cannot spoof identity or forge the gateway secret — only the posture hints
  remain client-supplied in the lab.
- **The revocation blacklist is in-memory** and single-process. A multi-replica
  gateway would need a shared store (e.g. Redis).
- **Keycloak runs in `start-dev`** with an ephemeral database — not for
  production. Use a persistent DB and `start` (production mode) for real use.

---

## 13. Extending the framework

**Add a new protected resource.**
1. Add a route to `services/protected-service/main.py`.
2. Add an entry to `resource_roles` in `opa/policies/data.json` with its
   `required_roles` and `sensitivity`.
3. Add a test in `opa/tests/authz_test.rego` and (optionally) `tests/`.

**Add a new role.**
1. Add the role and assign it to a user in `keycloak/realm-export.json`.
2. Reference it in the relevant `required_roles` in `data.json`.
3. Recreate Keycloak to re-import (`docker compose up -d --force-recreate keycloak`).

**Tighten or change the policy.** Edit `authz.rego` (keep `default allow :=
false`), run `make opa-test`, then `docker compose restart opa`. Every rule
should keep its CyBOK comment noting the principle it implements.

**Replace simulated signals with real ones.** Swap the `x-device-trust` header
for a device-posture agent, and `x-ip-risk` for an IP-reputation feed; feed both
into the existing `input` fields — no policy rewrite required.

Larger roadmap items (Istio sidecar enforcement, a real SIEM, SAML federation,
behavioural risk scoring, OPA bundle CI/CD) are discussed in
[`comparative-analysis.md`](comparative-analysis.md).

---

## 14. Repository layout

```
.
├── docker-compose.yml          # the whole stack
├── Makefile                    # convenience targets (see §6)
├── .env.example                # copy to .env (bootstrap does this)
├── scripts/
│   ├── bootstrap.sh            # one-command setup + up + wait-for-health
│   ├── generate-certs.sh       # mTLS PKI (idempotent)
│   ├── run-tests.sh            # isolated-venv pytest + log-chain check
│   ├── seed-keycloak.sh        # (re)seed the realm if needed
│   ├── verify_log_chain.py     # audit hash-chain verifier
│   └── demo.sh                 # scripted end-to-end demo
├── services/
│   ├── api-gateway/            # FastAPI PA (auth + OPA + forwarding)
│   ├── protected-service/      # downstream microservice
│   └── shared/                 # token blacklist + backchannel-logout handler
├── opa/
│   ├── Dockerfile
│   ├── policies/{authz.rego,rbac.rego,data.json}
│   └── tests/authz_test.rego
├── envoy/
│   ├── Dockerfile
│   ├── envoy.yaml              # listener, router, (commented) mTLS
│   └── certs/                  # generated; git-ignored except .gitkeep
├── keycloak/realm-export.json  # realm, users, roles, clients
├── elk/                        # Logstash pipeline (hash chain) + Kibana export
├── tests/                      # adversarial pytest suite
└── docs/                       # this guide + the focused companion docs
```

---

*ZTAC is an educational reference architecture. For the standards mapping behind
the design choices, read [`cybok-alignment-matrix.md`](cybok-alignment-matrix.md)
and [`comparative-analysis.md`](comparative-analysis.md).*
