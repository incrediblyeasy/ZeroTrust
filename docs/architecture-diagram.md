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
┌──────┐     HTTP       ┌──────────┐             ┌─────────┐
│      │ ──────────────► │  Envoy   │             │   OPA   │
│ User │                 │  (PEP)   │             │  (PDP)  │
│      │ ◄────────────── │ forward  │             │         │
└──────┘ 200/401/403/503 └────┬─────┘             └────▲────┘
                              │                        │ per-request
                  (mTLS-ready)│                        │ {"input":…}
                              ▼                        │ allow/deny
                        ┌───────────┐ ────────────────┘
                        │   API     │          ┌───────────────┐
                        │  Gateway  │ ────────►│   Keycloak    │
                        │   (PA)    │  JWKS    │    (IdP)      │
                        └─────┬─────┘ verify   └───────────────┘
                              │                + backchannel logout
                  (mTLS-ready)│
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

1. User sends an HTTP request with JWT `Authorization: Bearer <token>` to Envoy (port 8080).
2. Envoy (the PEP) terminates ingress and forwards the request to the API Gateway. Nothing reaches the protected service except through Envoy. (mTLS to the gateway is provisioned but disabled by default — see the commented `transport_socket` blocks in `envoy.yaml`.)
3. The Gateway (the PA) validates the JWT against Keycloak's JWKS — RS256 only, correct issuer, not expired, valid signature (refetching the JWKS once on an unknown `kid`).
4. The Gateway checks the token's `jti` and `session:<sid>` against the revocation blacklist (populated by Keycloak backchannel logout). A revoked session is rejected even though the JWT is otherwise valid.
5. The Gateway builds an `input` object (user, roles, action, resource, token expiry, device trust, IP risk) and `POST`s it to OPA at `/v1/data/authz/allow`.
6. OPA (the PDP) evaluates the Rego policy and returns `{"result": true|false}`.
7. If denied: the Gateway returns `403` (policy) / `401` (auth) / `503` (PDP unreachable, fail closed) with a structured JSON error. The decision is audited.
8. If allowed: the Gateway forwards to the Protected Service, injecting verified identity headers (`x-auth-user`, `x-auth-roles`, `x-auth-jti`, `x-auth-exp`, `x-request-id`) plus the secret `x-ztac-gateway-auth` header. (Client-supplied copies of these headers are stripped at Envoy ingress.)
9. The Protected Service verifies the `x-ztac-gateway-auth` secret (fail-closed; a direct call without it gets `403`), then trusts the identity headers, processes the request, and returns a response.
10. The Gateway emits a structured JSON audit record to Logstash (and Envoy emits access logs); Logstash adds keyed HMAC-SHA256 hash-chain fields and indexes into Elasticsearch.
11. Kibana provides dashboards for monitoring and audit.
