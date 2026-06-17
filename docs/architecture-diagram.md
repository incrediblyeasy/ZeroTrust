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
