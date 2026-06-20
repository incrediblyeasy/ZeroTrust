# Comparative Analysis — ZTAC vs. Established Zero-Trust Models

This document situates the ZTAC framework against two widely cited zero-trust
references: the **NIST SP 800-207** logical architecture and **Google
BeyondCorp**. It closes with a roadmap of future work.

## 1. NIST SP 800-207 mapping

NIST SP 800-207 decomposes a zero-trust architecture into logical components
arranged around a Policy Decision Point and a Policy Enforcement Point. ZTAC
implements each of these as a discrete, independently deployable service.

| NIST SP 800-207 Component | Our Framework Component | Notes |
|---|---|---|
| Policy Engine (PE) | OPA (Rego policies) | Declarative, hot-reloadable |
| Policy Administrator (PA) | API Gateway | JWT validation, request forwarding |
| Policy Decision Point (PDP) | OPA | REST API, ABAC evaluation |
| Policy Enforcement Point (PEP) | Envoy Proxy | `ext_authz` filter |
| Continuous Diagnostics & Mitigation (CDM) | ELK Stack | Audit logs, dashboards |
| Industry Compliance | CyBOK Alignment Matrix | Formal mapping to AAA KA |
| Data Access Policy | `data.json` + `authz.rego` | Resource sensitivity classification |
| Public Key Infrastructure | mTLS certs | CA-signed, OpenSSL generated |

### How the NIST control plane / data plane split is realised

In SP 800-207 the **control plane** establishes whether a subject may use a
connection, and the **data plane** carries the authorised traffic. In ZTAC:

- The **control plane** is the OPA PDP plus the gateway's PA logic. The gateway
  collects the subject's verified identity (from the Keycloak-issued JWT) and
  contextual attributes (device trust, IP risk, token freshness), then asks OPA
  for an allow/deny decision *per request* — not once per session. This delivers
  the NIST tenet of *dynamic, per-session authorisation*.
- The **data plane** is Envoy. No request reaches the protected service unless
  Envoy's `ext_authz` step and the gateway's checks both pass; Envoy fails
  **closed** if the PDP is unreachable, satisfying the tenet that *resources are
  not reachable without explicit authorisation*.
- The **Data Access Policy** (`data.json` + `authz.rego`) encodes resource
  sensitivity (`public` / `internal` / `confidential`) and the roles/attributes
  required for each, realising NIST's notion of policy as an explicit,
  auditable artefact rather than implicit firewall configuration.

### Tenets coverage summary

| NIST SP 800-207 tenet | ZTAC realisation |
|---|---|
| All data sources & services are resources | Every endpoint is mediated by Envoy + gateway |
| All communication is secured regardless of network location | JWT bearer auth on every call; mTLS PKI provisioned for service-to-service |
| Access granted per-session | OPA queried on every request; 5-minute token lifetime |
| Access determined by dynamic policy | Rego policy over identity + device + IP + expiry |
| Integrity/security of assets monitored | ELK hash-chained audit trail |
| Authentication & authorisation strictly enforced before access | Gateway validates JWT, then OPA decides, then Envoy forwards |
| As much information as possible collected to improve posture | Structured per-request audit logs in Elasticsearch |

## 2. Google BeyondCorp comparison

BeyondCorp is Google's production zero-trust model that removes the privileged
corporate network and authorises every request based on device and user state.
ZTAC mirrors its building blocks with open-source components.

| BeyondCorp concept | BeyondCorp implementation | ZTAC equivalent |
|---|---|---|
| Device inventory & trust | Managed device inventory + certificates feeding a trust tier | Simulated via the `x-device-trust` header (`managed` / `byod_compliant` / `untrusted`); evaluated by `authz.rego` |
| Access Proxy | Google-internal reverse proxy enforcing access | **Envoy** with the `ext_authz` filter |
| Single Sign-On | Google SSO / identity service | **Keycloak** (OIDC, RS256 JWTs) |
| Access Control Engine | Centralised policy engine consulted by the proxy | **OPA** (Rego ABAC/RBAC) |
| Trust Inference / tiers | Continuous trust scoring per device & user | `device_trust` + `ip_risk` attributes, re-evaluated per request |
| Logging & analysis | Centralised pipelines for audit & anomaly detection | **ELK stack** with hash-chained logs |

**Key difference.** BeyondCorp is proprietary, tightly coupled to Google's
infrastructure, and consumes rich real-time device-posture and threat signals.
ZTAC provides an *open-source, self-hostable* alternative that any organisation
can run and audit. The trade-off is fidelity of signals: ZTAC simulates device
posture and IP risk via request headers (intended to be replaced by a real
device-posture agent and IP-reputation feed), whereas BeyondCorp ingests them
from production telemetry. Architecturally, however, the enforcement model —
*proxy + central policy engine + per-request decision + centralised logging* —
is the same.

## 3. Future work

- **Device posture checking via a lightweight agent.** Replace the simulated
  `x-device-trust` header with a real endpoint agent reporting OS patch level,
  disk encryption, EDR status and certificate presence.
- **Kubernetes-native deployment with an Istio service mesh.** Move enforcement
  into sidecar proxies, using Istio `AuthorizationPolicy` backed by OPA for
  mesh-wide, mutual-TLS-by-default policy.
- **Integration with Wazuh or Splunk as a production SIEM.** Forward the
  hash-chained audit stream into a full SIEM for correlation, alerting and
  long-term retention beyond the lab's single-node Elasticsearch.
- **Federated identity with SAML 2.0 for multi-organisation deployments.**
  Extend Keycloak to broker external IdPs so partners authenticate with their
  own credentials while ZTAC policy still governs access.
- **Dynamic risk scoring based on behavioural analytics.** Compute `ip_risk`
  and a user-risk score from access patterns (impossible travel, velocity,
  anomalous resource access) and feed them into the Rego policy.
- **Policy versioning and rollback via OPA bundles with Git-based CI/CD.**
  Distribute signed policy bundles, gate changes behind `opa test` in CI, and
  support instant rollback to a previous bundle revision.
