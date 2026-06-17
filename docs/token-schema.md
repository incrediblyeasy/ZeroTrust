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
