"""
ZTAC API Gateway — Policy Administrator (PA).

Responsibilities (CyBOK AAA alignment in parentheses):
  * Validate Keycloak-issued JWTs against the realm JWKS        (Authentication)
  * Reject revoked tokens via the shared JTI blacklist          (Session Mgmt)
  * Consult the OPA Policy Decision Point on every request      (Authorisation)
  * Inject verified identity headers and forward to the backend (Enforcement)
  * Emit a structured audit log for every request              (Accountability)

Request flow:
  Client → Envoy:8080 → API-Gateway:8001 → Protected-Service:8000

The gateway is the component that turns validated JWT claims into the exact
OPA input object described in docs/token-schema.md.
"""

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.responses import JSONResponse, Response

from shared.keycloak_logout import apply_backchannel_logout
from shared.token_blacklist import blacklist

KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", "http://keycloak:8080/realms/ztac")
PROTECTED_SERVICE_URL = os.getenv("PROTECTED_SERVICE_URL", "http://protected-service:8000")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
LOGSTASH_URL = os.getenv("LOGSTASH_URL", "http://logstash:5050")
# Shared secret for authenticated audit-log ingest (prevents log injection).
LOGSTASH_INGEST_TOKEN = os.getenv("LOGSTASH_INGEST_TOKEN", "")
_LOGSTASH_AUTH = httpx.BasicAuth("ztac", LOGSTASH_INGEST_TOKEN) if LOGSTASH_INGEST_TOKEN else None

# Local durable fallback for audit records that fail to ship to Logstash. Without
# this, a Logstash outage would silently drop accountability records. The file
# lives on a mounted volume so the records survive container restarts and can be
# replayed/inspected after recovery.
AUDIT_FALLBACK_LOG = os.getenv("AUDIT_FALLBACK_LOG", "/var/log/ztac/audit-fallback.log")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("api-gateway")

# Confidential client this gateway represents; logout tokens are audience-bound
# to it, and (optionally) presented access tokens are restricted to it.
GATEWAY_CLIENT_ID = os.getenv("KEYCLOAK_GATEWAY_CLIENT_ID", "ztac-gateway")

# Only accept access tokens whose authorized party (azp) is in this allowlist.
# This rejects tokens minted for *other* clients in the same realm. Empty list
# disables the check.
JWT_ALLOWED_AZP = [
    a.strip() for a in os.getenv("JWT_ALLOWED_AZP", "ztac-cli,ztac-gateway").split(",")
    if a.strip()
]
# If set, the access token's audience (aud) must contain this value.
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "").strip()

# Shared secret the gateway injects so the protected service can prove a request
# arrived through the PEP/PA chain and not via a direct network bypass.
INTERNAL_GATEWAY_SECRET = os.getenv("INTERNAL_GATEWAY_SECRET", "")

# Reject request bodies larger than this to bound memory use (DoS guard).
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(1 * 1024 * 1024)))

JWKS_URI = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
TOKEN_ENDPOINT = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token"

ALLOWED_ALGORITHMS = ["RS256"]

JWKS_REFRESH_SECONDS = 300

GATEWAY_PATHS = {"/health", "/verify", "/token", "/backchannel-logout"}

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}

# Identity/trust headers a client must never be able to set: the gateway is the
# sole authority for these. They are stripped from inbound requests before
# forwarding so a client cannot impersonate a user or forge the internal-auth
# secret even if Envoy's ingress strip is bypassed.
RESERVED_HEADERS = {
    "x-auth-user", "x-auth-roles", "x-auth-jti", "x-auth-exp",
    "x-ztac-gateway-auth",
}

_http: httpx.AsyncClient | None = None
_jwks: dict = {"keys": []}
_jwks_lock = asyncio.Lock()
_refresh_task: asyncio.Task | None = None

async def _fetch_jwks() -> None:
    """Fetch and cache Keycloak's JWKS (public keys)."""
    global _jwks
    assert _http is not None
    resp = await _http.get(JWKS_URI)
    resp.raise_for_status()
    async with _jwks_lock:
        _jwks = resp.json()

async def _jwks_refresh_loop() -> None:
    """Background task: refresh the JWKS every JWKS_REFRESH_SECONDS."""
    while True:
        await asyncio.sleep(JWKS_REFRESH_SECONDS)
        try:
            await _fetch_jwks()
        except Exception:
            pass

def _find_key(kid: str) -> dict | None:
    """Return the JWK with the given kid from the cache, if present."""
    for key in _jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Manage the shared HTTP client and JWKS refresh task for the app's life.

    Replaces the deprecated @app.on_event startup/shutdown hooks.
    """
    global _http, _refresh_task
    _http = httpx.AsyncClient(timeout=10.0)
    try:
        await _fetch_jwks()
    except Exception:
        pass
    _refresh_task = asyncio.create_task(_jwks_refresh_loop())
    try:
        yield
    finally:
        if _refresh_task is not None:
            _refresh_task.cancel()
        if _http is not None:
            await _http.aclose()

app = FastAPI(title="ZTAC API Gateway", lifespan=lifespan)

class TokenError(Exception):
    """Raised when a presented JWT fails validation."""

def validate_token(token: str) -> dict:
    """
    Verify a JWT against Keycloak's JWKS and return its claims.

    Raises TokenError(reason) on any failure. The reason string is safe to
    surface to the client in the {"detail": ...} field.
    """
    if not token or token.count(".") != 2:
        raise TokenError("malformed_token")

    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise TokenError("malformed_header")

    alg = header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise TokenError(f"unsupported_algorithm:{alg}")

    kid = header.get("kid")
    key = _find_key(kid) if kid else None
    if key is None:
        raise TokenError("unknown_signing_key")

    decode_options = {"verify_aud": bool(JWT_AUDIENCE)}
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=ALLOWED_ALGORITHMS,
            issuer=KEYCLOAK_ISSUER,
            audience=JWT_AUDIENCE or None,
            options=decode_options,
        )
    except ExpiredSignatureError:
        raise TokenError("expired")
    except JWTClaimsError:
        # Do not echo verifier internals back to the client.
        raise TokenError("invalid_claims")
    except JWTError:
        raise TokenError("signature_verification_failed")

    # Restrict to tokens issued for known clients (defence against accepting a
    # valid token minted for a different client in the same realm).
    if JWT_ALLOWED_AZP:
        azp = claims.get("azp")
        if azp not in JWT_ALLOWED_AZP:
            raise TokenError("untrusted_client")

    return claims


async def validate_logout_token(token: str) -> dict:
    """
    Verify a Keycloak OIDC back-channel *logout token* against the JWKS and
    return its claims. Refreshes the JWKS once if the signing key is unknown.

    The logout token's audience must be one of the trusted clients that share
    this gateway's backchannel endpoint (the gateway's own confidential client
    and any client in JWT_ALLOWED_AZP). Keycloak audiences the logout token to
    the client whose session is ending — e.g. the public ``ztac-cli`` used to
    obtain access tokens — so pinning to a single client id would silently drop
    legitimate revocations.
    """
    if not token or token.count(".") != 2:
        raise TokenError("malformed_token")

    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise TokenError("malformed_header")

    if header.get("alg") not in ALLOWED_ALGORITHMS:
        raise TokenError(f"unsupported_algorithm:{header.get('alg')}")

    kid = header.get("kid")
    if kid and _find_key(kid) is None:
        try:
            await _fetch_jwks()
        except Exception:
            pass
    key = _find_key(kid) if kid else None
    if key is None:
        raise TokenError("unknown_signing_key")

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=ALLOWED_ALGORITHMS,
            issuer=KEYCLOAK_ISSUER,
            options={"verify_aud": False},
        )
    except ExpiredSignatureError:
        raise TokenError("expired")
    except JWTClaimsError:
        raise TokenError("invalid_claims")
    except JWTError:
        raise TokenError("signature_verification_failed")

    # Audience must be a trusted client sharing this backchannel endpoint.
    aud = claims.get("aud")
    token_aud = {aud} if isinstance(aud, str) else set(aud or [])
    allowed_aud = set(JWT_ALLOWED_AZP) | {GATEWAY_CLIENT_ID}
    if not token_aud & allowed_aud:
        raise TokenError("untrusted_logout_audience")

    return claims

async def validate_token_refreshing(token: str) -> dict:
    """
    Validate a JWT, transparently refreshing the JWKS once if the token's
    signing key is unknown. Keycloak rotates realm signing keys (e.g. on
    restart), so a previously cached JWKS can legitimately miss a fresh kid;
    rather than rejecting every token until the periodic refresh fires, we
    refetch on demand and retry exactly once.
    """
    try:
        return validate_token(token)
    except TokenError as exc:
        if str(exc) != "unknown_signing_key":
            raise
        try:
            await _fetch_jwks()
        except Exception:
            pass
        return validate_token(token)

def extract_identity(claims: dict) -> dict:
    """Pull the ZTAC-relevant fields out of validated claims."""
    realm_access = claims.get("realm_access") or {}
    return {
        "user": claims.get("preferred_username", "anonymous"),
        "roles": realm_access.get("roles", []) or [],
        "exp": claims.get("exp", 0) or 0,
        "iat": claims.get("iat", 0) or 0,
        "sub": claims.get("sub", "") or "",
        "jti": claims.get("jti", "") or "",
        "sid": claims.get("sid", "") or "",
    }

def build_opa_input(request: Request, identity: dict) -> dict:
    """Assemble the OPA input object per docs/token-schema.md."""
    return {
        "input": {
            "user": identity.get("user") or "anonymous",
            "roles": identity.get("roles") or [],
            "action": request.method,
            "resource": request.url.path,
            "token_exp": identity.get("exp") or 0,
            "token_jti": identity.get("jti") or "",
            "device_trust": request.headers.get("x-device-trust", "managed"),
            "ip_risk": request.headers.get("x-ip-risk", "low"),
        }
    }

class OPAUnavailable(Exception):
    """Raised when the OPA PDP cannot be reached."""

async def opa_allows(opa_input: dict) -> bool:
    """
    Query the OPA PDP. Returns True only when OPA returns {"result": true}.
    Raises OPAUnavailable if the PDP cannot be reached (caller maps to 503).
    """
    assert _http is not None
    try:
        resp = await _http.post(f"{OPA_URL}/v1/data/authz/allow", json=opa_input)
    except httpx.HTTPError as exc:
        raise OPAUnavailable(str(exc))
    if resp.status_code != 200:
        raise OPAUnavailable(f"opa_status_{resp.status_code}")
    return resp.json().get("result") is True

_fallback_lock = threading.Lock()


def _write_audit_fallback(entry: dict, reason: str) -> None:
    """Persist an audit record locally when it cannot be shipped to Logstash.

    Tries an append-only file on the mounted log volume first; if that is not
    writable, falls back to stdout (captured by `docker logs`). Either way the
    accountability record is never silently lost.
    """
    record = {"audit_fallback": True, "ship_error": reason, **entry}
    line = json.dumps(record)
    try:
        os.makedirs(os.path.dirname(AUDIT_FALLBACK_LOG) or ".", exist_ok=True)
        with _fallback_lock, open(AUDIT_FALLBACK_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        logger.warning(line)


async def ship_log(entry: dict) -> None:
    """Send a structured audit log to Logstash; never block or raise.

    If shipment fails (Logstash down, auth rejected, non-2xx), the record is
    written to a local durable fallback instead of being dropped.
    """
    assert _http is not None
    try:
        resp = await _http.post(
            LOGSTASH_URL, json=entry, timeout=2.0, auth=_LOGSTASH_AUTH
        )
        if resp.status_code >= 300:
            _write_audit_fallback(entry, f"logstash_status_{resp.status_code}")
    except Exception as exc:
        _write_audit_fallback(entry, f"{type(exc).__name__}")

def emit_audit(
    request: Request,
    request_id: str,
    identity: dict,
    decision: str,
    deny_reason: str | None,
    status_code: int,
    duration_ms: float,
) -> None:
    """Build the audit record and dispatch it without blocking the response."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_component": "api-gateway",
        "request_id": request_id,
        "method": request.method,
        "path": request.url.path,
        "user": identity.get("user", "anonymous"),
        "roles": identity.get("roles", []),
        "token_jti": identity.get("jti", ""),
        "decision": decision,
        "deny_reason": deny_reason,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 2),
        "client_ip": request.client.host if request.client else "unknown",
        "device_trust": request.headers.get("x-device-trust", "managed"),
        "ip_risk": request.headers.get("x-ip-risk", "low"),
    }
    asyncio.create_task(ship_log(entry))

async def forward_to_protected(
    request: Request, body: bytes, identity: dict, request_id: str
) -> Response:
    """Proxy an authorized request to the protected service with identity headers."""
    assert _http is not None

    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() not in RESERVED_HEADERS
    }
    headers["x-auth-user"] = identity.get("user", "anonymous")
    headers["x-auth-roles"] = json.dumps(identity.get("roles", []))
    headers["x-auth-jti"] = identity.get("jti", "")
    headers["x-auth-exp"] = str(identity.get("exp", 0))
    headers["x-request-id"] = request_id
    # Prove to the protected service that this request traversed the PEP/PA
    # chain. The secret is never exposed to clients, so a direct network call
    # cannot reproduce it.
    if INTERNAL_GATEWAY_SECRET:
        headers["x-ztac-gateway-auth"] = INTERNAL_GATEWAY_SECRET

    url = f"{PROTECTED_SERVICE_URL}{request.url.path}"
    try:
        upstream = await _http.request(
            request.method,
            url,
            params=dict(request.query_params),
            content=body,
            headers=headers,
        )
    except httpx.TimeoutException:
        # Upstream is reachable but too slow — surface a clean Gateway Timeout
        # instead of an unhandled 500 with a stack trace.
        return JSONResponse(
            {"error": "upstream_timeout", "detail": "protected_service_timeout"},
            status_code=504,
        )
    except httpx.HTTPError:
        # Upstream unreachable (connection refused, DNS failure, reset, ...).
        return JSONResponse(
            {"error": "bad_gateway", "detail": "protected_service_unavailable"},
            status_code=502,
        )

    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
    )

@app.middleware("http")
async def gateway_middleware(request: Request, call_next):
    if request.url.path in GATEWAY_PATHS:
        return await call_next(request)

    start = time.perf_counter()
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    identity: dict = {"user": "anonymous", "roles": [], "exp": 0, "jti": ""}

    def done(resp: Response, decision: str, reason: str | None) -> Response:
        duration_ms = (time.perf_counter() - start) * 1000
        emit_audit(request, request_id, identity, decision, reason,
                   resp.status_code, duration_ms)
        resp.headers["x-request-id"] = request_id
        return resp

    # Bound request body size to protect against memory-exhaustion DoS. We can
    # reject on the declared Content-Length without buffering the payload.
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return done(
                    JSONResponse({"error": "payload_too_large"}, status_code=413),
                    "deny", "payload_too_large",
                )
        except ValueError:
            return done(
                JSONResponse({"error": "invalid_content_length"}, status_code=400),
                "deny", "invalid_content_length",
            )

    auth_header = request.headers.get("authorization", "")

    if not auth_header:
        opa_input = build_opa_input(request, identity)
        try:
            allowed = await opa_allows(opa_input)
        except OPAUnavailable:
            return done(
                JSONResponse({"error": "policy_engine_unavailable"}, status_code=503),
                "deny", "policy_engine_unavailable",
            )
        if not allowed:
            return done(
                JSONResponse({"error": "missing_token"}, status_code=401),
                "deny", "missing_token",
            )
        body = await request.body()
        resp = await forward_to_protected(request, body, identity, request_id)
        return done(resp, "allow", None)

    if not auth_header.lower().startswith("bearer "):
        return done(
            JSONResponse({"error": "invalid_token", "detail": "missing_bearer_scheme"},
                         status_code=401),
            "deny", "missing_bearer_scheme",
        )

    token = auth_header[7:].strip()

    try:
        claims = await validate_token_refreshing(token)
    except TokenError as exc:
        return done(
            JSONResponse({"error": "invalid_token", "detail": str(exc)}, status_code=401),
            "deny", f"invalid_token:{exc}",
        )

    identity = extract_identity(claims)

    jti = identity["jti"]
    sid = identity.get("sid", "")
    sub = identity.get("sub", "")
    iat = identity.get("iat", 0)
    if (
        (jti and blacklist.is_revoked(jti))
        or (sid and blacklist.is_revoked(f"session:{sid}"))
        or (sub and blacklist.is_subject_revoked(sub, iat))
    ):
        return done(
            JSONResponse({"error": "token_revoked"}, status_code=401),
            "deny", "token_revoked",
        )

    opa_input = build_opa_input(request, identity)
    try:
        allowed = await opa_allows(opa_input)
    except OPAUnavailable:
        return done(
            JSONResponse({"error": "policy_engine_unavailable"}, status_code=503),
            "deny", "policy_engine_unavailable",
        )

    if not allowed:
        return done(
            JSONResponse({"error": "access_denied", "reason": "policy_denied"},
                         status_code=403),
            "deny", "policy_denied",
        )

    body = await request.body()
    resp = await forward_to_protected(request, body, identity, request_id)
    return done(resp, "allow", None)

# Registered after gateway_middleware so it is the OUTERMOST middleware and
# stamps security headers on every response, including the gateway's own deny
# responses (which short-circuit before gateway_middleware calls call_next).
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "api-gateway"}

@app.get("/verify")
async def verify():
    """Check connectivity to Keycloak, OPA and the protected service."""
    assert _http is not None
    checks: dict[str, str] = {}

    async def probe(name: str, url: str) -> None:
        try:
            r = await _http.get(url, timeout=3.0)
            checks[name] = "ok" if r.status_code < 500 else f"http_{r.status_code}"
        except Exception as exc:
            checks[name] = f"unreachable:{type(exc).__name__}"

    await asyncio.gather(
        probe("keycloak", f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration"),
        probe("opa", f"{OPA_URL}/health"),
        probe("protected_service", f"{PROTECTED_SERVICE_URL}/health"),
    )
    overall = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks, "jwks_keys": len(_jwks.get("keys", []))}

# Per-IP sliding-window rate limit for the unauthenticated token proxy, so it
# cannot be abused as an open password-guessing relay against Keycloak.
_token_rate: dict[str, list[float]] = {}
_token_rate_lock = threading.Lock()
TOKEN_RATE_LIMIT = int(os.getenv("TOKEN_RATE_LIMIT", "10"))
TOKEN_RATE_WINDOW = int(os.getenv("TOKEN_RATE_WINDOW", "60"))
ALLOWED_GRANT_TYPES = {"password", "refresh_token"}


def _token_rate_ok(client_ip: str) -> bool:
    """Return True if the request is within the per-IP rate limit."""
    now = time.time()
    with _token_rate_lock:
        hits = [t for t in _token_rate.get(client_ip, []) if now - t < TOKEN_RATE_WINDOW]
        if len(hits) >= TOKEN_RATE_LIMIT:
            _token_rate[client_ip] = hits
            return False
        hits.append(now)
        _token_rate[client_ip] = hits
        return True


@app.post("/token")
async def token_proxy(request: Request):
    """Convenience proxy to Keycloak's token endpoint (password/refresh grants).

    Rate-limited per client IP and restricted to safe grant types.
    """
    assert _http is not None

    client_ip = request.client.host if request.client else "unknown"
    if not _token_rate_ok(client_ip):
        return JSONResponse(
            {"error": "rate_limit_exceeded",
             "detail": f"max {TOKEN_RATE_LIMIT} requests per {TOKEN_RATE_WINDOW}s"},
            status_code=429,
        )

    form = await request.form()
    grant_type = form.get("grant_type", "password")
    if grant_type not in ALLOWED_GRANT_TYPES:
        return JSONResponse(
            {"error": "unsupported_grant_type",
             "detail": f"allowed: {sorted(ALLOWED_GRANT_TYPES)}"},
            status_code=400,
        )

    data = {
        "grant_type": grant_type,
        "client_id": form.get("client_id", ""),
        "username": form.get("username", ""),
        "password": form.get("password", ""),
    }
    if form.get("refresh_token"):
        data["refresh_token"] = form.get("refresh_token")
    if form.get("client_secret"):
        data["client_secret"] = form.get("client_secret")
    try:
        resp = await _http.post(TOKEN_ENDPOINT, data=data)
    except httpx.HTTPError as exc:
        return JSONResponse({"error": "keycloak_unreachable", "detail": str(exc)},
                            status_code=502)
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )

@app.post("/backchannel-logout")
async def backchannel_logout(request: Request):
    """
    Keycloak OIDC back-channel logout endpoint.

    The logout token's RS256 signature, issuer and audience are verified against
    Keycloak's JWKS *before* any session is revoked, so a forged or replayed
    token cannot force-logout users.
    """
    form = await request.form()
    logout_token = form.get("logout_token", "")
    if not logout_token:
        return JSONResponse(
            {"status": "error", "detail": "missing_logout_token"}, status_code=400
        )

    try:
        claims = await validate_logout_token(logout_token)
    except TokenError as exc:
        return JSONResponse(
            {"status": "error", "detail": f"invalid_logout_token:{exc}"},
            status_code=400,
        )

    result = apply_backchannel_logout(claims)
    status_code = 200 if result.get("status") == "ok" else 400
    return JSONResponse(result, status_code=status_code)
