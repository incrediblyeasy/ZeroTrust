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
import os
import time
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.responses import JSONResponse, Response

from shared.keycloak_logout import handle_backchannel_logout
from shared.token_blacklist import blacklist

KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", "http://keycloak:8080/realms/ztac")
PROTECTED_SERVICE_URL = os.getenv("PROTECTED_SERVICE_URL", "http://protected-service:8000")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
LOGSTASH_URL = os.getenv("LOGSTASH_URL", "http://logstash:5050")

JWKS_URI = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
TOKEN_ENDPOINT = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token"

ALLOWED_ALGORITHMS = ["RS256"]

JWKS_REFRESH_SECONDS = 300

GATEWAY_PATHS = {"/health", "/verify", "/token", "/backchannel-logout"}

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}

app = FastAPI(title="ZTAC API Gateway")

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

@app.on_event("startup")
async def _startup() -> None:
    global _http, _refresh_task
    _http = httpx.AsyncClient(timeout=10.0)
    try:
        await _fetch_jwks()
    except Exception:
        pass
    _refresh_task = asyncio.create_task(_jwks_refresh_loop())

@app.on_event("shutdown")
async def _shutdown() -> None:
    if _refresh_task is not None:
        _refresh_task.cancel()
    if _http is not None:
        await _http.aclose()

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
    except JWTClaimsError as exc:
        raise TokenError(f"invalid_claims:{exc}")
    except JWTError as exc:
        raise TokenError(f"signature_verification_failed:{exc}")

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

async def ship_log(entry: dict) -> None:
    """Send a structured audit log to Logstash; never block or raise."""
    assert _http is not None
    try:
        await _http.post(LOGSTASH_URL, json=entry, timeout=2.0)
    except Exception:
        pass

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
        k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP
    }
    headers["x-auth-user"] = identity.get("user", "anonymous")
    headers["x-auth-roles"] = json.dumps(identity.get("roles", []))
    headers["x-auth-jti"] = identity.get("jti", "")
    headers["x-auth-exp"] = str(identity.get("exp", 0))
    headers["x-request-id"] = request_id

    url = f"{PROTECTED_SERVICE_URL}{request.url.path}"
    upstream = await _http.request(
        request.method,
        url,
        params=dict(request.query_params),
        content=body,
        headers=headers,
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

@app.post("/token")
async def token_proxy(request: Request):
    """Convenience proxy to Keycloak's token endpoint (password grant)."""
    assert _http is not None
    form = await request.form()
    data = {
        "grant_type": form.get("grant_type", "password"),
        "client_id": form.get("client_id", ""),
        "username": form.get("username", ""),
        "password": form.get("password", ""),
    }
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
    """Keycloak backchannel logout — revokes the session via the shared handler."""
    form = await request.form()
    logout_token = form.get("logout_token", "")
    result = handle_backchannel_logout(logout_token)
    status_code = 200 if result.get("status") == "ok" else 400
    return JSONResponse(result, status_code=status_code)
