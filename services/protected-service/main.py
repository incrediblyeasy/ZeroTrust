"""
Protected Service — expanded with request tracking and internal-call validation.
"""

from fastapi import FastAPI, Request, Response
from starlette.responses import JSONResponse
from datetime import datetime, timezone
import hmac
import logging
import json
import uuid
import httpx
import asyncio
import os

app = FastAPI(title="ZTAC Protected Service")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("protected-service")

LOGSTASH_URL = os.getenv("LOGSTASH_URL", "http://logstash:5050")
# Shared secret for authenticated audit-log ingest (prevents log injection).
LOGSTASH_INGEST_TOKEN = os.getenv("LOGSTASH_INGEST_TOKEN", "")
_LOGSTASH_AUTH = httpx.BasicAuth("ztac", LOGSTASH_INGEST_TOKEN) if LOGSTASH_INGEST_TOKEN else None

# Shared secret the api-gateway injects on every forwarded request. The
# protected service is a zero-trust resource: it does not trust the network, so
# it verifies that each request actually traversed the PEP/PA chain instead of
# arriving via a direct connection that bypasses Envoy/OPA. The secret is never
# exposed to clients.
INTERNAL_GATEWAY_SECRET = os.getenv("INTERNAL_GATEWAY_SECRET", "")

# Routes reachable without the gateway secret (liveness probing only).
PUBLIC_PATHS = {"/health"}


@app.middleware("http")
async def gateway_auth_middleware(request: Request, call_next):
    """Reject any request that did not arrive through the trusted gateway."""
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    if not INTERNAL_GATEWAY_SECRET:
        # Fail closed: refuse to serve protected data without a configured
        # secret rather than silently trusting the network.
        return JSONResponse(
            {"error": "gateway_auth_misconfigured"}, status_code=503
        )

    presented = request.headers.get("x-ztac-gateway-auth", "")
    if not hmac.compare_digest(presented, INTERNAL_GATEWAY_SECRET):
        logger.info(json.dumps({
            "service": "protected-service",
            "event": "direct_access_blocked",
            "path": str(request.url.path),
            "client_ip": request.client.host if request.client else "unknown",
        }))
        return JSONResponse(
            {"error": "forbidden", "detail": "direct_access_denied"},
            status_code=403,
        )

    return await call_next(request)

async def ship_log(log_entry: dict):
    """Send structured log to Logstash asynchronously.

    The full record is already emitted to stdout (captured by `docker logs`) by
    the audit middleware, so a shipment failure never loses the record outright;
    we still surface the failure rather than swallowing it silently.
    """
    log_entry["source_component"] = "protected-service"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(LOGSTASH_URL, json=log_entry, auth=_LOGSTASH_AUTH)
        if resp.status_code >= 300:
            logger.warning(json.dumps(
                {"audit_fallback": True, "ship_error": f"logstash_status_{resp.status_code}", **log_entry}
            ))
    except Exception as exc:
        logger.warning(json.dumps(
            {"audit_fallback": True, "ship_error": type(exc).__name__, **log_entry}
        ))

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

    asyncio.create_task(ship_log(log_entry.copy()))

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
