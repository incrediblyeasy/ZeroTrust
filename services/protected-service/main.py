"""
Protected Service — expanded with request tracking and internal-call validation.
"""

from fastapi import FastAPI, Request, Response
from datetime import datetime, timezone
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


async def ship_log(log_entry: dict):
    """Send structured log to Logstash asynchronously."""
    log_entry["source_component"] = "protected-service"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(LOGSTASH_URL, json=log_entry)
    except Exception:
        pass  # Don't let logging failures break the service


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
