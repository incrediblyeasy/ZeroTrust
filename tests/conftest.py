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
