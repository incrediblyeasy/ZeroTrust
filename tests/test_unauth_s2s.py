"""
Adversarial Scenario 3: Unauthenticated / Service-to-Service Access.

Attack family: a caller with no (or a bogus) credential tries to reach a
protected resource, or attempts to bypass the Policy Enforcement Point (Envoy)
by talking to the protected service directly.

Expected behaviour:
  * No Authorization header on a protected endpoint  -> 401/403
  * No Authorization header on a PUBLIC endpoint      -> 200 (public is open)
  * Empty / garbage bearer token                      -> 401
  * Direct access to the protected service (bypassing Envoy) is refused: the
    service enforces app-level authentication via the shared gateway-auth
    secret that only the api-gateway injects, so a direct caller is rejected
    (403) or unreachable. In production, mTLS on the service would add a second
    layer, refusing any client without a CA-signed certificate.

CyBOK AAA alignment: Authentication (no anonymous access to protected data),
Authorisation (PEP mediates every request), Enforcement (no network bypass).

NOTE: these tests exercise the running stack. Bring it up first:
  docker compose up -d --build
"""

import os

import httpx

from conftest import ENVOY_URL

PROTECTED_DIRECT_URL = os.getenv("PROTECTED_DIRECT_URL", "http://localhost:8000")

class TestUnauthenticatedServiceToService:

    def test_no_auth_header_returns_error(self, http_client):
        """A protected endpoint with no Authorization header must be refused."""
        resp = http_client.get(f"{ENVOY_URL}/api/data/reports")
        assert resp.status_code in (401, 403), (
            f"Protected endpoint without auth should return 401/403, "
            f"got {resp.status_code}."
        )

    def test_no_auth_header_public_endpoint(self, http_client):
        """A public endpoint must work with no Authorization header."""
        resp = http_client.get(f"{ENVOY_URL}/api/data/public")
        assert resp.status_code == 200, (
            f"Public endpoint should be reachable without auth (200), "
            f"got {resp.status_code}."
        )

    def test_empty_bearer_token(self, http_client):
        """A bearer scheme carrying no token must be rejected.

        Note: the literal value 'Bearer ' (scheme + trailing space, empty
        token) cannot be transmitted — HTTP/1.1 forbids trailing whitespace
        in a header value, so a compliant client (h11) raises before the
        request leaves the process, which itself stops the malformed
        credential from ever reaching a resource. We therefore assert on the
        nearest transmittable equivalent: the bare scheme 'Bearer' with no
        token, which the gateway must reject with 401.
        """
        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": "Bearer"},
        )
        assert resp.status_code == 401, (
            f"Bearer scheme with no token should return 401, got {resp.status_code}."
        )

    def test_garbage_token(self, http_client):
        """A non-JWT bearer value must be rejected."""
        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": "Bearer not-a-real-jwt-token"},
        )
        assert resp.status_code == 401, (
            f"Garbage token should return 401, got {resp.status_code}."
        )

    def test_direct_service_access_bypassing_envoy(self):
        """
        Attempt to reach the protected service directly, bypassing Envoy/OPA.

        The protected service now enforces app-level authentication: it requires
        the shared gateway-auth secret that only the api-gateway injects on
        forwarded requests. A direct call therefore cannot read protected data —
        it must be rejected (403) or be unreachable (port not published / no
        secret reproducible). This closes the network-bypass that was previously
        a documented limitation.
        """
        try:
            resp = httpx.get(f"{PROTECTED_DIRECT_URL}/api/data/admin", timeout=5.0)
        except httpx.HTTPError as exc:
            print(
                f"[direct-access] protected service unreachable directly: {exc!r} "
                f"— bypass is closed."
            )
            return

        assert resp.status_code != 200, (
            "SECURITY REGRESSION: the protected service returned 200 to a direct "
            "call that bypassed Envoy/OPA. The gateway-auth secret check must "
            "reject any request that did not traverse the PEP/PA chain."
        )
        assert resp.status_code in (401, 403, 503), (
            f"Direct access should be denied (403), got {resp.status_code}."
        )

    def test_direct_service_access_with_forged_identity_headers(self):
        """
        A direct caller that spoofs x-auth-* identity headers (claiming admin)
        must still be rejected — identity headers are not a credential; only the
        gateway-injected secret is, and the attacker cannot reproduce it.
        """
        try:
            resp = httpx.get(
                f"{PROTECTED_DIRECT_URL}/api/data/admin",
                headers={
                    "x-auth-user": "alice",
                    "x-auth-roles": '["admin"]',
                    "x-ztac-gateway-auth": "guessed-secret",
                },
                timeout=5.0,
            )
        except httpx.HTTPError as exc:
            print(f"[direct-access] unreachable: {exc!r} — bypass is closed.")
            return

        assert resp.status_code != 200, (
            "SECURITY REGRESSION: forged identity headers granted direct access."
        )
        assert resp.status_code in (401, 403, 503)
