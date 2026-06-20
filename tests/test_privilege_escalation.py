"""
Adversarial Scenario 2: Privilege Escalation via Token Manipulation.

Attack family: an authenticated low-privilege user (charlie, a *viewer*) tries
to reach higher-privilege resources by (a) simply requesting them, or (b)
forging/tampering with the JWT to claim the "admin" role.

Expected behaviour:
  * A genuine viewer token is denied at the admin endpoint            -> 403
  * Any tampering that breaks the RS256 signature is rejected         -> 401
  * The "alg: none" downgrade is rejected                             -> 401
  * A token signed by an attacker-controlled key is rejected          -> 401

These properties are enforced by the api-gateway's JWT validation
(signature verified against Keycloak's JWKS, RS256-only) and by the OPA PDP
(role check). See services/api-gateway/main.py and opa/policies/authz.rego.

CyBOK AAA alignment: Authentication (token integrity), Authorisation (RBAC,
least privilege).

NOTE: these tests exercise the running stack through Envoy (ENVOY_URL). Bring
the stack up first:  docker compose up -d --build
"""

import base64
import json

import httpx
import pytest

from conftest import get_token, decode_jwt_payload, ENVOY_URL

def _b64url(raw: bytes) -> str:
    """Base64url-encode without padding (JWT segment encoding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

class TestPrivilegeEscalation:

    def test_valid_viewer_denied_admin_endpoint(self, http_client):
        """A legitimate viewer token must NOT reach the admin endpoint."""
        token = get_token("charlie", "charlie123")["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, (
            f"Viewer should be denied the admin endpoint with 403, "
            f"got {resp.status_code}."
        )

    def test_tampered_jwt_role_escalation(self, http_client):
        """
        Tamper with the payload (viewer -> admin) but keep the ORIGINAL header
        and signature. The RS256 signature no longer matches the payload, so
        the gateway must reject it.
        """
        token = get_token("charlie", "charlie123")["access_token"]
        header_b64, _payload_b64, signature_b64 = token.split(".")

        payload = decode_jwt_payload(token)
        payload.setdefault("realm_access", {})["roles"] = ["admin"]
        tampered_payload_b64 = _b64url(json.dumps(payload).encode("utf-8"))

        tampered = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {tampered}"},
        )
        assert resp.status_code == 401, (
            f"Tampered payload must fail signature verification (401), "
            f"got {resp.status_code}."
        )

    def test_tampered_jwt_with_none_algorithm(self, http_client):
        """
        Downgrade the header to 'alg: none' and claim admin in the payload,
        with no signature. A correct verifier rejects 'none'.
        """
        token = get_token("charlie", "charlie123")["access_token"]

        header = {"alg": "none", "typ": "JWT"}
        payload = decode_jwt_payload(token)
        payload.setdefault("realm_access", {})["roles"] = ["admin"]

        header_b64 = _b64url(json.dumps(header).encode("utf-8"))
        payload_b64 = _b64url(json.dumps(payload).encode("utf-8"))
        forged = f"{header_b64}.{payload_b64}."

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert resp.status_code == 401, (
            f"'alg: none' token must be rejected (401), got {resp.status_code}."
        )

    def test_forged_jwt_wrong_key(self, http_client):
        """
        Mint a syntactically valid, admin-claiming JWT signed with an
        attacker-generated RSA key. The signature cannot be verified against
        Keycloak's JWKS, so the gateway rejects it.
        """
        jwt = pytest.importorskip("jwt", reason="PyJWT needed to forge a token")
        pytest.importorskip("cryptography", reason="cryptography needed for RSA keygen")
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        claims = {
            "preferred_username": "charlie",
            "realm_access": {"roles": ["admin"]},
            "iss": "http://keycloak:8080/realms/ztac",
            "exp": 9999999999,
            "jti": "forged-jti-0001",
        }
        forged = jwt.encode(
            claims, priv_pem, algorithm="RS256", headers={"kid": "attacker-key"}
        )

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert resp.status_code == 401, (
            f"Token signed with an untrusted key must be rejected (401), "
            f"got {resp.status_code}."
        )
