"""
Offline unit tests for the security-critical gateway / service logic.

Unlike the adversarial integration tests, these run WITHOUT the Docker stack:
they import the gateway and protected-service apps directly, inject a synthetic
JWKS, and assert the hardened behaviour:

  * JWT signature / algorithm / issuer / azp enforcement
  * OIDC back-channel logout tokens are verified before any session is revoked
  * the protected service rejects requests lacking the gateway-auth secret
  * the gateway enforces a request body-size cap

Run:  pytest tests/test_offline_security.py -v
"""

import base64
import importlib.util
import json
import os
import sys
import time

import pytest

# Real dependencies (skip cleanly if a bare environment lacks them).
pytest.importorskip("jose")
pytest.importorskip("fastapi")
jwt = pytest.importorskip("jwt")  # PyJWT, used to mint test tokens
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://issuer.test/realms/ztac"
GATEWAY_CLIENT = "ztac-gateway"
GATEWAY_SECRET = "test-internal-secret"
KID = "test-kid-1"

# Configure the modules' environment BEFORE importing them.
os.environ["KEYCLOAK_ISSUER"] = ISSUER
os.environ["KEYCLOAK_GATEWAY_CLIENT_ID"] = GATEWAY_CLIENT
os.environ["INTERNAL_GATEWAY_SECRET"] = GATEWAY_SECRET
os.environ["JWT_ALLOWED_AZP"] = "ztac-cli,ztac-gateway"
os.environ["MAX_BODY_BYTES"] = "16"

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "services"))  # makes `shared` importable


def _load(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


gw = _load(os.path.join(ROOT, "services", "api-gateway", "main.py"), "gw_main")
pm = _load(os.path.join(ROOT, "services", "protected-service", "main.py"), "protected_main")
from shared.keycloak_logout import LOGOUT_EVENT  # noqa: E402


# --- test signing material -------------------------------------------------

_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIV_PEM = _PRIV.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
_ATTACKER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ATTACKER_PEM = _ATTACKER.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _install_jwks():
    pub = json.loads(RSAAlgorithm.to_jwk(_PRIV.public_key()))
    pub.update({"kid": KID, "alg": "RS256", "use": "sig"})
    gw._jwks = {"keys": [pub]}


_install_jwks()


def _sign(claims: dict, key_pem=_PRIV_PEM, kid=KID, alg="RS256") -> str:
    return jwt.encode(claims, key_pem, algorithm=alg, headers={"kid": kid})


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _access_claims(**over):
    now = int(time.time())
    base = {
        "iss": ISSUER, "sub": "user-1", "preferred_username": "bob",
        "azp": "ztac-cli", "realm_access": {"roles": ["analyst"]},
        "iat": now, "exp": now + 300, "jti": "jti-1",
    }
    base.update(over)
    return base


def _logout_claims(**over):
    now = int(time.time())
    base = {
        "iss": ISSUER, "aud": GATEWAY_CLIENT, "sub": "user-1", "sid": "sess-1",
        "iat": now, "events": {LOGOUT_EVENT: {}},
    }
    base.update(over)
    return base


# --- access-token validation ----------------------------------------------

class TestAccessTokenValidation:
    def test_valid_token_accepted(self):
        claims = gw.validate_token(_sign(_access_claims()))
        assert claims["preferred_username"] == "bob"

    def test_token_from_untrusted_client_rejected(self):
        with pytest.raises(gw.TokenError) as e:
            gw.validate_token(_sign(_access_claims(azp="evil-client")))
        assert "untrusted_client" in str(e.value)

    def test_alg_none_rejected(self):
        forged = _b64({"alg": "none", "typ": "JWT", "kid": KID}) + "." + \
            _b64(_access_claims()) + "."
        with pytest.raises(gw.TokenError) as e:
            gw.validate_token(forged)
        assert "unsupported_algorithm" in str(e.value)

    def test_wrong_issuer_rejected(self):
        with pytest.raises(gw.TokenError):
            gw.validate_token(_sign(_access_claims(iss="https://evil/realms/x")))

    def test_attacker_signed_token_rejected(self):
        with pytest.raises(gw.TokenError) as e:
            gw.validate_token(_sign(_access_claims(), key_pem=_ATTACKER_PEM))
        assert "signature_verification_failed" in str(e.value)

    def test_expired_token_rejected(self):
        old = int(time.time()) - 10
        with pytest.raises(gw.TokenError) as e:
            gw.validate_token(_sign(_access_claims(iat=old - 300, exp=old)))
        assert "expired" in str(e.value)


# --- back-channel logout: the critical fix --------------------------------

class TestBackchannelLogout:
    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_unsigned_logout_token_rejected(self):
        """An attacker-forged (unsigned) logout token must not verify."""
        forged = _b64({"alg": "none", "typ": "JWT", "kid": KID}) + "." + \
            _b64(_logout_claims(sid="victim")) + "."
        with pytest.raises(gw.TokenError):
            self._run(gw.validate_logout_token(forged))

    def test_attacker_signed_logout_token_rejected(self):
        token = _sign(_logout_claims(sid="victim"), key_pem=_ATTACKER_PEM)
        with pytest.raises(gw.TokenError):
            self._run(gw.validate_logout_token(token))

    def test_wrong_audience_logout_token_rejected(self):
        token = _sign(_logout_claims(aud="some-other-client"))
        with pytest.raises(gw.TokenError):
            self._run(gw.validate_logout_token(token))

    def test_valid_logout_revokes_session(self):
        from shared.token_blacklist import blacklist
        from shared.keycloak_logout import apply_backchannel_logout
        token = _sign(_logout_claims(sid="sess-xyz", sub="user-xyz"))
        claims = self._run(gw.validate_logout_token(token))
        result = apply_backchannel_logout(claims)
        assert result["status"] == "ok"
        assert blacklist.is_revoked("session:sess-xyz")

    def test_logout_without_event_marker_rejected(self):
        from shared.keycloak_logout import apply_backchannel_logout
        # Signature is fine, but it is not a logout token (no events claim).
        claims = self._run(gw.validate_logout_token(_sign(_logout_claims(events={}))))
        assert apply_backchannel_logout(claims)["status"] == "error"

    def test_logout_with_nonce_rejected(self):
        from shared.keycloak_logout import apply_backchannel_logout
        claims = self._run(gw.validate_logout_token(_sign(_logout_claims(nonce="x"))))
        assert apply_backchannel_logout(claims)["status"] == "error"


# --- protected service: direct-access bypass is closed ---------------------

class TestProtectedServiceGatewayAuth:
    def test_health_open(self):
        with TestClient(pm.app) as c:
            assert c.get("/health").status_code == 200

    def test_no_secret_denied(self):
        with TestClient(pm.app) as c:
            assert c.get("/api/data/public").status_code == 403

    def test_wrong_secret_denied(self):
        with TestClient(pm.app) as c:
            r = c.get("/api/data/admin", headers={"x-ztac-gateway-auth": "nope"})
            assert r.status_code == 403

    def test_forged_identity_headers_denied(self):
        with TestClient(pm.app) as c:
            r = c.get("/api/data/admin", headers={
                "x-auth-user": "alice", "x-auth-roles": '["admin"]',
            })
            assert r.status_code == 403

    def test_correct_secret_allowed(self):
        with TestClient(pm.app) as c:
            r = c.get("/api/data/public",
                      headers={"x-ztac-gateway-auth": GATEWAY_SECRET})
            assert r.status_code == 200


# --- gateway request body-size cap ----------------------------------------

class TestBodySizeLimit:
    def test_oversized_body_rejected_before_auth(self):
        # MAX_BODY_BYTES=16; a larger body must 413 before any token/OPA work.
        with TestClient(gw.app) as c:
            r = c.post("/api/data/reports", content=b"x" * 64)
            assert r.status_code == 413


# --- gateway security response headers -------------------------------------

class TestSecurityHeaders:
    def test_headers_on_health(self):
        with TestClient(gw.app) as c:
            r = c.get("/health")
            assert r.headers["x-content-type-options"] == "nosniff"
            assert r.headers["x-frame-options"] == "DENY"
            assert "default-src 'none'" in r.headers["content-security-policy"]

    def test_headers_on_deny_response(self):
        # Security headers must also be stamped on the gateway's own deny
        # responses, which short-circuit before call_next.
        with TestClient(gw.app) as c:
            r = c.post("/api/data/reports", content=b"x" * 64)
            assert r.status_code == 413
            assert r.headers["x-content-type-options"] == "nosniff"
