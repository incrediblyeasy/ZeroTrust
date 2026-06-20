"""
Adversarial Scenario 1: Stolen Token Replay

Attack: An attacker obtains a valid JWT (e.g., via network sniffing or
phishing) and attempts to reuse it after the user's session has been
revoked by an administrator.

Expected behaviour: The framework detects the revoked session and returns
401 Unauthorized, even though the JWT signature is still valid and the
token has not expired.

CyBOK AAA alignment: Session Management, Non-repudiation
"""

import time
from conftest import (
    get_token,
    get_user_id,
    revoke_user_sessions,
    decode_jwt_payload,
    ENVOY_URL,
)
import httpx

class TestTokenReplay:

    def test_valid_token_works_before_revocation(self, http_client):
        """Baseline: a fresh token should grant access."""
        token_resp = get_token("bob", "bob123")
        token = token_resp["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    def test_replayed_token_rejected_after_revocation(self, http_client):
        """
        Core test: obtain a token, revoke the session, then replay.
        The stolen token should be rejected.
        """
        token_resp = get_token("bob", "bob123")
        stolen_token = token_resp["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {stolen_token}"},
        )
        assert resp.status_code == 200

        user_id = get_user_id("bob")
        revoke_user_sessions(user_id)

        deadline = time.time() + 15
        status = None
        while time.time() < deadline:
            status = http_client.get(
                f"{ENVOY_URL}/api/data/reports",
                headers={"Authorization": f"Bearer {stolen_token}"},
            ).status_code
            if status in (401, 403):
                break
            time.sleep(0.5)

        assert status in (401, 403), (
            f"Replayed token should be rejected after session revocation. "
            f"Got {status} after polling for 15s. Keycloak backchannel logout "
            f"is asynchronous; this exceeds any reasonable propagation delay."
        )

    def test_new_token_works_after_revocation(self, http_client):
        """After revocation, a fresh login should still work."""
        user_id = get_user_id("bob")
        revoke_user_sessions(user_id)
        time.sleep(1)

        token_resp = get_token("bob", "bob123")
        new_token = token_resp["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/reports",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200, "Fresh token after revocation should work"
