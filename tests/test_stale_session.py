"""
Adversarial Scenario 4: Stale Session Exploitation

Attack: An attacker uses a token that has expired, hoping the framework
doesn't enforce token lifetimes on every request.

Expected behaviour: The framework rejects expired tokens with 401.

CyBOK AAA alignment: Session Management, Continuous Verification
"""

import time
from conftest import get_token, decode_jwt_payload, ENVOY_URL
import httpx

class TestStaleSession:

    def test_fresh_token_is_accepted(self, http_client):
        """Baseline: a fresh token within its lifespan works."""
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]
        claims = decode_jwt_payload(token)

        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        remaining = claims["exp"] - now
        assert remaining > 0, "Freshly issued token should not be expired"

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_expired_token_is_rejected(self, http_client):
        """
        Core test: wait for a token to expire, then attempt access.
        This requires Keycloak's access token lifespan to be set to a
        short duration (5 minutes in our config). For faster testing,
        temporarily set it to 60 seconds.

        Alternative: use the OPA expiry check, which validates the
        'exp' claim on every request.
        """
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]
        claims = decode_jwt_payload(token)

        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        wait_time = claims["exp"] - now + 2

        if wait_time > 120:
            import pytest
            pytest.skip(
                f"Token lifespan too long ({wait_time:.0f}s) for real-time test. "
                "Set Keycloak access token lifespan to 60s for this test."
            )

        print(f"Waiting {wait_time:.0f}s for token to expire...")
        time.sleep(wait_time)

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code in (401, 403), (
            f"Expired token should be rejected. Got {resp.status_code}."
        )

    def test_refresh_restores_access(self, http_client):
        """After expiry, using a refresh token to get a new access token works."""
        token_resp = get_token("alice", "alice123")
        refresh_token = token_resp.get("refresh_token")

        if not refresh_token:
            import pytest
            pytest.skip("No refresh token issued")

        from conftest import TOKEN_URL, CLIENT_ID
        resp = http_client.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
            },
        )
        assert resp.status_code == 200
        new_token = resp.json()["access_token"]

        resp = http_client.get(
            f"{ENVOY_URL}/api/data/admin",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200
