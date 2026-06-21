"""
Adversarial Scenario 5: Log Tampering Detection

Attack: An attacker with database access (e.g., compromised ES credentials)
inserts a fake log entry to cover their tracks or frame another user.

Expected behaviour: The hash chain verification detects the inserted entry
because it breaks the sequential chain of SHA-256 hashes.

CyBOK AAA alignment: Accountability — Audit Log Integrity, Non-repudiation
"""

import hashlib
import hmac
import json
import os
import time
import httpx
from conftest import ES_URL, ENVOY_URL, get_token

AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY", "ztac-dev-audit-key")


def _chain_hash(previous_hash: str, body: str) -> str:
    return hmac.new(
        AUDIT_HMAC_KEY.encode(), (previous_hash + body).encode(), hashlib.sha256
    ).hexdigest()

class TestLogTampering:

    def _get_logs(self, client: httpx.Client, count: int = 20) -> list[dict]:
        """Fetch recent logs sorted by sequence."""
        resp = client.post(
            f"{ES_URL}/ztac-audit-*/_search",
            json={
                "size": count,
                "sort": [{"log_sequence": "asc"}],
                "_source": [
                    "log_sequence", "log_hash", "previous_hash",
                    "log_body_for_hash"
                ],
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return [hit["_source"] for hit in resp.json()["hits"]["hits"]]

    def _verify_chain(self, logs: list[dict]) -> bool:
        """Verify hash chain integrity. Returns True if intact."""
        for i, log in enumerate(logs):
            prev = log.get("previous_hash", "")
            body = log.get("log_body_for_hash", "")
            stored = log.get("log_hash", "")

            expected = _chain_hash(prev, body)
            if stored != expected:
                return False

            if i > 0:
                if prev != logs[i - 1].get("log_hash", ""):
                    return False

        return True

    def test_chain_intact_before_tampering(self, http_client):
        """Baseline: generate some logs and verify the chain is valid."""
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]

        for _ in range(3):
            http_client.get(
                f"{ENVOY_URL}/api/data/reports",
                headers={"Authorization": f"Bearer {token}"},
            )

        time.sleep(3)

        logs = self._get_logs(http_client)
        if len(logs) < 2:
            import pytest
            pytest.skip("Not enough logs for chain verification")

        assert self._verify_chain(logs), "Hash chain should be intact before tampering"

    def test_tampered_log_breaks_chain(self, http_client):
        """
        Core test: insert a fake log and verify the chain breaks.
        """
        token_resp = get_token("alice", "alice123")
        token = token_resp["access_token"]

        for _ in range(3):
            http_client.get(
                f"{ENVOY_URL}/api/data/public",
                headers={"Authorization": f"Bearer {token}"},
            )

        time.sleep(3)

        logs_before = self._get_logs(http_client)
        assert len(logs_before) >= 2, "Need at least 2 logs"
        assert self._verify_chain(logs_before), "Chain should be intact before tampering"

        fake_log = {
            "timestamp": "2024-06-15T12:00:00.000Z",
            "source_component": "ATTACKER",
            "user": "alice",
            "action": "DELETE",
            "resource": "/api/data/admin",
            "status_code": 200,
            "log_sequence": logs_before[-1]["log_sequence"] + 1,
            "previous_hash": "FAKE_PREVIOUS_HASH",
            "log_hash": "FAKE_HASH_VALUE",
            "log_body_for_hash": '{"fake": true}',
            "message": "Attacker-injected log entry",
        }

        resp = http_client.post(
            f"{ES_URL}/ztac-audit-tampered/_doc",
            json=fake_log,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in (200, 201), "Fake log should be insertable"

        http_client.post(f"{ES_URL}/ztac-audit-tampered/_refresh")

        time.sleep(1)

        resp = http_client.post(
            f"{ES_URL}/ztac-audit-*/_search",
            json={
                "size": 50,
                "sort": [{"log_sequence": "asc"}],
                "_source": [
                    "log_sequence", "log_hash", "previous_hash",
                    "log_body_for_hash", "source_component"
                ],
            },
        )
        all_logs = [hit["_source"] for hit in resp.json()["hits"]["hits"]]

        assert not self._verify_chain(all_logs), (
            "Hash chain should be broken after inserting a fake log entry. "
            "The tampered entry's previous_hash does not match the preceding "
            "log's hash, demonstrating that hash chaining detects insertion attacks."
        )

    def test_cleanup_tampered_index(self, http_client):
        """Clean up the tampered index after testing."""
        http_client.delete(f"{ES_URL}/ztac-audit-tampered")
