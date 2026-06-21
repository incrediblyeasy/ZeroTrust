#!/usr/bin/env python3
"""
verify_log_chain.py — Verify the integrity of the ZTAC audit log hash chain.

Queries Elasticsearch for all audit logs in sequence order and verifies
that each log's hash is HMAC-SHA256(AUDIT_HMAC_KEY, previous_hash + log_body).
The key is a shared secret, so tampering cannot be masked by recomputing the
chain without it. Set AUDIT_HMAC_KEY to match the Logstash pipeline.

Usage:
    python scripts/verify_log_chain.py [--es-url http://localhost:9200] [--index ztac-audit-*]

CyBOK AAA alignment: Accountability — Non-repudiation, Audit Log Integrity
"""

import argparse
import hmac
import hashlib
import json
import os
import sys
import httpx

# Must match the key configured for Logstash (docker-compose AUDIT_HMAC_KEY).
# Fail closed: verifying against a guessed default key would give a false
# negative (or false PASS) rather than a real integrity check.
AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY", "")
if not AUDIT_HMAC_KEY:
    print("ERROR: AUDIT_HMAC_KEY is not set. Export the same value Logstash uses "
          "(see .env) before verifying the audit chain.")
    sys.exit(1)


def _chain_hash(previous_hash: str, body: str) -> str:
    """HMAC-SHA256(key, previous_hash + body) — the keyed audit-chain digest."""
    return hmac.new(
        AUDIT_HMAC_KEY.encode(),
        (previous_hash + body).encode(),
        hashlib.sha256,
    ).hexdigest()

def fetch_all_logs(es_url: str, index: str) -> list[dict]:
    """Fetch all audit logs from ES, sorted by log_sequence ascending."""
    logs = []
    search_after = None

    while True:
        body = {
            "size": 500,
            "sort": [{"log_sequence": "asc"}],
            "_source": [
                "log_sequence", "log_hash", "previous_hash", "log_body_for_hash"
            ],
        }
        if search_after is not None:
            body["search_after"] = [search_after]

        resp = httpx.post(
            f"{es_url}/{index}/_search",
            json=body,
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data["hits"]["hits"]

        if not hits:
            break

        for hit in hits:
            logs.append(hit["_source"])
            search_after = hit["sort"][0]

    return logs

def verify_chain(logs: list[dict]) -> tuple[bool, list[str]]:
    """
    Verify the hash chain integrity.
    Returns (is_valid, list_of_errors).
    """
    errors = []

    if not logs:
        return True, ["No logs found to verify."]

    for i, log in enumerate(logs):
        seq = log.get("log_sequence", i)
        stored_hash = log.get("log_hash", "")
        previous_hash = log.get("previous_hash", "")
        body = log.get("log_body_for_hash", "")

        if i == 0:
            if previous_hash != "GENESIS":
                errors.append(
                    f"Log #{seq}: first log should have previous_hash='GENESIS', "
                    f"got '{previous_hash}'"
                )
        else:
            expected_previous = logs[i - 1].get("log_hash", "")
            if previous_hash != expected_previous:
                errors.append(
                    f"Log #{seq}: previous_hash mismatch. "
                    f"Expected '{expected_previous[:16]}...', "
                    f"got '{previous_hash[:16]}...'"
                )

        expected_hash = _chain_hash(previous_hash, body)

        if stored_hash != expected_hash:
            errors.append(
                f"Log #{seq}: hash mismatch. "
                f"Stored '{stored_hash[:16]}...', "
                f"computed '{expected_hash[:16]}...'"
            )

    return len(errors) == 0, errors

def main():
    parser = argparse.ArgumentParser(
        description="Verify ZTAC audit log hash chain integrity"
    )
    parser.add_argument(
        "--es-url", default="http://localhost:9200",
        help="Elasticsearch URL"
    )
    parser.add_argument(
        "--index", default="ztac-audit-*",
        help="Elasticsearch index pattern"
    )
    args = parser.parse_args()

    print(f"Fetching logs from {args.es_url}/{args.index}...")
    logs = fetch_all_logs(args.es_url, args.index)
    print(f"Found {len(logs)} log entries.")

    if not logs:
        print("No logs to verify.")
        sys.exit(0)

    print("Verifying hash chain...")
    is_valid, errors = verify_chain(logs)

    if is_valid:
        print(f"PASS: All {len(logs)} log entries have valid hash chain integrity.")
        sys.exit(0)
    else:
        print(f"FAIL: {len(errors)} integrity error(s) detected:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()
