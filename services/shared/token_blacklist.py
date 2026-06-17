"""
In-memory JTI blacklist for token revocation.
In production, this would be backed by Redis or a database.
For the ZTAC lab, an in-memory set is sufficient.

CyBOK alignment: Session Management — ensures revoked tokens
cannot be reused even if they haven't expired yet.
"""

import threading
from datetime import datetime, timezone
from typing import Optional


class TokenBlacklist:
    """Thread-safe token revocation blacklist."""

    def __init__(self):
        self._revoked: dict[str, float] = {}  # jti -> revocation timestamp
        self._lock = threading.Lock()

    def revoke(self, jti: str) -> None:
        """Add a JTI to the blacklist."""
        with self._lock:
            self._revoked[jti] = datetime.now(timezone.utc).timestamp()

    def is_revoked(self, jti: str) -> bool:
        """Check if a JTI has been revoked."""
        with self._lock:
            return jti in self._revoked

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove entries older than max_age_seconds. Returns count removed."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            expired = [
                jti for jti, ts in self._revoked.items()
                if (now - ts) > max_age_seconds
            ]
            for jti in expired:
                del self._revoked[jti]
            return len(expired)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._revoked)


# Singleton instance — imported by the gateway
blacklist = TokenBlacklist()
