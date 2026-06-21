"""
File-backed JTI/subject blacklist for token revocation.

Revoked JTIs and subject not-before cutoffs are persisted to a JSON file so a
revoked-but-not-yet-expired token cannot be replayed after a gateway restart
(the in-memory-only version forgot every revocation on restart). The file also
lets multiple worker processes share revocation state. Writes degrade
gracefully: if the path is not writable, the blacklist still works in memory.
In production, back this with Redis or a database.

CyBOK alignment: Session Management — ensures revoked tokens
cannot be reused even if they haven't expired yet.
"""

import json
import os
import threading
from datetime import datetime, timezone

BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", "/tmp/ztac_blacklist.json")


class TokenBlacklist:
    """Thread-safe, file-backed token revocation blacklist."""

    def __init__(self, persist_path: str = BLACKLIST_FILE):
        self._revoked: dict[str, float] = {}
        self._subjects: dict[str, int] = {}
        self._lock = threading.Lock()
        self._persist_path = persist_path
        self._load()

    def _load(self) -> None:
        """Load persisted state from disk on startup."""
        if not self._persist_path or not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, "r") as f:
                data = json.load(f)
            self._revoked = data.get("revoked", {})
            self._subjects = data.get("subjects", {})
        except (json.JSONDecodeError, OSError, KeyError, ValueError):
            pass

    def _persist(self) -> None:
        """Write current state to disk. Called under lock; never raises."""
        if not self._persist_path:
            return
        try:
            with open(self._persist_path, "w") as f:
                json.dump({"revoked": self._revoked, "subjects": self._subjects}, f)
        except OSError:
            pass

    def revoke(self, jti: str) -> None:
        """Add a JTI to the blacklist."""
        with self._lock:
            self._revoked[jti] = datetime.now(timezone.utc).timestamp()
            self._persist()

    def is_revoked(self, jti: str) -> bool:
        """Check if a JTI has been revoked."""
        with self._lock:
            return jti in self._revoked

    def revoke_subject(self, sub: str, not_before: int) -> None:
        with self._lock:
            self._subjects[sub] = max(self._subjects.get(sub, 0), int(not_before))
            self._persist()

    def is_subject_revoked(self, sub: str, token_iat: int) -> bool:
        with self._lock:
            cutoff = self._subjects.get(sub)
            return cutoff is not None and int(token_iat) <= cutoff

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
            if expired:
                self._persist()
            return len(expired)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._revoked)


blacklist = TokenBlacklist()
