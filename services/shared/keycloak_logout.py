"""
Keycloak backchannel logout handler.
When a user logs out or an admin terminates a session,
Keycloak sends a POST with a logout token containing the session ID.
This handler extracts the session's JTIs and adds them to the blacklist.

Configure in Keycloak: Client → ztac-gateway → Advanced → Backchannel Logout URL:
  http://api-gateway:8001/backchannel-logout
"""

import json
import base64
from .token_blacklist import blacklist

def handle_backchannel_logout(logout_token: str) -> dict:
    """
    Process a Keycloak backchannel logout token.
    Extracts the session ID and revokes associated tokens.
    """
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(
                logout_token.split(".")[1] + "=="
            )
        )

        sid = payload.get("sid", "unknown")
        sub = payload.get("sub", "unknown")
        not_before = int(payload.get("iat", 0))

        blacklist.revoke(f"session:{sid}")
        if sub != "unknown":
            blacklist.revoke_subject(sub, not_before)

        return {
            "status": "ok",
            "revoked_session": sid,
            "user": sub,
            "blacklist_size": blacklist.size,
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}
