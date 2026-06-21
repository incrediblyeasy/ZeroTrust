"""
Keycloak backchannel logout handler.

When a user logs out or an admin terminates a session, Keycloak sends a POST
with a *signed* OIDC Back-Channel Logout Token (a JWT) to the client's
backchannel logout URL. This module applies a logout token to the shared
revocation blacklist — but ONLY after the caller has cryptographically
verified the token's signature and issuer against Keycloak's JWKS.

SECURITY: the logout token MUST be verified before it reaches
`apply_backchannel_logout`. An unverified logout token is attacker-forgeable,
which would allow anyone who can reach the backchannel endpoint to revoke any
(or every) user's session — a denial-of-service / forced-logout attack. The
verification is performed by the gateway (which owns the JWKS cache); this
module never trusts an unverified token.

Spec: https://openid.net/specs/openid-connect-backchannel-1_0.html

Configure in Keycloak: Client → ztac-gateway → Advanced → Backchannel Logout URL:
  http://api-gateway:8001/backchannel-logout
"""

from .token_blacklist import blacklist

# OIDC back-channel logout event identifier that MUST be present in the
# token's "events" claim (§2.4). Its presence distinguishes a logout token
# from an ordinary ID/access token and prevents token-substitution abuse.
LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def apply_backchannel_logout(claims: dict) -> dict:
    """
    Apply a *verified* Keycloak logout token's claims to the blacklist.

    The caller is responsible for having already verified the JWT signature,
    algorithm and issuer (see the gateway's ``validate_logout_token``). This
    function performs the remaining OIDC back-channel logout claim checks and,
    if they pass, revokes the session.

    Returns a status dict; status == "ok" only when a session was revoked.
    """
    if not isinstance(claims, dict):
        return {"status": "error", "detail": "invalid_claims"}

    # §2.6: the token must carry the backchannel-logout event marker.
    events = claims.get("events") or {}
    if not isinstance(events, dict) or LOGOUT_EVENT not in events:
        return {"status": "error", "detail": "not_a_logout_token"}

    # §2.6: a logout token MUST NOT contain a nonce.
    if claims.get("nonce") is not None:
        return {"status": "error", "detail": "nonce_not_allowed"}

    sid = claims.get("sid") or ""
    sub = claims.get("sub") or ""

    # §2.4: a logout token MUST contain a sub, an sid, or both.
    if not sid and not sub:
        return {"status": "error", "detail": "missing_sid_and_sub"}

    not_before = int(claims.get("iat", 0) or 0)

    if sid:
        blacklist.revoke(f"session:{sid}")
    if sub:
        # Revoke every access token for this subject issued at/before the
        # logout instant, covering tokens that omit sid.
        blacklist.revoke_subject(sub, not_before)

    return {
        "status": "ok",
        "revoked_session": sid,
        "user": sub,
        "blacklist_size": blacklist.size,
    }
