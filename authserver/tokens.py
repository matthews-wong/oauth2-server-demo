"""Token minting and verification.

Access tokens are signed JWTs (RFC 7519) using PyJWT. Refresh tokens are
opaque random strings whose state lives server-side in the store (see
``store.py``). Keeping refresh tokens opaque means revocation is a simple
server-side flag rather than something baked into a self-contained token.

The signing key here is a hard-coded demo secret — see the README security
notes. A real deployment would load a secret (or an asymmetric key pair) from
a secret manager and rotate it.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

import jwt

# --------------------------------------------------------------------------- #
# Demo signing configuration — NOT for production use.
# --------------------------------------------------------------------------- #

# HS256 symmetric secret. A real server would use RS256/ES256 with a key from
# a secret manager and publish a JWKS document.
DEMO_JWT_SECRET = "demo-secret-do-not-use-in-production"  # noqa: S105
JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_TTL_SECONDS = 3600  # 1 hour
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 14  # 14 days


def mint_access_token(
    *,
    issuer: str,
    subject: str,
    client_id: str,
    scope: str,
    now: float | None = None,
) -> tuple[str, int]:
    """Mint a signed JWT access token.

    Returns a ``(token, expires_in)`` tuple where ``expires_in`` is the
    lifetime in seconds, matching the ``expires_in`` field of the token
    response (RFC 6749 §5.1).
    """
    issued_at = int(now if now is not None else time.time())
    expires_at = issued_at + ACCESS_TOKEN_TTL_SECONDS
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "client_id": client_id,
        "scope": scope,
        "iat": issued_at,
        "exp": expires_at,
        # A unique token id makes tokens individually identifiable / revocable.
        "jti": secrets.token_urlsafe(16),
        "token_use": "access",
    }
    token = jwt.encode(claims, DEMO_JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, ACCESS_TOKEN_TTL_SECONDS


def verify_access_token(
    token: str, *, issuer: str, client_id: str | None = None
) -> dict[str, Any]:
    """Verify a JWT access token and return its claims.

    Verifies the signature, expiry, and issuer. If ``client_id`` is given the
    audience is checked too; ``/userinfo`` omits it because it does not know
    which client the bearer belongs to until the token is decoded.

    Raises ``jwt.InvalidTokenError`` (or a subclass) on any failure; callers
    translate that into an OAuth2 error response.
    """
    return jwt.decode(
        token,
        DEMO_JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        audience=client_id,
        issuer=issuer,
        options={
            "require": ["exp", "iat", "sub", "iss", "aud"],
            "verify_aud": client_id is not None,
        },
    )


def mint_refresh_token() -> str:
    """Return a fresh opaque refresh token value.

    The value carries no meaning on its own; the server looks it up in the
    store to find the associated client, subject, and scope.
    """
    return secrets.token_urlsafe(32)
