"""Pydantic models and lightweight dataclasses used across the demo server.

These describe the shapes we exchange over the wire (token responses,
userinfo) and the internal records held by the in-memory store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from pydantic import BaseModel


# --------------------------------------------------------------------------- #
# Internal store records (not serialised to clients directly)
# --------------------------------------------------------------------------- #


@dataclass
class Client:
    """A registered OAuth2 client application.

    In this demo clients are public (no secret) and PKCE is mandatory,
    which mirrors the recommended pattern for SPAs / native apps.
    """

    client_id: str
    redirect_uris: list[str]
    allowed_scopes: list[str]


@dataclass
class User:
    """A demo end-user (resource owner)."""

    sub: str
    username: str
    password: str  # plaintext ONLY because this is an in-memory demo
    name: str
    email: str


@dataclass
class AuthorizationCode:
    """A short-lived authorization code plus the PKCE challenge bound to it.

    Per RFC 7636 the code is tied to the ``code_challenge`` presented at
    ``/authorize``; the matching ``code_verifier`` must be supplied at
    ``/token``.
    """

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    sub: str
    code_challenge: str
    code_challenge_method: str
    expires_at: float
    used: bool = False


@dataclass
class RefreshToken:
    """An opaque refresh token record kept server-side."""

    token: str
    client_id: str
    sub: str
    scope: str
    expires_at: float
    revoked: bool = False


# --------------------------------------------------------------------------- #
# Wire models (JSON responses)
# --------------------------------------------------------------------------- #


class TokenResponse(BaseModel):
    """Successful response body from the ``/token`` endpoint (RFC 6749 §5.1)."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: str


class UserInfoResponse(BaseModel):
    """Response body from the protected ``/userinfo`` endpoint."""

    sub: str
    name: str
    email: str
    scope: str


class ErrorResponse(BaseModel):
    """OAuth2 error response body (RFC 6749 §5.2)."""

    error: str
    error_description: Optional[str] = None


class AuthorizationServerMetadata(BaseModel):
    """Subset of RFC 8414 authorization server metadata."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    response_types_supported: list[str] = field(default_factory=lambda: ["code"])  # type: ignore[assignment]
    grant_types_supported: list[str] = field(  # type: ignore[assignment]
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    code_challenge_methods_supported: list[str] = field(default_factory=lambda: ["S256"])  # type: ignore[assignment]
    scopes_supported: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])  # type: ignore[assignment]
    token_endpoint_auth_methods_supported: list[str] = field(  # type: ignore[assignment]
        default_factory=lambda: ["none"]
    )
