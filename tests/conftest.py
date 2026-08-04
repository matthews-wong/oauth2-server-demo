"""Shared pytest fixtures.

Each test gets a fresh app backed by an isolated in-memory store, so tests
stay independent and order-free.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest
from fastapi.testclient import TestClient

from authserver.main import create_app
from authserver.store import Store

DEMO_CLIENT_ID = "demo-client"
DEMO_REDIRECT_URI = "http://localhost:8080/callback"
DEMO_USERNAME = "demo-user"
DEMO_PASSWORD = "demo-password"
DEMO_SCOPE = "openid profile email"


@pytest.fixture
def client() -> TestClient:
    """A TestClient over a fresh app; redirects are not auto-followed so we
    can inspect the /authorize -> callback ``Location`` header directly."""
    app = create_app(Store())
    return TestClient(app, follow_redirects=False)


def make_pkce_pair() -> tuple[str, str]:
    """Return a ``(code_verifier, code_challenge)`` S256 pair (RFC 7636)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge
