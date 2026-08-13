"""End-to-end tests for the Authorization Code + PKCE flow."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.conftest import (
    DEMO_CLIENT_ID,
    DEMO_PASSWORD,
    DEMO_REDIRECT_URI,
    DEMO_SCOPE,
    DEMO_USERNAME,
    make_pkce_pair,
)


def _authorize(client: TestClient, code_challenge: str) -> str:
    """Drive login/consent and return the issued authorization code."""
    resp = client.post(
        "/authorize",
        data={
            "response_type": "code",
            "client_id": DEMO_CLIENT_ID,
            "redirect_uri": DEMO_REDIRECT_URI,
            "scope": DEMO_SCOPE,
            "state": "xyz-123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "username": DEMO_USERNAME,
            "password": DEMO_PASSWORD,
        },
    )
    assert resp.status_code == 303, resp.text
    location = resp.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert query["state"] == ["xyz-123"]
    return query["code"][0]


def test_full_authorization_code_pkce_happy_path(client: TestClient) -> None:
    """auth code + PKCE -> tokens -> /userinfo returns the demo user."""
    verifier, challenge = make_pkce_pair()

    # The login form renders and mentions the demo credentials.
    form = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": DEMO_CLIENT_ID,
            "redirect_uri": DEMO_REDIRECT_URI,
            "scope": DEMO_SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert form.status_code == 200
    assert "demo-user" in form.text

    code = _authorize(client, challenge)

    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DEMO_REDIRECT_URI,
            "client_id": DEMO_CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    assert body["scope"] == DEMO_SCOPE
    access_token = body["access_token"]
    refresh_token = body["refresh_token"]

    info = client.get(
        "/userinfo", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert info.status_code == 200, info.text
    assert info.json() == {
        "sub": "user-001",
        "name": "Demo User",
        "email": "demo-user@example.com",
        "scope": DEMO_SCOPE,
    }

    # Refresh token grant rotates and yields a working access token.
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": DEMO_CLIENT_ID,
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["access_token"]


def test_pkce_mismatch_is_rejected(client: TestClient) -> None:
    """A wrong code_verifier must fail PKCE validation at /token."""
    _verifier, challenge = make_pkce_pair()
    wrong_verifier, _ = make_pkce_pair()

    code = _authorize(client, challenge)

    resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DEMO_REDIRECT_URI,
            "client_id": DEMO_CLIENT_ID,
            "code_verifier": wrong_verifier,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_unknown_client_is_rejected_at_authorize(client: TestClient) -> None:
    """An unregistered client_id must be rejected before any code is issued."""
    _verifier, challenge = make_pkce_pair()
    resp = client.post(
        "/authorize",
        data={
            "response_type": "code",
            "client_id": "not-a-real-client",
            "redirect_uri": DEMO_REDIRECT_URI,
            "scope": DEMO_SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": DEMO_USERNAME,
            "password": DEMO_PASSWORD,
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_bad_client_at_token_is_rejected(client: TestClient) -> None:
    """A valid code redeemed with an unknown client_id must be rejected."""
    verifier, challenge = make_pkce_pair()
    code = _authorize(client, challenge)

    resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DEMO_REDIRECT_URI,
            "client_id": "not-a-real-client",
            "code_verifier": verifier,
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_authorization_code_is_single_use(client: TestClient) -> None:
    """Redeeming the same code twice must fail the second time."""
    verifier, challenge = make_pkce_pair()
    code = _authorize(client, challenge)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DEMO_REDIRECT_URI,
        "client_id": DEMO_CLIENT_ID,
        "code_verifier": verifier,
    }
    first = client.post("/token", data=data)
    assert first.status_code == 200
    second = client.post("/token", data=data)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_scope_outside_client_registration_is_rejected(client: TestClient) -> None:
    """A scope the client is not registered for must yield invalid_scope and
    issue no authorization code (RFC 6749 §3.3 / §4.1.2.1)."""
    _verifier, challenge = make_pkce_pair()
    resp = client.post(
        "/authorize",
        data={
            "response_type": "code",
            "client_id": DEMO_CLIENT_ID,
            "redirect_uri": DEMO_REDIRECT_URI,
            # "admin" is not among the client's allowed scopes.
            "scope": "openid admin",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": DEMO_USERNAME,
            "password": DEMO_PASSWORD,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_registered_subset_scope_is_accepted(client: TestClient) -> None:
    """A scope that is a subset of the client's registration is honoured and
    reflected verbatim in the issued token."""
    verifier, challenge = make_pkce_pair()
    subset_scope = "openid email"
    auth = client.post(
        "/authorize",
        data={
            "response_type": "code",
            "client_id": DEMO_CLIENT_ID,
            "redirect_uri": DEMO_REDIRECT_URI,
            "scope": subset_scope,
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": DEMO_USERNAME,
            "password": DEMO_PASSWORD,
        },
    )
    assert auth.status_code == 303, auth.text
    code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]

    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DEMO_REDIRECT_URI,
            "client_id": DEMO_CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    assert token_resp.json()["scope"] == subset_scope


def test_userinfo_requires_bearer_token(client: TestClient) -> None:
    """/userinfo must reject a missing/garbage Authorization header."""
    assert client.get("/userinfo").status_code == 401
    bad = client.get("/userinfo", headers={"Authorization": "Bearer not-a-jwt"})
    assert bad.status_code == 401
    assert bad.json()["error"] == "invalid_token"


def test_wrong_password_is_denied(client: TestClient) -> None:
    """Bad credentials at /authorize yield access_denied, no code."""
    _verifier, challenge = make_pkce_pair()
    resp = client.post(
        "/authorize",
        data={
            "response_type": "code",
            "client_id": DEMO_CLIENT_ID,
            "redirect_uri": DEMO_REDIRECT_URI,
            "scope": DEMO_SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": DEMO_USERNAME,
            "password": "wrong-password",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "access_denied"


def test_metadata_endpoint(client: TestClient) -> None:
    """RFC 8414 discovery document advertises the expected capabilities."""
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["token_endpoint"].endswith("/token")
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert "authorization_code" in doc["grant_types_supported"]
