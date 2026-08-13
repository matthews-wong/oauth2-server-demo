"""FastAPI application wiring the OAuth2 Authorization Code + PKCE flow.

Routes:
  * ``GET  /authorize``  — demo login/consent screen.
  * ``POST /authorize``  — verify credentials, mint an auth code, redirect back.
  * ``POST /token``      — exchange code (or refresh token) for tokens; PKCE checked.
  * ``GET  /userinfo``   — protected resource, requires a Bearer access token.
  * ``GET  /.well-known/oauth-authorization-server`` — RFC 8414 metadata.

This is an educational demo. See the README security notes: in-memory state,
hard-coded demo secret, plaintext demo passwords — do not deploy as-is.
"""

from __future__ import annotations

import time
from urllib.parse import urlencode

import jwt
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import __version__
from .models import (
    AuthorizationServerMetadata,
    TokenResponse,
    UserInfoResponse,
)
from .pkce import S256, verify_s256
from .store import Store, store
from .tokens import (
    REFRESH_TOKEN_TTL_SECONDS,
    mint_access_token,
    mint_refresh_token,
    verify_access_token,
)

# The issuer identifies this authorization server in token claims and metadata.
# In a real deployment this is the server's public HTTPS base URL.
ISSUER = "http://localhost:8000"

SUPPORTED_RESPONSE_TYPE = "code"
GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_REFRESH_TOKEN = "refresh_token"


def _oauth_error(
    error: str, description: str, status_code: int = 400
) -> JSONResponse:
    """Build an RFC 6749 §5.2 error response."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


def create_app(data_store: Store | None = None) -> FastAPI:
    """Build the FastAPI app.

    Accepts an optional store so tests can inject a fresh, isolated instance.
    """
    app = FastAPI(
        title="oauth2-server-demo",
        version=__version__,
        description="A minimal, educational OAuth2 Authorization Server (demo only).",
    )
    db = data_store or store

    # ------------------------------------------------------------------ #
    # Discovery metadata (RFC 8414)
    # ------------------------------------------------------------------ #

    @app.get("/.well-known/oauth-authorization-server")
    def authorization_server_metadata() -> AuthorizationServerMetadata:
        return AuthorizationServerMetadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            userinfo_endpoint=f"{ISSUER}/userinfo",
        )

    # ------------------------------------------------------------------ #
    # /authorize — login + consent
    # ------------------------------------------------------------------ #

    @app.get("/authorize", response_class=HTMLResponse, response_model=None)
    def authorize_form(
        request: Request,
        response_type: str = "",
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "",
        state: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "",
    ) -> HTMLResponse | JSONResponse:
        error = _validate_authorization_request(
            db,
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        if error is not None:
            return error

        # Render a minimal login + consent form. Real servers would use a
        # session and CSRF protection; this is intentionally bare-bones.
        html = _login_page(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        return HTMLResponse(content=html)

    @app.post("/authorize", response_model=None)
    def authorize_submit(
        response_type: str = Form(""),
        client_id: str = Form(""),
        redirect_uri: str = Form(""),
        scope: str = Form(""),
        state: str = Form(""),
        code_challenge: str = Form(""),
        code_challenge_method: str = Form(""),
        username: str = Form(""),
        password: str = Form(""),
    ) -> RedirectResponse | JSONResponse:
        error = _validate_authorization_request(
            db,
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        if error is not None:
            return error

        user = db.verify_user_credentials(username, password)
        if user is None:
            return _oauth_error(
                "access_denied", "Invalid username or password.", status_code=401
            )

        code = db.create_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            sub=user.sub,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # Redirect back to the client with the code (and state, if supplied).
        params = {"code": code.code}
        if state:
            params["state"] = state
        location = f"{redirect_uri}?{urlencode(params)}"
        # 303 so the browser issues a GET to the callback.
        return RedirectResponse(url=location, status_code=303)

    # ------------------------------------------------------------------ #
    # /token — code -> tokens, or refresh
    # ------------------------------------------------------------------ #

    @app.post("/token")
    def token(
        grant_type: str = Form(""),
        code: str = Form(""),
        redirect_uri: str = Form(""),
        client_id: str = Form(""),
        code_verifier: str = Form(""),
        refresh_token: str = Form(""),
    ) -> JSONResponse:
        if grant_type == GRANT_AUTHORIZATION_CODE:
            return _handle_authorization_code_grant(
                db,
                code=code,
                redirect_uri=redirect_uri,
                client_id=client_id,
                code_verifier=code_verifier,
            )
        if grant_type == GRANT_REFRESH_TOKEN:
            return _handle_refresh_token_grant(
                db, refresh_token=refresh_token, client_id=client_id
            )
        return _oauth_error(
            "unsupported_grant_type", f"Unsupported grant_type: {grant_type!r}."
        )

    # ------------------------------------------------------------------ #
    # /userinfo — protected resource
    # ------------------------------------------------------------------ #

    @app.get("/userinfo")
    def userinfo(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        scheme, _, raw_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw_token:
            return _oauth_error(
                "invalid_request",
                "Missing or malformed Authorization header.",
                status_code=401,
            )

        try:
            claims = verify_access_token(raw_token, issuer=ISSUER)
        except jwt.InvalidTokenError as exc:
            return _oauth_error(
                "invalid_token", f"Access token rejected: {exc}", status_code=401
            )

        user = db.get_user_by_sub(claims["sub"])
        if user is None:
            return _oauth_error(
                "invalid_token", "Subject no longer exists.", status_code=401
            )

        body = UserInfoResponse(
            sub=user.sub,
            name=user.name,
            email=user.email,
            scope=claims.get("scope", ""),
        )
        return JSONResponse(content=body.model_dump())

    return app


# --------------------------------------------------------------------------- #
# Grant handlers
# --------------------------------------------------------------------------- #


def _handle_authorization_code_grant(
    db: Store,
    *,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: str,
) -> JSONResponse:
    """Exchange an authorization code for tokens, validating PKCE (RFC 7636)."""
    client = db.get_client(client_id)
    if client is None:
        return _oauth_error("invalid_client", "Unknown client_id.", status_code=401)

    record = db.get_authorization_code(code)
    if record is None or record.used:
        return _oauth_error("invalid_grant", "Authorization code is invalid.")

    if record.expires_at < time.time():
        return _oauth_error("invalid_grant", "Authorization code has expired.")

    # The code is bound to the client and redirect_uri it was issued for.
    if record.client_id != client_id:
        return _oauth_error(
            "invalid_grant", "Authorization code was issued to another client."
        )
    if record.redirect_uri != redirect_uri:
        return _oauth_error("invalid_grant", "redirect_uri mismatch.")

    # PKCE: recompute the S256 challenge from the verifier and compare.
    if not code_verifier or not verify_s256(code_verifier, record.code_challenge):
        return _oauth_error("invalid_grant", "PKCE verification failed.")

    # Single-use: consume the code before issuing tokens.
    db.consume_authorization_code(code)

    return _issue_tokens(db, client_id=client_id, sub=record.sub, scope=record.scope)


def _handle_refresh_token_grant(
    db: Store, *, refresh_token: str, client_id: str
) -> JSONResponse:
    """Rotate a refresh token and issue a fresh access token."""
    client = db.get_client(client_id)
    if client is None:
        return _oauth_error("invalid_client", "Unknown client_id.", status_code=401)

    record = db.get_refresh_token(refresh_token)
    if record is None or record.revoked:
        return _oauth_error("invalid_grant", "Refresh token is invalid.")
    if record.client_id != client_id:
        return _oauth_error(
            "invalid_grant", "Refresh token was issued to another client."
        )
    if record.expires_at < time.time():
        return _oauth_error("invalid_grant", "Refresh token has expired.")

    # Rotate: revoke the presented token and issue a new pair.
    db.revoke_refresh_token(refresh_token)
    return _issue_tokens(db, client_id=client_id, sub=record.sub, scope=record.scope)


def _issue_tokens(
    db: Store, *, client_id: str, sub: str, scope: str
) -> JSONResponse:
    """Mint an access token + rotating refresh token and build the response."""
    access_token, expires_in = mint_access_token(
        issuer=ISSUER, subject=sub, client_id=client_id, scope=scope
    )
    refresh_value = mint_refresh_token()
    db.create_refresh_token(
        token=refresh_value,
        client_id=client_id,
        sub=sub,
        scope=scope,
        ttl_seconds=REFRESH_TOKEN_TTL_SECONDS,
    )
    body = TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=refresh_value,
        scope=scope,
    )
    return JSONResponse(content=body.model_dump())


# --------------------------------------------------------------------------- #
# Request validation + rendering helpers
# --------------------------------------------------------------------------- #


def _validate_authorization_request(
    db: Store,
    *,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str,
    code_challenge_method: str,
) -> JSONResponse | None:
    """Validate the shared parts of GET/POST ``/authorize``.

    Returns an error response, or ``None`` if the request is valid. Per RFC
    6749 §4.1.2.1, client/redirect_uri errors must NOT redirect back to the
    client (the redirect target cannot be trusted yet), so we return them
    directly.
    """
    client = db.get_client(client_id)
    if client is None:
        return _oauth_error("invalid_client", "Unknown client_id.", status_code=401)

    if redirect_uri not in client.redirect_uris:
        return _oauth_error(
            "invalid_request", "redirect_uri is not registered for this client."
        )

    if response_type != SUPPORTED_RESPONSE_TYPE:
        return _oauth_error(
            "unsupported_response_type",
            f"Only response_type={SUPPORTED_RESPONSE_TYPE!r} is supported.",
        )

    # The requested scope must be a subset of what the client is registered
    # for; otherwise the code (and the access token minted from it) would carry
    # privileges the client was never granted (RFC 6749 §3.3, §4.1.2.1).
    unregistered = [s for s in scope.split() if s not in client.allowed_scopes]
    if unregistered:
        return _oauth_error(
            "invalid_scope",
            f"Scope(s) not allowed for this client: {' '.join(unregistered)}.",
        )

    # PKCE is mandatory in this demo (public clients).
    if not code_challenge:
        return _oauth_error("invalid_request", "code_challenge is required (PKCE).")
    if code_challenge_method != S256:
        return _oauth_error(
            "invalid_request", f"Only code_challenge_method={S256!r} is supported."
        )

    return None


def _login_page(
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
) -> str:
    """Render the demo login/consent form.

    Hidden fields carry the OAuth2 parameters through the POST. Field values
    are drawn from validated request parameters, not free-form user input.
    """
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Demo Sign-in</title></head>
<body>
  <h1>oauth2-server-demo</h1>
  <p><strong>DEMO login</strong> — client <code>{client_id}</code> is requesting
     scope <code>{scope or "(none)"}</code>.</p>
  <p>Use the seeded demo credentials: <code>demo-user</code> / <code>demo-password</code>.</p>
  <form method="post" action="/authorize">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <label>Username <input name="username" autocomplete="username"></label><br>
    <label>Password <input name="password" type="password" autocomplete="current-password"></label><br>
    <button type="submit">Sign in and consent</button>
  </form>
</body>
</html>"""


# Module-level app for ``uvicorn authserver.main:app``.
app = create_app()
