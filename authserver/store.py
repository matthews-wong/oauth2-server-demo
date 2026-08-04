"""In-memory data store for the demo authorization server.

Everything here lives in process memory and is reset on restart. That is
deliberate: this is an educational demo, not a real identity provider. A
production server would back these with a database, hashed passwords, and a
proper client registry.

The store owns:
  * a fixed set of demo clients and users (clearly labelled DEMO),
  * short-lived authorization codes (single-use, PKCE-bound),
  * opaque refresh tokens (revocable).
"""

from __future__ import annotations

import secrets
import time

from .models import AuthorizationCode, Client, RefreshToken, User

# Authorization codes are intentionally short-lived (RFC 6749 §4.1.2 advises
# a maximum of ~10 minutes; we use 60s to keep the demo tight).
AUTH_CODE_TTL_SECONDS = 60


class Store:
    """A tiny in-memory store. One instance is shared by the app."""

    def __init__(self) -> None:
        self._clients: dict[str, Client] = {}
        self._users_by_name: dict[str, User] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._seed_demo_data()

    # ------------------------------------------------------------------ #
    # Seed data — DEMO ONLY.
    # ------------------------------------------------------------------ #

    def _seed_demo_data(self) -> None:
        """Populate the store with obviously-fake demo clients and users."""
        demo_client = Client(
            client_id="demo-client",
            redirect_uris=["http://localhost:8080/callback"],
            allowed_scopes=["openid", "profile", "email"],
        )
        self._clients[demo_client.client_id] = demo_client

        demo_user = User(
            sub="user-001",
            username="demo-user",
            password="demo-password",  # plaintext: in-memory demo only
            name="Demo User",
            email="demo-user@example.com",
        )
        self._users_by_name[demo_user.username] = demo_user

    # ------------------------------------------------------------------ #
    # Clients
    # ------------------------------------------------------------------ #

    def get_client(self, client_id: str) -> Client | None:
        return self._clients.get(client_id)

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #

    def get_user_by_username(self, username: str) -> User | None:
        return self._users_by_name.get(username)

    def get_user_by_sub(self, sub: str) -> User | None:
        for user in self._users_by_name.values():
            if user.sub == sub:
                return user
        return None

    def verify_user_credentials(self, username: str, password: str) -> User | None:
        """Return the user if credentials match, else ``None``.

        Plaintext comparison — acceptable only because this is a demo.
        """
        user = self._users_by_name.get(username)
        if user is None or user.password != password:
            return None
        return user

    # ------------------------------------------------------------------ #
    # Authorization codes
    # ------------------------------------------------------------------ #

    def create_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        sub: str,
        code_challenge: str,
        code_challenge_method: str,
        now: float | None = None,
    ) -> AuthorizationCode:
        """Mint and persist a single-use, PKCE-bound authorization code."""
        issued = now if now is not None else time.time()
        record = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            sub=sub,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=issued + AUTH_CODE_TTL_SECONDS,
        )
        self._codes[record.code] = record
        return record

    def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        return self._codes.get(code)

    def consume_authorization_code(self, code: str) -> None:
        """Mark a code as used so it cannot be redeemed twice (RFC 6749 §4.1.2)."""
        record = self._codes.get(code)
        if record is not None:
            record.used = True

    # ------------------------------------------------------------------ #
    # Refresh tokens
    # ------------------------------------------------------------------ #

    def create_refresh_token(
        self,
        *,
        token: str,
        client_id: str,
        sub: str,
        scope: str,
        ttl_seconds: int,
        now: float | None = None,
    ) -> RefreshToken:
        issued = now if now is not None else time.time()
        record = RefreshToken(
            token=token,
            client_id=client_id,
            sub=sub,
            scope=scope,
            expires_at=issued + ttl_seconds,
        )
        self._refresh_tokens[token] = record
        return record

    def get_refresh_token(self, token: str) -> RefreshToken | None:
        return self._refresh_tokens.get(token)

    def revoke_refresh_token(self, token: str) -> None:
        record = self._refresh_tokens.get(token)
        if record is not None:
            record.revoked = True


# A single shared store instance for the running app.
store = Store()
