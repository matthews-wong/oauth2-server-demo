"""PKCE (Proof Key for Code Exchange, RFC 7636) helpers.

We support only the recommended ``S256`` method. The client sends a
``code_challenge`` at ``/authorize`` and proves possession of the matching
``code_verifier`` at ``/token``; the server recomputes the challenge and
compares in constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

S256 = "S256"


def _b64url_no_pad(raw: bytes) -> str:
    """Base64url-encode without padding, as required by RFC 7636 §A."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compute_s256_challenge(code_verifier: str) -> str:
    """Return the S256 code challenge for a given verifier.

    challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return _b64url_no_pad(digest)


def verify_s256(code_verifier: str, code_challenge: str) -> bool:
    """Verify that ``code_verifier`` matches the stored ``code_challenge``.

    Uses a constant-time comparison to avoid leaking timing information.
    Returns ``False`` for any malformed input rather than raising.
    """
    if not code_verifier or not code_challenge:
        return False
    try:
        expected = compute_s256_challenge(code_verifier)
    except (UnicodeEncodeError, ValueError):
        return False
    return hmac.compare_digest(expected, code_challenge)
