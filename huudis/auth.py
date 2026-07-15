"""Access-token verification for Huudis-issued JWTs.

Fetches the issuer's JWKS (cached in-process), verifies the signature with
PyJWT, and returns a typed claims dict. Reads `HUUDIS_ISSUER` and
`HUUDIS_AUDIENCE` from env when not passed explicitly — matches the
three-line middleware example on the landing page.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
import jwt
from jwt import PyJWKClient

from .errors import HuudisAuthError


@dataclass
class HuudisClaims:
    """Typed view over the JWT payload."""

    iss: str
    aud: str
    sub: str
    exp: int
    iat: int
    account_id: str
    identity_id: str
    identity_type: str  # "user" | "service_account"
    scope: str
    mfa_verified: bool = False
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


_jwks_clients: Dict[str, PyJWKClient] = {}


def _jwks_client(issuer: str) -> PyJWKClient:
    url = f"{issuer.rstrip('/')}/.well-known/jwks.json"
    client = _jwks_clients.get(url)
    if client is None:
        client = PyJWKClient(url, cache_keys=True, lifespan=3600)
        _jwks_clients[url] = client
    return client


_BEARER_RE = re.compile(r"^\s*Bearer\s+(.+)$", re.IGNORECASE)


def _strip_bearer(value: str) -> str:
    m = _BEARER_RE.match(value)
    return m.group(1).strip() if m else value.strip()


def verify_access_token(
    token_or_header: Optional[str],
    *,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    require_mfa: bool = False,
) -> HuudisClaims:
    """Verify a Huudis-issued access token.

    Pass the raw Authorization header value — we strip the `Bearer ` prefix.

        claims = verify_access_token(request.headers["authorization"])
        return {"user_id": claims.sub, "email": claims.email}

    Raises :class:`HuudisAuthError` on any failure.
    """
    if not token_or_header:
        raise HuudisAuthError("MISSING_TOKEN", "No Authorization header / token provided.")
    token = _strip_bearer(token_or_header)

    resolved_issuer = issuer or os.environ.get("HUUDIS_ISSUER")
    resolved_audience = audience or os.environ.get("HUUDIS_AUDIENCE")
    if not resolved_issuer:
        raise HuudisAuthError("MISSING_ISSUER", "Set HUUDIS_ISSUER env or pass issuer=...")
    if not resolved_audience:
        raise HuudisAuthError("MISSING_AUDIENCE", "Set HUUDIS_AUDIENCE env or pass audience=...")

    try:
        signing_key = _jwks_client(resolved_issuer).get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["ES256", "RS256"],
            audience=resolved_audience,
            issuer=resolved_issuer,
        )
    except jwt.PyJWTError as e:
        raise HuudisAuthError("INVALID_TOKEN", str(e)) from None
    except (httpx.HTTPError, ValueError) as e:
        raise HuudisAuthError("JWKS_FETCH_FAILED", str(e)) from None

    required = ["accountId", "identityId", "identityType", "scope"]
    missing = [k for k in required if k not in payload]
    if missing:
        raise HuudisAuthError(
            "INCOMPLETE_CLAIMS",
            f"Token is missing required Huudis claims: {', '.join(missing)}.",
        )

    mfa_verified = bool(payload.get("mfaVerified"))
    if require_mfa and not mfa_verified:
        raise HuudisAuthError("MFA_REQUIRED", "This operation requires an MFA-verified token.")

    return HuudisClaims(
        iss=payload["iss"],
        aud=payload["aud"] if isinstance(payload["aud"], str) else payload["aud"][0],
        sub=payload["sub"],
        exp=int(payload["exp"]),
        iat=int(payload.get("iat", time.time())),
        account_id=payload["accountId"],
        identity_id=payload["identityId"],
        identity_type=payload["identityType"],
        scope=payload["scope"],
        mfa_verified=mfa_verified,
        email=payload.get("email"),
        email_verified=payload.get("email_verified"),
        name=payload.get("name"),
        raw=payload,
    )
