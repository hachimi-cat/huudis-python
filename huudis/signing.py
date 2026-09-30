"""Access-key request signing (``Huudis-HMAC-SHA256``) and OIDC client credentials.

An IAM access key (``AKIA…`` + the secret shown once at creation) signs each request::

    StringToSign = METHOD "\\n" PATH-WITH-QUERY "\\n" X-Huudis-Date "\\n" hex(sha256(body))
    Signature    = hex(HMAC-SHA256(secret, StringToSign))
    Authorization: Huudis-HMAC-SHA256 Credential=<access key id>, Signature=<signature>

PATH-WITH-QUERY is exactly the request line's target (``/api/v1/iam/users?x=1``), the
body the exact bytes sent (empty for none), and Huudis accepts an ``X-Huudis-Date``
within 5 minutes of its clock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Dict, Generator, Optional, Union

import httpx


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sign_request(
    access_key_id: str,
    secret_access_key: str,
    *,
    method: str,
    path_with_query: str,
    body: Union[bytes, str, None] = None,
    date: Optional[str] = None,
) -> Dict[str, str]:
    """The ``Authorization`` and ``X-Huudis-Date`` headers for one request."""
    stamp = date or _iso_now()
    raw = body.encode() if isinstance(body, str) else (body or b"")
    body_hash = hashlib.sha256(raw).hexdigest()
    string_to_sign = f"{method.upper()}\n{path_with_query}\n{stamp}\n{body_hash}"
    signature = hmac.new(secret_access_key.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "authorization": f"Huudis-HMAC-SHA256 Credential={access_key_id}, Signature={signature}",
        "x-huudis-date": stamp,
    }


class AccessKeyAuth(httpx.Auth):
    """httpx auth that signs every request with an access key. A request that already
    carries an ``Authorization`` header (a per-call ``auth_token``) is sent as it is."""

    requires_request_body = True

    def __init__(self, access_key_id: str, secret_access_key: str) -> None:
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if "authorization" not in request.headers:
            headers = sign_request(
                self.access_key_id,
                self.secret_access_key,
                method=request.method,
                path_with_query=request.url.raw_path.decode("ascii"),
                body=request.content,
            )
            request.headers.update(headers)
        yield request


class ClientCredentialsAuth(httpx.Auth):
    """httpx auth for ``/api/v1/app/*``: the OIDC client's ``client_id:client_secret``
    as HTTP Basic."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        self._header = f"Basic {token}"

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["authorization"] = self._header
        yield request
