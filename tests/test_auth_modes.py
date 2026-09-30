"""Each route group takes its own credential: the session bearer, an IAM access key
(Huudis-HMAC-SHA256) for programs, the OIDC client credentials for /api/v1/app/*."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, List

import httpx
import pytest

from huudis import HuudisAuthError, HuudisClient, sign_request

KEY_ID = "AKIA0123456789ABCDEF01234567"
SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTAxMjM="


class _SignedIn:
    data = SimpleNamespace(access_token="tok_live")

    def will_expire_soon(self, buffer_sec: int = 300) -> bool:
        return False

    def refresh(self) -> None:  # pragma: no cover
        pass


def _client(seen: List[httpx.Request], **kwargs: Any) -> HuudisClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = {"data": {"ok": True}, "error": None, "meta": {"requestId": "r"}}
        return httpx.Response(200, content=json.dumps(body).encode())

    http = httpx.Client(transport=httpx.MockTransport(handler))
    return HuudisClient(issuer="https://huudis.test", http=http, **kwargs)


def _expected(method: str, path_with_query: str, date: str, body: bytes = b"") -> str:
    """What the Huudis server computes (backend/src/services/iam-access-keys.ts), restated."""
    body_hash = hashlib.sha256(body).hexdigest()
    return hmac.new(SECRET.encode(), f"{method}\n{path_with_query}\n{date}\n{body_hash}".encode(), hashlib.sha256).hexdigest()


def _signature(request: httpx.Request) -> str:
    m = re.match(r"^Huudis-HMAC-SHA256 Credential=([A-Z0-9]+), Signature=([a-f0-9]{64})$", request.headers["authorization"])
    assert m, request.headers["authorization"]
    assert m.group(1) == KEY_ID
    return m.group(2)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HUUDIS_ACCESS_KEY_ID", "HUUDIS_SECRET_ACCESS_KEY", "HUUDIS_WORKSPACE_ID", "HUUDIS_CLIENT_ID", "HUUDIS_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)


def test_access_key_signs_method_path_with_query_date_and_empty_body() -> None:
    seen: List[httpx.Request] = []
    client = _client(seen, access_key_id=KEY_ID, secret_access_key=SECRET)
    client.api.account_audit(limit=5, outcome="denied")
    request = seen[0]
    path = request.url.raw_path.decode()
    assert path == "/api/v1/account/audit?limit=5&outcome=denied"
    date = request.headers["x-huudis-date"]
    skew = abs(datetime.now(timezone.utc) - datetime.fromisoformat(date.replace("Z", "+00:00")))
    assert skew.total_seconds() < 60
    assert _signature(request) == _expected("GET", path, date)


def test_access_key_signs_the_exact_body_bytes() -> None:
    seen: List[httpx.Request] = []
    client = _client(seen, access_key_id=KEY_ID, secret_access_key=SECRET)
    client.api.iam_create_groups(name="Ops", description="on call")
    request = seen[0]
    assert request.method == "POST"
    assert json.loads(request.content) == {"name": "Ops", "description": "on call"}
    assert _signature(request) == _expected("POST", "/api/v1/iam/groups", request.headers["x-huudis-date"], request.content)


def test_access_key_from_the_environment_signs_the_resource_namespaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUUDIS_ACCESS_KEY_ID", KEY_ID)
    monkeypatch.setenv("HUUDIS_SECRET_ACCESS_KEY", SECRET)
    monkeypatch.setenv("HUUDIS_WORKSPACE_ID", "acc_123")
    seen: List[httpx.Request] = []
    client = _client(seen)
    client.iam.list_users()
    _signature(seen[0])
    assert seen[0].headers["x-huudis-workspace-id"] == "acc_123"


def test_a_signed_in_session_wins_over_the_key_and_a_per_call_token_is_kept() -> None:
    seen: List[httpx.Request] = []
    session: Any = _SignedIn()
    both = _client(seen, client_id="c", session=session, access_key_id=KEY_ID, secret_access_key=SECRET)
    both.api.iam_users()
    assert seen[0].headers["authorization"] == "Bearer tok_live"
    key_only = _client(seen, access_key_id=KEY_ID, secret_access_key=SECRET)
    key_only.iam.list_users(auth_token="tok_other")
    assert seen[1].headers["authorization"] == "Bearer tok_other"


def test_sign_request_is_the_same_algorithm() -> None:
    headers = sign_request(KEY_ID, SECRET, method="post", path_with_query="/api/v1/authz/check?x=1",
                           body='{"a":1}', date="2026-09-30T12:00:00.000Z")
    assert headers["x-huudis-date"] == "2026-09-30T12:00:00.000Z"
    assert headers["authorization"].endswith(
        _expected("POST", "/api/v1/authz/check?x=1", "2026-09-30T12:00:00.000Z", b'{"a":1}'))


def test_app_routes_take_the_client_credentials_even_with_a_session() -> None:
    seen: List[httpx.Request] = []
    session: Any = _SignedIn()
    client = _client(seen, client_id="oc_app", client_secret="s3cret", session=session)
    client.api.app_users(status="active")
    client.api.iam_users()
    assert str(seen[0].url) == "https://huudis.test/api/v1/app/users?status=active"
    assert seen[0].headers["authorization"] == "Basic " + base64.b64encode(b"oc_app:s3cret").decode()
    assert seen[1].headers["authorization"] == "Bearer tok_live"


def test_app_routes_say_what_is_missing_without_a_client_secret() -> None:
    seen: List[httpx.Request] = []
    session: Any = _SignedIn()
    client = _client(seen, client_id="oc_app", session=session)
    with pytest.raises(HuudisAuthError) as err:
        client.api.app_users()
    assert err.value.code == "MISSING_CLIENT_CREDENTIALS"
    assert seen == []


def test_needs_a_client_id_or_an_access_key() -> None:
    with pytest.raises(HuudisAuthError):
        HuudisClient(issuer="https://huudis.test")
    seen: List[httpx.Request] = []
    client = _client(seen, access_key_id=KEY_ID, secret_access_key=SECRET)
    with pytest.raises(HuudisAuthError):
        client.authorization_url(redirect_uri="https://x", state="s")
