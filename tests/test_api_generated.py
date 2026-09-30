"""client.api: every feature route, one method each, generated from the API spec
(scripts/apigen.sh). Calls carry the client's session bearer, like the resource
namespaces."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, List
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from huudis import HuudisClient


class _SignedIn:
    """What ApiClient reads from a Session: the bearer, and whether to refresh."""

    data = SimpleNamespace(access_token="tok_live")

    def will_expire_soon(self, buffer_sec: int = 300) -> bool:
        return False

    def refresh(self) -> None:  # pragma: no cover - never due
        pass


def _client(seen: List[httpx.Request]) -> HuudisClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = {"data": {"ok": True}, "error": None, "meta": {"requestId": "r"}}
        return httpx.Response(200, content=json.dumps(body).encode())

    http = httpx.Client(transport=httpx.MockTransport(handler))
    session: Any = _SignedIn()
    return HuudisClient(issuer="https://huudis.test", client_id="huudis-cli", session=session, http=http)


def test_create_sends_the_fields_huudis_validates_with_the_session_bearer() -> None:
    seen: List[httpx.Request] = []
    client = _client(seen)
    client.api.iam_create_users(email="rina@example.com", role="member", send_invite_email=False)
    request = seen[0]
    assert (request.method, request.url.path) == ("POST", "/api/v1/iam/users")
    assert json.loads(request.content) == {"email": "rina@example.com", "role": "member", "sendInviteEmail": False}
    assert request.headers["authorization"] == "Bearer tok_live"


def test_path_and_query() -> None:
    seen: List[httpx.Request] = []
    client = _client(seen)
    client.api.iam_delete_groups_members("grp 1", "usr/2")
    client.api.account_audit(limit=5, outcome="denied")
    assert seen[0].method == "DELETE"
    assert seen[0].url.raw_path.decode() == "/api/v1/iam/groups/grp%201/members/usr%2F2"
    assert seen[1].url.path == "/api/v1/account/audit"
    assert parse_qs(urlsplit(str(seen[1].url)).query) == {"limit": ["5"], "outcome": ["denied"]}


def test_a_delete_that_takes_a_body_sends_it() -> None:
    seen: List[httpx.Request] = []
    client = _client(seen)
    client.api.account_delete(password="pw")
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/api/v1/account")
    assert json.loads(seen[0].content) == {"password": "pw"}


def test_a_required_field_is_asked_for() -> None:
    client = _client([])
    with pytest.raises(ValueError, match="needs email"):
        client.api.iam_create_users(name="Rina")


def test_the_low_level_client_still_answers_on_client_api() -> None:
    seen: List[httpx.Request] = []
    client = _client(seen)
    assert client.api.get("/api/v1/account") == {"ok": True}
    assert seen[0].url.path == "/api/v1/account"
    assert client.api.base_url == client.api_client.base_url == "https://huudis.test"


def test_every_feature_route_has_a_method() -> None:
    methods = [n for n in dir(_client([]).api) if not n.startswith("_")]
    assert len(methods) > 105
