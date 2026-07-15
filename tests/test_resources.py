"""Smoke tests for HuudisClient resource namespaces.

Mocks httpx so we just verify each resource method hits the right path
with the right method + body — same testing strategy as the Node SDK.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import httpx
import pytest

from huudis import HuudisClient


def _envelope(data: Any) -> bytes:
    return json.dumps({"data": data, "error": None, "meta": {"requestId": "req_test", "timestamp": "now"}}).encode()


def _make_client():
    captured: List[Dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode() if request.method in {"POST", "PATCH", "PUT"} else None
        captured.append({
            "url": str(request.url),
            "method": request.method,
            "headers": dict(request.headers),
            "body": body,
        })
        return httpx.Response(200, content=_envelope({"ok": True}))

    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport, timeout=5.0)
    client = HuudisClient(issuer="https://huudis.test", client_id="huudis-cli", http=http)
    return client, captured


def test_iam_list_users_with_query():
    client, captured = _make_client()
    client.iam.list_users(limit=25, auth_token="t")
    c = captured[0]
    assert c["method"] == "GET"
    assert "/api/v1/iam/users" in c["url"]
    assert "limit=25" in c["url"]
    assert c["headers"]["authorization"] == "Bearer t"


def test_iam_create_access_key_post():
    client, captured = _make_client()
    client.iam.create_access_key({"principalArn": "forjio:huudis::acc_1:user/u1"}, auth_token="t")
    c = captured[0]
    assert c["method"] == "POST"
    assert "/api/v1/iam/access-keys" in c["url"]
    assert json.loads(c["body"]) == {"principalArn": "forjio:huudis::acc_1:user/u1"}


def test_iam_revoke_access_key_path():
    client, captured = _make_client()
    client.iam.revoke_access_key("ak_1", auth_token="t")
    assert "/api/v1/iam/access-keys/ak_1/revoke" in captured[0]["url"]
    assert captured[0]["method"] == "POST"


def test_workspaces_switch_post():
    client, captured = _make_client()
    client.workspaces.switch("ws_1", auth_token="t")
    assert "/api/v1/account/workspaces/ws_1/switch" in captured[0]["url"]
    assert captured[0]["method"] == "POST"


def test_end_users_disable_with_body():
    client, captured = _make_client()
    client.end_users.disable("eu_1", {"reason": "fraud"}, auth_token="t")
    c = captured[0]
    assert "/api/v1/ops/end-users/eu_1/disable" in c["url"]
    assert json.loads(c["body"]) == {"reason": "fraud"}


def test_mfa_delete_device():
    client, captured = _make_client()
    client.mfa.delete_device("dev_1", auth_token="t")
    assert captured[0]["method"] == "DELETE"
    assert "/api/v1/mfa/devices/dev_1" in captured[0]["url"]


def test_webhook_subscriptions_list_deliveries_query():
    client, captured = _make_client()
    client.webhook_subscriptions.list_deliveries("ws_1", status="failed", limit=10, auth_token="t")
    url = captured[0]["url"]
    assert "/api/v1/account/webhook-subscriptions/ws_1/deliveries" in url
    assert "status=failed" in url
    assert "limit=10" in url


def test_billing_plans():
    client, captured = _make_client()
    client.billing.plans(auth_token="t")
    assert "/api/v1/account/billing/plans" in captured[0]["url"]


def test_account_sessions_revoke_all():
    client, captured = _make_client()
    client.account.sessions.revoke_all(auth_token="t")
    assert "/api/v1/account/sessions/revoke-all" in captured[0]["url"]


def test_account_linked_unlink():
    client, captured = _make_client()
    client.account.linked.unlink("google", auth_token="t")
    assert captured[0]["method"] == "DELETE"
    assert "/api/v1/account/linked-accounts/google" in captured[0]["url"]


def test_identity_providers_create():
    client, captured = _make_client()
    client.identity_providers.create({"kind": "oidc", "name": "GW"}, auth_token="t")
    assert "/api/v1/iam/identity-providers" in captured[0]["url"]
    assert captured[0]["method"] == "POST"


def test_authz_check():
    client, captured = _make_client()
    client.authz.check(
        {
            "principal": {"type": "user", "id": "u1", "accountId": "acc_1"},
            "action": "huudis:iam:ListUsers",
            "resource": "forjio:huudis::acc_1:*",
        },
        auth_token="t",
    )
    assert "/api/v1/authz/check" in captured[0]["url"]


def test_legacy_authz_check_forwards():
    client, captured = _make_client()
    client.authz_check(
        access_token="legacy",
        principal={"type": "user", "id": "u", "accountId": "a"},
        action="x",
        resource="y",
    )
    assert "/api/v1/authz/check" in captured[0]["url"]
    assert captured[0]["headers"]["authorization"] == "Bearer legacy"


def test_no_auth_header_when_no_token():
    client, captured = _make_client()
    client.iam.list_users()
    assert "authorization" not in captured[0]["headers"]
