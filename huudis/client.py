"""High-level Huudis client wrapping every developer-facing endpoint.

v0.4.0 adds resource namespaces (IAM, workspaces, end-users, MFA, billing,
webhook subscriptions, etc.) on top of the existing OIDC auth helpers.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

from .auth import HuudisClaims, verify_access_token
from .errors import HuudisAuthError
from .http_client import ApiClient
from .resources import (
    AccountResources,
    AssumedSessionsResources,
    AuthzResources,
    BillingResources,
    ConnectedAppsResources,
    EndUsersResources,
    IamResources,
    IdentityProvidersResources,
    MfaResources,
    OidcClientsResources,
    ServicesResources,
    WebhookSubscriptionsResources,
    WorkspacesResources,
    build_resources,
)
from .session import Session


class HuudisClient:
    """Sign users in, exchange codes, call /authz/check, verify tokens,
    plus full admin API via resource namespaces."""

    # Type hints for IDE completion — populated in __init__
    iam: IamResources
    identity_providers: IdentityProvidersResources
    assumed_sessions: AssumedSessionsResources
    authz: AuthzResources
    workspaces: WorkspacesResources
    end_users: EndUsersResources
    mfa: MfaResources
    oidc_clients: OidcClientsResources
    connected_apps: ConnectedAppsResources
    services: ServicesResources
    webhook_subscriptions: WebhookSubscriptionsResources
    billing: BillingResources
    account: AccountResources

    def __init__(
        self,
        *,
        issuer: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        audience: Optional[str] = None,
        api_base: Optional[str] = None,
        session: Optional[Session] = None,
        http: Optional[httpx.Client] = None,
    ) -> None:
        resolved_issuer = issuer or os.environ.get("HUUDIS_ISSUER")
        resolved_client_id = client_id or os.environ.get("HUUDIS_CLIENT_ID")
        if not resolved_issuer:
            raise HuudisAuthError("MISSING_ISSUER", "Set HUUDIS_ISSUER env or pass issuer=...")
        if not resolved_client_id:
            raise HuudisAuthError("MISSING_CLIENT_ID", "Set HUUDIS_CLIENT_ID env or pass client_id=...")
        self.issuer = resolved_issuer.rstrip("/")
        self.client_id = resolved_client_id
        self.client_secret = client_secret or os.environ.get("HUUDIS_CLIENT_SECRET")
        self.audience = audience or resolved_client_id
        self.api_base = (api_base or self.issuer).rstrip("/")
        self._http = http or httpx.Client(timeout=10.0)
        self._owns_http = http is None
        self.api = ApiClient(base_url=self.api_base, session=session, http=self._http)
        # Resource namespaces
        resources = build_resources(self.api)
        self.iam = resources["iam"]  # type: ignore[assignment]
        self.identity_providers = resources["identity_providers"]  # type: ignore[assignment]
        self.assumed_sessions = resources["assumed_sessions"]  # type: ignore[assignment]
        self.authz = resources["authz"]  # type: ignore[assignment]
        self.workspaces = resources["workspaces"]  # type: ignore[assignment]
        self.end_users = resources["end_users"]  # type: ignore[assignment]
        self.mfa = resources["mfa"]  # type: ignore[assignment]
        self.oidc_clients = resources["oidc_clients"]  # type: ignore[assignment]
        self.connected_apps = resources["connected_apps"]  # type: ignore[assignment]
        self.services = resources["services"]  # type: ignore[assignment]
        self.webhook_subscriptions = resources["webhook_subscriptions"]  # type: ignore[assignment]
        self.billing = resources["billing"]  # type: ignore[assignment]
        self.account = resources["account"]  # type: ignore[assignment]

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> "HuudisClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ─── Token verification ──────────────────────────────────────────────

    def verify_access_token(
        self, token_or_header: Optional[str], *, require_mfa: bool = False,
    ) -> HuudisClaims:
        return verify_access_token(
            token_or_header,
            issuer=self.issuer,
            audience=self.audience,
            require_mfa=require_mfa,
        )

    # ─── OIDC authorization-code flow ────────────────────────────────────

    def authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        scope: str = "openid profile email",
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
        login_hint: Optional[str] = None,
        idp_hint: Optional[str] = None,
    ) -> str:
        params: Dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method
        if login_hint:
            params["login_hint"] = login_hint
        if idp_hint:
            params["idp_hint"] = idp_hint
        return f"{self.issuer}/api/v1/oidc/authorize?{urlencode(params)}"

    def password_grant(
        self,
        *,
        email: str,
        password: str,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, str] = {
            "grant_type": "password",
            "username": email,
            "password": password,
            "client_id": self.client_id,
        }
        if self.client_secret:
            body["client_secret"] = self.client_secret
        if scope:
            body["scope"] = scope
        return self._token_endpoint(body)

    def signup_direct(
        self,
        *,
        email: str,
        password: str,
        name: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, str] = {
            "grant_type": "urn:forjio:grant-type:signup",
            "email": email,
            "password": password,
            "client_id": self.client_id,
        }
        if self.client_secret:
            body["client_secret"] = self.client_secret
        if name:
            body["name"] = name
        if scope:
            body["scope"] = scope
        return self._token_endpoint(body)

    def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            body["client_secret"] = self.client_secret
        if code_verifier:
            body["code_verifier"] = code_verifier
        return self._token_endpoint(body)

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        body: Dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            body["client_secret"] = self.client_secret
        return self._token_endpoint(body)

    # ─── Userinfo ────────────────────────────────────────────────────────

    def userinfo(self, access_token: str) -> Dict[str, Any]:
        res = self._http.get(
            f"{self.issuer}/api/v1/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if res.status_code >= 400:
            raise HuudisAuthError("USERINFO_FAILED", f"HTTP {res.status_code}: {res.text}")
        return res.json()

    # ─── Authz check (legacy convenience; prefer client.authz.check) ─────

    def authz_check(
        self,
        *,
        access_token: str,
        principal: Dict[str, Any],
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"principal": principal, "action": action, "resource": resource}
        if context is not None:
            payload["context"] = context
        return self.authz.check(payload, auth_token=access_token)

    # ─── Internal ────────────────────────────────────────────────────────

    def _token_endpoint(self, body: Dict[str, str]) -> Dict[str, Any]:
        res = self._http.post(
            f"{self.issuer}/api/v1/oidc/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=urlencode(body),
        )
        if res.status_code >= 400:
            try:
                err = res.json()
                msg = err.get("error_description") or err.get("error") or res.text
            except ValueError:
                msg = res.text
            raise HuudisAuthError("TOKEN_ENDPOINT_FAILED", str(msg))
        return res.json()
