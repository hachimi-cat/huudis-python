"""Resource namespaces for HuudisClient — Python parity with huudis-node v0.4.0.

Each builder takes an ApiClient and returns a small object whose methods
map 1:1 to backend REST routes. Methods accept an optional `auth_token`
to override the client-level bearer for a single call.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .http_client import ApiClient


def _opts(auth_token: Optional[str] = None) -> Dict[str, Any]:
    return {"auth_token": auth_token} if auth_token else {}


class _Namespace:
    """Lightweight base — just stashes the ApiClient so subclasses stay terse."""

    def __init__(self, api: ApiClient) -> None:
        self.api = api


class IamResources(_Namespace):
    # Users
    def list_users(self, *, limit: Optional[int] = None, cursor: Optional[str] = None, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/users", query={"limit": limit, "cursor": cursor}, **_opts(auth_token))

    def create_user(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/users", body, **_opts(auth_token))

    def update_user(self, user_id: str, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch(f"/api/v1/iam/users/{user_id}", body, **_opts(auth_token))

    def delete_user(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/users/{user_id}", **_opts(auth_token))

    def reset_user_password(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/iam/users/{user_id}/reset-password", None, **_opts(auth_token))

    # Invites
    def list_invites(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/invites", **_opts(auth_token))

    def send_invite(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/invites", body, **_opts(auth_token))

    def cancel_invite(self, invite_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/invites/{invite_id}", **_opts(auth_token))

    # Access keys
    def list_access_keys(self, *, principal_arn: Optional[str] = None, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/access-keys", query={"principalArn": principal_arn}, **_opts(auth_token))

    def create_access_key(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/access-keys", body, **_opts(auth_token))

    def revoke_access_key(self, key_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/iam/access-keys/{key_id}/revoke", None, **_opts(auth_token))

    def delete_access_key(self, key_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/access-keys/{key_id}", **_opts(auth_token))

    # Groups
    def list_groups(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/groups", **_opts(auth_token))

    def get_group(self, group_id: str, *, auth_token: Optional[str] = None):
        return self.api.get(f"/api/v1/iam/groups/{group_id}", **_opts(auth_token))

    def create_group(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/groups", body, **_opts(auth_token))

    def delete_group(self, group_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/groups/{group_id}", **_opts(auth_token))

    def add_group_member(self, group_id: str, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/iam/groups/{group_id}/members", {"userId": user_id}, **_opts(auth_token))

    def remove_group_member(self, group_id: str, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/groups/{group_id}/members/{user_id}", **_opts(auth_token))

    # Roles
    def list_roles(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/roles", **_opts(auth_token))

    def get_role(self, role_id: str, *, auth_token: Optional[str] = None):
        return self.api.get(f"/api/v1/iam/roles/{role_id}", **_opts(auth_token))

    def create_role(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/roles", body, **_opts(auth_token))

    def delete_role(self, role_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/roles/{role_id}", **_opts(auth_token))

    # Service accounts
    def list_service_accounts(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/service-accounts", **_opts(auth_token))

    def get_service_account(self, sa_id: str, *, auth_token: Optional[str] = None):
        return self.api.get(f"/api/v1/iam/service-accounts/{sa_id}", **_opts(auth_token))

    def create_service_account(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/service-accounts", body, **_opts(auth_token))

    def delete_service_account(self, sa_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/service-accounts/{sa_id}", **_opts(auth_token))

    # Policies
    def list_policies(self, *, kind: Optional[str] = None, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/policies", query={"kind": kind}, **_opts(auth_token))

    def get_policy(self, policy_id: str, *, auth_token: Optional[str] = None):
        return self.api.get(f"/api/v1/iam/policies/{policy_id}", **_opts(auth_token))

    def create_policy(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/policies", body, **_opts(auth_token))

    def update_policy(self, policy_id: str, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch(f"/api/v1/iam/policies/{policy_id}", body, **_opts(auth_token))

    def delete_policy(self, policy_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/policies/{policy_id}", **_opts(auth_token))

    # Policy attachments
    def list_policy_attachments(self, *, policy_id: Optional[str] = None, principal_arn: Optional[str] = None, auth_token: Optional[str] = None):
        return self.api.get(
            "/api/v1/iam/policy-attachments",
            query={"policyId": policy_id, "principalArn": principal_arn},
            **_opts(auth_token),
        )

    def attach_policy(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/policy-attachments", body, **_opts(auth_token))

    def detach_policy(self, attachment_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/policy-attachments/{attachment_id}", **_opts(auth_token))


class IdentityProvidersResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/identity-providers", **_opts(auth_token))

    def create(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/iam/identity-providers", body, **_opts(auth_token))

    def update(self, idp_id: str, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch(f"/api/v1/iam/identity-providers/{idp_id}", body, **_opts(auth_token))

    def delete(self, idp_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/iam/identity-providers/{idp_id}", **_opts(auth_token))


class AssumedSessionsResources(_Namespace):
    def list(self, *, active_only: Optional[bool] = None, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/iam/assumed-sessions", query={"activeOnly": active_only}, **_opts(auth_token))

    def revoke(self, session_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/iam/assumed-sessions/{session_id}/revoke", None, **_opts(auth_token))


class AuthzResources(_Namespace):
    def check(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/authz/check", body, **_opts(auth_token))

    def assume_role(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/authz/assume-role", body, **_opts(auth_token))

    def whoami(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/authz/whoami", **_opts(auth_token))


class WorkspacesResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/workspaces", **_opts(auth_token))

    def create(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/workspaces", body, **_opts(auth_token))

    def update(self, workspace_id: str, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch(f"/api/v1/account/workspaces/{workspace_id}", body, **_opts(auth_token))

    def switch(self, workspace_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/account/workspaces/{workspace_id}/switch", None, **_opts(auth_token))


class EndUsersResources(_Namespace):
    def list(self, *, limit: Optional[int] = None, cursor: Optional[str] = None, search: Optional[str] = None, auth_token: Optional[str] = None):
        return self.api.get(
            "/api/v1/ops/end-users",
            query={"limit": limit, "cursor": cursor, "search": search},
            **_opts(auth_token),
        )

    def get(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.get(f"/api/v1/ops/end-users/{user_id}", **_opts(auth_token))

    def revoke(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/ops/end-users/{user_id}/revoke", None, **_opts(auth_token))

    def send_password_reset(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/ops/end-users/{user_id}/send-password-reset", None, **_opts(auth_token))

    def verify_email(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/ops/end-users/{user_id}/verify-email", None, **_opts(auth_token))

    def impersonate(self, user_id: str, body: Optional[Dict[str, Any]] = None, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/ops/end-users/{user_id}/impersonate", body, **_opts(auth_token))

    def stop_impersonation(self, *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/ops/end-users/stop-impersonation", None, **_opts(auth_token))

    def disable(self, user_id: str, body: Optional[Dict[str, Any]] = None, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/ops/end-users/{user_id}/disable", body, **_opts(auth_token))

    def enable(self, user_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/ops/end-users/{user_id}/enable", None, **_opts(auth_token))


class MfaResources(_Namespace):
    def enroll(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/mfa/enroll", body, **_opts(auth_token))

    def verify_enrollment(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/mfa/verify-enrollment", body, **_opts(auth_token))

    def verify_login(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/mfa/verify-login", body, **_opts(auth_token))

    def list_devices(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/mfa/devices", **_opts(auth_token))

    def delete_device(self, device_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/mfa/devices/{device_id}", **_opts(auth_token))


class OidcClientsResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/oidc/clients", **_opts(auth_token))

    def create(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/oidc/clients", body, **_opts(auth_token))

    def update(self, client_id: str, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch(f"/api/v1/oidc/clients/{client_id}", body, **_opts(auth_token))

    def rotate_secret(self, client_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/oidc/clients/{client_id}/rotate-secret", None, **_opts(auth_token))

    def delete(self, client_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/oidc/clients/{client_id}", **_opts(auth_token))


class ConnectedAppsResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/connected-apps", **_opts(auth_token))

    def revoke(self, app_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/account/connected-apps/{app_id}", **_opts(auth_token))


class ServicesResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/services", **_opts(auth_token))

    def enable(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/services/enable", body, **_opts(auth_token))

    def disable(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/services/disable", body, **_opts(auth_token))


class WebhookSubscriptionsResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/webhook-subscriptions", **_opts(auth_token))

    def create(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/webhook-subscriptions", body, **_opts(auth_token))

    def get(self, sub_id: str, *, auth_token: Optional[str] = None):
        return self.api.get(f"/api/v1/account/webhook-subscriptions/{sub_id}", **_opts(auth_token))

    def update(self, sub_id: str, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch(f"/api/v1/account/webhook-subscriptions/{sub_id}", body, **_opts(auth_token))

    def delete(self, sub_id: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/account/webhook-subscriptions/{sub_id}", **_opts(auth_token))

    def rotate_secret(self, sub_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/account/webhook-subscriptions/{sub_id}/rotate-secret", None, **_opts(auth_token))

    def list_deliveries(self, sub_id: str, *, status: Optional[str] = None, limit: Optional[int] = None, auth_token: Optional[str] = None):
        return self.api.get(
            f"/api/v1/account/webhook-subscriptions/{sub_id}/deliveries",
            query={"status": status, "limit": limit},
            **_opts(auth_token),
        )

    def replay_delivery(self, delivery_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(
            f"/api/v1/account/webhook-subscriptions/deliveries/{delivery_id}/replay",
            None,
            **_opts(auth_token),
        )

    def events_catalog(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/webhook-subscriptions/events/catalog", **_opts(auth_token))


class BillingResources(_Namespace):
    def summary(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/billing", **_opts(auth_token))

    def plans(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/billing/plans", **_opts(auth_token))

    def usage(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/billing/usage", **_opts(auth_token))

    def invoices(self, *, limit: Optional[int] = None, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/billing/invoices", query={"limit": limit}, **_opts(auth_token))

    def checkout(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/billing/checkout", body, **_opts(auth_token))

    def cancel(self, *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/billing/cancel", None, **_opts(auth_token))


class _AccountSessionsResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/sessions", **_opts(auth_token))

    def revoke(self, session_id: str, *, auth_token: Optional[str] = None):
        return self.api.post(f"/api/v1/account/sessions/{session_id}/revoke", None, **_opts(auth_token))

    def revoke_all(self, *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/sessions/revoke-all", None, **_opts(auth_token))


class _AccountLinkedResources(_Namespace):
    def list(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account/linked-accounts", **_opts(auth_token))

    def unlink(self, provider: str, *, auth_token: Optional[str] = None):
        return self.api.delete(f"/api/v1/account/linked-accounts/{provider}", **_opts(auth_token))


class AccountResources(_Namespace):
    def __init__(self, api: ApiClient) -> None:
        super().__init__(api)
        self.sessions = _AccountSessionsResources(api)
        self.linked = _AccountLinkedResources(api)

    def get(self, *, auth_token: Optional[str] = None):
        return self.api.get("/api/v1/account", **_opts(auth_token))

    def update(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.patch("/api/v1/account", body, **_opts(auth_token))

    def change_email(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/email-change", body, **_opts(auth_token))

    def change_password(self, body: Dict[str, Any], *, auth_token: Optional[str] = None):
        return self.api.post("/api/v1/account/password-change", body, **_opts(auth_token))

    def audit(self, *, event_type: Optional[str] = None, since: Optional[str] = None, limit: Optional[int] = None, auth_token: Optional[str] = None):
        return self.api.get(
            "/api/v1/account/audit",
            query={"eventType": event_type, "since": since, "limit": limit},
            **_opts(auth_token),
        )


def build_resources(api: ApiClient) -> Dict[str, _Namespace]:
    return {
        "iam": IamResources(api),
        "identity_providers": IdentityProvidersResources(api),
        "assumed_sessions": AssumedSessionsResources(api),
        "authz": AuthzResources(api),
        "workspaces": WorkspacesResources(api),
        "end_users": EndUsersResources(api),
        "mfa": MfaResources(api),
        "oidc_clients": OidcClientsResources(api),
        "connected_apps": ConnectedAppsResources(api),
        "services": ServicesResources(api),
        "webhook_subscriptions": WebhookSubscriptionsResources(api),
        "billing": BillingResources(api),
        "account": AccountResources(api),
    }
