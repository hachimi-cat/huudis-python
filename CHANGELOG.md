# Changelog

## 0.8.0
- New: `client.api.iam_key_requests`, `iam_get_key_requests`, `iam_key_requests_challenge`, `iam_key_requests_approve`, `iam_key_requests_deny` (what access keys ask a workspace owner to approve) and `iam_key_actions`, `iam_key_actions_undo` (what keys did to the workspace's members, and undoing it).
- An access key can now add, invite, re-role and remove members, reset another member's password and manage SSO identity providers, when its user's policy names the action itself (`huudis:AddMember`, `huudis:InviteMember`, `huudis:UpdateMember`, `huudis:RemoveMember`, `huudis:ResetMemberPassword`, `huudis:CreateIdentityProvider`, `huudis:UpdateIdentityProvider`, `huudis:DeleteIdentityProvider`; a wildcard such as `huudis:*` does not grant them). Member changes run at once and every workspace owner is emailed a link to undo them. SSO, password resets and anything about the owner role answer `{"approvalRequired": True, "request": …}` (HTTP 202) until an owner approves with a second-factor code; then the same call runs once. A key never sets or sees a member's password.

## 0.7.0
- `client.api.ops_end_users_impersonate(id, duration_seconds=…, reason=…)` takes `reason`, and `end_users.impersonate(id, reason=…)` now reaches the server: the audit log and the `huudis.ops.impersonation_*` webhook events carry it.
- Huudis now delivers every webhook event its catalog lists (they were reserved): verify them with `verify_webhook_signature` as before; see /docs/api/webhooks for who receives which.

## 0.6.0
- A route read by id next to its list is named `get` + the list's name: `client.api.account_get_webhook_subscriptions` (was `client.api.account_webhook_subscriptions_2`), `client.api.iam_get_groups` (was `client.api.iam_groups_2`), `client.api.iam_get_policies` (was `client.api.iam_policies_2`), `client.api.iam_get_roles` (was `client.api.iam_roles_2`), `client.api.iam_get_service_accounts` (was `client.api.iam_service_accounts_2`), `client.api.ops_get_end_users` (was `client.api.ops_end_users_2`). Each old name stays as a deprecated alias.

## 0.5.0
- **Published on PyPI as `forjio-huudis`** (`pip install forjio-huudis`); the import is still `import huudis`. The PyPI name `huudis` belongs to an account Forjio no longer publishes from (like `forjio-linksnap`).
- Access keys: `access_key_id` + `secret_access_key` (or `HUUDIS_ACCESS_KEY_ID` + `HUUDIS_SECRET_ACCESS_KEY`) sign every call `Huudis-HMAC-SHA256` when there is no `session` — the key acts as its user on `/account/*`, `/iam/*`, `/authz/*` within the user's IAM policies. `client_id` is optional with a key.
- `client.api` sends `/api/v1/app/*` with the OIDC client credentials (`client_id` + `client_secret`, HTTP Basic) instead of the session bearer, which those routes refuse.
- `workspace_id` (`HUUDIS_WORKSPACE_ID`) sends `X-Huudis-Workspace-Id`.
- New exports: `sign_request`, `AccessKeyAuth`, `ClientCredentialsAuth`; `ApiClient(auth=...)`.

## 0.4.1
- `client.api`: every feature route of the Huudis API, one method each (`client.api.<area>_<action>(...)`), generated from the API spec; calls carry the client's `session` bearer like the resource namespaces.
- The low-level `ApiClient` is now `client.api_client`; `client.api.get/post/patch/put/delete/paginate` still work (delegated to it).

## 0.4.0
- Initial tracked release.
