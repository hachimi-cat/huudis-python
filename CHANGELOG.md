# Changelog

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
