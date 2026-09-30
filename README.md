# huudis (Python)

Official Python SDK for [Huudis](https://huudis.com). Works with FastAPI,
Flask, Django, or anything else that speaks WSGI/ASGI.

## Install

```bash
pip install forjio-huudis
```

## Quickstart

Set env vars (or pass them to the client):

```bash
HUUDIS_ISSUER=https://huudis.com
HUUDIS_AUDIENCE=oc_your_client_id
HUUDIS_CLIENT_ID=oc_your_client_id
HUUDIS_CLIENT_SECRET=cs_...   # omit for public clients (PKCE)
```

### Verify an access token

```python
from fastapi import FastAPI, Header, HTTPException
from huudis import verify_access_token, HuudisAuthError

app = FastAPI()

@app.get("/me")
def me(authorization: str = Header(...)):
    try:
        claims = verify_access_token(authorization)
    except HuudisAuthError as e:
        raise HTTPException(401, detail=e.message)
    return {"user_id": claims.sub, "email": claims.email}
```

### OIDC sign-in flow

```python
from huudis import HuudisClient

huudis = HuudisClient()

# Step 1: redirect the user
url = huudis.authorization_url(
    redirect_uri="https://yourapp.com/callback",
    state=session["state"],
    code_challenge=session["pkce_challenge"],
)

# Step 2: exchange the code
tokens = huudis.exchange_code(
    code=request.args["code"],
    redirect_uri="https://yourapp.com/callback",
    code_verifier=session["pkce_verifier"],
)
userinfo = huudis.userinfo(tokens["access_token"])
```

### Authorization check

```python
result = huudis.authz_check(
    access_token=token,
    principal={"type": "user", "id": claims.sub, "accountId": claims.account_id},
    action="plugipay:DeleteInvoice",
    resource="forjio:plugipay::acc_.../invoice/inv_9F8",
)
if not result["allow"]:
    raise HTTPException(403, detail=result.get("reason"))
```

## Call the API — every route, with the right credential

`client.api` has one method per Huudis API route (generated from the API spec). Each call
carries the credential its route group takes: a signed-in person's `session` bearer; else,
for programs, an IAM access key (`access_key_id` + `secret_access_key`, or
`HUUDIS_ACCESS_KEY_ID` + `HUUDIS_SECRET_ACCESS_KEY`), each request signed
`Huudis-HMAC-SHA256` and acting as the key's user within the user's IAM policies; and for
`/app/*`, your OIDC app's `client_id` + `client_secret` (HTTP Basic).

```python
from huudis import HuudisClient

huudis = HuudisClient(issuer="https://huudis.com", access_key_id="AKIA…", secret_access_key="…",
                      workspace_id="acc_…")  # workspace_id is optional
users = huudis.api.iam_users()
huudis.api.iam_create_groups(name="On call")

app = HuudisClient(issuer="https://huudis.com", client_id="oc_…", client_secret="cs_…")
signed_in = app.api.app_users(status="active")
```

Person-only routes (password, sessions, account deletion, adding members, …) refuse a key
with `PERSON_ONLY`; see <https://huudis.com/docs/api/authentication>. `sign_request(...)`
and `AccessKeyAuth` (an `httpx.Auth`) sign requests you build yourself.

## Types

| Name | Description |
|---|---|
| `verify_access_token(header_or_token, *, issuer=None, audience=None, require_mfa=False)` | Module-level convenience — reads `HUUDIS_ISSUER` / `HUUDIS_AUDIENCE` from env. |
| `HuudisClient(issuer=..., client_id=..., client_secret=..., audience=..., api_base=...)` | Full surface. Use as a context manager (`with HuudisClient() as huudis:`) or call `.close()`. |
| `HuudisClaims` | Dataclass returned by verification — `sub`, `email`, `account_id`, `scope`, `mfa_verified`, etc. |
| `HuudisAuthError` | Raised on any failure; carries `.code` + `.message`. |

JWKS is cached in-process via PyJWT's `PyJWKClient`.

## Docs

- Full docs: <https://huudis.com/docs>
- Source: <https://github.com/hachimi-cat/huudis-python>

## License

MIT
