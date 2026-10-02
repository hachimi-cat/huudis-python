"""Official Python SDK for Huudis.

v0.4.0 adds:
- Resource namespaces on HuudisClient (iam, workspaces, end_users, mfa,
  billing, webhook_subscriptions, etc.) — Python parity with huudis-node.
- OIDC device authorization grant (RFC 8628) for CLI sign-in.
- Multi-profile Session for ~/.huudis/credentials.
- ApiClient with proactive + reactive token refresh.
- password_grant + signup_direct grants + idp_hint on authorization_url.
"""

from .auth import HuudisClaims, verify_access_token
from .client import HuudisClient
from .device_flow import (
    DeviceFlowStart,
    DeviceTokens,
    DiscoveryDocument,
    clear_discovery_cache,
    fetch_discovery,
    poll_device_token,
    refresh_access_token,
    start_device_flow,
)
from .errors import ApiError, HuudisAuthError, NetworkError, RefreshError
from .http_client import ApiClient
from .session import ProfileData, Session
from .signing import AccessKeyAuth, ClientCredentialsAuth, sign_request
from .webhooks import verify_webhook_signature

__all__ = [
    # auth
    "HuudisClaims",
    "verify_access_token",
    # client
    "HuudisClient",
    # device flow
    "DeviceFlowStart",
    "DeviceTokens",
    "DiscoveryDocument",
    "clear_discovery_cache",
    "fetch_discovery",
    "poll_device_token",
    "refresh_access_token",
    "start_device_flow",
    # errors
    "ApiError",
    "HuudisAuthError",
    "NetworkError",
    "RefreshError",
    # http client
    "ApiClient",
    # session
    "ProfileData",
    "Session",
    # signing
    "AccessKeyAuth",
    "ClientCredentialsAuth",
    "sign_request",
    # webhooks
    "verify_webhook_signature",
]

__version__ = "0.8.0"
