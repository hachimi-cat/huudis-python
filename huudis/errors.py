"""Typed error classes for the Huudis SDK."""

from __future__ import annotations

from typing import Any, Dict, Optional


class HuudisAuthError(Exception):
    """Raised on Huudis auth / OIDC / authz-check failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"HuudisAuthError({self.code!r}, {self.message!r})"


class RefreshError(Exception):
    """Raised when refreshing an OIDC access token fails."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"RefreshError({self.code!r}, {self.message!r})"


class NetworkError(Exception):
    """Raised on transport failures (DNS, connect refused, TLS, etc.)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ApiError(Exception):
    """Raised on enveloped errors (data=null, error.code/message)
    or non-2xx HTTP responses from Huudis APIs."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int,
        *,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.request_id = request_id
        self.details = details

    def __repr__(self) -> str:
        return f"ApiError({self.code!r}, {self.message!r}, status={self.status})"
