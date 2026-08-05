"""OAuth token data structures shared by the OIDC client and token store."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

EXPIRY_SKEW_SECONDS = 60


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: float
    scope: str

    def is_expired(self, *, skew_seconds: float = EXPIRY_SKEW_SECONDS) -> bool:
        return time.time() >= (self.expires_at - skew_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenSet:
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=float(data["expires_at"]),
            scope=data.get("scope", ""),
        )

    @classmethod
    def from_token_response(cls, payload: dict[str, Any]) -> TokenSet:
        expires_in = float(payload.get("expires_in", 1800))
        return cls(
            access_token=payload["access_token"],
            refresh_token=payload.get("refresh_token"),
            expires_at=time.time() + expires_in,
            scope=payload.get("scope", ""),
        )
