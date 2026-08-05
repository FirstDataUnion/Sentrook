"""HTTP helpers for Sentrook library sync and OIDC discovery.

``urllib.request.urlopen`` inherits ``HTTP(S)_PROXY`` from the environment.
Cursor sandboxes and some CI images inject a localhost proxy that returns 403
for external HTTPS, which breaks Rookery library sync and identity discovery
even when direct egress would work. These helpers open URLs without env proxies
unless ``SENTROOK_HTTP_USE_ENV_PROXY=1``.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from typing import Any


def _use_env_proxy() -> bool:
    return os.environ.get("SENTROOK_HTTP_USE_ENV_PROXY", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def urlopen(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
) -> Any:
    """Open a URL, bypassing process proxy env by default."""
    if _use_env_proxy():
        return urllib.request.urlopen(request, timeout=timeout)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(request, timeout=timeout)


def read_response_body(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()


__all__ = ["urlopen", "read_response_body"]
