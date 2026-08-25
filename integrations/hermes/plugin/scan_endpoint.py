"""Hosted Sentrook scan base URL (default production)."""

from __future__ import annotations

import os
from typing import Mapping

DEFAULT_SCAN_BASE_URL = "https://sentrook.firstdataunion.org"


def resolve_scan_base_url(
    settings: dict | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve scan base URL from settings, then env, then default.

    ``env`` should be the merged Hermes dotenv view (``env_with_hermes_dotenv``)
    so ``SENTROOK_SCAN_BASE_URL`` in ``~/.hermes/.env`` is honoured even when it
    is not exported into the process environment.
    """
    settings = settings or {}
    env_map = env if env is not None else os.environ
    raw = (
        (settings.get("scan_base_url") or "").strip()
        or str(env_map.get("SENTROOK_SCAN_BASE_URL", "") or "").strip()
        or DEFAULT_SCAN_BASE_URL
    )
    return raw.rstrip("/")
