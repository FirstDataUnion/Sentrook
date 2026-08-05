from __future__ import annotations

import os
from pathlib import Path

DEFAULT_LIBRARY_DIR = Path.home() / ".sentrook" / "library"
DEFAULT_REGISTRY_URL = "http://127.0.0.1:8080"
MANIFEST_FILENAME = "manifest.json"


def resolve_library_dir() -> Path:
    raw = os.environ.get("SENTROOK_LIBRARY_DIR")
    if raw:
        return Path(raw).expanduser()
    return DEFAULT_LIBRARY_DIR


def resolve_registry_url() -> str:
    return os.environ.get("SENTROOK_LIBRARY_URL") or DEFAULT_REGISTRY_URL
