"""Resolve the rules/corpus bundle version for shadow logging."""

from __future__ import annotations

import json
from pathlib import Path

from sentrook.library.paths import DEFAULT_LIBRARY_DIR, MANIFEST_FILENAME


def resolve_bundle_version(rules_path: Path) -> str | None:
    """Read ``bundle_version`` from ``manifest.json`` near *rules_path*, if present."""
    rules_path = rules_path.expanduser().resolve()
    candidates = [
        rules_path.parent / MANIFEST_FILENAME,
        rules_path / MANIFEST_FILENAME,
        DEFAULT_LIBRARY_DIR / MANIFEST_FILENAME,
    ]
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        version = data.get("bundle_version")
        if isinstance(version, str) and version:
            return version
    return None
