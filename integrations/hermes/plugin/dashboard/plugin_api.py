"""Backend of the Sentrook dashboard tab, mounted by `hermes dashboard` at /api/plugins/sentrook/.

One read-only route, `GET /model`, returns the dashboard model (`dashboard.py`) built from this profile's
traffic log. Hermes loads this file on its own, outside the plugin package, so it loads the plugin's modules
by path under a private package name without running the plugin's `__init__.py` (which hooks into the agent).
Everything is resolved per request: Hermes scopes the dashboard to a profile per request, and
`hermes config set` changes apply without a restart.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import types
from pathlib import Path
from typing import Any

from fastapi import APIRouter

router = APIRouter()

_PLUGIN_DIR = Path(__file__).resolve().parent.parent
_PACKAGE = "_sentrook_dashboard_plugin"


def _module(name: str) -> Any:
    """`dashboard.py` and friends from the plugin directory, as submodules of a bare package."""
    if _PACKAGE not in sys.modules:
        pkg = types.ModuleType(_PACKAGE)
        pkg.__path__ = [str(_PLUGIN_DIR)]
        pkg.__package__ = _PACKAGE
        sys.modules[_PACKAGE] = pkg
    return importlib.import_module(f"{_PACKAGE}.{name}")


def _settings() -> dict[str, Any]:
    """The plugin's settings (`plugins.entries.sentrook.settings`), as the agent's `ctx.get_config` reads them."""
    try:
        from hermes_cli import config as hermes_config
    except ImportError:
        return {}
    load = getattr(hermes_config, "load_config_readonly", None) or getattr(
        hermes_config, "load_config", None
    )
    if load is None:
        return {}
    try:
        data = load() or {}
    except Exception:  # noqa: BLE001 - unreadable config: env and defaults, as the agent falls back
        return {}
    plugins = data.get("plugins") if isinstance(data, dict) else None
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    entry = entries.get("sentrook") if isinstance(entries, dict) else None
    if not isinstance(entry, dict):
        return {}
    for key in ("settings", "config"):
        if isinstance(entry.get(key), dict):
            return entry[key]
    return {}


def _env() -> dict[str, str]:
    """The process env, with this request's profile home when Hermes knows it and no state dir is pinned."""
    env = dict(os.environ)
    if not env.get("HERMES_STATE_DIR"):
        try:
            from hermes_constants import get_hermes_home

            env["HERMES_HOME"] = str(get_hermes_home())
        except Exception:  # noqa: BLE001 - outside Hermes: HERMES_HOME or ~/.hermes, as the agent resolves it
            pass
    return env


def build(n: str | None) -> dict[str, Any]:
    config = _module("config")
    dashboard = _module("dashboard")
    cfg = config.resolve_config(_settings(), _env())
    return dashboard.build_model(cfg, dashboard.limit_of(n))


@router.get("/model")
async def model(n: str | None = None) -> dict[str, Any]:
    # The traffic-log read is blocking file I/O; keep it off the shared event loop.
    return await asyncio.to_thread(build, n)
