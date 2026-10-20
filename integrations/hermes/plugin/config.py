"""Plugin configuration: endpoints, credentials, decision policy, storage and grants.

Every value resolves as plugin settings (`plugins.entries.sentrook.settings` in config.yaml), then env
(process env plus the Hermes `.env`), then the default.

Endpoints default to the hosted service. A non-default scan, Rookery or identity URL must be https on a
firstdataunion.org host: a scan URL the agent could redirect would send every tool call somewhere else.
`SENTROOK_DEV_ENDPOINTS=1` (env only) lifts that for local sandboxes and dev stacks. An endpoint that
fails these checks is a configuration error and scans fail closed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SCAN_URL = "https://sentrook.firstdataunion.org"
DEFAULT_ROOKERY_URL = "https://rookery.firstdataunion.org"
DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org"
TRUSTED_ENDPOINT_DOMAIN = "firstdataunion.org"

DEFAULT_REVIEW_AT = 45.0
DEFAULT_BLOCK_AT = 80.0
DEFAULT_SCAN_TIMEOUT_MS = 30_000
DEFAULT_HISTORY_LIMIT = 20
DEFAULT_INPUT_CAP_BYTES = 256 * 1024
DEFAULT_HISTORY_ARGS_CAP_BYTES = 4 * 1024
DEFAULT_TRAFFIC_LOG_MAX_BYTES = 50 * 1024 * 1024

ON_SCAN_ERROR = ("allow", "deny", "review")


@dataclass(frozen=True)
class Endpoint:
    ok: bool
    url: str = ""
    reason: str = ""


@dataclass(frozen=True)
class Endpoints:
    scan: Endpoint
    rookery: Endpoint
    issuer: Endpoint
    dev: bool


@dataclass(frozen=True)
class PluginConfig:
    endpoints: Endpoints
    mode: str
    review_at: float
    block_at: float
    on_scan_error: str
    timeout_ms: int
    state_dir: Path
    traffic_log_enabled: bool
    traffic_log_path: Path
    traffic_log_max_bytes: int
    history_limit: int
    input_cap_bytes: int
    history_args_cap_bytes: int
    packs: list[str]
    attended_platforms: frozenset[str] = frozenset()
    grants: list[dict[str, Any]] = field(default_factory=list)


def hermes_home(env: dict[str, str]) -> Path:
    """`HERMES_HOME` is Hermes's own directory (`~/.hermes`, or `/opt/data` in the Docker image)."""
    explicit = (env.get("HERMES_STATE_DIR") or env.get("HERMES_HOME") or "").strip()
    if explicit:
        return Path(explicit)
    return Path(env.get("HOME", "").strip() or str(Path.home())) / ".hermes"


def resolve_state_dir(env: dict[str, str], override: Any = None) -> Path:
    """`<hermes home>/sentrook`: every plugin-side file lives here (the scanner's guardrail list
    protects the segment)."""
    if isinstance(override, str) and override.strip():
        return Path(override.strip())
    return hermes_home(env) / "sentrook"


def _str(raw: Any) -> str | None:
    return raw.strip() if isinstance(raw, str) and raw.strip() else None


def _bool(raw: Any, fallback: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        v = raw.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    return fallback


def _num(raw: Any, fallback: float, lo: float = 0, hi: float = float("inf")) -> float:
    try:
        n = float(raw) if raw is not None and raw != "" else None
    except (TypeError, ValueError):
        n = None
    if n is None or n != n or n < lo or n > hi:
        return fallback
    return n


def _list(raw: Any) -> list[str]:
    if isinstance(raw, (list, tuple)):
        return [str(v).strip() for v in raw if str(v).strip()]
    if isinstance(raw, str) and raw.strip():
        return [v.strip() for v in raw.split(",") if v.strip()]
    return []


def _trusted_host(host: str) -> bool:
    h = host.lower()
    return h == TRUSTED_ENDPOINT_DOMAIN or h.endswith("." + TRUSTED_ENDPOINT_DOMAIN)


def parse_endpoint(raw: str, dev: bool) -> Endpoint:
    """Rebuild an endpoint from its URL components so config text is never used as a fetch target
    directly. Outside dev mode: https only, firstdataunion.org hosts only, no explicit port."""
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return Endpoint(False, reason=f"invalid URL: {raw[:80]}")
    if parts.scheme not in ("http", "https"):
        return Endpoint(False, reason=f"URL must be http or https (got {parts.scheme or 'none'})")
    if parts.username or parts.password:
        return Endpoint(False, reason="URL must not include credentials")
    host = parts.hostname or ""
    if not host or not all(c.isalnum() or c in "._-:" for c in host):
        return Endpoint(False, reason="URL hostname is invalid")
    if host in ("169.254.169.254", "fd00:ec2::254"):
        return Endpoint(False, reason="URL must not target a metadata address")
    if not dev:
        if parts.scheme != "https":
            return Endpoint(
                False, reason="URL must be https (set SENTROOK_DEV_ENDPOINTS=1 for a local stack)"
            )
        if not _trusted_host(host) or port is not None:
            return Endpoint(
                False,
                reason=f"URL host {host} is not a {TRUSTED_ENDPOINT_DOMAIN} host "
                "(set SENTROOK_DEV_ENDPOINTS=1 for a local stack)",
            )
    netloc = host if port is None else f"{host}:{port}"
    return Endpoint(True, url=f"{parts.scheme}://{netloc}{parts.path}".rstrip("/"))


def resolve_endpoints(cfg: dict[str, Any], env: dict[str, str]) -> Endpoints:
    # Env only: plugin settings are easier for an agent to reach than the gateway's environment.
    dev = _bool(env.get("SENTROOK_DEV_ENDPOINTS"), False)

    def pick(key: str, var: str, default: str) -> Endpoint:
        return parse_endpoint(_str(cfg.get(key)) or _str(env.get(var)) or default, dev)

    return Endpoints(
        scan=pick("scan_url", "SENTROOK_SCAN_URL", DEFAULT_SCAN_URL),
        rookery=pick("rookery_url", "SENTROOK_ROOKERY_URL", DEFAULT_ROOKERY_URL),
        issuer=pick("oidc_issuer", "SENTROOK_OIDC_ISSUER", DEFAULT_OIDC_ISSUER),
        dev=dev,
    )


def _grants(raw: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for g in raw if isinstance(raw, list) else []:
        if not isinstance(g, dict) or not _str(g.get("kind")) or not _str(g.get("pattern")):
            continue
        grant: dict[str, Any] = {
            "kind": g["kind"].strip(),
            "pattern": g["pattern"].strip(),
            "scope": "session" if g.get("scope") == "session" else "persistent",
        }
        if isinstance(g.get("allows"), list):
            grant["allows"] = _list(g["allows"])
        if _str(g.get("granted_at")):
            grant["granted_at"] = g["granted_at"].strip()
        out.append(grant)
    return out


def resolve_config(
    settings: dict[str, Any] | None, env: dict[str, str] | None = None
) -> PluginConfig:
    cfg = settings or {}
    env = dict(os.environ) if env is None else env
    state_dir = resolve_state_dir(env, cfg.get("state_dir"))
    mode = (_str(cfg.get("mode")) or _str(env.get("SENTROOK_MODE")) or "enforce").lower()
    review_at = _num(cfg.get("review_at", env.get("SENTROOK_REVIEW_AT")), DEFAULT_REVIEW_AT, 0, 100)
    block_at = max(
        review_at, _num(cfg.get("block_at", env.get("SENTROOK_BLOCK_AT")), DEFAULT_BLOCK_AT, 0, 101)
    )
    on_error = (
        _str(cfg.get("on_scan_error")) or _str(env.get("SENTROOK_ON_SCAN_ERROR")) or "review"
    ).lower()
    traffic = cfg.get("traffic_log") if isinstance(cfg.get("traffic_log"), dict) else {}
    traffic_path = _str(traffic.get("path")) or _str(env.get("SENTROOK_TRAFFIC_LOG"))
    return PluginConfig(
        endpoints=resolve_endpoints(cfg, env),
        mode="observe" if mode == "observe" else "enforce",
        review_at=review_at,
        block_at=block_at,
        on_scan_error=on_error if on_error in ON_SCAN_ERROR else "review",
        timeout_ms=int(
            _num(
                cfg.get("timeout_ms", env.get("SENTROOK_SCAN_TIMEOUT_MS")),
                DEFAULT_SCAN_TIMEOUT_MS,
                1000,
            )
        ),
        state_dir=state_dir,
        traffic_log_enabled=_bool(
            traffic.get("enabled", env.get("SENTROOK_TRAFFIC_LOG_ENABLED")), True
        ),
        traffic_log_path=Path(traffic_path) if traffic_path else state_dir / "traffic.jsonl",
        traffic_log_max_bytes=int(
            _num(traffic.get("max_bytes"), DEFAULT_TRAFFIC_LOG_MAX_BYTES, 1024)
        ),
        history_limit=int(_num(cfg.get("history_limit"), DEFAULT_HISTORY_LIMIT, 1, 200)),
        input_cap_bytes=int(_num(cfg.get("input_cap_bytes"), DEFAULT_INPUT_CAP_BYTES, 1024)),
        history_args_cap_bytes=int(
            _num(cfg.get("history_args_cap_bytes"), DEFAULT_HISTORY_ARGS_CAP_BYTES, 256)
        ),
        packs=_list(cfg.get("packs")) or ["tier1"],
        attended_platforms=frozenset(
            p.lower()
            for p in _list(cfg.get("attended_platforms") or env.get("SENTROOK_ATTENDED_PLATFORMS"))
        ),
        grants=_grants(cfg.get("grants"))
        + [
            {"kind": "destination", "pattern": p, "scope": "persistent"}
            for p in _list(cfg.get("channel_bindings"))
        ],
    )
