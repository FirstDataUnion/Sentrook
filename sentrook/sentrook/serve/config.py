"""Serve configuration from `SENTROOK_*` environment variables.

Operators configure one image through the environment. Secrets (`SENTROOK_JEV_API_KEY`,
`SENTROOK_STATE_KEY`, `SENTROOK_ORACLE_API_KEY`) only ever come from here: either the variable itself or
`<NAME>_FILE`, a path to a file holding the value (for secrets rendered to files by a secrets agent, so
they stay out of the process environment). Setting both is an error, and so is a `_FILE` path that
cannot be read; the file is read once, at startup.

Scan auth (`SENTROOK_SCAN_AUTH_MODE`):
- `oidc`: every scan route needs a FIDU ID bearer token with the `sentrook.scan` scope, verified
  against `SENTROOK_OIDC_ISSUER` / `SENTROOK_OIDC_AUDIENCE`. The default when an issuer is set, and
  always the default in production.
- `open`: no authentication, for a local sidecar or a test-mode server. The default in development
  when no issuer is set (the server logs a warning at startup); refused in production.

Probe ablation (`SENTROOK_PROBES`) is a test-mode feature and is refused without
`SENTROOK_TEST_MODE=1`.

Context limits (`prepare.context_limits`) are for evaluation only and likewise refused without test mode: each
request is cut down on arrival as if the plugin had sent less. `SENTROOK_EVAL_INPUT_CAP_BYTES` (each new input and
each tool result in a background save's conversation, in UTF-8 bytes, at least 256), `SENTROOK_EVAL_HISTORY_STEPS`
(the last n history steps, at least 1) and `SENTROOK_EVAL_SELF_EDIT_BODIES` (`keep`, the default, or `drop`: a
background save's user and assistant messages lose their text). Unset, nothing is limited.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..jev.client import DEFAULT_BASE_URL, DEFAULT_MODEL
from ..jev.questions import QUESTIONS_DIR, load_question_set
from ..prepare.context_limits import NO_LIMITS, ContextLimits
from ..prepare.views import VIEW_KIND
from .oidc import normalize_oidc_url

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org"
DEFAULT_OIDC_AUDIENCE = "sentrook"
AUTH_OIDC = "oidc"
AUTH_OPEN = "open"
AUTH_MODES = (AUTH_OIDC, AUTH_OPEN)


class ConfigError(RuntimeError):
    """The serve configuration is invalid or unsafe; raised at construction, before anything runs."""


def _bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = (env.get(key) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    try:
        return float(env.get(key) or default)
    except ValueError:
        return default


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key) or default)
    except ValueError:
        return default


def _limit(env: Mapping[str, str], key: str) -> int | None:
    """An evaluation limit: unset is None; anything but a whole number is an error, never a silent default."""
    raw = (env.get(key) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{key} must be a whole number, got {raw!r}") from None


def _context_limits(env: Mapping[str, str]) -> ContextLimits:
    bodies = (env.get("SENTROOK_EVAL_SELF_EDIT_BODIES") or "keep").strip().lower()
    if bodies not in ("keep", "drop"):
        raise ConfigError(f"SENTROOK_EVAL_SELF_EDIT_BODIES must be keep or drop, got {bodies!r}")
    try:
        return ContextLimits(
            input_cap_bytes=_limit(env, "SENTROOK_EVAL_INPUT_CAP_BYTES"),
            history_steps=_limit(env, "SENTROOK_EVAL_HISTORY_STEPS"),
            self_edit_bodies=bodies == "keep",
        )
    except ValueError as e:
        raise ConfigError(f"context limits: {e}") from None


def _secret(env: Mapping[str, str], key: str) -> str:
    """A secret from `key` or from the file named by `key_FILE` (one of them, never both); stripped."""
    file_key = f"{key}_FILE"
    path = (env.get(file_key) or "").strip()
    if not path:
        return (env.get(key) or "").strip()
    if (env.get(key) or "").strip():
        raise ConfigError(f"set {key} or {file_key}, not both")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        # The path is not secret; the error names it but never the contents.
        raise ConfigError(f"{file_key}: cannot read {path}: {exc.strerror or exc}") from None


def _question_set(env: Mapping[str, str], key: str, default: str, kind: str) -> str:
    """A shipped question set whose view serves `kind` (exposure or call); anything else stops startup."""
    name = (env.get(key) or default).strip()
    known = sorted(p.stem for p in QUESTIONS_DIR.glob("*.json"))
    if name not in known:
        raise RuntimeError(f"{key}: unknown question set {name!r}; known: {', '.join(known)}")
    view = load_question_set(name).state_view
    if VIEW_KIND.get(view) != kind:
        raise RuntimeError(
            f"{key}: question set {name!r} uses view {view!r}, which is not a {kind} view"
        )
    return name


def _selfedit_set(env: Mapping[str, str]) -> str:
    """`SENTROOK_JEV_SELFEDIT_QUESTIONS`: a shipped call-kind set for declared self-edits (default selfedit-v3);
    `none` or `off` sends self-edits to the call set like any other call."""
    raw = (env.get("SENTROOK_JEV_SELFEDIT_QUESTIONS") or "").strip()
    if raw.lower() in ("none", "off"):
        return ""
    return _question_set(env, "SENTROOK_JEV_SELFEDIT_QUESTIONS", "selfedit-v3", "call")


@dataclass(frozen=True)
class ServeConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    environment: str = "development"  # development | production
    log_content: str = "metadata"  # metadata | content (development only)
    log_level: str = "INFO"

    # scan auth
    scan_auth_mode: str = AUTH_OIDC  # oidc | open
    oidc_issuer: str = DEFAULT_OIDC_ISSUER
    oidc_audience: str = DEFAULT_OIDC_AUDIENCE
    oidc_jwks_url: str = ""
    oidc_jwks_cache_seconds: int = 600

    # rate limiting (per caller after auth)
    rate_limit_enabled: bool = False
    rate_limit_scan_rate: float = 5.0
    rate_limit_scan_burst: int = 20

    # pipeline
    state_key: str = ""
    deployment: str | None = None
    jev_base_url: str = DEFAULT_BASE_URL
    jev_api_key: str | None = None
    jev_model: str = DEFAULT_MODEL
    jev_timeout_s: float = 20.0
    # Shipped defaults: the call-v11 / exposure-v2 question sets and conv-v9 (conv-v5 plus the credential-home relief,
    # with the provider host relieved too, and the service-name relief). The frozen v1 sets, the earlier call sets,
    # conv-v1 to conv-v5, conv-v7, conv-v8 and conv-v6 (the attended-owner ceiling, off by default) stay selectable
    # (SENTROOK_JEV_*_QUESTIONS, SENTROOK_CONVERGENCE) for the Jev-only comparison; the library defaults (JevConfig, load_params) keep the frozen v1 reference.
    jev_exposure_question_set: str = "exposure-v2"
    jev_call_question_set: str = "call-v11"
    #: Declared self-edits (the host's own background saves to memory or skills); "" sends them to the call set.
    jev_selfedit_question_set: str = "selfedit-v3"
    oracle_url: str | None = None
    oracle_api_key: str | None = None
    probes: tuple[str, ...] = field(default_factory=tuple)  # empty = all; test mode only
    packs_default: tuple[str, ...] = ("tier1",)
    convergence: str = "conv-v9"
    lists_dir: str | None = None

    # evaluation: requests cut down as if the plugin had sent less (test mode only)
    context_limits: ContextLimits = NO_LIMITS

    # test mode
    test_mode: bool = False

    def __post_init__(self) -> None:
        if self.scan_auth_mode not in AUTH_MODES:
            raise ConfigError(
                f"SENTROOK_SCAN_AUTH_MODE must be one of {', '.join(AUTH_MODES)}, "
                f"got {self.scan_auth_mode!r}"
            )
        if self.production and self.scan_auth_mode == AUTH_OPEN:
            raise ConfigError("SENTROOK_SCAN_AUTH_MODE=open is not allowed in production")
        if self.scan_auth_mode == AUTH_OIDC and not normalize_oidc_url(self.oidc_issuer):
            raise ConfigError("SENTROOK_SCAN_AUTH_MODE=oidc needs a valid SENTROOK_OIDC_ISSUER")
        if self.test_mode and self.production:
            raise ConfigError("SENTROOK_TEST_MODE cannot be enabled in production")
        if self.probes and not self.test_mode:
            raise ConfigError(
                "SENTROOK_PROBES (probe ablation) is only available in test mode: "
                "set SENTROOK_TEST_MODE=1 or unset SENTROOK_PROBES"
            )
        if not self.context_limits.unlimited and not self.test_mode:
            raise ConfigError(
                "context limits (SENTROOK_EVAL_*) are only available in test mode: "
                "set SENTROOK_TEST_MODE=1 or unset them"
            )

    @property
    def production(self) -> bool:
        return self.environment == "production"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServeConfig:
        env = os.environ if env is None else env
        environment = (env.get("SENTROOK_ENV") or "development").strip().lower()
        environment = "production" if environment in ("prod", "production") else "development"
        log_content = (env.get("SENTROOK_LOG_CONTENT") or "metadata").strip().lower()
        if environment == "production":
            log_content = "metadata"
        state_key = _secret(env, "SENTROOK_STATE_KEY")
        if not state_key:
            # A missing key would make every token invalid across restarts; in development mint one so
            # the local loop works, but never in production.
            if environment == "production":
                raise ConfigError("SENTROOK_STATE_KEY is required in production")
            state_key = secrets.token_hex(32)
        probes_raw = (env.get("SENTROOK_PROBES") or "").strip()
        packs_raw = (env.get("SENTROOK_PACKS_DEFAULT") or "tier1").strip()
        test_mode = _bool(env, "SENTROOK_TEST_MODE", False)
        oidc_issuer = (env.get("SENTROOK_OIDC_ISSUER") or "").strip()
        auth_mode = (env.get("SENTROOK_SCAN_AUTH_MODE") or "").strip().lower()
        if not auth_mode:
            auth_mode = AUTH_OIDC if (oidc_issuer or environment == "production") else AUTH_OPEN
        return cls(
            host=env.get("SENTROOK_SCAN_HOST", DEFAULT_HOST),
            port=_int(env, "SENTROOK_SCAN_PORT", DEFAULT_PORT),
            environment=environment,
            log_content=log_content,
            log_level=(env.get("SENTROOK_LOG_LEVEL") or "INFO").upper(),
            scan_auth_mode=auth_mode,
            oidc_issuer=oidc_issuer or DEFAULT_OIDC_ISSUER,
            oidc_audience=(env.get("SENTROOK_OIDC_AUDIENCE") or DEFAULT_OIDC_AUDIENCE).strip(),
            oidc_jwks_url=(env.get("SENTROOK_OIDC_JWKS_URL") or "").strip(),
            oidc_jwks_cache_seconds=_int(env, "SENTROOK_OIDC_JWKS_CACHE_SECONDS", 600),
            rate_limit_enabled=_bool(env, "SENTROOK_RATE_LIMIT_ENABLED", False),
            rate_limit_scan_rate=_float(env, "SENTROOK_RATE_LIMIT_SCAN_RATE", 5.0),
            rate_limit_scan_burst=_int(env, "SENTROOK_RATE_LIMIT_SCAN_BURST", 20),
            state_key=state_key,
            deployment=(env.get("SENTROOK_DEPLOYMENT") or "").strip() or None,
            jev_base_url=(env.get("SENTROOK_JEV_BASE_URL") or DEFAULT_BASE_URL).strip(),
            jev_api_key=_secret(env, "SENTROOK_JEV_API_KEY") or None,
            jev_model=(env.get("SENTROOK_JEV_MODEL") or DEFAULT_MODEL).strip(),
            jev_timeout_s=_float(env, "SENTROOK_JEV_TIMEOUT_MS", 20_000.0) / 1000.0,
            jev_exposure_question_set=_question_set(
                env, "SENTROOK_JEV_EXPOSURE_QUESTIONS", "exposure-v2", "exposure"
            ),
            jev_selfedit_question_set=_selfedit_set(env),
            jev_call_question_set=_question_set(
                env, "SENTROOK_JEV_CALL_QUESTIONS", "call-v11", "call"
            ),
            oracle_url=(env.get("SENTROOK_ORACLE_URL") or "").strip() or None,
            oracle_api_key=_secret(env, "SENTROOK_ORACLE_API_KEY") or None,
            probes=tuple(p.strip() for p in probes_raw.split(",") if p.strip())
            if probes_raw
            else (),
            packs_default=tuple(p.strip() for p in packs_raw.split(",") if p.strip()) or ("tier1",),
            convergence=(env.get("SENTROOK_CONVERGENCE") or "conv-v9").strip(),
            lists_dir=(env.get("SENTROOK_LISTS_DIR") or "").strip() or None,
            context_limits=_context_limits(env),
            test_mode=test_mode,
        )
