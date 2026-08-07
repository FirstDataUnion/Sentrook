"""Environment-driven configuration for the scan serve sidecar.

Operators configure the live hook through ``SENTROOK_*`` env vars so the same image
behaves correctly whether it runs as a sidecar container, a host daemon, or a
one-shot CLI. Defaults mirror the rest of Sentrook (``tie_breaker`` L3, repo/home
rules and corpus discovery).

Logging privacy (disk):

- ``SENTROOK_ENV=production`` defaults ``SENTROOK_LOG_CONTENT=metadata`` (no
  PlanIR intent/command excerpts in ``scan.log.jsonl``) and refuses to start
  unless sanitize stays on.
- Development defaults to ``scrubbed`` (pattern redaction only — not a PII
  guarantee). Use ``full`` only for local debugging.
- ``SENTROOK_LOG_LEVEL`` controls stdlib verbosity (HTTP access lines are DEBUG).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from sentrook.config import L3Config, L3Policy, ScannerConfig
from sentrook.corpus.loader import resolve_corpus_dir
from sentrook.corpus.personal import resolve_personal_corpus_dir
from sentrook.library.paths import DEFAULT_LIBRARY_DIR
from sentrook.serve.bundle import resolve_bundle_version
from sentrook.serve.oidc import DEFAULT_OIDC_AUDIENCE, DEFAULT_OIDC_ISSUER, normalize_oidc_url

DEFAULT_RULES_DIR = Path.home() / ".sentrook" / "rules"
DEFAULT_LOG_PATH = Path.home() / ".sentrook" / "scan.log.jsonl"
DEFAULT_LATENCY_LOG_PATH = Path.home() / ".sentrook" / "latency.log.jsonl"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9099
DEFAULT_LIBRARY_SYNC_INTERVAL_SEC = 86_400
DEFAULT_PERSONAL_CORPUS_DIR = Path.home() / ".sentrook" / "personal-corpus"
DEFAULT_OIDC_JWKS_CACHE_SECONDS = 300
VALID_SCAN_AUTH_MODES = frozenset({"auto", "oidc", "apikey"})
# Disk scan-log content policy. ``metadata`` omits PlanIR free text (intent /
# command excerpts) so production hosts can guarantee no submission prose on disk.
# ``scrubbed`` keeps pattern-redacted text (not a PII guarantee). ``full`` is
# developer-only and writes unsanitized excerpts.
VALID_LOG_CONTENT_MODES = frozenset({"metadata", "scrubbed", "full"})
VALID_ENVIRONMENTS = frozenset({"production", "development"})
VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _env_bool(env: dict[str, str], key: str, *, default: bool = False) -> bool:
    raw = (env.get(key) or "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _parse_environment(raw: str | None) -> str:
    """Normalize SENTROOK_ENV to production | development (default development)."""
    value = (raw or "").strip().lower()
    if value in ("production", "prod"):
        return "production"
    if value in ("development", "dev", ""):
        return "development"
    if value in VALID_ENVIRONMENTS:
        return value
    return "development"


def _parse_log_content(raw: str | None, *, environment: str) -> str:
    value = (raw or "").strip().lower()
    if value in VALID_LOG_CONTENT_MODES:
        return value
    # Production defaults to metadata-only disk logs (zero free-text from PlanIR).
    if environment == "production":
        return "metadata"
    return "scrubbed"


def _parse_log_level(raw: str | None) -> str:
    value = (raw or "INFO").strip().upper()
    if value in VALID_LOG_LEVELS:
        return value
    return "INFO"


@dataclass
class FeedbackConfig:
    """Corpus submission from live reviews (plugin consent + server mode).

    ``mode`` is operator-controlled on the scan host (``SENTROOK_FEEDBACK_MODE``).
    The OpenClaw plugin separately gates whether review resolutions are POSTed
    via ``feedback.mode`` / configure ``contributeCorpus`` (default contribute,
    user may opt out).

    ``derive_intent`` replaces prompt-as-intent with a trajectory-derived string
    before Rookery submit (privacy). See ADR — Derived Intent for Community
    Feedback. Toggle with ``SENTROOK_FEEDBACK_DERIVE_INTENT``.
    """

    mode: str = "off"  # off | submit
    rookery_url: str | None = None
    max_excerpt_chars: int = 200
    derive_intent: bool = True


@dataclass
class ServeConfig:
    """Resolved observe/enforce serve settings."""

    mode: str = "observe"
    rules_path: Path = DEFAULT_RULES_DIR
    corpus_dir: Path | None = None
    log_path: Path = DEFAULT_LOG_PATH
    latency_log_path: Path = DEFAULT_LATENCY_LOG_PATH
    l3_policy: L3Policy = L3Policy.TIE_BREAKER
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    bundle_version: str | None = None
    library_url: str | None = None
    library_dir: Path = DEFAULT_LIBRARY_DIR
    library_sync_interval_sec: int = DEFAULT_LIBRARY_SYNC_INTERVAL_SEC
    rookery_api_key: str | None = None
    scan_api_key: str | None = None
    scan_auth_mode: str = "auto"  # auto | oidc | apikey
    oidc_issuer: str = DEFAULT_OIDC_ISSUER
    oidc_audience: str = DEFAULT_OIDC_AUDIENCE
    oidc_jwks_url: str = ""
    oidc_jwks_cache_seconds: int = DEFAULT_OIDC_JWKS_CACHE_SECONDS
    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    personal_corpus_dir: Path | None = DEFAULT_PERSONAL_CORPUS_DIR
    personal_corpus_enabled: bool = True
    server_sanitize_planir: bool = True
    #: deployment profile: production | development (from SENTROOK_ENV).
    environment: str = "development"
    #: What free text from PlanIR may be written to scan.log.jsonl.
    log_content: str = "scrubbed"  # metadata | scrubbed | full
    #: Stdlib logger level for sentrook.serve (access lines are DEBUG).
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ServeConfig:
        env = env if env is not None else dict(os.environ)

        rules = env.get("SENTROOK_RULES")
        corpus = env.get("SENTROOK_CORPUS")
        log_path = env.get("SENTROOK_LOG_PATH")
        latency_log_path = env.get("SENTROOK_LATENCY_LOG_PATH")
        policy_raw = env.get("SENTROOK_L3_POLICY")
        bundle_raw = env.get("SENTROOK_BUNDLE_VERSION")
        library_url = env.get("SENTROOK_LIBRARY_URL") or None
        library_dir_raw = env.get("SENTROOK_LIBRARY_DIR")
        sync_interval_raw = env.get("SENTROOK_LIBRARY_SYNC_INTERVAL_SEC")

        rules_path = Path(rules).expanduser() if rules else DEFAULT_RULES_DIR
        bundle_version = bundle_raw or resolve_bundle_version(rules_path)
        library_dir = Path(library_dir_raw).expanduser() if library_dir_raw else DEFAULT_LIBRARY_DIR
        sync_interval = (
            int(sync_interval_raw) if sync_interval_raw else DEFAULT_LIBRARY_SYNC_INTERVAL_SEC
        )
        feedback_mode = env.get("SENTROOK_FEEDBACK_MODE", "off")
        # Alias: queue previously wrote a local JSONL; always submit now.
        if feedback_mode == "queue":
            feedback_mode = "submit"
        # Prefer an explicit feedback URL; fall back to the library sync base
        # so hosted deploys need only SENTROOK_LIBRARY_URL for pull + submit.
        feedback_url = (
            env.get("SENTROOK_FEEDBACK_ROOKERY_URL") or env.get("SENTROOK_LIBRARY_URL") or None
        )
        feedback_excerpt = env.get("SENTROOK_FEEDBACK_MAX_EXCERPT_CHARS")
        rookery_api_key = (env.get("SENTROOK_ROOKERY_API_KEY") or "").strip() or None
        scan_api_key = (env.get("SENTROOK_SCAN_API_KEY") or "").strip() or None
        auth_mode_raw = (env.get("SENTROOK_SCAN_AUTH_MODE") or "auto").strip().lower()
        scan_auth_mode = auth_mode_raw if auth_mode_raw in VALID_SCAN_AUTH_MODES else "auto"
        oidc_issuer = (
            normalize_oidc_url(env.get("SENTROOK_OIDC_ISSUER") or DEFAULT_OIDC_ISSUER)
            or DEFAULT_OIDC_ISSUER
        )
        oidc_audience = (env.get("SENTROOK_OIDC_AUDIENCE") or DEFAULT_OIDC_AUDIENCE).strip() or (
            DEFAULT_OIDC_AUDIENCE
        )
        oidc_jwks_url = normalize_oidc_url(env.get("SENTROOK_OIDC_JWKS_URL") or "")
        jwks_cache_raw = env.get("SENTROOK_OIDC_JWKS_CACHE_SECONDS")
        personal_corpus_raw = env.get("SENTROOK_PERSONAL_CORPUS_DIR")
        personal_enabled_raw = (env.get("SENTROOK_PERSONAL_CORPUS_ENABLED") or "").strip().lower()
        personal_corpus_enabled = personal_enabled_raw not in ("0", "false", "no")
        environment = _parse_environment(env.get("SENTROOK_ENV"))
        log_content = _parse_log_content(env.get("SENTROOK_LOG_CONTENT"), environment=environment)
        log_level = _parse_log_level(env.get("SENTROOK_LOG_LEVEL"))

        return cls(
            mode=env.get("SENTROOK_MODE", "observe"),
            rules_path=rules_path,
            corpus_dir=Path(corpus).expanduser() if corpus else None,
            log_path=Path(log_path).expanduser() if log_path else DEFAULT_LOG_PATH,
            latency_log_path=(
                Path(latency_log_path).expanduser()
                if latency_log_path
                else (
                    Path(log_path).expanduser().parent / "latency.log.jsonl"
                    if log_path
                    else DEFAULT_LATENCY_LOG_PATH
                )
            ),
            l3_policy=L3Policy(policy_raw) if policy_raw else L3Policy.TIE_BREAKER,
            host=env.get("SENTROOK_SCAN_HOST", DEFAULT_HOST),
            port=int(env.get("SENTROOK_SCAN_PORT", str(DEFAULT_PORT))),
            bundle_version=bundle_version,
            library_url=library_url,
            library_dir=library_dir,
            library_sync_interval_sec=sync_interval,
            rookery_api_key=rookery_api_key,
            scan_api_key=scan_api_key,
            scan_auth_mode=scan_auth_mode,
            oidc_issuer=oidc_issuer,
            oidc_audience=oidc_audience,
            oidc_jwks_url=oidc_jwks_url,
            oidc_jwks_cache_seconds=(
                int(jwks_cache_raw) if jwks_cache_raw else DEFAULT_OIDC_JWKS_CACHE_SECONDS
            ),
            feedback=FeedbackConfig(
                mode=feedback_mode,
                rookery_url=feedback_url,
                max_excerpt_chars=int(feedback_excerpt) if feedback_excerpt else 200,
                derive_intent=_env_bool(env, "SENTROOK_FEEDBACK_DERIVE_INTENT", default=True),
            ),
            personal_corpus_dir=Path(personal_corpus_raw).expanduser()
            if personal_corpus_raw
            else DEFAULT_PERSONAL_CORPUS_DIR,
            personal_corpus_enabled=personal_corpus_enabled,
            server_sanitize_planir=_env_bool(env, "SENTROOK_SERVER_SANITIZE_PLANIR", default=True),
            environment=environment,
            log_content=log_content,
            log_level=log_level,
        )

    def resolved_corpus_dir(self) -> Path:
        return resolve_corpus_dir(
            str(self.corpus_dir) if self.corpus_dir else L3Config().corpus_dir
        )

    def resolved_personal_corpus_dir(self) -> Path | None:
        if not self.personal_corpus_enabled:
            return None
        return resolve_personal_corpus_dir(self.personal_corpus_dir)

    def scanner_config(self) -> ScannerConfig:
        return ScannerConfig(
            l3_policy=self.l3_policy,
            l3=L3Config(corpus_dir=str(self.resolved_corpus_dir())),
        )


def validate_production_logging(config: ServeConfig) -> list[str]:
    """Return hard errors when production logging cannot guarantee no PlanIR prose on disk."""
    if config.environment != "production":
        return []
    errors: list[str] = []
    if not config.server_sanitize_planir:
        errors.append(
            "production requires SENTROOK_SERVER_SANITIZE_PLANIR=1 "
            "(ingress must sanitize before scan/log)"
        )
    if config.log_content != "metadata":
        errors.append(
            "production requires SENTROOK_LOG_CONTENT=metadata "
            "(omit intent/command excerpts from scan.log.jsonl; "
            "pattern scrubbing is not a PII guarantee)"
        )
    return errors
