"""Scan sidecar runtime: library sync, reload, health, and latency tracking."""

from __future__ import annotations

import logging
import signal
import threading
from datetime import UTC, datetime
from typing import Any

from sentrook import __version__
from sentrook.corpus.models import LoadedRuleCorpus
from sentrook.library.paths import MANIFEST_FILENAME
from sentrook.library.sync import LibraryAuthError, library_status, sync_library
from sentrook.planir import PlanIR
from sentrook.result import ScanResult
from sentrook.sanitize.ingress import maybe_sanitize_planir
from sentrook.serve.auth import oidc_available, scan_auth_health_label
from sentrook.serve.config import ServeConfig
from sentrook.serve.log import ScanLogRecord, append_scan_log, build_log_record
from sentrook.serve.oidc import normalize_oidc_url
from sentrook.serve.service import ScanService
from sentrook.serve.stats import LatencyTracker

logger = logging.getLogger("sentrook.serve")

DEFAULT_SYNC_INTERVAL_SEC = 86_400  # 24 hours


class ServeRuntime:
    """Wraps a warm :class:`ScanService` with ops hooks for long-running serve mode."""

    def __init__(self, config: ServeConfig) -> None:
        self.config = config
        self.scanner = ScanService(config)
        self.scanner.warm()
        self._latency = LatencyTracker()
        self._scan_count = 0
        self._feedback_count = 0
        self._feedback_by_status: dict[str, int] = {}
        self._last_feedback_at: str | None = None
        self._last_feedback_status: str | None = None
        self._last_feedback_reason: str | None = None
        self._last_feedback_resolution: str | None = None
        self._last_sync_at: str | None = None
        self._last_sync_error: str | None = None
        self._last_sync_error_kind: str | None = None
        self._library_auth_action: str | None = None
        self._remote_bundle_version: str | None = None
        self._update_available: bool | None = None
        self._stop = threading.Event()
        self._sync_thread: threading.Thread | None = None
        self._ops_lock = threading.Lock()
        self._seed_last_sync_from_manifest()
        self._refresh_library_status()

    @property
    def scanner_config(self):
        return self.scanner.scanner_config

    @property
    def rules(self):
        return self.scanner.rules

    @property
    def corpus(self):
        return self.scanner.corpus

    def warm(self) -> None:
        self.scanner.warm()

    def prepare_plan(self, plan: PlanIR) -> tuple[PlanIR, int]:
        """Optionally sanitize an ingress PlanIR before scan or feedback."""
        return maybe_sanitize_planir(
            plan,
            enabled=self.config.server_sanitize_planir,
        )

    def scan_and_log(
        self, plan: PlanIR, *, request_ms: int | None = None
    ) -> tuple[ScanResult, ScanLogRecord]:
        result = self.scanner.scan(plan)
        return self.log_scan(plan, result, request_ms=request_ms)

    def log_scan(
        self,
        plan: PlanIR,
        result: ScanResult,
        *,
        request_ms: int | None = None,
    ) -> tuple[ScanResult, ScanLogRecord]:
        self._latency.record(result.timing.total_ms)
        with self._ops_lock:
            self._scan_count += 1
        record = build_log_record(
            result,
            plan,
            mode=self.config.mode,
            bundle_version=self.config.bundle_version,
            request_ms=request_ms,
            sanitize_log_fields=self.config.server_sanitize_planir,
        )
        append_scan_log(self.config.log_path, record)
        return result, record

    def reload_from_disk(self) -> None:
        """Reload rules, corpus, and the L3 scorer from configured paths."""
        with self._ops_lock:
            self.scanner.reload()
        logger.info(
            "scan library reloaded from disk: bundle=%s rules=%d corpus_rules=%d",
            self.config.bundle_version,
            len(self.scanner.rules),
            len(self.scanner.corpus),
        )

    def sync_and_reload(self) -> bool:
        """Pull from Rookery when configured, then reload the warm scanner."""
        updated = False
        with self._ops_lock:
            if self.config.library_url:
                try:
                    result = sync_library(
                        url=self.config.library_url,
                        library_dir=self.config.library_dir,
                        api_key=self.config.rookery_api_key,
                    )
                    updated = result.updated
                    self._last_sync_at = datetime.now(UTC).isoformat()
                    self._clear_sync_error()
                    if result.updated:
                        logger.info(
                            "library sync updated bundle to %s",
                            result.bundle_version,
                        )
                    else:
                        logger.info("library sync: already up to date (%s)", result.bundle_version)
                except Exception as exc:
                    self._record_sync_error(exc)
                    if isinstance(exc, LibraryAuthError):
                        logger.warning("library sync auth failed: %s", exc)
                    else:
                        logger.warning("library sync failed: %s", exc)
                    raise
            else:
                self._last_sync_at = datetime.now(UTC).isoformat()

            self.scanner.reload()
            self._refresh_library_status_unlocked()
        return updated

    def _clear_sync_error(self) -> None:
        self._last_sync_error = None
        self._last_sync_error_kind = None
        self._library_auth_action = None

    def _record_sync_error(self, exc: Exception) -> None:
        self._last_sync_error = str(exc)
        if isinstance(exc, LibraryAuthError):
            self._last_sync_error_kind = exc.error_kind
            self._library_auth_action = exc.action_hint
        else:
            self._last_sync_error_kind = "other"
            self._library_auth_action = None

    def _seed_last_sync_from_manifest(self) -> None:
        manifest = self.config.library_dir / MANIFEST_FILENAME
        if not manifest.is_file():
            return
        mtime = datetime.fromtimestamp(manifest.stat().st_mtime, tz=UTC)
        self._last_sync_at = mtime.isoformat()

    def _refresh_library_status(self) -> None:
        with self._ops_lock:
            self._refresh_library_status_unlocked()

    def _refresh_library_status_unlocked(self) -> None:
        if not self.config.library_url:
            self._remote_bundle_version = None
            self._update_available = None
            return
        try:
            status = library_status(
                url=self.config.library_url,
                library_dir=self.config.library_dir,
                api_key=self.config.rookery_api_key,
            )
            if status.remote_manifest is not None:
                self._remote_bundle_version = status.remote_manifest.bundle_version
            self._update_available = status.update_available
        except LibraryAuthError as exc:
            self._record_sync_error(exc)
            logger.warning("library status auth failed: %s", exc)
        except Exception as exc:
            self._record_sync_error(exc)
            logger.warning("library status check failed: %s", exc)

    def note_feedback(
        self,
        result: dict[str, Any],
        *,
        resolution: str | None = None,
    ) -> None:
        status = str(result.get("status") or result.get("feedback_status") or "unknown")
        reason = result.get("reason") or result.get("feedback_reason")
        with self._ops_lock:
            self._feedback_count += 1
            self._feedback_by_status[status] = self._feedback_by_status.get(status, 0) + 1
            self._last_feedback_at = datetime.now(UTC).isoformat()
            self._last_feedback_status = status
            self._last_feedback_reason = str(reason) if reason else None
            self._last_feedback_resolution = resolution

    def health_payload(self) -> dict[str, Any]:
        latency = self._latency.snapshot()
        corpus_examples = _count_corpus_examples(self.scanner.corpus)
        with self._ops_lock:
            return {
                "status": "ok",
                "mode": self.config.mode,
                "scanner_version": __version__,
                "rules_loaded": len(self.scanner.rules),
                "corpus_rules": len(self.scanner.corpus),
                "corpus_examples": corpus_examples,
                "l3_policy": self.scanner.scanner_config.l3_policy.value,
                "bundle_version": self.config.bundle_version,
                "remote_bundle_version": self._remote_bundle_version,
                "update_available": self._update_available,
                "last_sync_at": self._last_sync_at,
                "last_sync_error": self._last_sync_error,
                "last_sync_error_kind": self._last_sync_error_kind,
                "library_auth_action": self._library_auth_action,
                "library_url": self.config.library_url,
                "library_sync_interval_sec": self.config.library_sync_interval_sec,
                "feedback_mode": self.config.feedback.mode,
                "feedback_rookery_url": self.config.feedback.rookery_url,
                "feedback_derive_intent": self.config.feedback.derive_intent,
                "feedback_count": self._feedback_count,
                "feedback_by_status": dict(self._feedback_by_status),
                "last_feedback_at": self._last_feedback_at,
                "last_feedback_status": self._last_feedback_status,
                "last_feedback_reason": self._last_feedback_reason,
                "last_feedback_resolution": self._last_feedback_resolution,
                "scan_auth": scan_auth_health_label(self.config),
                "oidc_issuer": (
                    normalize_oidc_url(self.config.oidc_issuer)
                    if oidc_available(self.config)
                    else None
                ),
                "oidc_audience": (
                    self.config.oidc_audience if oidc_available(self.config) else None
                ),
                "server_sanitize_planir": self.config.server_sanitize_planir,
                "scan_count": self._scan_count,
                "scan_latency_ms": latency,
            }

    def start_background_sync(self) -> None:
        if not self.config.library_url:
            return
        if self._sync_thread is not None:
            return

        interval = self.config.library_sync_interval_sec

        def _loop() -> None:
            logger.info(
                "background library sync enabled: every %ds from %s",
                interval,
                self.config.library_url,
            )
            while not self._stop.wait(interval):
                try:
                    self.sync_and_reload()
                except Exception:
                    pass  # already logged in sync_and_reload

        self._sync_thread = threading.Thread(
            target=_loop,
            name="sentrook-library-sync",
            daemon=True,
        )
        self._sync_thread.start()

    def stop_background_sync(self) -> None:
        self._stop.set()
        if self._sync_thread is not None:
            self._sync_thread.join(timeout=2)
            self._sync_thread = None

    def install_signal_handlers(self) -> None:
        """Register SIGHUP to trigger sync+reload (Unix only)."""

        def _on_sighup(_signum: int, _frame: object) -> None:
            logger.info("SIGHUP received: syncing library and reloading scanner")
            try:
                if self.config.library_url:
                    self.sync_and_reload()
                else:
                    self.reload_from_disk()
            except Exception as exc:
                logger.warning("SIGHUP reload failed: %s", exc)

        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, _on_sighup)


def _count_corpus_examples(corpus: dict[str, LoadedRuleCorpus]) -> int:
    return sum(len(rule_corpus.pos) + len(rule_corpus.neg) for rule_corpus in corpus.values())
