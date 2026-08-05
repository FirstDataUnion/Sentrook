"""Loopback/in-network HTTP daemon for live shadow scanning.

Built on the standard library only (no extra deps in the sidecar image). The
scanner is created and warmed once at startup; each ``POST /scan`` reuses it.
In shadow mode the response always reports ``block: false``; in enforce mode
``block`` and review metadata reflect the scanner decision.
"""

from __future__ import annotations

import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic import ValidationError

from sentrook import __version__
from sentrook.shadow.auth import scan_auth_health_label, verify_scan_auth
from sentrook.shadow.config import ShadowConfig
from sentrook.shadow.feedback import FeedbackRequest, process_feedback
from sentrook.shadow.latency import LatencyReport, append_latency_log, build_latency_record
from sentrook.shadow.oidc import OIDCError, oidc_enabled, validate_oidc_configuration
from sentrook.shadow.response import build_scan_response
from sentrook.shadow.runtime import ShadowRuntime
from sentrook.shadow.snapshot import ShadowSnapshot

logger = logging.getLogger("sentrook.shadow")

_MAX_BODY_BYTES = 4 * 1024 * 1024


def _should_validate_oidc_at_startup(config: ShadowConfig) -> bool:
    if config.scan_auth_mode == "oidc":
        return oidc_enabled(config)
    # auto/apikey: skip network JWKS check unless explicitly requested (hosted cutover).
    import os

    raw = (os.environ.get("SENTROOK_OIDC_VALIDATE_AT_STARTUP") or "").strip().lower()
    return raw in ("1", "true", "yes", "on") and oidc_enabled(config)


def _make_handler(runtime: ShadowRuntime) -> type[BaseHTTPRequestHandler]:
    class ShadowHandler(BaseHTTPRequestHandler):
        server_version = f"sentrook-shadow/{__version__}"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            logger.debug("%s - %s", self.address_string(), format % args)

        def _write_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") in ("/health", "/healthz"):
                self._write_json(200, runtime.health_payload())
                return
            self._write_json(404, {"error": "not found"})

        def _require_scan_auth(self) -> bool:
            result = verify_scan_auth(runtime.config, self.headers)
            if result.ok:
                return True
            status = 403 if result.error == "insufficient_scope" else 401
            detail = (
                "insufficient scope"
                if result.error == "insufficient_scope"
                else "unauthorized"
            )
            self._write_json(status, {"error": detail})
            return False

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.rstrip("/")
            if path in ("/scan", "/feedback", "/latency") and not self._require_scan_auth():
                return
            if path == "/scan":
                self._handle_scan()
                return
            if path == "/feedback":
                self._handle_feedback()
                return
            if path == "/latency":
                self._handle_latency()
                return
            self._write_json(404, {"error": "not found"})

        def _read_json_body(self) -> tuple[dict | None, int | None]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > _MAX_BODY_BYTES:
                return None, 400
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                self._write_json(400, {"error": f"bad json: {exc}"})
                return None, None
            if not isinstance(payload, dict):
                self._write_json(400, {"error": "body must be a json object"})
                return None, None
            return payload, None

        def _handle_scan(self) -> None:
            started = time.perf_counter()
            raw_payload, error_status = self._read_json_body()
            if error_status is not None:
                if raw_payload is None:
                    self._write_json(error_status, {"error": "missing or oversized body"})
                return
            assert raw_payload is not None

            try:
                snapshot = ShadowSnapshot.model_validate(raw_payload)
            except ValidationError as exc:
                self._write_json(422, {"error": "invalid snapshot", "detail": exc.errors()})
                return

            snapshot, _sanitize_ms = runtime.prepare_snapshot(snapshot)

            try:
                result = runtime.scanner.scan(snapshot)
                request_ms = int((time.perf_counter() - started) * 1000)
                result, record = runtime.log_scan(snapshot, result, request_ms=request_ms)
                payload = build_scan_response(
                    runtime.config, result, record, request_ms=request_ms
                )
            except Exception as exc:
                logger.exception("shadow scan failed")
                from sentrook.shadow.log import build_log_record

                try:
                    result = runtime.scanner.scan(snapshot)
                    request_ms = int((time.perf_counter() - started) * 1000)
                    record = build_log_record(
                        result,
                        snapshot,
                        mode=runtime.config.mode,
                        request_ms=request_ms,
                        sanitize_log_fields=runtime.config.server_sanitize_snapshots,
                    )
                    payload = build_scan_response(
                        runtime.config,
                        result,
                        record,
                        error=f"scan failed: {exc}",
                        request_ms=request_ms,
                    )
                except Exception:
                    self._write_json(
                        200,
                        {
                            "block": False,
                            "decision": "allow",
                            "error": f"scan failed: {exc}",
                        },
                    )
                    return

            self._write_json(200, payload)

        def _handle_latency(self) -> None:
            raw_payload, error_status = self._read_json_body()
            if error_status is not None:
                if raw_payload is None:
                    self._write_json(error_status, {"error": "missing or oversized body"})
                return
            assert raw_payload is not None

            try:
                report = LatencyReport.model_validate(raw_payload)
            except ValidationError as exc:
                self._write_json(422, {"error": "invalid latency report", "detail": exc.errors()})
                return

            try:
                append_latency_log(
                    runtime.config.latency_log_path,
                    build_latency_record(report),
                )
            except Exception as exc:
                logger.exception("latency log append failed")
                self._write_json(500, {"error": f"latency log failed: {exc}"})
                return

            self._write_json(200, {"status": "ok"})

        def _handle_feedback(self) -> None:
            raw_payload, error_status = self._read_json_body()
            if error_status is not None:
                if raw_payload is None:
                    self._write_json(error_status, {"error": "missing or oversized body"})
                return
            assert raw_payload is not None

            try:
                request = FeedbackRequest.model_validate(raw_payload)
            except ValidationError as exc:
                self._write_json(422, {"error": "invalid feedback", "detail": exc.errors()})
                return

            try:
                result = process_feedback(runtime.config, request)
            except Exception as exc:
                logger.exception("feedback processing failed")
                runtime.note_feedback(
                    {
                        "status": "feedback_error",
                        "reason": str(exc),
                    },
                    resolution=request.resolution,
                )
                self._write_json(500, {"error": f"feedback failed: {exc}"})
                return

            runtime.note_feedback(result, resolution=request.resolution)
            logger.info(
                "feedback resolution=%s status=%s rule_ids=%s reason=%s submission_id=%s",
                request.resolution,
                result.get("status") or result.get("feedback_status"),
                result.get("rule_ids") or result.get("rule_id") or "-",
                result.get("reason") or result.get("feedback_reason") or "-",
                result.get("submission_id") or "-",
            )

            if result.get("reload_recommended"):
                try:
                    runtime.reload_from_disk()
                except Exception as exc:
                    logger.warning("personal corpus reload failed: %s", exc)
                    result["reload_error"] = str(exc)

            self._write_json(200, result)

    return ShadowHandler


def serve(config: ShadowConfig | None = None) -> None:
    config = config or ShadowConfig.from_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if _should_validate_oidc_at_startup(config):
        try:
            validate_oidc_configuration(config)
        except OIDCError as exc:
            logger.error("OIDC configuration invalid: %s", exc)
            raise SystemExit(1) from exc

    logger.info(
        "sentrook shadow starting: mode=%s rules=%s corpus=%s l3=%s log=%s library=%s feedback=%s scan_auth=%s server_sanitize=%s",
        config.mode,
        config.rules_path,
        config.resolved_corpus_dir(),
        config.l3_policy.value,
        config.log_path,
        config.library_url or "(local only)",
        config.feedback.mode,
        scan_auth_health_label(config),
        config.server_sanitize_snapshots,
    )
    runtime = ShadowRuntime(config)
    runtime.install_signal_handlers()
    runtime.start_background_sync()
    logger.info(
        "scanner warm: %d rules, %d corpus rules; listening on %s:%d",
        len(runtime.rules),
        len(runtime.corpus),
        config.host,
        config.port,
    )

    httpd = ThreadingHTTPServer((config.host, config.port), _make_handler(runtime))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        runtime.stop_background_sync()
        httpd.server_close()
