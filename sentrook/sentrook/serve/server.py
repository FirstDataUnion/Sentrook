"""Loopback/in-network HTTP daemon for live scan serving.

Built on the standard library HTTP server (no Flask/FastAPI). The scanner is
created and warmed once at startup; each ``POST /scan`` reuses it.
Prometheus metrics are exposed at ``GET /metrics`` via ``prometheus_client``.
In observe mode the response always reports ``block: false``; in enforce mode
``block`` and review metadata reflect the scanner decision.
"""

from __future__ import annotations

import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic import ValidationError

from sentrook import __version__
from sentrook.planir import PlanIR
from sentrook.serve.auth import scan_auth_health_label, verify_scan_auth
from sentrook.serve.config import ServeConfig, validate_production_logging
from sentrook.serve.feedback import FeedbackRequest, process_feedback
from sentrook.serve.latency import LatencyReport, append_latency_log, build_latency_record
from sentrook.serve.metrics import (
    CONTENT_TYPE,
    endpoint_label,
    exposition,
    record_fail_open,
    record_http,
    record_oidc_scan_caller,
    record_plugin_e2e_ms,
    refresh_from_runtime,
)
from sentrook.serve.oidc import OIDCError, oidc_enabled, validate_oidc_configuration
from sentrook.serve.rate_limit import check_request, rate_limit_headers
from sentrook.serve.response import build_scan_response
from sentrook.serve.runtime import ServeRuntime

logger = logging.getLogger("sentrook.serve")

_MAX_BODY_BYTES = 4 * 1024 * 1024


def _configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")
    # basicConfig is a no-op if already configured (e.g. tests); force our level.
    logging.getLogger().setLevel(level)
    logger.setLevel(level)


def _should_validate_oidc_at_startup(config: ServeConfig) -> bool:
    if config.scan_auth_mode == "oidc":
        return oidc_enabled(config)
    # auto/apikey: skip network JWKS check unless explicitly requested (hosted cutover).
    import os

    raw = (os.environ.get("SENTROOK_OIDC_VALIDATE_AT_STARTUP") or "").strip().lower()
    return raw in ("1", "true", "yes", "on") and oidc_enabled(config)


def _make_handler(runtime: ServeRuntime) -> type[BaseHTTPRequestHandler]:
    class ServeHandler(BaseHTTPRequestHandler):
        server_version = f"sentrook-scan/{__version__}"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            logger.debug("%s - %s", self.address_string(), format % args)

        def _write_json(
            self, status: int, payload: dict, extra_headers: dict[str, str] | None = None
        ) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if extra_headers:
                for name, value in extra_headers.items():
                    self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            self._record_http(status)

        def _record_http(self, status: int) -> None:
            started = getattr(self, "_metrics_started", None)
            endpoint = getattr(self, "_metrics_endpoint", None)
            if started is None or endpoint is None:
                return
            record_http(
                self.command,
                endpoint,
                status,
                time.perf_counter() - started,
            )
            self._metrics_started = None

        def _write_metrics(self) -> None:
            refresh_from_runtime(runtime)
            body = exposition()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._metrics_started = time.perf_counter()
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            self._metrics_endpoint = endpoint_label(path)
            if path in ("/health", "/healthz"):
                self._write_json(200, runtime.health_payload())
                return
            if path == "/metrics":
                self._write_metrics()
                return
            self._write_json(404, {"error": "not found"})

        def _require_scan_auth(self):
            result = verify_scan_auth(runtime.config, self.headers)
            if not result.ok:
                status = 403 if result.error == "insufficient_scope" else 401
                detail = (
                    "insufficient scope" if result.error == "insufficient_scope" else "unauthorized"
                )
                self._write_json(status, {"error": detail})
                return None
            decision = check_request(
                runtime.limiter,
                result,
                self.path,
                enabled=runtime.config.rate_limit_enabled,
                scan_rate=runtime.config.rate_limit_scan_rate,
                scan_burst=runtime.config.rate_limit_scan_burst,
                aux_rate=runtime.config.rate_limit_aux_rate,
                aux_burst=runtime.config.rate_limit_aux_burst,
            )
            if decision is not None and not decision.allowed:
                self._write_json(
                    429,
                    {"error": "rate limited"},
                    extra_headers=dict(rate_limit_headers(decision)),
                )
                return None
            return result

        def do_POST(self) -> None:  # noqa: N802
            self._metrics_started = time.perf_counter()
            path = self.path.split("?", 1)[0].rstrip("/")
            self._metrics_endpoint = endpoint_label(path)
            if path in ("/scan", "/feedback", "/latency"):
                auth = self._require_scan_auth()
                if auth is None:
                    return
                if path == "/scan" and auth.method == "oidc":
                    record_oidc_scan_caller(runtime.caller_mix, auth.caller_id)
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
            # None payload: either already responded (bad JSON / non-object) or
            # length error (caller must write). Never assert — ThreadingHTTPServer
            # would print a noisy traceback after a successful 400.
            if raw_payload is None:
                if error_status is not None:
                    self._write_json(error_status, {"error": "missing or oversized body"})
                return

            try:
                plan = PlanIR.model_validate(raw_payload)
            except ValidationError as exc:
                self._write_json(422, {"error": "invalid planir", "detail": exc.errors()})
                return

            plan, _sanitize_ms = runtime.prepare_plan(plan)

            try:
                result = runtime.scanner.scan(plan)
                request_ms = int((time.perf_counter() - started) * 1000)
                result, record = runtime.log_scan(plan, result, request_ms=request_ms)
                payload = build_scan_response(runtime.config, result, record, request_ms=request_ms)
            except Exception as exc:
                logger.exception("scan request failed")
                from sentrook.serve.log import build_log_record

                try:
                    result = runtime.scanner.scan(plan)
                    request_ms = int((time.perf_counter() - started) * 1000)
                    record = build_log_record(
                        result,
                        plan,
                        mode=runtime.config.mode,
                        request_ms=request_ms,
                        sanitize_log_fields=runtime.config.server_sanitize_planir,
                        log_content=runtime.config.log_content,
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
                    record_fail_open()
                    return

            if payload.get("error"):
                record_fail_open()
            self._write_json(200, payload)

        def _handle_latency(self) -> None:
            raw_payload, error_status = self._read_json_body()
            if raw_payload is None:
                if error_status is not None:
                    self._write_json(error_status, {"error": "missing or oversized body"})
                return

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

            record_plugin_e2e_ms(report.plugin_e2e_ms)
            self._write_json(200, {"status": "ok"})

        def _handle_feedback(self) -> None:
            raw_payload, error_status = self._read_json_body()
            if raw_payload is None:
                if error_status is not None:
                    self._write_json(error_status, {"error": "missing or oversized body"})
                return

            try:
                request = FeedbackRequest.model_validate(raw_payload)
            except ValidationError as exc:
                self._write_json(422, {"error": "invalid feedback", "detail": exc.errors()})
                return

            try:
                result = process_feedback(
                    runtime.config,
                    request,
                    session_caps=runtime.feedback_session_caps,
                )
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

    return ServeHandler


def serve(config: ServeConfig | None = None) -> None:
    if config is None:
        from sentrook.openbao import OpenBaoError

        try:
            config = ServeConfig.from_env_with_openbao()
        except OpenBaoError as exc:
            logger.error("OpenBao secret load failed: %s", exc)
            raise SystemExit(1) from exc
    _configure_logging(config.log_level)

    logging_errors = validate_production_logging(config)
    if logging_errors:
        for err in logging_errors:
            logger.error("refusing to start: %s", err)
        raise SystemExit(1)

    if config.log_content == "full":
        logger.warning(
            "SENTROOK_LOG_CONTENT=full writes unsanitized PlanIR intent/command "
            "excerpts to scan.log.jsonl — development only"
        )
    elif config.log_content == "scrubbed":
        logger.info(
            "scan log content=scrubbed (pattern redaction only; not a PII guarantee). "
            "Use SENTROOK_ENV=production / SENTROOK_LOG_CONTENT=metadata for "
            "metadata-only disk logs."
        )

    if _should_validate_oidc_at_startup(config):
        try:
            validate_oidc_configuration(config)
        except OIDCError as exc:
            logger.error("OIDC configuration invalid: %s", exc)
            raise SystemExit(1) from exc

    logger.info(
        "sentrook serve starting: env=%s mode=%s rules=%s corpus=%s l3=%s log=%s "
        "log_content=%s log_level=%s library=%s feedback=%s scan_auth=%s "
        "rate_limit=%s server_sanitize=%s",
        config.environment,
        config.mode,
        config.rules_path,
        config.resolved_corpus_dir(),
        config.l3_policy.value,
        config.log_path,
        config.log_content,
        config.log_level,
        config.library_url or "(local only)",
        config.feedback.mode,
        scan_auth_health_label(config),
        (
            f"{config.rate_limit_scan_rate:g}r/s burst={config.rate_limit_scan_burst}"
            if config.rate_limit_enabled
            else "off"
        ),
        config.server_sanitize_planir,
    )
    runtime = ServeRuntime(config)
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
