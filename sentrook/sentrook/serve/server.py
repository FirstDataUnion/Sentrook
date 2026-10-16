"""HTTP daemon (build plan 6.9), stdlib `ThreadingHTTPServer` as in 1.x.

Routes:
- `GET /healthz` (and `/health`), `GET /metrics`.
- `POST /scan`: a PlanIR 2.0 body → Response 2.0. HTTP 200 for `ok` and `degraded`; HTTP 422 with the
  same Response shape (`status: error`) when the body is not a scoreable PlanIR, so the plugin's
  fail-open or fail-closed policy applies to one shape.
- `POST /testnest/scan`: registered only when `SENTROOK_TEST_MODE=1` (build plan section 2):
  `{fixture, state_seed, oracle_seed, options}` → `{response, probes, prepared}`.
Auth and rate limiting run before any scan route.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..enums import ScanStatus
from ..scan import ScanOptions
from .auth import verify_scan_auth
from .config import ServeConfig
from .metrics import CONTENT_TYPE, endpoint_label, exposition, record_http, record_scan
from .rate_limit import check_request, rate_limit_headers
from .runtime import ServeRuntime

logger = logging.getLogger("sentrook.serve")
MAX_BODY_BYTES = 4 * 1024 * 1024
TESTNEST_PATH = "/testnest/scan"


def _parse_clock(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def testnest_options(body: dict[str, Any]) -> ScanOptions:
    opts = body.get("options") or {}
    probes = opts.get("probes")
    return ScanOptions(
        deterministic=bool(opts.get("deterministic", True)),
        clock=_parse_clock(opts.get("clock")) or datetime(2026, 10, 5, 10, 28, tzinfo=UTC),
        salt=str(opts.get("salt") or "testnest"),
        repeat=int(opts["repeat"]) if opts.get("repeat") else None,
        probes_enabled=tuple(probes) if isinstance(probes, list) and probes else None,
        state_seed=body.get("state_seed") or {},
        oracle_seed=body.get("oracle_seed") or {"entities": []},
        deployment=opts.get("deployment"),
    )


def make_handler(runtime: ServeRuntime) -> type[BaseHTTPRequestHandler]:
    config = runtime.config

    class Handler(BaseHTTPRequestHandler):
        server_version = "sentrook-scan/2.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (stdlib signature)
            logger.debug("%s - %s", self.address_string(), format % args)

        # ---------------------------------------------------------------- plumbing
        def _write(
            self,
            status: int,
            payload: dict | bytes,
            content_type: str = "application/json",
            headers: dict[str, str] | None = None,
        ) -> None:
            body = (
                payload
                if isinstance(payload, bytes)
                else json.dumps(payload, ensure_ascii=False).encode("utf-8")
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            started = getattr(self, "_started", None)
            if started is not None:
                record_http(
                    self.command, endpoint_label(self._path), status, time.perf_counter() - started
                )

        def _begin(self) -> None:
            self._started = time.perf_counter()
            self._path = self.path.split("?", 1)[0].rstrip("/") or "/"

        def _drain(self) -> None:
            """Consume an unread body so a keep-alive connection is not left mid-request."""
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if 0 < length <= MAX_BODY_BYTES:
                self.rfile.read(length)

        def _read_json(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_BODY_BYTES:
                self._write(
                    400, {"error": {"code": "bad_request", "message": "missing or oversized body"}}
                )
                return None
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as e:
                self._write(400, {"error": {"code": "bad_json", "message": str(e)}})
                return None
            if not isinstance(payload, dict):
                self._write(
                    400, {"error": {"code": "bad_request", "message": "body must be a JSON object"}}
                )
                return None
            return payload

        def _authorise(self) -> bool:
            result = verify_scan_auth(config, self.headers)
            if not result.ok:
                self._drain()
                status = 403 if result.error == "insufficient_scope" else 401
                self._write(
                    status,
                    {"error": {"code": result.error, "message": result.error.replace("_", " ")}},
                )
                return False
            decision = check_request(
                runtime.limiter,
                result,
                enabled=config.rate_limit_enabled,
                rate=config.rate_limit_scan_rate,
                burst=config.rate_limit_scan_burst,
            )
            if decision is not None and not decision.allowed:
                self._drain()
                self._write(
                    429,
                    {"error": {"code": "rate_limited", "message": "rate limited"}},
                    headers=dict(rate_limit_headers(decision)),
                )
                return False
            return True

        # ---------------------------------------------------------------- routes
        def do_GET(self) -> None:  # noqa: N802
            self._begin()
            if self._path in ("/health", "/healthz"):
                self._write(200, runtime.health_payload())
            elif self._path == "/metrics":
                self._write(200, exposition(), content_type=CONTENT_TYPE)
            else:
                self._write(
                    404, {"error": {"code": "not_found", "message": f"no route GET {self._path}"}}
                )

        def do_POST(self) -> None:  # noqa: N802
            self._begin()
            if self._path == "/scan":
                if self._authorise():
                    self._scan()
            elif self._path == TESTNEST_PATH and config.test_mode:
                if self._authorise():
                    self._testnest_scan()
            else:
                self._drain()
                self._write(
                    404, {"error": {"code": "not_found", "message": f"no route POST {self._path}"}}
                )

        def _scan(self) -> None:
            body = self._read_json()
            if body is None:
                return
            result = runtime.scanner.scan(body, ScanOptions(deployment=config.deployment))
            record_scan(result.response)
            status = 422 if result.response.status is ScanStatus.ERROR else 200
            self._write(status, result.response.model_dump(mode="json"))

        def _testnest_scan(self) -> None:
            body = self._read_json()
            if body is None:
                return
            fixture = body.get("fixture")
            if not isinstance(fixture, dict):
                self._write(
                    400,
                    {
                        "error": {
                            "code": "bad_request",
                            "message": "fixture must be a PlanIR object",
                        }
                    },
                )
                return
            result = runtime.scanner.scan(fixture, testnest_options(body))
            record_scan(result.response)
            status = 422 if result.response.status is ScanStatus.ERROR else 200
            self._write(
                status,
                {
                    "response": result.response.model_dump(mode="json"),
                    "probes": [env.model_dump(mode="json") for env in result.envelopes],
                    "prepared": result.prepared_views,
                },
            )

    return Handler


class ScanServer:
    """A bound server; `start()` serves on a background thread, `serve_forever()` in the foreground."""

    def __init__(self, runtime: ServeRuntime, host: str | None = None, port: int | None = None):
        self.runtime = runtime
        self._httpd = ThreadingHTTPServer(
            (host or runtime.config.host, runtime.config.port if port is None else port),
            make_handler(runtime),
        )
        self._httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._httpd.server_address[0]

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="sentrook-scan", daemon=True
        )
        self._thread.start()

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def serve(config: ServeConfig | None = None) -> None:
    config = config or ServeConfig.from_env()
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    runtime = ServeRuntime.build(config)
    server = ScanServer(runtime)
    logger.info(
        "sentrook-scan listening on %s (test_mode=%s, auth=%s)",
        server.url,
        config.test_mode,
        runtime.health_payload()["auth"],
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
