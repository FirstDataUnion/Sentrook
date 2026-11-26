"""The scan service logs metadata only: method, route and status, never the client's address, the request
line's path or query, headers, body, or an exception's message."""

from __future__ import annotations

import logging
import socket

import httpx
import pytest

from sentrook.serve.config import ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer

SECRET_PATH = "/scan-quillon.marsh@bramblecourt.example"
SECRET_QUERY = "token=sk-not-a-real-key-0123456789"


@pytest.fixture
def server():
    config = ServeConfig(state_key="k" * 32, scan_auth_mode="open", log_level="DEBUG")
    srv = ScanServer(ServeRuntime.build(config), host="127.0.0.1", port=0)
    srv.start()
    yield srv
    srv.stop()


def test_request_logs_hold_method_route_and_status_only(server, caplog):
    caplog.set_level(logging.DEBUG, logger="sentrook.serve")
    with httpx.Client(base_url=server.url) as c:
        c.get("/healthz")
        c.get(f"{SECRET_PATH}?{SECRET_QUERY}")
        c.post("/scan", content=b'{"note": "quillon.marsh@bramblecourt.example"}')
    text = caplog.text
    assert "GET /healthz 200" in text
    assert "GET other 404" in text
    for leak in ("quillon", "bramblecourt", "sk-not-a-real-key", "127.0.0.1 -"):
        assert leak not in text


def test_a_malformed_request_line_is_not_quoted(server, caplog):
    caplog.set_level(logging.DEBUG, logger="sentrook.serve")
    with socket.create_connection((server.host, server.port), timeout=3) as s:
        s.sendall(b"BREW /quillon.marsh@bramblecourt.example HTCPCP/9\r\n\r\n")
        s.recv(4096)
    assert "request error" in caplog.text
    assert "quillon" not in caplog.text and "bramblecourt" not in caplog.text


def test_an_unhandled_error_logs_its_type_and_place_only(server, caplog, monkeypatch):
    def boom(*_a, **_k):
        raise ValueError("content quillon.marsh@bramblecourt.example")

    monkeypatch.setattr(server.runtime.scanner, "scan", boom)
    caplog.set_level(logging.DEBUG, logger="sentrook.serve")
    with httpx.Client(base_url=server.url) as c:
        with pytest.raises(httpx.HTTPError):
            c.post("/scan", json={"x": 1})
    assert "unhandled error serving a request: ValueError at" in caplog.text
    assert "quillon" not in caplog.text
