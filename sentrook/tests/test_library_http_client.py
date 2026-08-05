from __future__ import annotations

import urllib.request

import pytest

from sentrook.library import http_client


@pytest.fixture(autouse=True)
def stub_direct_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route library HTTP through urllib.request so existing test fakes keep working."""

    def _urlopen(request: urllib.request.Request, *, timeout: float | None = None):
        return urllib.request.urlopen(request, timeout=timeout)

    monkeypatch.setattr(http_client, "urlopen", _urlopen)
