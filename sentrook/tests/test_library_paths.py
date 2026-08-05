from __future__ import annotations

from pathlib import Path

import pytest

from sentrook.library.paths import (
    DEFAULT_LIBRARY_DIR,
    DEFAULT_REGISTRY_URL,
    resolve_library_dir,
    resolve_registry_url,
)


def test_resolve_registry_url_defaults_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTROOK_LIBRARY_URL", raising=False)
    assert resolve_registry_url() == DEFAULT_REGISTRY_URL


def test_resolve_registry_url_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_LIBRARY_URL", "https://rookery.example.test")
    assert resolve_registry_url() == "https://rookery.example.test"


def test_resolve_registry_url_treats_empty_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_LIBRARY_URL", "")
    assert resolve_registry_url() == DEFAULT_REGISTRY_URL


def test_resolve_library_dir_defaults_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTROOK_LIBRARY_DIR", raising=False)
    assert resolve_library_dir() == DEFAULT_LIBRARY_DIR


def test_resolve_library_dir_reads_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_LIBRARY_DIR", str(tmp_path / "library"))
    assert resolve_library_dir() == tmp_path / "library"
