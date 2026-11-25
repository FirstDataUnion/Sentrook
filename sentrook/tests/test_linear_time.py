"""The timing checks in `linear_time.py`: a fixed bound first, the growth of the time with the input
when a run goes over it."""

from __future__ import annotations

import re
import time

import pytest
from linear_time import ALWAYS_ENV, CEILING, TEXT_CACHES, assert_fast_or_linear

_QUADRATIC = re.compile(r"QQ\w*?z")  # each start scans to the end of a run of Q


def _quadratic(d: int) -> None:
    _QUADRATIC.search("Q" * (12_000 // d))


def _linear(d: int) -> None:
    re.search(r"Qz", "Q" * (24_000_000 // d))


def _sleep_linear(d: int) -> None:
    """Linear, and never faster than its sleep: a real search of a long text can finish under a
    small bound on a fast runner."""
    time.sleep(0.08 / d)


def test_a_run_under_its_bound_passes_without_timing_again(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(ALWAYS_ENV, raising=False)
    calls = []
    assert_fast_or_linear(0.1, 1.0, calls.append, "fast")
    assert calls == []


def test_a_quadratic_run_over_its_bound_fails(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(ALWAYS_ENV, raising=False)
    with pytest.raises(AssertionError, match="super-linear"):
        assert_fast_or_linear(2.0, 1.0, _quadratic, "quadratic")


def test_a_linear_run_over_its_bound_passes_with_a_warning(monkeypatch: pytest.MonkeyPatch):
    """A slow machine: the run missed its bound, but grows linearly."""
    monkeypatch.delenv(ALWAYS_ENV, raising=False)
    with pytest.warns(UserWarning, match="grows linearly"):
        assert_fast_or_linear(2.0, 1.0, _linear, "linear")


def test_the_switch_checks_growth_under_the_bound_too(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ALWAYS_ENV, "1")
    with pytest.raises(AssertionError, match="super-linear"):
        assert_fast_or_linear(0.1, 1.0, _quadratic, "quadratic")


def test_a_linear_run_far_over_its_bound_fails(monkeypatch: pytest.MonkeyPatch):
    """However linearly it grows, a run must stay within CEILING times its bound."""
    monkeypatch.delenv(ALWAYS_ENV, raising=False)
    with pytest.raises(AssertionError, match="however it grows"):
        assert_fast_or_linear(1.0, 0.01, _sleep_linear, "linear")
    assert CEILING == 3.0


def test_every_cache_on_a_text_is_cleared_between_timed_runs():
    """A function the scanner caches per text would make a repeated run a cache hit, so the growth
    check would not time it. Every `lru_cache` in the scanner is listed here: the text caches in
    `TEXT_CACHES`, the rest load configuration once."""
    import importlib
    import pkgutil

    import sentrook

    found = set()
    for info in pkgutil.walk_packages(sentrook.__path__, "sentrook."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if hasattr(value, "cache_clear") and getattr(value, "__module__", None) == info.name:
                found.add(f"{info.name}.{name}")
    config = {
        "sentrook.prepare.steering.load_markers",
        "sentrook.prepare.redact_shapes._cached",
        "sentrook.aira.exec_shape._parser",
        "sentrook.aira.lists._cached",
    }
    assert found == set(TEXT_CACHES) | config
