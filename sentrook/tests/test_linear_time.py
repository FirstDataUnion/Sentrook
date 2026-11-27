"""The timing checks in `linear_time.py`: a fixed bound first, the growth of the time with the input
when a run goes over it."""

from __future__ import annotations

import re
import time

import linear_time
import pytest
from linear_time import (
    ALWAYS_ENV,
    CEILING,
    FACTOR,
    TEXT_CACHES,
    assert_fast_or_linear,
    assert_linear,
)

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


def test_with_a_bound_a_quadratic_run_over_it_fails():
    with pytest.raises(AssertionError, match="super-linear"):
        assert_linear(_quadratic, "quadratic", bound=1e-9)


def test_with_a_bound_a_linear_run_over_it_passes_with_a_warning():
    """A slow machine: the run missed its bound, but grows linearly."""
    with pytest.warns(UserWarning, match="grows linearly"):
        assert_linear(_sleep_linear, "linear", bound=0.05)


def test_with_a_bound_a_linear_run_far_over_it_fails():
    with pytest.raises(AssertionError, match="however it grows"):
        assert_linear(_sleep_linear, "linear", bound=0.01)


def test_with_a_bound_a_run_under_it_passes_quietly(recwarn: pytest.WarningsRecorder):
    assert_linear(_sleep_linear, "linear", bound=1.0)
    assert not recwarn.list


def _scripted(monkeypatch: pytest.MonkeyPatch, small: list[float], large: list[float]) -> list[int]:
    """Timed runs report these seconds in order, quarter size from `small` and full size from `large`,
    so a noisy reading can be replayed. Returns the divisor of every timed run, in order."""
    times = {FACTOR: iter(small), 1: iter(large)}
    calls: list[int] = []

    def seconds(run, divisor: int) -> float:
        calls.append(divisor)
        return next(times[divisor])

    monkeypatch.setattr(linear_time, "_seconds", seconds)
    return calls


def test_a_quadratic_run_read_once_under_the_limit_still_fails(monkeypatch: pytest.MonkeyPatch):
    """16x growth whose first reading is 9x, both quarter-size runs slowed (a busy runner): the reading
    is not clear enough to pass on, and the next ones show the real growth."""
    _scripted(monkeypatch, small=[0.111, 0.111] + [0.0625] * 4, large=[1.0] * 5)
    with pytest.raises(AssertionError, match="super-linear"):
        assert_linear(lambda d: None, "quadratic")


def test_a_linear_run_read_once_near_the_limit_passes(monkeypatch: pytest.MonkeyPatch):
    """4x growth whose first reading is 9x (the full-size run slowed): measured again, and passes."""
    calls = _scripted(monkeypatch, small=[0.25] * 3, large=[2.25, 1.0])
    assert assert_linear(lambda d: None, "linear") == (0.25, 1.0)
    assert calls == [FACTOR, 1, FACTOR, FACTOR, 1]


@pytest.mark.parametrize(
    "large", [0.8, 1.46]
)  # linear 4x, and 7.3x as the slowest-growing scans read
def test_a_clear_reading_passes_with_no_more_runs(monkeypatch: pytest.MonkeyPatch, large: float):
    """Three timed runs, the quarter-size ones on either side of the full-size one, so one pause
    cannot slow both."""
    calls = _scripted(monkeypatch, small=[0.2, 0.2], large=[large])
    assert_linear(lambda d: None, "linear")
    assert calls == [FACTOR, 1, FACTOR]


def test_growth_steadily_under_the_limit_passes_after_every_try(monkeypatch: pytest.MonkeyPatch):
    """9x on every reading is not a clear pass, but it is under the limit: the extra runs change the
    cost, not the verdict."""
    calls = _scripted(monkeypatch, small=[0.1] * 6, large=[0.9] * 5)
    assert_linear(lambda d: None, "capped")
    assert len(calls) == 2 + 1 + 2 * (linear_time.ATTEMPTS - 1)


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
        # Keyed by the host trees, home, workspace and file system, not by the text scanned.
        "sentrook.aira.detectors._tree_roots",
    }
    assert found == set(TEXT_CACHES) | config
