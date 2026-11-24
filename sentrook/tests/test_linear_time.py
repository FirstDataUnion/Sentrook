"""The timing checks in `linear_time.py`: a fixed bound first, the growth of the time with the input
when a run goes over it."""

from __future__ import annotations

import re

import pytest
from linear_time import ALWAYS_ENV, assert_fast_or_linear

_QUADRATIC = re.compile(r"QQ\w*?z")  # each start scans to the end of a run of Q


def _quadratic(d: int) -> None:
    _QUADRATIC.search("Q" * (12_000 // d))


def _linear(d: int) -> None:
    re.search(r"Qz", "Q" * (24_000_000 // d))


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
