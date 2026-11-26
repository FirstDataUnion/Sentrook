"""Linear-time checks that do not depend on how fast the machine is.

A fixed wall-clock bound fails on a slow CI runner, while the thing it guards against, a super-linear
regex (catastrophic backtracking), shows in how the time grows with the input. So the work runs at
1/4 size and at full size and the two times are compared: linear work takes about 4 times as long,
quadratic work about 16 times, on any machine.

`assert_fast_or_linear` keeps a time bound as the first check and falls back to the growth check only
when a run goes over it, for tests whose bound is also a promise (a scan well under the probe
timeout): a fast machine still holds the bound, and a slow one is judged by how the time grows.

Measured on the redaction inputs: 3.6-4.7 for the scanner's own patterns and the vendor shapes. A shape
whose match is capped at a few thousand characters grows quadratically on runs shorter than a few caps
and linearly on longer ones, so its input is sized past the cap at both sizes (`CAP_RUNS` in
test_redact_shapes.py); sized across the cap, it read 6.5x on a fast machine and 12x on a CI runner.
Whole scans of long inputs read up to about 7.3."""

from __future__ import annotations

import gc
import importlib
import os
import time
import warnings
from collections.abc import Callable

FACTOR = 4
LIMIT = 10.0  # t(full) / t(full / FACTOR): linear about 4, quadratic about 16
#: A first reading under this share of the limit passes at once; one between it and the limit is
#: measured again, as one over the limit is. Real inputs read up to about 7.3x, and a quadratic one
#: 14-16x, which a busy runner slowing its quarter-size runs can pull under the limit but rarely under
#: 8x.
CLEAR = 0.8
FLOOR_S = 0.02  # a full-size run faster than this is too short to time, and passes
ATTEMPTS = 5
#: Set to 1 to run the growth check of `assert_fast_or_linear` even when a run is under its bound, to
#: try the fallback on every input.
ALWAYS_ENV = "SENTROOK_TEST_GROWTH_ALWAYS"
#: Over its bound, a run must still finish within this many times the bound (with FAST, 6 s locally
#: and 15 s in CI, half the probe timeout), however linearly it grows.
CEILING = 3.0
#: The scanner's results cached per text: cleared before every timed run, or a second run of the same
#: size would be a cache hit and the growth check would not time that work.
TEXT_CACHES = (
    "sentrook.prepare.entities._segments_of",
    "sentrook.prepare.views._protected_spans",
    "sentrook.prepare.views._secret_spans",
    "sentrook.aira.detectors._program_name",
)


def _clear_text_caches() -> None:
    for path in TEXT_CACHES:
        module, name = path.rsplit(".", 1)
        getattr(importlib.import_module(module), name).cache_clear()


def _seconds(run: Callable[[int], object], divisor: int) -> float:
    """With the garbage collector off, as `timeit` does: a full collection costs time in proportion to
    everything the test process holds, not to the input, and would land in whichever run triggers it."""
    _clear_text_caches()
    enabled = gc.isenabled()
    gc.disable()
    try:
        t0 = time.perf_counter()
        run(divisor)
        return time.perf_counter() - t0
    finally:
        if enabled:
            gc.enable()


def assert_linear(
    run: Callable[[int], object], what: str = "", limit: float = LIMIT
) -> tuple[float, float]:
    """`run(d)` does the work at 1/d of its full size; it is called with d = FACTOR and d = 1.

    The small size runs twice, before and after the first full-size run, and keeps its faster time, so
    one pause cannot slow both and hide a super-linear pattern (a slow small run makes the growth look
    lower); it costs a quarter of a full run. Only a clear reading, under CLEAR times `limit`, passes
    at once. Otherwise both sizes run again and the fastest time of each is kept, so a pause during a
    full run does not fail the check and a pause during both small runs does not pass it, while a real
    super-linear pattern grows the same way every time. Returns the fastest times seen at 1/FACTOR and at full size."""
    small = _seconds(run, FACTOR)
    large = _seconds(run, 1)
    small = min(small, _seconds(run, FACTOR))
    for _ in range(ATTEMPTS - 1):
        if large < FLOOR_S or large / max(small, 1e-9) < CLEAR * limit:
            return small, large
        small = min(small, _seconds(run, FACTOR))
        large = min(large, _seconds(run, 1))
    growth = large / max(small, 1e-9)
    assert large < FLOOR_S or growth < limit, (
        f"{what}: {large:.3f} s at full size vs {small:.3f} s at 1/{FACTOR}, "
        f"{growth:.1f}x for {FACTOR}x the input (limit {limit}x): super-linear?"
    )
    return small, large


def assert_fast_or_linear(
    spent: float, bound: float, run: Callable[[int], object], what: str = ""
) -> None:
    """`spent` is a full-size run's time, already measured. Under `bound` it passes, as a fixed bound
    would. Over it, the machine may only be slow, so the growth of `run` decides (see
    `assert_linear`), and a run that is slow but linear passes with a warning, up to CEILING times the
    bound (the fastest full-size time counts)."""
    if spent < bound and os.environ.get(ALWAYS_ENV) != "1":
        return
    _, large = assert_linear(run, what)
    best = min(spent, large)
    assert best < CEILING * bound, (
        f"{what}: {best:.2f} s, over {CEILING:g}x the {bound:.2f} s bound, however it grows"
    )
    if spent >= bound:
        warnings.warn(
            f"{what}: {spent:.2f} s, over the {bound:.2f} s bound, but it grows linearly: a slow "
            "machine?",
            stacklevel=2,
        )
