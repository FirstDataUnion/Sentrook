"""Linear-time checks that do not depend on how fast the machine is.

A fixed wall-clock bound fails on a slow CI runner, while the thing it guards against, a super-linear
regex (catastrophic backtracking), shows in how the time grows with the input. So the work runs at
1/4 size and at full size and the two times are compared: linear work takes about 4 times as long,
quadratic work about 16 times, on any machine.

Measured on the redaction inputs: 3.7-4.3 for the scanner's own patterns, up to about 6.5 for a vendor
shape whose match is capped at a few thousand characters (quadratic below the cap, linear above it)."""

from __future__ import annotations

import gc
import time
from collections.abc import Callable

FACTOR = 4
LIMIT = 10.0  # t(full) / t(full / FACTOR): linear about 4, quadratic about 16
FLOOR_S = 0.02  # a full-size run faster than this is too short to time, and passes
ATTEMPTS = 3


def _seconds(run: Callable[[int], object], divisor: int) -> float:
    """With the garbage collector off, as `timeit` does: a full collection costs time in proportion to
    everything the test process holds, not to the input, and would land in whichever run triggers it."""
    enabled = gc.isenabled()
    gc.disable()
    try:
        t0 = time.perf_counter()
        run(divisor)
        return time.perf_counter() - t0
    finally:
        if enabled:
            gc.enable()


def assert_linear(run: Callable[[int], object], what: str = "", limit: float = LIMIT) -> None:
    """`run(d)` does the work at 1/d of its full size; it is called with d = FACTOR and d = 1.

    The small size runs twice and keeps its faster time, so a pause there cannot hide a super-linear
    pattern (a slow small run makes the growth look lower); it costs a quarter of a full run. If the
    growth is over `limit`, both sizes run again and the fastest time of each is kept, so a pause
    during a full run does not fail the check, while a real super-linear pattern grows the same way
    every time."""
    small = min(_seconds(run, FACTOR), _seconds(run, FACTOR))
    large = _seconds(run, 1)
    for _ in range(ATTEMPTS - 1):
        if large < FLOOR_S or large / max(small, 1e-9) < limit:
            return
        small = min(small, _seconds(run, FACTOR))
        large = min(large, _seconds(run, 1))
    growth = large / max(small, 1e-9)
    assert large < FLOOR_S or growth < limit, (
        f"{what}: {large:.3f} s at full size vs {small:.3f} s at 1/{FACTOR}, "
        f"{growth:.1f}x for {FACTOR}x the input (limit {limit}x): super-linear?"
    )
