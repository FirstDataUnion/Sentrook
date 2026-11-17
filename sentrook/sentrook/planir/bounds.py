"""How much of one call preparation analyses.

Preparation's work grows with the size of a call, and a scan has to answer well inside the probe
timeout whatever it is sent. So a call's arguments are analysed up to `MAX_CALL_CHARS` characters in
all (every value counts at least one, so a long list of empty or numeric items counts too), and each
string of a shell command up to `MAX_COMMAND_SEGMENTS` simple commands. Past either bound a string is
cut the way the plugins cut a long tool result: the first two thirds and the last third of its share
are kept, with the cut marked in between, so what a long command ends with is still read. When the
values are too many to give each a useful share, the shallowest and shortest are kept whole (a call's
own `command` or `path` before the items of a padded list) and the rest are left out.

The caller records the cut as a coverage note; a call of the request that was cut is held for the
owner's review, since nobody read all of it.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import islice
from typing import Any

from .models import ToolKind

#: Characters of argument values analysed per call: several times the largest calls seen in real use.
MAX_CALL_CHARS = 100_000
#: Simple commands analysed per string of a shell command (separated by `;`, `&&`, `||`, `|` or a
#: newline, as the entity extractor splits them): over a hundred times the most seen in real use.
MAX_COMMAND_SEGMENTS = 10_000

SEGMENT_SEPARATOR_RE = re.compile(r"&&|\|\||[;|\n]")
#: The plugins' own cut marker (`cap_head_tail`), so a cut file read back later is known to be partial.
_MARKER = "\n…[sentrook: {n} bytes cut]…\n"
#: Room left for the marker inside a string's share.
_MARKER_ROOM = 48
#: Below this share per value, cutting each one keeps too little of it to be worth it.
_MIN_SHARE = 2 * _MARKER_ROOM


def _marker(cut: str) -> str:
    return _MARKER.format(n=len(cut.encode("utf-8")))


def cut_head_tail(text: str, keep: int) -> str:
    """`text` with at most `keep` of its characters kept, two thirds from the head and one third from
    the tail, and the cut marked between them."""
    if len(text) <= keep:
        return text
    keep = max(0, keep)
    head_n = keep * 2 // 3
    tail_start = len(text) - (keep - head_n)
    return text[:head_n] + _marker(text[head_n:tail_start]) + text[tail_start:]


def segments_over(text: str) -> bool:
    """More than `MAX_COMMAND_SEGMENTS` simple commands. Counts separators and stops at the bound."""
    if len(text) < MAX_COMMAND_SEGMENTS:
        return False
    for n, _ in enumerate(SEGMENT_SEPARATOR_RE.finditer(text), start=1):
        if n >= MAX_COMMAND_SEGMENTS:
            return True
    return False


def cut_segments(text: str) -> str:
    """`text` with the first two thirds and the last third of its simple commands kept, the cut marked
    between them (the marker is a simple command of its own), `MAX_COMMAND_SEGMENTS` in all."""
    seps = list(SEGMENT_SEPARATOR_RE.finditer(text))
    if len(seps) < MAX_COMMAND_SEGMENTS:
        return text
    keep = MAX_COMMAND_SEGMENTS - 1
    head_n = keep * 2 // 3
    tail_n = keep - head_n
    head_end = seps[head_n - 1].start()
    tail_start = seps[-tail_n].end()
    return text[:head_end] + _marker(text[head_end:tail_start]) + text[tail_start:]


def bound_text(
    text: str, *, shell: bool, max_chars: int = MAX_CALL_CHARS
) -> tuple[str, str | None]:
    """One text cut to the bounds (`shell`: also to the simple-command bound), and what was over them
    (None, with `text` itself, when nothing was)."""
    over: list[str] = []
    if shell and segments_over(text):
        over.append(f"{len(SEGMENT_SEPARATOR_RE.findall(text)) + 1:,} simple commands")
        text = cut_segments(text)
    if len(text) > max_chars:
        over.insert(0, f"{len(text):,} characters")
        text = cut_head_tail(text, max_chars - _MARKER_ROOM)
    return text, ", ".join(over) or None


class _Leaf:
    __slots__ = ("cost", "depth", "keep", "value")

    def __init__(self, value: Any, depth: int, cost: int):
        self.value = value
        self.depth = depth
        self.cost = cost
        #: The value to keep, or `_DROP`.
        self.keep: Any = value


_DROP = object()


def _is_branch(v: Any) -> bool:
    return isinstance(v, dict | list | tuple) and bool(v)


def _children(c: dict[str, Any] | list[Any] | tuple[Any, ...]) -> Iterator[tuple[Any, Any]]:
    return iter(c.items()) if isinstance(c, dict) else enumerate(c)


@dataclass
class _Walk:
    """The values of a call's arguments: strings, scalars and empty containers. A string costs its
    length, anything else one. Walked breadth first, so a call's own top-level values come before the
    items of a long list, and stopped once more values were seen than the bound could ever keep."""

    order: list[_Leaf] = field(default_factory=list)
    #: (id of the containing dict or list, child position) → the value there.
    at: dict[tuple[int, int], _Leaf] = field(default_factory=dict)
    #: id of each container walked → how many of its children were walked.
    walked: dict[int, int] = field(default_factory=dict)
    key_chars: int = 0
    complete: bool = True


def _walk(arguments: dict[str, Any]) -> _Walk:
    w = _Walk()
    queue: deque[tuple[Any, int]] = deque([(arguments, 0)])
    while queue and w.complete:
        c, depth = queue.popleft()
        n = 0
        for i, (k, v) in enumerate(_children(c)):
            if len(w.order) > MAX_CALL_CHARS:
                w.complete = False
                break
            n += 1
            if isinstance(c, dict):
                w.key_chars += len(str(k))
            if _is_branch(v):
                queue.append((v, depth + 1))
                continue
            leaf = _Leaf(v, depth + 1, max(1, len(v) if isinstance(v, str) else 1))
            w.at[(id(c), i)] = leaf
            w.order.append(leaf)
        w.walked[id(c)] = max(w.walked.get(id(c), 0), n)
    w.complete = w.complete and not queue
    return w


def _rebuild(c: Any, w: _Walk) -> Any:
    """Container `c` with each value replaced by what is kept of it; a dropped value, or one the walk
    never reached, is left out of its dict or list."""
    n = w.walked.get(id(c))
    if n is None:
        return _DROP
    kept: list[tuple[Any, Any]] = []
    for i, (k, v) in enumerate(islice(_children(c), n)):
        value = _rebuild(v, w) if _is_branch(v) else w.at[(id(c), i)].keep
        if value is not _DROP:
            kept.append((k, value))
    if isinstance(c, dict):
        return dict(kept)
    return [v for _, v in kept]


def _share(costs: list[int], budget: int) -> int:
    """The largest per-value limit `L` with sum(min(cost, L)) within `budget`."""
    remaining = budget
    ordered = sorted(costs)
    for i, n in enumerate(ordered):
        share = remaining // (len(ordered) - i)
        if n > share:
            return share
        remaining -= n
    return max(ordered, default=0)


def bound_arguments(
    arguments: dict[str, Any], tool_kind: ToolKind
) -> tuple[dict[str, Any], str | None]:
    """The arguments preparation analyses, and what was over the bounds (None, with `arguments`
    itself, when nothing was)."""
    w = _walk(arguments)
    leaves = w.order
    key_chars = w.key_chars
    total = sum(leaf.cost for leaf in leaves) if w.complete else MAX_CALL_CHARS + 1
    shell = tool_kind is ToolKind.EXEC
    over_segments = shell and any(
        isinstance(leaf.value, str) and segments_over(leaf.value) for leaf in leaves
    )
    if total <= MAX_CALL_CHARS and key_chars <= MAX_CALL_CHARS and not over_segments:
        return arguments, None

    over: list[str] = []
    if not w.complete:
        over.append(f"more than {MAX_CALL_CHARS:,} values")
    elif total > MAX_CALL_CHARS or key_chars > MAX_CALL_CHARS:
        over.append(f"{max(total, key_chars):,} characters in {len(leaves):,} values")
    if over_segments:
        most = max(
            len(SEGMENT_SEPARATOR_RE.findall(leaf.value)) + 1
            for leaf in leaves
            if isinstance(leaf.value, str)
        )
        over.append(f"{most:,} simple commands")
    detail = ", ".join(over)

    if key_chars > MAX_CALL_CHARS:
        # Keys this long are no tool's arguments: keep the head and tail of the JSON.
        dumped = json.dumps(arguments, ensure_ascii=False, default=str)
        return {"_truncated": cut_head_tail(dumped, MAX_CALL_CHARS - _MARKER_ROOM)}, detail

    if over_segments:
        for leaf in leaves:
            if isinstance(leaf.value, str) and segments_over(leaf.value):
                leaf.keep = cut_segments(leaf.value)
                leaf.cost = max(1, leaf.cost - len(leaf.value) + len(leaf.keep))
    total = sum(leaf.cost for leaf in leaves)
    if total > MAX_CALL_CHARS:
        share = _share([leaf.cost for leaf in leaves], MAX_CALL_CHARS)
        if share >= _MIN_SHARE:
            for leaf in leaves:
                if leaf.cost > share:
                    leaf.keep = cut_head_tail(leaf.keep, share - _MARKER_ROOM)
        else:
            # Too many values to share the budget: keep the shallowest and shortest whole, cut the
            # first that does not fit if a useful part of it does, and leave the rest out.
            remaining = MAX_CALL_CHARS
            for leaf in sorted(leaves, key=lambda x: (x.depth, x.cost)):
                if leaf.cost <= remaining:
                    remaining -= leaf.cost
                elif isinstance(leaf.keep, str) and remaining >= _MIN_SHARE:
                    leaf.keep = cut_head_tail(leaf.keep, remaining - _MARKER_ROOM)
                    remaining = 0
                else:
                    leaf.keep = _DROP
    kept = _rebuild(arguments, w)
    return (kept if isinstance(kept, dict) else {}), detail
