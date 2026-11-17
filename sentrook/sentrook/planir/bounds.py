"""How much of one call preparation analyses.

Preparation's work grows with the size of a call, and a scan has to answer well inside the probe
timeout whatever it is sent. So the string values in a call's arguments are analysed up to
`MAX_CALL_CHARS` characters in all, and each string of a shell command up to `MAX_COMMAND_SEGMENTS`
simple commands. Past either bound a string is cut the way the plugins cut a long tool result: the
first two thirds and the last third of its share are kept, with the cut marked in between, so what a
long command ends with is still read. A call whose strings are too many to give each a useful share
is replaced by the head and tail of its JSON.

The caller records the cut as a coverage note; a pending call or sibling that was cut is held for the
owner's review, since nobody read all of it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .models import ToolKind

#: Characters of string values analysed per call: several times the largest calls seen in real use.
MAX_CALL_CHARS = 100_000
#: Simple commands analysed per string of a shell command (separated by `;`, `&&`, `||`, `|` or a
#: newline, as the entity extractor splits them).
MAX_COMMAND_SEGMENTS = 2_000

SEGMENT_SEPARATOR_RE = re.compile(r"&&|\|\||[;|\n]")
#: The plugins' own cut marker (`cap_head_tail`), so a cut file read back later is known to be partial.
_MARKER = "\n…[sentrook: {n} bytes cut]…\n"
#: Room left for the marker inside a string's share.
_MARKER_ROOM = 48
#: Below this share per string, cutting each string keeps too little of it to be worth it.
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


def _segments_over(text: str) -> bool:
    """More than `MAX_COMMAND_SEGMENTS` simple commands. Counts separators and stops at the bound."""
    if len(text) < MAX_COMMAND_SEGMENTS:
        return False
    for n, _ in enumerate(SEGMENT_SEPARATOR_RE.finditer(text), start=1):
        if n >= MAX_COMMAND_SEGMENTS:
            return True
    return False


def cut_segments(text: str) -> str:
    """`text` with its first two thirds and last third of `MAX_COMMAND_SEGMENTS` simple commands
    kept and the cut marked between them."""
    seps = list(SEGMENT_SEPARATOR_RE.finditer(text))
    if len(seps) < MAX_COMMAND_SEGMENTS:
        return text
    head_n = MAX_COMMAND_SEGMENTS * 2 // 3
    tail_n = MAX_COMMAND_SEGMENTS - head_n
    head_end = seps[head_n - 1].start()
    tail_start = seps[-tail_n].end()
    return text[:head_end] + _marker(text[head_end:tail_start]) + text[tail_start:]


def _strings(value: Any, out: list[str], keys: list[int]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            keys[0] += len(str(k))
            _strings(v, out, keys)
    elif isinstance(value, list | tuple):
        for v in value:
            _strings(v, out, keys)


def _rebuild(value: Any, fix: dict[int, str]) -> Any:
    """`value` with each string whose id is in `fix` replaced."""
    if isinstance(value, str):
        return fix.get(id(value), value)
    if isinstance(value, dict):
        return {k: _rebuild(v, fix) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_rebuild(v, fix) for v in value]
    return value


def _share(lengths: list[int], budget: int) -> int:
    """The largest per-string limit `L` with sum(min(length, L)) within `budget`."""
    remaining = budget
    ordered = sorted(lengths)
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
    strings: list[str] = []
    key_chars = [0]
    _strings(arguments, strings, key_chars)
    total = sum(len(s) for s in strings)
    over_segments = tool_kind is ToolKind.EXEC and any(_segments_over(s) for s in strings)
    if total <= MAX_CALL_CHARS and key_chars[0] <= MAX_CALL_CHARS and not over_segments:
        return arguments, None

    over: list[str] = []
    if total > MAX_CALL_CHARS or key_chars[0] > MAX_CALL_CHARS:
        over.append(f"{total + key_chars[0]:,} characters")
    if over_segments:
        most = max(len(SEGMENT_SEPARATOR_RE.findall(s)) + 1 for s in strings)
        over.append(f"{most:,} simple commands")
    detail = ", ".join(over)

    fix: dict[int, str] = {}
    cut = strings
    if over_segments:
        cut = []
        for s in strings:
            kept = cut_segments(s)
            if kept is not s:
                fix[id(s)] = kept
            cut.append(kept)
    lengths = [len(s) for s in cut]
    share = _share(lengths, MAX_CALL_CHARS) if sum(lengths) > MAX_CALL_CHARS else None
    if key_chars[0] > MAX_CALL_CHARS or (share is not None and share < _MIN_SHARE):
        dumped = json.dumps(arguments, ensure_ascii=False, default=str)
        return {"_truncated": cut_head_tail(dumped, MAX_CALL_CHARS - _MARKER_ROOM)}, detail
    if share is not None:
        for original, s in zip(strings, cut, strict=True):
            if len(s) > share:
                fix[id(original)] = cut_head_tail(s, share - _MARKER_ROOM)
    return _rebuild(arguments, fix), detail
