"""Chunking long exposure inputs under the model's context window.

Jev's window is 32k tokens and the API refuses oversize requests with a hard 400, so a request that
would not fit is split before sending and the highest chunk score is taken. Truncation without a signal
is an evasion vector, so the split keeps every byte: an input too large on its own is cut into pieces
with a small overlap, each piece sent as its own input entry; smaller inputs are packed greedily.

Token estimates are conservative (canonical JSON characters / 2.5; PlanIR JSON tokenises at about 2.5
characters per token, measured against the API's `usage`). The API's count is authoritative.
"""

from __future__ import annotations

import copy
import math
from typing import Any

from .client import CONTEXT_TOKENS
from .questions import canonical_json

CHARS_PER_TOKEN = 2.5
#: Leave room for the questions and the model's own output.
BUDGET_TOKENS = int(CONTEXT_TOKENS * 0.85)
OVERLAP_CHARS = 400


def est_tokens(obj: Any) -> int:
    return math.ceil(len(canonical_json(obj)) / CHARS_PER_TOKEN)


def chunk_exposure_state(state: dict[str, Any], questions_tokens: int) -> list[dict[str, Any]]:
    """Split an exposure view into one or more states that each fit the budget. Returns `[state]`
    unchanged when it already fits (the common case, and the cache-parity case)."""
    if est_tokens(state) + questions_tokens <= BUDGET_TOKENS:
        return [state]
    base = {k: v for k, v in state.items() if k != "new_inputs"}
    base_tokens = est_tokens(base) + questions_tokens
    # JSON escaping and the chunk metadata add overhead the character estimate does not see.
    room_chars = max(2000, int((BUDGET_TOKENS - base_tokens) * CHARS_PER_TOKEN * 0.75))

    pieces: list[dict[str, Any]] = []
    for inp in state.get("new_inputs") or []:
        content = inp.get("content")
        if not isinstance(content, str) or len(content) <= room_chars:
            pieces.append(inp)
            continue
        step = max(1000, room_chars - OVERLAP_CHARS)
        n = 0
        for start in range(0, len(content), step):
            piece = copy.deepcopy(inp)
            piece["content"] = content[start : start + room_chars]
            piece["chunk"] = {"index": n, "of": None, "offset": start}
            pieces.append(piece)
            n += 1
        for p in pieces[-n:]:
            p["chunk"]["of"] = n

    chunks: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for piece in pieces:
        candidate = current + [piece]
        if (
            current
            and est_tokens({**base, "new_inputs": candidate}) + questions_tokens > BUDGET_TOKENS
        ):
            chunks.append({**copy.deepcopy(base), "new_inputs": current})
            current = [piece]
        else:
            current = candidate
    if current:
        chunks.append({**copy.deepcopy(base), "new_inputs": current})
    return chunks
