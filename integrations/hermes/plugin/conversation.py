"""The conversation a background save is judged against.

Hermes's background review reads the session's conversation and then saves memory or skills. It runs with
no request and no chat of its own (its `pre_llm_call` never fires), so the plugin keeps the conversation
itself and sends the part the save draws on as the PlanIR's top-level `self_edit` block:

    {"kind": "background_review", "store": "memory" | "skills", "conversation": [entries, oldest first]}

Entries:
- `{"role": "user", "turn", "sender", "text", "truncated"?}` from `pre_llm_call`;
- `{"role": "assistant", "turn", "text", "truncated"?}` from `post_api_request`, except while the write
  origin is the background review (the review talking to itself);
- `{"role": "tool", "turn", "tool", "arguments", "content", "excerpt_of_chars"?}` from `post_tool_call`,
  the review's own reads included.

Everything is redacted with the plugin's `Redactor` before it is stored. The log is kept per session in
the store, rolling: at most `LOG_MAX_ENTRIES` entries and about `LOG_MAX_BYTES`; the oldest tool contents
go first, then the oldest entries. `select` picks what a save carries (see there).
"""

from __future__ import annotations

import json
import re
from typing import Any

from .redact import Redactor, cap_args, cap_head_tail

#: Stored per user or assistant message, in characters, and per tool result, in bytes (head and tail).
STORE_TEXT_CAP = 16 * 1024
#: Stored per tool call's arguments, in bytes of JSON (as the plugin caps history arguments).
ARGS_CAP_BYTES = 1024
LOG_MAX_ENTRIES = 200
LOG_MAX_BYTES = 400 * 1024

#: What a save carries: every user message (the most recent `USER_KEEP`), each cut to `USER_CAP`
#: characters; the most recent `ASSISTANT_KEEP` assistant messages, each cut to `ASSISTANT_CAP`; the
#: `TOOL_TOP` tool results whose wording overlaps most with what is saved and the `TOOL_RECENT` latest,
#: each reduced to the `TOOL_WINDOW`-character window with the most overlap; about `BLOCK_BUDGET` in all.
USER_CAP, USER_KEEP = 2000, 30
ASSISTANT_CAP, ASSISTANT_KEEP = 1500, 20
TOOL_WINDOW, TOOL_TOP, TOOL_RECENT = 1500, 10, 4
BLOCK_BUDGET = 48 * 1024

#: The saved text whose wording picks tool results: these argument keys, also inside `operations`.
SAVE_TEXT_KEYS = ("content", "file_content", "new_string")
_WORD = re.compile(r"[a-z0-9_./@-]{4,}")


# ---- the log ---------------------------------------------------------------------------------------------


def user_entry(
    turn: int, sender: dict[str, Any], text: Any, redactor: Redactor, turn_id: Any = None
) -> dict[str, Any]:
    t = redactor.string(text if isinstance(text, str) else "")
    return {
        "role": "user",
        "turn": turn,
        "sender": sender,
        "text": t[:STORE_TEXT_CAP],
        "chars": len(t),
        **({"_turn_id": str(turn_id)} if turn_id else {}),
    }


def assistant_entry(turn: int, text: Any, redactor: Redactor) -> dict[str, Any] | None:
    if not isinstance(text, str) or not text.strip():
        return None
    t = redactor.string(text.strip())
    return {"role": "assistant", "turn": turn, "text": t[:STORE_TEXT_CAP], "chars": len(t)}


def tool_entry(
    turn: int, tool: str, args: Any, redacted_content: str, redactor: Redactor
) -> dict[str, Any]:
    """`redacted_content`: the result as the model saw it, already redacted."""
    content, _, _ = cap_head_tail(redacted_content, STORE_TEXT_CAP)
    return {
        "role": "tool",
        "turn": turn,
        "tool": tool,
        "arguments": cap_args(
            redactor.value(args if isinstance(args, dict) else {"value": args}), ARGS_CAP_BYTES
        ),
        "content": content,
        "chars": len(redacted_content),
    }


def _size(e: dict[str, Any]) -> int:
    return len(json.dumps(e, ensure_ascii=False, default=str).encode("utf-8"))


def trim(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rolling caps: at most `LOG_MAX_ENTRIES`, about `LOG_MAX_BYTES`; the oldest tool contents are
    dropped first (the call stays, with an empty content), then the oldest entries."""
    entries = entries[-LOG_MAX_ENTRIES:]
    sizes = [_size(e) for e in entries]
    total = sum(sizes)
    i = 0
    while total > LOG_MAX_BYTES and i < len(entries):
        e = entries[i]
        if e.get("role") == "tool" and e.get("content"):
            entries[i] = {**e, "content": ""}
            new = _size(entries[i])
            total += new - sizes[i]
            sizes[i] = new
        i += 1
    while total > LOG_MAX_BYTES and entries:
        total -= sizes.pop(0)
        entries.pop(0)
    return entries


def append(entry: dict[str, Any]):
    """A store change that appends `entry` (a user message once per turn) and applies the caps."""

    def change(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        tid = entry.get("_turn_id")
        if tid and any(e.get("_turn_id") == tid and e.get("role") == "user" for e in entries):
            return entries
        return trim([*entries, entry])

    return change


# ---- the block -------------------------------------------------------------------------------------------


def _words(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def save_text(value: Any, depth: int = 0) -> str:
    """The text a save writes: `SAVE_TEXT_KEYS` values, including inside `operations` (any nesting)."""
    if depth > 8:
        return ""
    if isinstance(value, list):
        return " ".join(save_text(v, depth + 1) for v in value)
    if not isinstance(value, dict):
        return ""
    out = [value[k] for k in SAVE_TEXT_KEYS if isinstance(value.get(k), str)]
    out += [save_text(v, depth + 1) for v in value.values() if isinstance(v, dict | list)]
    return " ".join(x for x in out if x)


def excerpt(text: str, want: set[str], window: int = TOOL_WINDOW) -> tuple[str, int]:
    """The `window`-character stretch of `text` holding the most distinct words of `want` (stepping by a
    quarter window; the earliest on a tie), and how many it holds."""
    if len(text) <= window:
        return text, len(want & _words(text))
    hits = [
        (m.start(), m.end(), m.group()) for m in _WORD.finditer(text.lower()) if m.group() in want
    ]
    best, at = -1, 0
    starts = list(range(0, len(text) - window + 1, window // 4))
    if starts[-1] != len(text) - window:
        starts.append(len(text) - window)
    for start in starts:
        n = len({w for s, e, w in hits if s >= start and e <= start + window})
        if n > best:
            best, at = n, start
    return text[at : at + window], best


def _public(e: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in e.items() if not k.startswith("_") and k != "chars"}


def select(entries: list[dict[str, Any]], save_args: Any) -> list[dict[str, Any]]:
    """The conversation a save carries, in conversation order:
    - every user message (the most recent `USER_KEEP`), cut to `USER_CAP` (`truncated: true` when cut);
    - the most recent `ASSISTANT_KEEP` assistant messages, cut to `ASSISTANT_CAP`;
    - the `TOOL_TOP` tool results whose wording overlaps most with the saved text (`save_text`; words are
      lowercase runs of 4+ of `[a-z0-9_./@-]`, results with no overlap are not ranked, the later one wins a
      tie) and the `TOOL_RECENT` latest, each reduced to its `excerpt` (`excerpt_of_chars`: the full length,
      when it is an excerpt);
    then, while over about `BLOCK_BUDGET` bytes, the oldest assistant and tool entries are dropped, and
    the oldest user messages only if still over."""
    want = _words(save_text(save_args))
    users = [i for i, e in enumerate(entries) if e.get("role") == "user"][-USER_KEEP:]
    assistants = [i for i, e in enumerate(entries) if e.get("role") == "assistant"][
        -ASSISTANT_KEEP:
    ]
    tools = [i for i, e in enumerate(entries) if e.get("role") == "tool"]
    scored = {i: excerpt(str(entries[i].get("content") or ""), want) for i in tools}
    ranked = sorted((i for i in tools if scored[i][1] > 0), key=lambda i: (-scored[i][1], -i))
    keep = set(users) | set(assistants) | set(ranked[:TOOL_TOP]) | set(tools[-TOOL_RECENT:])

    out: list[dict[str, Any]] = []
    for i in sorted(keep):
        e = entries[i]
        role = e.get("role")
        if role in ("user", "assistant"):
            cap = USER_CAP if role == "user" else ASSISTANT_CAP
            text = str(e.get("text") or "")
            full = max(int(e.get("chars") or 0), len(text))
            out.append(
                {**_public(e), "text": text[:cap], **({"truncated": True} if full > cap else {})}
            )
        else:
            text = scored[i][0]
            full = max(int(e.get("chars") or 0), len(str(e.get("content") or "")))
            out.append(
                {
                    **_public(e),
                    "content": text,
                    **({"excerpt_of_chars": full} if full > len(text) else {}),
                }
            )

    sizes = [_size(e) for e in out]
    total = sum(sizes)
    for role_set in (("assistant", "tool"), ("user",)):
        i = 0
        while total > BLOCK_BUDGET and i < len(out):
            if out[i]["role"] in role_set:
                total -= sizes.pop(i)
                out.pop(i)
            else:
                i += 1
    return out


def block(kind: str, store: str, entries: list[dict[str, Any]], save_args: Any) -> dict[str, Any]:
    return {"kind": kind, "store": store, "conversation": select(entries, save_args)}
