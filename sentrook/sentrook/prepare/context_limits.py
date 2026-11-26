"""Context limits for evaluation: a scan request cut down as if the plugin had sent less.

The plugins send up to `input_cap_bytes` (256 KB) of each new tool result, file read or message, the last
`history_limit` (20) steps, and with a background save the conversation it was made from, message bodies included.
Whether less would still do is a measurement, not a guess: an evaluation run sets these limits (test mode only,
`serve.config`) and the scanner trims each request on arrival, before preparation, so every probe sees what a plugin
configured that way would have sent, and nothing else changes. With no limit set, which is the default and the only
setting outside test mode, the request is untouched.

What each limit does, mirroring the plugins' own cuts so the result is what a plugin change would send:

- `input_cap_bytes`: each `new_inputs[].content`, and each tool entry's `content` in a background save's
  conversation, cut to that many UTF-8 bytes, two thirds head and one third tail with the plugins' marker between
  (`cap_head_tail` in both plugins). A cut input carries `truncated: true`; `size_bytes` keeps the original size.
  The pending call's own arguments are left whole: they are the action being judged.
- `history_steps`: only the last `history_steps` history steps are kept, and a tool result whose call is no longer
  in that window is left out, as the plugins leave it out (every tool result must refer to a call in the history).
  At least 1, as in the plugins: the last step fixes the session's step number.
- `self_edit_bodies`: when false, the user and assistant entries of a background save's conversation lose their
  `text` (role, turn, sender and length stay) and carry `truncated: true`; tool entries keep their arguments and
  content, which `input_cap_bytes` bounds.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

#: The plugins' cut marker (`cap_head_tail` in both plugins).
_MARKER = "\n…[sentrook: {n} bytes cut]…\n"
#: Conversation roles whose `text` is a message body.
_BODY_ROLES = frozenset({"user", "assistant"})


@dataclass(frozen=True)
class ContextLimits:
    """Limits on what a scan request may carry. `None` (or `True` for the bodies) is no limit."""

    input_cap_bytes: int | None = None
    history_steps: int | None = None
    self_edit_bodies: bool = True

    def __post_init__(self) -> None:
        if self.input_cap_bytes is not None and self.input_cap_bytes < 256:
            raise ValueError(f"input_cap_bytes must be at least 256, got {self.input_cap_bytes}")
        if self.history_steps is not None and self.history_steps < 1:
            raise ValueError(f"history_steps must be at least 1, got {self.history_steps}")

    @property
    def unlimited(self) -> bool:
        return self.input_cap_bytes is None and self.history_steps is None and self.self_edit_bodies

    def label(self) -> dict[str, Any]:
        """The limits as reported in the health payload: only those that are set."""
        out: dict[str, Any] = {}
        if self.input_cap_bytes is not None:
            out["input_cap_bytes"] = self.input_cap_bytes
        if self.history_steps is not None:
            out["history_steps"] = self.history_steps
        if not self.self_edit_bodies:
            out["self_edit_bodies"] = "drop"
        return out


NO_LIMITS = ContextLimits()


def cap_head_tail(text: str, cap_bytes: int) -> tuple[str, bool]:
    """`text` cut to `cap_bytes` UTF-8 bytes, marker included, two thirds head and one third tail, exactly as the
    plugins cut a tool result; and whether it was cut."""
    raw = text.encode("utf-8")
    size = len(raw)
    if size <= cap_bytes:
        return text, False
    marker = _MARKER.format(n=size - cap_bytes)
    budget = max(0, cap_bytes - len(marker.encode("utf-8")))
    head_n = budget * 2 // 3
    tail_n = budget - head_n
    head = raw[:head_n].decode("utf-8", errors="ignore")
    tail = raw[size - tail_n :].decode("utf-8", errors="ignore") if tail_n else ""
    return head + marker + tail, True


def _cap_content(entry: dict[str, Any], cap_bytes: int, *, record_size: bool) -> None:
    content = entry.get("content")
    if not isinstance(content, str):
        return
    cut, was_cut = cap_head_tail(content, cap_bytes)
    if was_cut:
        entry["content"] = cut
        entry["truncated"] = True
        if record_size and entry.get("size_bytes") is None:
            entry["size_bytes"] = len(content.encode("utf-8"))


def apply_context_limits(raw: Any, limits: ContextLimits) -> Any:
    """A copy of the request `raw` with `limits` applied; `raw` itself when nothing is limited or it is not an
    object (a malformed request is left for validation to refuse). Never mutates `raw`."""
    if limits.unlimited or not isinstance(raw, dict):
        return raw
    out = copy.deepcopy(raw)
    history = out.get("history")
    if limits.history_steps is not None and isinstance(history, list):
        window = history[-limits.history_steps :]
        out["history"] = window
        kept_calls = {h.get("call_id") for h in window if isinstance(h, dict)}
        inputs = out.get("new_inputs")
        if isinstance(inputs, list):
            out["new_inputs"] = [
                i
                for i in inputs
                if not (
                    isinstance(i, dict)
                    and i.get("kind") == "tool_result"
                    and i.get("call_id") not in kept_calls
                )
            ]
    if limits.input_cap_bytes is not None:
        for entry in out.get("new_inputs") or []:
            if isinstance(entry, dict):
                _cap_content(entry, limits.input_cap_bytes, record_size=True)
    self_edit = out.get("self_edit")
    conversation = self_edit.get("conversation") if isinstance(self_edit, dict) else None
    if isinstance(conversation, list):
        for entry in conversation:
            if not isinstance(entry, dict):
                continue
            if limits.input_cap_bytes is not None and entry.get("role") == "tool":
                _cap_content(entry, limits.input_cap_bytes, record_size=False)
            if (
                not limits.self_edit_bodies
                and entry.get("role") in _BODY_ROLES
                and entry.get("text") is not None
            ):
                entry.pop("text")
                entry["truncated"] = True
    return out
