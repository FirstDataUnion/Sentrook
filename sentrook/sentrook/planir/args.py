"""Canonical tool argument shapes for PlanIR (adapter → matcher contract)."""

from __future__ import annotations

from typing import Any

# Alternate keys adapters may use before normalization.
_EXEC_COMMAND_ALIASES = ("cmd", "shell", "script", "line")
_WRITE_PATH_ALIASES = ("file", "filepath", "target")
_MESSAGE_BODY_ALIASES = ("body", "content", "message", "msg")


def canonicalize_tool_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Map adapter-native arg keys/structures to stable PlanIR keys for YAIRA ``args_match``.

    Adapters (OpenClaw replay, live hooks) should call this before populating ``PlanStep.args``.
    The L2 matcher assumes rules refer to these canonical keys only.
    """
    if not args:
        return {}

    if tool == "exec":
        return _canonicalize_exec(args)
    if tool in ("write", "edit"):
        return _canonicalize_write(args)
    if tool == "message":
        return _canonicalize_message(args)

    return dict(args)


def stringify_arg_value(value: Any) -> str:
    """Coerce a single arg value to a flat string (nested JSON → searchable text)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(stringify_arg_value(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(stringify_arg_value(v) for v in value)
    return str(value)


def _canonicalize_exec(args: dict[str, Any]) -> dict[str, Any]:
    out = dict(args)
    if "command" not in out:
        for alias in _EXEC_COMMAND_ALIASES:
            if alias in out:
                out["command"] = out.pop(alias)
                break
    if "command" in out:
        out["command"] = stringify_arg_value(out["command"])
    return out


def _canonicalize_write(args: dict[str, Any]) -> dict[str, Any]:
    out = dict(args)
    if "path" not in out:
        for alias in _WRITE_PATH_ALIASES:
            if alias in out:
                out["path"] = out.pop(alias)
                break
    if "path" in out:
        out["path"] = stringify_arg_value(out["path"])
    # Flatten write.content and edit.edits[*].{newText,new_string,...} into
    # canonical ``content`` so YAIRA args_match (and signal packing) see nested
    # OpenClaw edit payloads the same way as flat write bodies.
    body = _write_body_text(out)
    if body:
        out["content"] = body
    return out


def _write_body_text(args: dict[str, Any]) -> str:
    pieces: list[str] = []
    if "content" in args:
        pieces.append(stringify_arg_value(args["content"]))
    if "edits" in args:
        pieces.append(stringify_arg_value(args["edits"]))
    for key in ("newText", "new_string", "text", "body"):
        if key in args:
            pieces.append(stringify_arg_value(args[key]))
    return " ".join(p for p in pieces if p)


def _canonicalize_message(args: dict[str, Any]) -> dict[str, Any]:
    out = dict(args)
    if "text" not in out:
        for alias in _MESSAGE_BODY_ALIASES:
            if alias in out:
                out["text"] = out.pop(alias)
                break
    if "text" in out:
        out["text"] = stringify_arg_value(out["text"])
    return out
