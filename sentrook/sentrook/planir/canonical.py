"""Argument canonicalisation (preparation step 3), keyed on the host platform.

Hosts name the same thing differently (`command` / `cmd` / `code`; `path` / `file_path` / `filename`;
`to` / `recipients` / `target`). Every call is mapped to canonical keys per `tool_kind` so detectors
read one vocabulary. Raw arguments are kept beside the canonical ones.

Two derived texts travel with each call:
- `text`: every string leaf of the raw arguments, joined, for pattern matching.
- `analysis_text`: `text` with URL query strings percent-decoded. Decoding is canonicalisation, never
  suspicion: the inspector RCE case hides `sh -c 'curl … | sh'` in an encoded query
  parameter, and detectors must see it without treating encoding itself as evidence.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from .models import HistoryStep, PendingCall, Provider, Sibling, ToolKind

# Alias tables: canonical key → raw keys tried in order. Shared across platforms; the platform hook
# below adds the few host-specific shapes.
_ALIASES: dict[ToolKind, dict[str, tuple[str, ...]]] = {
    ToolKind.EXEC: {
        "command": ("command", "cmd", "shell", "script", "code"),
        "cwd": ("cwd", "dir", "working_directory", "workdir"),
        "title": ("title", "description", "label"),
    },
    ToolKind.FILE_READ: {
        "path": ("path", "file_path", "file", "filename", "target_file", "source"),
    },
    ToolKind.FILE_WRITE: {
        "path": ("path", "file_path", "file", "filename", "target_file", "target"),
        "content": ("content", "text", "data", "body"),
    },
    ToolKind.FILE_EDIT: {
        "path": ("path", "file_path", "file", "filename", "target_file"),
    },
    ToolKind.WEB_FETCH: {
        "url": ("url", "uri", "href", "endpoint", "link"),
        "method": ("method",),
        "body": ("body", "data", "payload", "content"),
        "headers": ("headers",),
    },
    ToolKind.BROWSER: {
        "url": ("url", "uri", "href"),
        "text": ("text", "value", "input"),
        "action": ("action",),
    },
    ToolKind.MESSAGE_SEND: {
        "channel": ("channel", "platform", "service"),
        "subject": ("subject", "title"),
        "body": ("body", "message", "text", "content"),
        "action": ("action",),
    },
    ToolKind.MEMORY_WRITE: {
        "path": ("path", "target", "file", "key"),
        "content": ("content", "text", "value", "data"),
        "action": ("action",),
    },
    ToolKind.SUBAGENT_SPAWN: {
        "task": ("task", "goal", "prompt", "message", "instructions"),
        "agent": ("agentId", "agent_id", "agent", "name", "taskName"),
        "visible": ("visible",),
    },
}

_RECIPIENT_KEYS = (
    "recipients",
    "to",
    "recipient",
    "target",
    "targets",
    "email",
    "emails",
    "phone",
    "number",
)
_CC_KEYS = ("cc",)
_BCC_KEYS = ("bcc",)
_ATTACHMENT_KEYS = ("attachments", "files", "attachment", "file_paths")
_GENERIC_URL_KEYS = ("url", "uri", "endpoint", "href", "webhook", "link")
_GENERIC_PATH_KEYS = ("path", "file", "filename", "file_path", "source", "target_file")
_GENERIC_CONTENT_KEYS = ("body", "content", "text", "message", "data", "sql", "query", "note")
_GENERIC_PACKAGE_KEYS = ("package", "packages", "name_or_url", "plugin")
_GENERIC_AMOUNT_KEYS = ("amount", "value", "sum")
# Canonical keys read as text. An alias keeps only a string here: a list of files under `path` or a
# memory key that is a number is left out (its string leaves still reach `text`). When no alias of
# the key holds a string, the raw keys left out are named in `CanonicalCall.dropped`, so the rest of
# the call is scored, with lower coverage.
_TEXT_KEYS = frozenset({"command", "cwd", "path", "content", "url"})

_URL_RE = re.compile(r"https?://[^\s\"'<>`|;)\]}]+", re.IGNORECASE)


@dataclass
class CanonicalCall:
    """One call (pending, sibling or history step) in canonical form."""

    source: str  # pending | sibling | history
    tool: str
    tool_kind: ToolKind
    provider: Provider
    call_id: str | None
    step: int | None
    raw: dict[str, Any]
    args: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    analysis_text: str = ""
    #: Raw keys whose value was not kept because it was not the type the canonical key needs.
    dropped: list[str] = field(default_factory=list)

    def get(self, key: str, default: Any = None) -> Any:
        return self.args.get(key, default)

    @property
    def command(self) -> str | None:
        return self.args.get("command")

    @property
    def path(self) -> str | None:
        return self.args.get("path")

    @property
    def recipients(self) -> list[str]:
        out: list[str] = []
        for k in ("recipients", "cc", "bcc"):
            out.extend(self.args.get(k) or [])
        return out


def _first(raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in raw and raw[k] not in (None, ""):
            return raw[k]
    return None


def _first_text(
    raw: dict[str, Any], keys: tuple[str, ...], skipped: list[str], *, argv: bool = False
) -> str | None:
    """The first non-empty string among `keys`; with `argv`, a list of strings is a command's argv
    and is quoted back into one command line. Values of another type are named in `skipped`."""
    for k in keys:
        v = raw.get(k)
        if argv and isinstance(v, list) and v and all(isinstance(a, str) for a in v):
            v = shlex.join(v)
        if isinstance(v, str):
            if v:
                return v
        elif v is not None and k not in skipped:
            skipped.append(k)
    return None


def _first_str(raw: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    return _first_text(raw, keys, [])


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = (
            re.split(r"[,;]\s*", value.strip())
            if ("," in value or ";" in value)
            else [value.strip()]
        )
        return [p for p in parts if p]
    if isinstance(value, list | tuple | set):
        out: list[str] = []
        for v in value:
            if isinstance(v, str):
                out.append(v.strip())
            elif isinstance(v, dict):
                for k in ("email", "address", "id", "name", "value"):
                    if isinstance(v.get(k), str):
                        out.append(v[k].strip())
                        break
        return [o for o in out if o]
    if isinstance(value, dict):
        return _as_list([value])
    return [str(value)]


def _string_leaves(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _string_leaves(v, out)
    elif isinstance(value, list | tuple):
        for v in value:
            _string_leaves(v, out)
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int | float):
        out.append(str(value))


def joined_text(raw: dict[str, Any]) -> str:
    leaves: list[str] = []
    _string_leaves(raw, leaves)
    return "\n".join(leaves)


def decode_url_queries(text: str) -> str:
    """Percent-decode the query and fragment of every URL in `text` (analysis only)."""

    def _decode(m: re.Match[str]) -> str:
        url = m.group(0)
        head, sep, tail = url.partition("?")
        if not sep:
            return url
        return head + sep + unquote(tail)

    return _URL_RE.sub(_decode, text)


def _normalise_edits(raw: dict[str, Any]) -> list[dict[str, str]]:
    edits: list[dict[str, str]] = []
    raw_edits = raw.get("edits")
    for e in raw_edits if isinstance(raw_edits, list) else []:
        if isinstance(e, dict):
            old = e.get("oldText", e.get("old_string", e.get("old_str", e.get("old", ""))))
            new = e.get("newText", e.get("new_string", e.get("new_str", e.get("new", ""))))
            edits.append(
                {
                    "old": old if isinstance(old, str) else "",
                    "new": new if isinstance(new, str) else "",
                }
            )
    if not edits:
        old = _first_str(raw, ("old_string", "old_str", "oldText", "old"))
        new = _first_str(raw, ("new_string", "new_str", "newText", "new", "content"))
        if old is not None or new is not None:
            edits.append({"old": old or "", "new": new or ""})
    return edits


def canonical_arguments(
    platform: str,
    tool: str,
    tool_kind: ToolKind,
    raw: dict[str, Any],
    dropped: list[str] | None = None,
) -> dict[str, Any]:
    """Map raw arguments to canonical keys for `tool_kind`. Unknown shapes fall back to generic
    role-ish keys so MCP and `other` tools still expose recipients, URLs, paths and content.
    Keys read as text keep only strings; the raw keys left out for that are appended to `dropped`."""
    args: dict[str, Any] = {}
    skipped: dict[str, list[str]] = {}  # canonical key -> raw keys left out for it
    aliases = _ALIASES.get(tool_kind, {})
    for canon, keys in aliases.items():
        if canon in _TEXT_KEYS:
            v = _first_text(raw, keys, skipped.setdefault(canon, []), argv=canon == "command")
        else:
            v = _first(raw, keys)
        if v is not None:
            args[canon] = v

    if tool_kind is ToolKind.EXEC:
        code = raw.get("code")
        if (
            platform == "hermes"
            and tool == "execute_code"
            and isinstance(code, str)
            and not isinstance(raw.get("command"), str)
        ):
            args["command"] = code
            args["interpreter"] = "python"
    if tool_kind is ToolKind.FILE_EDIT:
        edits = _normalise_edits(raw)
        if edits:
            args["edits"] = edits
            args["content"] = "\n".join(e["new"] for e in edits)
    if tool_kind is ToolKind.FILE_WRITE and "content" not in args:
        edits = _normalise_edits(raw)
        if edits:
            args["content"] = "\n".join(e["new"] for e in edits)

    # Recipients, attachments and generic role keys apply to every kind: an MCP `send_email` is
    # `message_send`, but a `pay_slate` or `post_board` is `mcp` and still names people and files.
    recipients: list[str] = []
    for k in _RECIPIENT_KEYS:
        if k in raw:
            recipients.extend(_as_list(raw[k]))
    if recipients:
        args["recipients"] = list(dict.fromkeys(recipients))
    for canon, keys in (("cc", _CC_KEYS), ("bcc", _BCC_KEYS), ("attachments", _ATTACHMENT_KEYS)):
        vals: list[str] = []
        for k in keys:
            if k in raw:
                vals.extend(_as_list(raw[k]))
        if vals:
            args[canon] = list(dict.fromkeys(vals))
    # A generic body or query is often an object (a JSON payload), so only a URL or path that is not
    # a string counts as left out.
    if "url" not in args:
        v = _first_text(raw, _GENERIC_URL_KEYS, skipped.setdefault("url", []))
        if v is not None:
            args["url"] = v
    if "path" not in args and tool_kind not in (ToolKind.EXEC,):
        v = _first_text(raw, _GENERIC_PATH_KEYS, skipped.setdefault("path", []))
        if v is not None:
            args["path"] = v
    if "content" not in args and tool_kind not in (ToolKind.EXEC, ToolKind.FILE_READ):
        v = _first(raw, _GENERIC_CONTENT_KEYS)
        if isinstance(v, str):
            args["content"] = v
    v = _first(raw, _GENERIC_PACKAGE_KEYS)
    if v is not None:
        args["packages"] = _as_list(v)
    v = _first(raw, _GENERIC_AMOUNT_KEYS)
    if isinstance(v, int | float) and not isinstance(v, bool):
        args["amount"] = v
    if "action" in raw and "action" not in args and isinstance(raw["action"], str):
        args["action"] = raw["action"]
    if "password" in raw or "new_password" in raw or "secret" in raw:
        args["sets_credential"] = True
    if dropped is not None:
        # `target` is a path alias and a recipient key: read as recipients, it was not lost.
        listed = {*_RECIPIENT_KEYS, *_CC_KEYS, *_BCC_KEYS, *_ATTACHMENT_KEYS}
        for canon, keys in skipped.items():
            if canon not in args:
                dropped.extend(k for k in keys if k not in listed and k not in dropped)
    return args


def canonicalise(
    platform: str,
    *,
    source: str,
    tool: str,
    tool_kind: ToolKind,
    provider: Provider,
    arguments: dict[str, Any],
    call_id: str | None = None,
    step: int | None = None,
) -> CanonicalCall:
    text = joined_text(arguments)
    dropped: list[str] = []
    args = canonical_arguments(platform, tool, tool_kind, arguments, dropped)
    return CanonicalCall(
        source=source,
        tool=tool,
        tool_kind=tool_kind,
        provider=provider,
        call_id=call_id,
        step=step,
        raw=arguments,
        args=args,
        text=text,
        analysis_text=decode_url_queries(text),
        dropped=dropped,
    )


def canonical_pending(platform: str, call: PendingCall) -> CanonicalCall:
    return canonicalise(
        platform,
        source="pending",
        tool=call.tool,
        tool_kind=call.tool_kind,
        provider=call.provider,
        arguments=call.arguments,
        call_id=call.call_id,
    )


def canonical_sibling(platform: str, sib: Sibling) -> CanonicalCall:
    return canonicalise(
        platform,
        source="sibling",
        tool=sib.tool,
        tool_kind=sib.tool_kind,
        provider=sib.provider,
        arguments=sib.arguments,
        call_id=sib.call_id,
    )


def canonical_history(platform: str, step: HistoryStep) -> CanonicalCall:
    return canonicalise(
        platform,
        source="history",
        tool=step.tool,
        tool_kind=step.tool_kind,
        provider=step.provider,
        arguments=step.arguments,
        call_id=step.call_id,
        step=step.step,
    )
