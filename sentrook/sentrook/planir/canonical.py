"""Argument canonicalisation (preparation step 3), keyed on the host platform.

Hosts name the same thing differently (`command` / `cmd` / `code`; `path` / `file_path` / `filename`;
`to` / `recipients` / `target`). Every call is mapped to canonical keys per `tool_kind` so detectors
read one vocabulary. Raw arguments are kept beside the canonical ones.

Two derived texts travel with each call:
- `text`: every string leaf of the raw arguments, joined, for pattern matching.
- `analysis_text`: `text` with URL query strings percent-decoded. Decoding is canonicalisation, never
  suspicion (RUBRIC decision 17): the inspector RCE case hides `sh -c 'curl … | sh'` in an encoded query
  parameter, and detectors must see it without treating encoding itself as evidence.
"""

from __future__ import annotations

import re
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
    for e in raw.get("edits") or []:
        if isinstance(e, dict):
            old = e.get("oldText", e.get("old_string", e.get("old_str", e.get("old", ""))))
            new = e.get("newText", e.get("new_string", e.get("new_str", e.get("new", ""))))
            edits.append({"old": str(old or ""), "new": str(new or "")})
    if not edits:
        old = _first(raw, ("old_string", "old_str", "oldText", "old"))
        new = _first(raw, ("new_string", "new_str", "newText", "new", "content"))
        if old is not None or new is not None:
            edits.append({"old": str(old or ""), "new": str(new or "")})
    return edits


def canonical_arguments(
    platform: str, tool: str, tool_kind: ToolKind, raw: dict[str, Any]
) -> dict[str, Any]:
    """Map raw arguments to canonical keys for `tool_kind`. Unknown shapes fall back to generic
    role-ish keys so MCP and `other` tools still expose recipients, URLs, paths and content."""
    args: dict[str, Any] = {}
    aliases = _ALIASES.get(tool_kind, {})
    for canon, keys in aliases.items():
        v = _first(raw, keys)
        if v is not None:
            args[canon] = v

    if tool_kind is ToolKind.EXEC:
        if (
            platform == "hermes"
            and tool == "execute_code"
            and "code" in raw
            and "command" not in raw
        ):
            args["command"] = raw["code"]
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
    if "url" not in args:
        v = _first(raw, _GENERIC_URL_KEYS)
        if isinstance(v, str):
            args["url"] = v
    if "path" not in args and tool_kind not in (ToolKind.EXEC,):
        v = _first(raw, _GENERIC_PATH_KEYS)
        if isinstance(v, str):
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
    return CanonicalCall(
        source=source,
        tool=tool,
        tool_kind=tool_kind,
        provider=provider,
        call_id=call_id,
        step=step,
        raw=arguments,
        args=canonical_arguments(platform, tool, tool_kind, arguments),
        text=text,
        analysis_text=decode_url_queries(text),
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
