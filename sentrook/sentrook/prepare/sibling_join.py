"""Join a sibling's write into the pending call's resolution.

A call issued in the same batch as the pending one can decide what the pending call acts on: it
writes the file whose content the pending command substitutes (`truncate "$(cat target.path)"`),
the config the pending program reads its URL from, the link a sync follows, or the archive an
upload sends. The pending command alone names none of that; read through the sibling's write it
does. `sibling_writes` says what a sibling writes; `resolve_pending` rewrites the pending command
through those writes into one or more resolved commands, which preparation extracts with the
pending call's roles and the sibling's origin, and which AIRA analyses as the pending call's own.

What a sibling writes:
- a file write or edit, or an MCP or other write tool with a path and content: the file's content
  (an edit's new text);
- `ln -s TARGET LINK`: the link now points at TARGET;
- a write tool with an output and a list of inputs (an archiver): the output carries the inputs.

How the pending command is resolved (exec calls only):
- a command substitution (`$(…)` or backticks) that names the written file is replaced by the
  written value: the value under the JSON key the substitution reads, the only string in a JSON
  document, or the stripped content;
- a command that runs the file resolves to the file's content, the program that runs;
- a command that reads the file some other way (a program opening it) gets the value appended as
  an argument, so it takes the command's role (a destination when the command sends);
- the link path, or a path inside it, is replaced by the link target;
- the archive path is replaced by each input in turn (one resolved command per input).
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from ..planir.canonical import CanonicalCall, canonicalise
from ..planir.models import Provider, ProviderKind, ToolKind
from .entities import (
    _WRITEISH_TOOL,
    EntityKind,
    Found,
    Role,
    display_path,
    normalise_path,
    resolve_token,
    shell_segments,
)

#: Resolved commands from one pending call at most (an archive fans out per input).
MAX_RESOLVED = 8

_FILE_WRITE_KINDS = frozenset({ToolKind.FILE_WRITE, ToolKind.FILE_EDIT, ToolKind.MEMORY_WRITE})
_ARCHIVE_OUTPUT_KEYS = ("output", "out", "archive", "destination", "dest")
_ARCHIVE_INPUT_KEYS = ("inputs", "sources", "files", "paths")


@dataclass(frozen=True)
class SiblingWrite:
    call_id: str | None
    path: str  # normalised path the sibling writes
    content: str | None = None  # a file's content, or an edit's new text
    target: str | None = None  # a link: the normalised path it points at
    carried: tuple[str, ...] = field(default=())  # an archive: the normalised paths packed in


def sibling_writes(
    sib: CanonicalCall, *, home: str | None, workspace_root: str | None
) -> list[SiblingWrite]:
    """What one sibling writes, in the forms the join can resolve through."""

    def norm(p: str, cwd: str | None = None) -> str:
        return normalise_path(p, home=home, workspace_root=workspace_root, cwd=cwd)

    kind = sib.tool_kind
    if kind is ToolKind.EXEC:
        cwd = norm(str(sib.get("cwd"))) if sib.get("cwd") else (workspace_root or "/")
        out: list[SiblingWrite] = []
        for toks in shell_segments(sib.command or ""):
            if toks[0] != "ln" or not any(_is_symbolic_flag(t) for t in toks[1:]):
                continue
            operands = [t for t in toks[1:] if not t.startswith("-")]
            if len(operands) != 2:
                continue
            target, link = (
                resolve_token(t, cwd, home=home, workspace_root=workspace_root)[0] for t in operands
            )
            out.append(SiblingWrite(sib.call_id, link, target=target))
        return out
    if kind not in _FILE_WRITE_KINDS and not (
        kind in (ToolKind.MCP, ToolKind.OTHER) and _WRITEISH_TOOL.search(sib.tool)
    ):
        return []
    output = _first_str(sib.raw, _ARCHIVE_OUTPUT_KEYS)
    inputs = _first_list(sib.raw, _ARCHIVE_INPUT_KEYS)
    if output and inputs:
        return [SiblingWrite(sib.call_id, norm(output), carried=tuple(norm(i) for i in inputs))]
    content = sib.get("content")
    if sib.path and isinstance(content, str):
        return [SiblingWrite(sib.call_id, norm(sib.path), content=content)]
    return []


def resolve_pending(
    platform: str,
    pending: CanonicalCall,
    writes: list[SiblingWrite],
    pending_found: list[Found],
    *,
    home: str | None,
    workspace_root: str | None,
) -> list[CanonicalCall]:
    """The pending command read through the siblings' writes: one synthetic exec call (source
    `resolved`, call id `resolved:<sibling ids>`) per resolved command, none when no sibling write
    reaches the command. `pending_found` is the pending call's own extraction: a written path the
    pending call only writes to is not read through."""
    command = pending.command if pending.tool_kind is ToolKind.EXEC else None
    if not command or not writes:
        return []
    cwd_raw = pending.get("cwd")
    cwd = (
        normalise_path(str(cwd_raw), home=home, workspace_root=workspace_root)
        if cwd_raw
        else (workspace_root or "/")
    )
    write_only = {
        f.value
        for f in pending_found
        if f.kind is EntityKind.PATH and f.role is Role.DATA_DESTINATION
    } - {
        f.value
        for f in pending_found
        if f.kind is EntityKind.PATH and f.role in (Role.DATA_SOURCE, Role.EXECUTABLE)
    }

    executed = {
        f.value for f in pending_found if f.kind is EntityKind.PATH and f.role is Role.EXECUTABLE
    }

    variants = [command]
    scripts: list[tuple[str, str | None, str | None]] = []
    used: list[str] = []
    for w in writes:
        names = _names(w.path, cwd=cwd, home=home, workspace_root=workspace_root)
        inside = w.content is None  # a link or an archive is followed into, a file is not
        if w.path in write_only or not any(_mentions(command, n, inside=inside) for n in names):
            continue
        if w.content is not None and w.path in executed:
            # The pending call runs the file: its content is the program that runs.
            scripts.append((w.content, _interpreter_for(w.path), w.call_id))
        elif w.content is not None:
            variants = [_through_content(v, names, w.content) for v in variants]
        elif w.target is not None:
            variants = [_replace(v, names, w.target, inside=True) for v in variants]
        else:
            variants = [_replace(v, names, c, inside=False) for v in variants for c in w.carried]
        variants = variants[:MAX_RESOLVED]
        if w.call_id and w.call_id not in used:
            used.append(w.call_id)

    def synthetic(cmd: str, interpreter: str | None, ids: list[str]) -> CanonicalCall:
        arguments: dict[str, Any] = {"command": cmd}
        if cwd_raw:
            arguments["cwd"] = cwd_raw
        call = canonicalise(
            platform,
            source="resolved",
            tool=pending.tool,
            tool_kind=ToolKind.EXEC,
            provider=Provider(kind=ProviderKind.HOST),
            arguments=arguments,
            call_id="resolved:" + ",".join(ids),
            step=pending.step,
        )
        if interpreter:
            call.args["interpreter"] = interpreter
        return call

    out = [
        synthetic(v, pending.get("interpreter"), used)
        for v in dict.fromkeys(variants)
        if v != command
    ]
    for content, interpreter, call_id in scripts[:MAX_RESOLVED]:
        if content.strip():
            out.append(synthetic(content, interpreter, [call_id] if call_id else []))
    return out


def _interpreter_for(path: str) -> str | None:
    if path.endswith(".py"):
        return "python"
    if path.endswith((".js", ".mjs", ".cjs")):
        return "node"
    return None


# --------------------------------------------------------------------------- helpers


def _is_symbolic_flag(tok: str) -> bool:
    if tok == "--symbolic":
        return True
    return tok.startswith("-") and not tok.startswith("--") and "s" in tok[1:]


def _first_str(raw: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = raw.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _first_list(raw: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    for k in keys:
        v = raw.get(k)
        if isinstance(v, list) and v and all(isinstance(i, str) for i in v):
            return v
    return []


def _names(path: str, *, cwd: str, home: str | None, workspace_root: str | None) -> list[str]:
    """The spellings a command may use for `path`: absolute, home-relative, relative to the cwd
    or the workspace. Longest first, so the replacement takes the whole spelling."""
    names = {path, display_path(path, home)}
    for root in (cwd, workspace_root):
        if root and path.startswith(root.rstrip("/") + "/"):
            rel = path[len(root.rstrip("/")) + 1 :]
            names.update({rel, "./" + rel})
    return sorted((n for n in names if n), key=len, reverse=True)


def _name_re(name: str, *, inside: bool) -> re.Pattern[str]:
    tail = r"(?=$|[^\w.-])" if not inside else r"(?=$|/|[^\w.-])"
    return re.compile(r"(?<![\w./~-])" + re.escape(name) + tail)


def _mentions(text: str, name: str, *, inside: bool) -> bool:
    return bool(_name_re(name, inside=inside).search(text))


def _replace(command: str, names: list[str], new: str, *, inside: bool) -> str:
    for n in names:
        command = _name_re(n, inside=inside).sub(lambda _m: new, command)
    return command


def _substitutions(command: str) -> list[tuple[int, int]]:
    """Spans of `$(…)` (balanced parentheses) and backtick substitutions, outermost only."""
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(command):
        if command.startswith("$(", i):
            depth, j = 0, i + 1
            while j < len(command):
                if command[j] == "(":
                    depth += 1
                elif command[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= len(command):
                break
            spans.append((i, j + 1))
            i = j + 1
        elif command[i] == "`":
            j = command.find("`", i + 1)
            if j < 0:
                break
            spans.append((i, j + 1))
            i = j + 1
        else:
            i += 1
    return spans


def _through_content(command: str, names: list[str], content: str) -> str:
    """Replace each substitution that names the file with the written value; when none does, the
    file is read some other way and the value is appended as an argument."""
    out, last, hit = [], 0, False
    for start, end in _substitutions(command):
        span = command[start:end]
        if any(_mentions(span, n, inside=False) for n in names):
            value = _value(content, span)
            if command[start - 1 : start] == '"' and command[end : end + 1] == '"':
                # `"$(cat f)"` becomes the value quoted only if it needs quoting, as it would
                # be typed.
                start, end, value = start - 1, end + 1, shlex.quote(value)
            out.append(command[last:start])
            out.append(value)
            last, hit = end, True
    if hit:
        out.append(command[last:])
        return "".join(out)
    return command + " " + shlex.quote(_value(content, command))


def _value(content: str, reader: str) -> str:
    """The value a reader takes from written content: the JSON string under a key the reader
    names, the only JSON string, or the stripped text."""
    text = content.strip()
    try:
        data = json.loads(text)
    except ValueError:
        return text
    leaves: dict[str, str] = {}
    _string_leaves(data, None, leaves)
    for key, value in leaves.items():
        if re.search(r"""[\[.'"]""" + re.escape(key) + r"""['"\]]""", reader):
            return value
    if len(set(leaves.values())) == 1:
        return next(iter(leaves.values()))
    return text


def _string_leaves(value: Any, key: str | None, out: dict[str, str]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _string_leaves(v, str(k), out)
    elif isinstance(value, list):
        for v in value:
            _string_leaves(v, key, out)
    elif isinstance(value, str) and key is not None:
        out.setdefault(key, value)
