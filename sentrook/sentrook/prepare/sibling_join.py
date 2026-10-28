"""Join a sibling's write into the pending call's resolution.

A call issued in the same batch as the pending one can decide what the pending call acts on: it
writes the file whose content the pending command substitutes (`truncate "$(cat target.path)"`),
the config the pending program reads its URL from, the script the pending call runs, the link a
sync follows, or the archive an upload sends. The pending command alone names none of that; read
through the sibling's write it does. `sibling_writes` says what a sibling writes; `resolve_pending`
rewrites the pending command through those writes into resolved commands, which preparation
extracts with the pending call's roles and the sibling's origin, and which AIRA analyses as the
pending call's own action.

What a sibling writes:
- a file write or edit, or an MCP or other write tool with a path and content: the file's content
  (an edit's new text);
- `ln -s TARGET LINK`: the link now points at TARGET;
- a write tool with an output and a list of inputs (an archiver): the output carries the inputs.

How the pending command uses a written path, segment by segment: a redirect target, the operand
of `rm`, `truncate`, `tee` and the like, or the last operand of `cp`, `mv`, `rsync` is written, and
a path the pending call only writes (or only names, to `echo`, `ls`, `stat` and the like) is never
read through; the first operand of `bash`, `python3`
and the like (or the command itself) is run; code given to an interpreter with `-c` or `-e` that
names the file reads it; any other operand (`cat f`, `curl -F file=@f`) reads it. Spellings are
the absolute path, the home-relative one and the one relative to the pending call's cwd.

How the pending command is resolved (exec calls only):
- a command substitution (`$(…)` or backticks) that names the written file is replaced by the
  written value: the value under the JSON keys the substitution reads, the only string in a JSON
  document, or the stripped content;
- a command that runs the file resolves to the file's content, the program that runs;
- a command that reads the file some other way gets the value appended as an argument, so it
  takes the command's role (a destination when the command sends);
- the link path, or a path inside it, is replaced by the link target;
- the archive path is replaced by each input in turn (one resolved command per input).
At most `MAX_RESOLVED` resolved commands come out; `Resolution.truncated` says when more would have.
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
    _ENV_ASSIGN_RE,
    _RUN_HEADS,
    _WRAPPER_HEADS,
    _WRITEISH_TOOL,
    display_path,
    is_under,
    normalise_path,
    resolve_token,
)

#: Resolved commands from one pending call at most (an archive fans out per input).
MAX_RESOLVED = 16

_FILE_WRITE_KINDS = frozenset({ToolKind.FILE_WRITE, ToolKind.FILE_EDIT})
_ARCHIVE_OUTPUT_KEYS = ("output", "out", "archive", "destination", "dest")
_ARCHIVE_INPUT_KEYS = ("inputs", "sources", "files", "paths")
_WRITE_HEADS = frozenset(
    "rm truncate shred unlink touch tee mkdir rmdir chmod chown chgrp dd".split()
)
_COPY_HEADS = frozenset("cp mv install ln rsync scp".split())
#: Heads that take a path as a name, not as content to read.
_NAMING_HEADS = frozenset("echo printf ls stat test [ basename dirname realpath readlink".split())
_INTERPRETERS = frozenset("python python2 python3 node perl ruby deno bun".split())
_PROGRAM_FLAGS = frozenset({"-c", "-e", "-E", "--eval"})
_OUTPUT_FLAGS = frozenset({"-o", "--output", "-O", "--output-document"})
_SUB = " __sibling_join_sub__ "


@dataclass(frozen=True)
class SiblingWrite:
    call_id: str | None
    path: str  # normalised absolute path the sibling writes
    content: str | None = None  # a file's content, or an edit's new text
    target: str | None = None  # a link: the normalised path it points at
    carried: tuple[str, ...] = field(default=())  # an archive: the normalised paths packed in


@dataclass
class Resolution:
    calls: list[CanonicalCall] = field(default_factory=list)
    #: More resolved commands than `MAX_RESOLVED` would have come out; the rest were dropped.
    truncated: bool = False


def sibling_writes(
    sib: CanonicalCall, *, home: str | None, workspace_root: str | None
) -> list[SiblingWrite]:
    """What one sibling writes, in the forms the join can resolve through. Arguments of the wrong
    type, or a path that does not resolve to an absolute one, give nothing."""

    def norm(p: Any, cwd: str | None = None) -> str | None:
        if not isinstance(p, str) or not p.strip():
            return None
        out = normalise_path(p, home=home, workspace_root=workspace_root, cwd=cwd)
        return out if out.startswith("/") else None

    kind = sib.tool_kind
    if kind is ToolKind.EXEC:
        cwd = norm(sib.get("cwd")) or workspace_root or "/"
        command = sib.command if isinstance(sib.command, str) else ""
        out: list[SiblingWrite] = []
        for toks in _segments(command):
            if toks[0] != "ln" or not any(_is_symbolic_flag(t) for t in toks[1:]):
                continue
            operands = [t for t in toks[1:] if not t.startswith("-")]
            if len(operands) != 2:
                continue
            target, link = (
                resolve_token(t, cwd, home=home, workspace_root=workspace_root)[0] for t in operands
            )
            if target.startswith("/") and link.startswith("/"):
                out.append(SiblingWrite(sib.call_id, link, target=target))
        return out
    if kind not in _FILE_WRITE_KINDS and not (
        kind in (ToolKind.MCP, ToolKind.OTHER) and _WRITEISH_TOOL.search(sib.tool)
    ):
        return []
    output = norm(_first_str(sib.raw, _ARCHIVE_OUTPUT_KEYS))
    inputs = [i for i in (norm(x) for x in _first_list(sib.raw, _ARCHIVE_INPUT_KEYS)) if i]
    if output and inputs:
        return [SiblingWrite(sib.call_id, output, carried=tuple(inputs))]
    path, content = norm(sib.path), sib.get("content")
    if path and isinstance(content, str):
        return [SiblingWrite(sib.call_id, path, content=content)]
    return []


def resolve_pending(
    platform: str,
    pending: CanonicalCall,
    writes: list[SiblingWrite],
    *,
    home: str | None,
    workspace_root: str | None,
) -> Resolution:
    """The pending command read through the siblings' writes: one synthetic exec call (source
    `resolved`, call id `resolved:<sibling ids>`) per resolved command, none when no sibling write
    reaches the command."""
    command = pending.command if pending.tool_kind is ToolKind.EXEC else None
    if not isinstance(command, str) or not command or not writes:
        return Resolution()
    cwd_raw = pending.get("cwd")
    cwd = (
        normalise_path(cwd_raw, home=home, workspace_root=workspace_root)
        if isinstance(cwd_raw, str) and cwd_raw
        else (workspace_root or "/")
    )

    variants = [command]
    scripts: list[tuple[str, str | None, str | None]] = []
    used: list[str] = []
    truncated = False
    for w in writes:
        names = _names(w.path, cwd=cwd, home=home)
        inside = w.content is None  # a link or an archive is followed into, a file is not
        if w.content is not None and _substituted(command, names):
            variants = [_substitute(v, names, w.content) for v in variants]
        else:
            uses = _uses(
                command, w.path, names, inside=inside, cwd=cwd, home=home, ws=workspace_root
            )
            if not uses & {"read", "run"}:
                continue  # not used, or only written
            if w.content is not None and "run" in uses:
                # The pending call runs the file: its content is the program that runs.
                scripts.append((w.content, _interpreter_for(w.path), w.call_id))
            elif w.content is not None:
                variants = [f"{v} {shlex.quote(_value(w.content, command))}" for v in variants]
            elif w.target is not None:
                variants = [_replace(v, names, w.target) for v in variants]
            else:
                variants = [_replace(v, names, c) for v in variants for c in w.carried]
        if len(variants) > MAX_RESOLVED:
            variants, truncated = variants[:MAX_RESOLVED], True
        if w.call_id and w.call_id not in used:
            used.append(w.call_id)

    def synthetic(cmd: str, interpreter: Any, ids: list[str]) -> CanonicalCall:
        arguments: dict[str, Any] = {"command": cmd}
        if isinstance(cwd_raw, str) and cwd_raw:
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
    for content, interpreter, call_id in scripts:
        if content.strip():
            out.append(synthetic(content, interpreter, [call_id] if call_id else []))
    if len(out) > MAX_RESOLVED:
        out, truncated = out[:MAX_RESOLVED], True
    return Resolution(out, truncated)


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


def _names(path: str, *, cwd: str, home: str | None) -> list[str]:
    """The spellings a command may use for `path`: absolute, home-relative, relative to the cwd.
    Longest first, so a replacement takes the whole spelling."""
    names = {path, display_path(path, home)}
    if path.startswith(cwd.rstrip("/") + "/"):
        rel = path[len(cwd.rstrip("/")) + 1 :]
        names.update({rel, "./" + rel})
    return sorted((n for n in names if n), key=len, reverse=True)


def _name_re(name: str, *, inside: bool) -> re.Pattern[str]:
    tail = r"(?=$|/|[^\w.-])" if inside else r"(?=$|[^\w.-])"
    return re.compile(r"(?<![\w./~-])" + re.escape(name) + tail)


def _mentions(text: str, names: list[str], *, inside: bool = False) -> bool:
    return any(_name_re(n, inside=inside).search(text) for n in names)


def _replace(command: str, names: list[str], new: str) -> str:
    for n in names:
        command = _name_re(n, inside=True).sub(lambda _m: new, command)
    return command


def _segments(command: str) -> list[list[str]]:
    """Simple commands as token lists, quotes honoured, operators (`;`, `&&`, `|`, parentheses)
    splitting segments and redirect operators kept as tokens; wrappers and leading assignments
    dropped. An unparseable command splits on whitespace."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    try:
        toks = list(lex)
    except ValueError:
        toks = command.split()
    segs: list[list[str]] = [[]]
    for t in toks:
        if t and set(t) <= set(";&|()"):
            segs.append([])
        else:
            segs[-1].append(t)
    out: list[list[str]] = []
    for seg in segs:
        while seg and (seg[0] in _WRAPPER_HEADS or _ENV_ASSIGN_RE.match(seg[0])):
            seg = seg[1:]
        if seg:
            out.append(seg)
    return out


def _uses(
    command: str,
    path: str,
    names: list[str],
    *,
    inside: bool,
    cwd: str,
    home: str | None,
    ws: str | None,
) -> set[str]:
    """How the command uses `path`: any of `read`, `run`, `write`."""

    def hits(tok: str) -> bool:
        for cand in {tok, tok.rsplit("@", 1)[-1], tok.split("=", 1)[-1]}:
            cand = cand.strip("'\"")
            if not cand or "://" in cand or cand.startswith("-"):
                continue
            resolved, _ = resolve_token(cand, cwd, home=home, workspace_root=ws)
            if resolved == path or (inside and is_under(resolved, path)):
                return True
        return False

    stripped = command
    for start, end in reversed(_substitutions(command)):
        stripped = stripped[:start] + _SUB + stripped[end:]
    uses: set[str] = set()
    for seg in _segments(stripped):
        head = seg[0].rsplit("/", 1)[-1]
        if hits(seg[0]):
            uses.add("run")
        mode, prev = None, None
        operands: list[str] = []
        for tok in seg[1:]:
            if tok in (">", ">>", ">|", "&>"):
                mode = "write"
            elif tok == "<":
                mode = "read"
            elif mode is not None:
                if hits(tok):
                    uses.add(mode)
                mode = None
            elif head in _INTERPRETERS and prev in _PROGRAM_FLAGS:
                if _mentions(tok, names, inside=inside):
                    uses.add("read")
            elif prev in _OUTPUT_FLAGS:
                if hits(tok):
                    uses.add("write")
            elif not tok.startswith("-"):
                operands.append(tok)
            prev = tok
        for k, tok in enumerate(operands):
            if not hits(tok):
                continue
            if head in _NAMING_HEADS:
                continue
            if head in _WRITE_HEADS:
                uses.add("write")
            elif head in _COPY_HEADS and k == len(operands) - 1 and len(operands) > 1:
                uses.add("write")
            elif head in _RUN_HEADS and k == 0:
                uses.add("run")
            else:
                uses.add("read")
    return uses


def _substitutions(command: str) -> list[tuple[int, int]]:
    """Spans of `$(…)` and backtick substitutions, outermost only. Parentheses inside quotes do
    not count; an unclosed substitution ends the scan."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(command)
    while i < n:
        if command.startswith("$(", i):
            depth, j, quote = 0, i + 1, None
            while j < n:
                c = command[j]
                if quote:
                    if c == "\\" and quote == '"':
                        j += 1
                    elif c == quote:
                        quote = None
                elif c in ("'", '"'):
                    quote = c
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n:
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


def _substituted(command: str, names: list[str]) -> bool:
    return any(_mentions(command[a:b], names) for a, b in _substitutions(command))


def _substitute(command: str, names: list[str], content: str) -> str:
    """Replace each substitution that names the file with the written value."""
    out, last = [], 0
    for start, end in _substitutions(command):
        span = command[start:end]
        if not _mentions(span, names):
            continue
        value = _value(content, span)
        if command[start - 1 : start] == '"' and command[end : end + 1] == '"':
            # `"$(cat f)"` becomes the value, quoted only if it needs quoting, as it would be typed.
            start, end, value = start - 1, end + 1, shlex.quote(value)
        out.append(command[last:start])
        out.append(value)
        last = end
    out.append(command[last:])
    return "".join(out)


def _value(content: str, reader: str) -> str:
    """The value a reader takes from written content: the JSON string whose keys the reader names
    (the most of its key path, the last key required), the only JSON string, or the stripped
    text."""
    text = content.strip()
    try:
        data = json.loads(text)
    except ValueError:
        return text
    leaves: list[tuple[tuple[str, ...], str]] = []
    _string_leaves(data, (), leaves)

    def named(key: str) -> bool:
        return bool(
            re.search(r"""(?:\[\s*['"]|['"]|\.)""" + re.escape(key) + r"""(?:['"]|\b)""", reader)
        )

    best, best_score = None, 0
    for keys, value in leaves:
        if not keys or not named(keys[-1]):
            continue
        score = sum(1 for k in keys if named(k))
        if score > best_score:
            best, best_score = value, score
    if best is not None:
        return best
    values = {v for _, v in leaves}
    if len(values) == 1:
        return values.pop()
    return text


def _string_leaves(
    value: Any, keys: tuple[str, ...], out: list[tuple[tuple[str, ...], str]]
) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _string_leaves(v, (*keys, str(k)), out)
    elif isinstance(value, list):
        for v in value:
            _string_leaves(v, keys, out)
    elif isinstance(value, str) and keys:
        out.append((keys, value))
