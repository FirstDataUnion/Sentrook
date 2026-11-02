"""Grant kinds: what each kind of owner grant covers and what it relieves.

One closed table (`GRANT_KINDS`). A kind it does not list still reaches the Jev views with the rest of
the PlanIR but never gives deterministic relief. Adding a kind is a table entry plus, where it needs a
new way of matching, a matcher here.

Every grant passes the same gates before its kind is consulted:

- **Live**: a grant whose `expires_at` is at or before the request's `sent_at` has lapsed, whatever its
  scope. A `session` grant covers only the session named by its `session_ref`; one without a
  `session_ref` covers no session.
- **Not over-broad**: a pattern that would match everything (`*`, `**`, `*.*`, `/`, `~/`) is refused.
- **Allowed action**: for kinds with an `allows` vocabulary, the grant covers an entity only when it
  allows every action the call takes on it (an empty `allows` means the kind's default).

Matching, by kind:

- `destination`: a host, recipient or channel against a glob; `*.example.com` also covers
  `example.com`, and a recipient is matched by its domain when the pattern has no `@`.
- `file`: a path against a glob (`*` matches `/` too); a pattern ending in `/` covers that directory
  and everything under it.
- `provider`: an MCP server or plugin identity against a glob; a pattern ending in `/` covers the scope.
- `tool`: the whole call, when every command in it is covered: a pattern without spaces against the
  command name (directory stripped), one with spaces against the whole command.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from ..planir.canonical import CanonicalCall
from ..planir.models import Grant, GrantScope, PlanIR, ToolKind
from .entities import (
    _ENV_ASSIGN_RE,
    _SEGMENT_SPLIT_RE,
    Entity,
    EntityKind,
    Role,
    is_under,
    resolve_token,
    shell_segments,
)

DISTRUST = "suspicion.distrust"
UNTRUSTED_ORIGIN = "suspicion.untrusted_origin"
SENSITIVITY = "consequence.sensitivity"
SELF_MODIFICATION = "consequence.self_modification"


@dataclass(frozen=True)
class GrantKind:
    name: str
    #: Entity kinds the pattern is matched against; empty for a kind matched on the call itself.
    entity_kinds: frozenset[EntityKind] = frozenset()
    #: The `allows` vocabulary; empty when the kind takes no `allows`.
    actions: frozenset[str] = frozenset()
    #: What an empty `allows` means.
    default_allows: frozenset[str] = frozenset()
    #: Signals removed on each covered entity.
    relieves: tuple[str, ...] = ()
    #: Signals removed whatever their subject, when the grant covers the whole call.
    relieves_call: tuple[str, ...] = ()
    #: Reason code of the relief; None for a kind that gives no deterministic relief.
    reason: str | None = None
    #: No relief when the call also sends data off the host.
    local_only: bool = False

    def allows(self, grant: Grant) -> frozenset[str]:
        return frozenset(a.lower() for a in grant.allows) or self.default_allows


_FILE_ACTIONS = frozenset({"read", "write", "edit", "delete", "exec"})

GRANT_KINDS: dict[str, GrantKind] = {
    k.name: k
    for k in (
        GrantKind(
            "destination",
            entity_kinds=frozenset({EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL}),
            relieves=(DISTRUST, UNTRUSTED_ORIGIN),
            reason="relief.destination_grant",
        ),
        GrantKind(
            "file",
            entity_kinds=frozenset({EntityKind.PATH}),
            actions=_FILE_ACTIONS,
            default_allows=frozenset({"read"}),
            relieves=(SENSITIVITY,),
            reason="relief.file_grant",
            local_only=True,
        ),
        GrantKind(
            "provider",
            entity_kinds=frozenset({EntityKind.MCP_SERVER, EntityKind.PLUGIN}),
            relieves=(DISTRUST,),
            reason="relief.provider_grant",
        ),
        GrantKind(
            "tool",
            actions=frozenset({"exec"}),
            default_allows=frozenset({"exec"}),
            relieves_call=(SELF_MODIFICATION,),
            reason="relief.tool_grant",
        ),
        # Read by Jev from the grants block; no deterministic relief yet.
        GrantKind("automation"),
    )
}


# --------------------------------------------------------------------------- gates


def lapse(grant: Grant, planir: PlanIR) -> str | None:
    """Why `grant` does not apply to this request (`expired`, `unbound_session`, `other_session`), or
    None when it does."""
    if grant.expires_at is not None and _aware(grant.expires_at) <= _aware(planir.sent_at):
        return "expired"
    if grant.scope is GrantScope.SESSION:
        if not grant.session_ref:
            return "unbound_session"
        if grant.session_ref != planir.session.session_ref:
            return "other_session"
    return None


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo is not None else t.replace(tzinfo=UTC)


#: What is left of a pattern once its glob characters, separators and home markers are removed;
#: nothing left means the pattern matches everything.
_NOT_LITERAL = re.compile(r"\[[^\]]*\]|\$HOME|[*?/~.\s]")


def over_broad(pattern: str) -> bool:
    """`*`, `?*`, `[a-z]*`, `*.*`, `/`, `/*`, `~/*`, `* *` and the like: nothing literal to match."""
    return _NOT_LITERAL.sub("", pattern) == ""


def sends_off_host(call: CanonicalCall, pending: Iterable[Entity]) -> bool:
    """The call sends something off this machine: a destination or recipient among its entities, or
    an exec command that sends (`nc`, `rsync`, `scp`, `ssh`, `git push`, an upload with `curl`, …)
    to a host that may not be written as one (`backup:/x`, `origin`)."""
    if any(
        e.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
        and e.kind in (EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL)
        for e in pending
    ):
        return True
    command = call.command or "" if call.tool_kind is ToolKind.EXEC else ""
    return bool(_SENDS.search(command))


#: Commands that send: network tools, `git push`, and `curl`/`wget` with an upload flag.
_SENDS = re.compile(
    r"/dev/tcp/|\b(?:nc|ncat|socat|scp|rsync|sftp|ssh|ftp|mail|sendmail|mutt)\b"
    r"|\bgit\b[^;&|\n]*\spush\b"
    r"|\b(?:curl|wget)\b[^;&|\n]*\s(?:-d|--data[\w-]*|-F|--form|-T|--upload-file|--post-data|"
    r"--post-file|-X\s*(?:POST|PUT|PATCH)|--request\s*(?:POST|PUT|PATCH))(?=[\s=]|$)"
)


# --------------------------------------------------------------------------- matchers


def _destination(pat: str, entity: Entity) -> bool:
    value = entity.value.lower()
    if entity.kind is EntityKind.RECIPIENT and "@" in value and "@" not in pat:
        value = value.split("@", 1)[1]
    if fnmatch.fnmatch(value, pat):
        return True
    return pat.startswith("*.") and value == pat[2:]


def _file(pat: str, entity: Entity) -> bool:
    if pat.endswith("/"):
        root = pat.rstrip("/")
        return is_under(entity.value, root) or is_under(entity.display, root)
    return fnmatch.fnmatch(entity.value, pat) or fnmatch.fnmatch(entity.display, pat)


def _provider(pat: str, entity: Entity) -> bool:
    value = entity.value.lower()
    if pat.endswith("/"):
        return value.startswith(pat)
    return fnmatch.fnmatch(value, pat)


_ENTITY_MATCHERS: dict[str, Callable[[str, Entity], bool]] = {
    "destination": _destination,
    "file": _file,
    "provider": _provider,
}


def grant_matches(kind: str, pattern: str, entity: Entity) -> bool:
    """Does a grant of `kind` with `pattern` cover `entity`, before scope, expiry and `allows`?
    Over-broad patterns never match."""
    spec = GRANT_KINDS.get(kind)
    matcher = _ENTITY_MATCHERS.get(kind)
    if spec is None or matcher is None or entity.kind not in spec.entity_kinds:
        return False
    if over_broad(pattern):
        return False
    return matcher(pattern.strip().lower(), entity)


#: Commands that only move the shell around; a tool grant need not cover them.
_NAVIGATION = frozenset({"cd", "pushd", "popd"})
#: Shell forms that run something a segment list does not show: a background `&`, command and
#: process substitution.
_HIDDEN_COMMAND = re.compile(r"\$\(|`|<\(|>\(|(?<![&>|0-9])&(?![&>])")
_OUTPUT_REDIRECT = re.compile(r"(?:[0-9]|&)?>>?\s*(\S+)")


def tool_covers(pattern: str, call: CanonicalCall) -> bool:
    """Does a `tool` grant cover every command `call` runs? Only exec calls are covered, and only
    when nothing else runs or is written: no background `&`, command or process substitution,
    variable assignment or `env` in front of a command, or output redirected anywhere but
    `/dev/null` or another descriptor."""
    command = call.command or ""
    if call.tool_kind is not ToolKind.EXEC or over_broad(pattern):
        return False
    if _HIDDEN_COMMAND.search(command):
        return False
    for m in _OUTPUT_REDIRECT.finditer(command):
        target = m.group(1).strip("'\"")
        if not (target.startswith("&") or target == "/dev/null"):
            return False
    for seg in _SEGMENT_SPLIT_RE.split(command):
        head = seg.strip().lstrip("(").split(maxsplit=1)[:1]
        if head and (head[0] == "env" or _ENV_ASSIGN_RE.match(head[0])):
            return False
    pat = pattern.strip().lower()
    commands = [t for t in shell_segments(command) if posixpath.basename(t[0]) not in _NAVIGATION]
    if not commands:
        return False
    for tokens in commands:
        if " " in pat:
            subject = " ".join([posixpath.basename(tokens[0]), *tokens[1:]]).lower()
        else:
            subject = posixpath.basename(tokens[0]).lower()
        if not fnmatch.fnmatch(subject, pat):
            return False
    return True


# --------------------------------------------------------------------------- actions

_OP_FOR_KIND: dict[ToolKind, str] = {
    ToolKind.FILE_READ: "read",
    ToolKind.FILE_WRITE: "write",
    ToolKind.FILE_EDIT: "edit",
    ToolKind.MEMORY_WRITE: "write",
}
_DELETE_HEADS = frozenset({"rm", "rmdir", "unlink", "shred", "srm"})
_COPY_HEADS = frozenset({"cp", "install", "rsync", "scp"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_IN_PLACE_HEADS = frozenset({"sed", "perl", "ruby"})
_REDIRECTS = (">>", ">", "1>", "2>", "&>")


def path_actions(
    call: CanonicalCall, entity: Entity, *, home: str | None, workspace_root: str | None
) -> frozenset[str]:
    """What `call` does to the path `entity`: read, write, edit, delete or exec, all of them.

    Deleting: `rm`, `rmdir`, `unlink`, `shred`, the source of `mv`, `find -delete` or `-exec rm`
    on it, `xargs rm` anywhere in a command naming it. Writing: a redirection, `tee`, the destination
    of `cp`/`mv`/`install`, `dd of=`. Editing: `sed -i` and the like. A wildcard argument counts for
    every path it could reach, and `sh -c '…'` is read through. Running it, or the call's role for it
    (a write target), adds to what the command shows; a path the command shows nothing for is read."""
    if call.tool_kind in _OP_FOR_KIND:
        return frozenset({_OP_FOR_KIND[call.tool_kind]})
    found: set[str] = set()
    if call.tool_kind is ToolKind.EXEC:
        cwd = call.get("cwd") or workspace_root or "/"
        found = _exec_actions(call.command or "", entity, cwd, home, workspace_root, 0)
    if Role.EXECUTABLE in entity.roles:
        found.add("exec")
    if Role.DATA_DESTINATION in entity.roles and not found & {"write", "delete"}:
        found.add("write")
    return frozenset(found or {"read"})


def _exec_actions(
    command: str, entity: Entity, cwd: str, home: str | None, ws: str | None, depth: int
) -> set[str]:
    def here(tok: str) -> bool:
        norm, wildcard = resolve_token(tok, cwd, home=home, workspace_root=ws)
        if norm == entity.value:
            return True
        return wildcard and (is_under(entity.value, norm) or is_under(norm, entity.value))

    found: set[str] = set()
    named = False
    xargs_delete = False
    for tokens in shell_segments(command):
        head = posixpath.basename(tokens[0])
        args: list[str] = []
        rest = iter(tokens[1:])
        for tok in rest:
            if tok in _REDIRECTS:
                target = next(rest, None)
                if target is not None and here(target):
                    found.add("write")
                continue
            bare = tok.lstrip("&12")
            if bare.startswith(">"):
                if here(bare.lstrip(">")):
                    found.add("write")
                continue
            if not tok.startswith("-"):
                args.append(tok)
        named = named or any(here(a) for a in args)
        flags = tokens[1:]
        if head in _SHELLS and depth < 3:
            for i, tok in enumerate(flags[:-1]):
                if tok.startswith("-") and not tok.startswith("--") and "c" in tok:
                    found |= _exec_actions(flags[i + 1], entity, cwd, home, ws, depth + 1)
                    break
        if head in _DELETE_HEADS:
            found |= {"delete" for a in args if here(a)}
        elif head in _COPY_HEADS or head == "mv":
            target = _target_dir(flags)
            dest = target if target is not None else (args[-1] if len(args) >= 2 else None)
            if dest is not None:
                source_op = "delete" if head == "mv" else "read"
                found |= {source_op for a in args if a != dest and here(a)}
                if here(dest):
                    found.add("write")
        elif head == "tee":
            found |= {"write" for a in args if here(a)}
        elif head == "find":
            first_flag = next((i for i, t in enumerate(flags) if t.startswith("-")), len(flags))
            removes = "-delete" in flags or any(
                t in ("-exec", "-execdir", "-ok")
                and i + 1 < len(flags)
                and posixpath.basename(flags[i + 1]) in _DELETE_HEADS
                for i, t in enumerate(flags)
            )
            if removes:
                found |= {"delete" for a in flags[:first_flag] if here(a)}
        elif head in _IN_PLACE_HEADS and any(_in_place(t) for t in flags):
            found |= {"edit" for a in args if here(a)}
        elif head == "dd":
            found |= {"write" for t in flags if t.startswith("of=") and here(t[3:])}
        elif head == "xargs":
            cmd = [t for t in flags if not t.startswith("-")]
            xargs_delete = xargs_delete or bool(cmd and posixpath.basename(cmd[0]) in _DELETE_HEADS)
    if xargs_delete and named:
        found.add("delete")  # the paths fed to it are not in the command; any path named may be
    return found


def _in_place(flag: str) -> bool:
    """`-i`, `-i.bak`, `--in-place`, or a bundle such as perl's `-pi`."""
    return flag.startswith("--in-place") or (
        flag.startswith("-") and not flag.startswith("--") and "i" in flag[1:3]
    )


def _target_dir(flags: list[str]) -> str | None:
    """The `-t DIR` / `--target-directory=DIR` destination of `mv`, `cp` or `install`."""
    for i, tok in enumerate(flags):
        if tok == "-t" and i + 1 < len(flags):
            return flags[i + 1]
        if tok.startswith("--target-directory="):
            return tok.split("=", 1)[1]
    return None
