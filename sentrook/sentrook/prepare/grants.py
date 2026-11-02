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
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ..planir.canonical import CanonicalCall
from ..planir.models import Grant, GrantScope, PlanIR, ToolKind
from .entities import (
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


def over_broad(pattern: str) -> bool:
    p = pattern.strip()
    return p in ("*", "**", "*.*", "") or p.strip("*") == "" or p.rstrip("/") in ("", "~", "$HOME")


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


def tool_covers(pattern: str, call: CanonicalCall) -> bool:
    """Does a `tool` grant cover every command `call` runs? Only exec calls are covered."""
    if call.tool_kind is not ToolKind.EXEC or over_broad(pattern):
        return False
    pat = pattern.strip().lower()
    commands = [
        t for t in shell_segments(call.command or "") if posixpath.basename(t[0]) not in _NAVIGATION
    ]
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
_REDIRECTS = (">>", ">", "1>", "2>", "&>")


def path_actions(
    call: CanonicalCall, entity: Entity, *, home: str | None, workspace_root: str | None
) -> frozenset[str]:
    """What `call` does to the path `entity`: read, write, edit, delete or exec. A command removing
    the path (`rm`, the source of `mv`) deletes it; a redirection, `tee`, or the destination of
    `cp`/`mv` writes it. Otherwise the entity's role decides."""
    if call.tool_kind in _OP_FOR_KIND:
        return frozenset({_OP_FOR_KIND[call.tool_kind]})
    found: set[str] = set()
    if call.tool_kind is ToolKind.EXEC:
        cwd = call.get("cwd") or workspace_root or "/"

        def here(tok: str) -> bool:
            norm, _ = resolve_token(tok, cwd, home=home, workspace_root=workspace_root)
            return norm == entity.value

        for tokens in shell_segments(call.command or ""):
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
            if head in _DELETE_HEADS:
                found |= {"delete" for a in args if here(a)}
            elif head == "mv" and len(args) >= 2:
                found |= {"delete" for a in args[:-1] if here(a)}
                found |= {"write" for a in args[-1:] if here(a)}
            elif head in _COPY_HEADS and len(args) >= 2:
                found |= {"read" for a in args[:-1] if here(a)}
                found |= {"write" for a in args[-1:] if here(a)}
            elif head == "tee":
                found |= {"write" for a in args if here(a)}
    if found:
        return frozenset(found)
    if Role.EXECUTABLE in entity.roles:
        return frozenset({"exec"})
    if Role.DATA_DESTINATION in entity.roles:
        return frozenset({"write"})
    return frozenset({"read"})
