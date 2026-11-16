"""Copies and moves in the history: a file the agent copied, moved or linked is the same file under
another name.

`cp a b`, `mv a b`, `rsync a b` and `ln a b` steps that ran (not denied or blocked) are recorded in
step order. `CopyHistory.ancestors` walks them back from a path: the files it was copied from, as
the path stood before a given step. A whole-file write to the path after the copy replaces what was
copied there and ends the chain; an edit does not.

Used to read the content of a script the call runs from a copy, and to match a retry of a denied step
made through a copy of the denied file. Shell redirection (`cat a > b`) is not followed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..planir.canonical import CanonicalCall
from ..planir.models import ToolKind
from .entities import normalise_path, resolve_token, shell_segments

COPY_HEADS = frozenset({"cp", "mv", "rsync", "ln"})
#: Flags of cp/mv/rsync/ln that take a value.
_VALUE_FLAGS = frozenset({"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh"})
#: How many copies back a chain is followed.
MAX_DEPTH = 8


@dataclass(frozen=True)
class Copy:
    step: int
    head: str
    source: str  # normalised
    destination: str  # normalised: the new name, or the directory the source was put in

    def lands_on(self, path: str) -> bool:
        if self.destination == path:
            return True
        name = self.source.rstrip("/").rsplit("/", 1)[-1]
        return bool(name) and self.destination.rstrip("/") + "/" + name == path


@dataclass
class CopyHistory:
    copies: list[Copy] = field(default_factory=list)
    #: Path → the steps that wrote the whole file (a write replaces whatever was copied there).
    writes: dict[str, list[int]] = field(default_factory=dict)

    def onto(self, path: str, before: int, order: int | None = None) -> Copy | None:
        """The latest copy that put a file at `path` before step `before` (or, with `order`, before
        that position in the list: an earlier copy in the same command), unless a whole-file write
        to the path came after it."""
        latest: Copy | None = None
        for i, c in enumerate(self.copies):
            if order is not None and i >= order:
                break
            if order is None and c.step >= before:
                continue
            if c.lands_on(path):
                latest = c  # the list is in step order
        if latest is None:
            return None
        if any(latest.step < w < before for w in self.writes.get(path, ())):
            return None
        return latest

    def ancestors(self, path: str, before: int) -> list[str]:
        """The files `path` was copied from, nearest first, as it stood before step `before`."""
        out: list[str] = []
        order: int | None = None
        while len(out) < MAX_DEPTH:
            link = self.onto(path, before, order)
            if link is None or link.source == path or link.source in out:
                break
            out.append(link.source)
            path, before, order = link.source, link.step + 1, self.copies.index(link)
        return out


def _operands(args: list[str]) -> tuple[list[str], str] | None:
    """(sources, destination) of a cp/mv/rsync/ln argument list."""
    positional: list[str] = []
    target_dir: str | None = None
    pending_flag: str | None = None
    for tok in args:
        if pending_flag is not None:
            if pending_flag in ("-t", "--target-directory"):
                target_dir = tok
            pending_flag = None
            continue
        if tok in _VALUE_FLAGS:
            pending_flag = tok
            continue
        if tok.startswith("--target-directory="):
            target_dir = tok.split("=", 1)[1]
            continue
        if tok.startswith("-"):
            continue
        positional.append(tok)
    if target_dir is not None:
        return (positional, target_dir) if positional else None
    if len(positional) >= 2:
        return positional[:-1], positional[-1]
    return None


def copy_history(
    history: list[CanonicalCall], skipped: frozenset[int], *, home: str, workspace_root: str
) -> CopyHistory:
    """The copies and whole-file writes of the history steps that ran (`skipped`: steps that were
    denied, blocked or timed out in review, so nothing was copied)."""
    out = CopyHistory()
    for call in history:
        if call.step is None or call.step in skipped:
            continue
        if call.tool_kind is ToolKind.FILE_WRITE and call.path:
            path = normalise_path(call.path, home=home, workspace_root=workspace_root)
            out.writes.setdefault(path, []).append(call.step)
            continue
        if call.tool_kind is not ToolKind.EXEC or not call.command:
            continue
        cwd = call.get("cwd")
        cwd = (
            normalise_path(cwd, home=home, workspace_root=workspace_root)
            if isinstance(cwd, str) and cwd
            else workspace_root
        )
        for tokens in shell_segments(call.command):
            head, args = tokens[0], tokens[1:]
            if head == "cd" and args:
                cwd, _ = resolve_token(args[0], cwd, home=home, workspace_root=workspace_root)
                continue
            if head not in COPY_HEADS:
                continue
            operands = _operands(args)
            if operands is None:
                continue
            sources, dest = operands
            if ":" in dest.split("/", 1)[0]:
                continue  # a remote rsync destination
            dest_path, wild = resolve_token(dest, cwd, home=home, workspace_root=workspace_root)
            if wild:
                continue
            for src in sources:
                if ":" in src.split("/", 1)[0]:
                    continue
                src_path, wild = resolve_token(src, cwd, home=home, workspace_root=workspace_root)
                if wild or src_path == dest_path:
                    continue
                out.copies.append(
                    Copy(step=call.step, head=head, source=src_path, destination=dest_path)
                )
    return out
