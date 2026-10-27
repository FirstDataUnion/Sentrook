"""Whether a pipeline stage runs what is piped into it.

A shell or interpreter after a pipe runs its stdin only when it reads its program from there. Given
its own program (a program flag, a script file) it reads stdin as data, unless that inline program
itself runs its input. AIRA's code checks and entity extraction's code-source role both ask this,
from the same `installers` list entries, so the two cannot drift.
"""

from __future__ import annotations

from typing import Any

from .exec_shape import ExecSegment
from .lists import Lists


def _stage_program(head: str, lists: Lists) -> dict[str, Any] | None:
    for entry in lists.get("installers", "stage_programs", default=[]) or []:
        if isinstance(entry, dict) and head in (entry.get("heads") or ()):
            return entry
    return None


def _looks_like_script(token: str) -> bool:
    return "/" in token or "." in token.lstrip(".")


def stage_runs_stdin(seg: ExecSegment, lists: Lists) -> bool:
    """Whether a pipeline stage takes its program from stdin, so that what is piped into it runs.

    A stage given its own program (a program flag, a script file) reads stdin as data, unless that
    inline program itself runs its input (`exec(sys.stdin.read())`, `bash -c "$(cat)"`). Anything
    the argv walk cannot settle counts as running stdin.
    """
    entry = _stage_program(seg.head, lists)
    shells = set(lists.strings("installers", "shell_heads"))
    if entry is None:
        return True
    program = {str(f) for f in entry.get("program_flags") or ()}
    stdin = {str(f) for f in entry.get("stdin_flags") or ()}
    values = {str(f) for f in entry.get("value_flags") or ()}
    bundle = str(entry.get("bundle_letters") or "")
    subcommands = {str(s) for s in entry.get("subcommands") or ()}
    program_subcommands = {str(s) for s in entry.get("program_subcommands") or ()}
    stdin_modules = {str(m) for m in entry.get("stdin_modules") or ()}
    program_letters = {f[1] for f in program if len(f) == 2 and f[0] == "-" and f[1] != "-"}
    stdin_letters = {f[1] for f in stdin if len(f) == 2 and f[0] == "-" and f[1] != "-"}
    key = "shell_inline_stdin_exec_patterns" if seg.head in shells else "inline_stdin_exec_patterns"
    runs_input = lists.patterns("installers", key)
    from_stdin = {"-", *lists.strings("installers", "stdin_paths")}

    def inline(flag: str, value: str | None) -> bool:
        if value is None:
            return True
        if flag == "-m":
            return value in stdin_modules
        return any(rx.search(value) for rx in runs_input)

    argv = seg.argv
    i, first_positional = 0, True
    while i < len(argv):
        token = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if token in from_stdin:
            return True
        if token == "--":
            return nxt is None or nxt in from_stdin or not _looks_like_script(nxt)
        if token in stdin:
            return True
        if token in program:
            return inline(token, nxt)
        if token.startswith("--") and "=" in token:
            name, value = token.split("=", 1)
            if name in program:
                return inline(name, value)
            i += 1
            continue
        if token in values:
            i += 2
            continue
        if token.startswith("-") and not token.startswith("--"):
            for j, letter in enumerate(token[1:], start=1):
                if letter in stdin_letters:
                    return True
                if letter in program_letters:
                    return inline(f"-{letter}", token[j + 1 :] or nxt)
                if letter not in bundle:
                    break
            i += 1
            continue
        if token.startswith(("-", "+")):
            i += 1
            continue
        if first_positional and token in subcommands:
            first_positional = False
            i += 1
            continue
        if first_positional and token in program_subcommands:
            return inline(token, nxt)
        return not _looks_like_script(token)
    return True
