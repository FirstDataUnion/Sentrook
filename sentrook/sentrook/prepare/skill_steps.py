"""The commands a saved skill tells the agent to run.

A skill is a procedure the agent follows in later sessions, so the shell commands it holds are future exec calls. For
a declared self-edit that writes a skill, the commands in the written text become synthetic exec calls with source
`resolved`, so the rule-based probe judges them as it would judge the agent running them now: fetching code into a
shell, sending local data off the host, reading credential stores, and so on.

- It applies to any self-edit whose store is `skills` (a skill tool, or a file `write`, `edit` or `apply_patch` into
  the agent's skill directory), and to a skill tool (`skill_manage`, `skill_workshop`) with no known store; never to
  a memory save.
- Only text the save writes is read (`content`, `file_content`, `new_string`, `new_text`, `newText`, also inside
  `operations` and `edits`, and the lines a patch in `input` adds), never the text it replaces.
- Commands come from fenced blocks (``` or ~~~; a line ending in `\\` continues on the next) and from inline code that
  reads as a command.
- A command the text warns against ("never run `…`", "don't use `…`", a fence right after "do not run this:") is
  still judged, marked as negated; the probe weighs it less, since a skill that warns against a command does not run
  it, but a warning word alone never hides a command.
- At most `MAX_COMMANDS` per save, the ones that look riskiest first, so a long skill cannot push a risky step out.
"""

from __future__ import annotations

import re
from typing import Any

from ..planir.canonical import CanonicalCall, canonicalise
from ..planir.models import Provider, ProviderKind, ToolKind

SKILL_TOOLS = frozenset({"skill_manage", "skill_workshop"})
WRITTEN_KEYS = ("content", "file_content", "new_string", "new_text", "newText")
#: Lists of edits whose entries carry written text of their own.
NESTED_KEYS = ("operations", "edits")
#: The argument a patch tool takes its patch text in.
PATCH_KEY = "input"
MAX_COMMANDS = 60
MAX_COMMAND_CHARS = 2000
#: The call id of a synthetic skill-step call; a negated one ends in `NEGATED_SUFFIX`.
CALL_ID_PREFIX = "skill_step:"
NEGATED_SUFFIX = ":negated"

_FENCE = re.compile(r"(?m)^[ \t]*(```|~~~)[^\n]*\n(.*?)^[ \t]*\1[ \t]*$", re.S)
_INLINE = re.compile(r"`([^`\n]{4,})`")
#: A command starts with a program name or path and has at least one argument.
_COMMANDISH = re.compile(r"^(?:sudo\s+)?(?:[\w.~/-]+=\S+\s+)*[./~]?[\w./-]+\s+\S")
_PROMPT = re.compile(r"^\s*\$\s+")
_NEGATION = re.compile(
    r"\b(?:never|don'?t|do not|does not|must not|should not|shouldn'?t|avoid|instead of|rather than|"
    r"no longer|deprecated|not)\b",
    re.I,
)
#: Marks of a command worth judging first when a skill holds more than `MAX_COMMANDS`.
_RISKY = re.compile(
    r"\||\bcurl\b|\bwget\b|https?://|@|~/|\.ssh|\.env\b|base64|\bnc\b|\bsudo\b|\beval\b|\$\(|>\s*/",
    re.I,
)


def patch_added_text(patch: str) -> str:
    """The lines a patch (`*** Begin Patch` format, or a unified diff) adds, without their `+`: what it writes."""
    out: list[str] = []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return "\n".join(out)


def written_texts(arguments: Any) -> list[str]:
    """The text a skill save writes."""
    out: list[str] = []

    def take(obj: Any) -> None:
        if isinstance(obj, dict):
            for k in WRITTEN_KEYS:
                if isinstance(obj.get(k), str):
                    out.append(obj[k])
            if isinstance(obj.get(PATCH_KEY), str) and "\n+" in obj[PATCH_KEY]:
                added = patch_added_text(obj[PATCH_KEY])
                if added:
                    out.append(added)
            for key in NESTED_KEYS:
                ops = obj.get(key)
                if isinstance(ops, list):
                    for op in ops:
                        take(op)

    take(arguments)
    return out


def _fence_lines(block: str) -> list[str]:
    """A fenced block's command lines, continuation lines joined, prompts and comments dropped."""
    lines: list[str] = []
    pending = ""
    for raw in block.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        line = (pending + line.strip()).strip()
        pending = ""
        line = _PROMPT.sub("", line).strip()
        if line and not line.startswith("#"):
            lines.append(line)
    if pending.strip():
        lines.append(_PROMPT.sub("", pending).strip())
    return lines


_CLAUSE_END = re.compile(r"[;.!?](?:\s|$)")


def _line_before(text: str, at: int) -> str:
    """The clause before `at`: the text on the same line since the last `;`, `.`, `!` or `?`, or, when `at` starts a
    line, the last clause of the last non-empty line before it."""
    start = text.rfind("\n", 0, at) + 1
    same = text[start:at]
    if not same.strip():
        prev = text[:start].rstrip("\n")
        same = prev[prev.rfind("\n") + 1 :]
    return _CLAUSE_END.split(same)[-1] if not same.rstrip().endswith((":",)) else same


def steps_in(text: str) -> list[tuple[str, bool]]:
    """Commands in a skill's text, each with whether the text warns against it."""
    found: dict[str, bool] = {}

    def add(cmd: str, negated: bool) -> None:
        cmd = cmd[:MAX_COMMAND_CHARS]
        if _COMMANDISH.match(cmd):
            found[cmd] = found.get(cmd, True) and negated

    for m in _FENCE.finditer(text):
        negated = bool(_NEGATION.search(_line_before(text, m.start())))
        for line in _fence_lines(m.group(2)):
            add(line, negated)
    without_fences = _FENCE.sub(lambda m: " " * len(m.group(0)), text)
    for m in _INLINE.finditer(without_fences):
        span = _PROMPT.sub("", m.group(1)).strip()
        add(span, bool(_NEGATION.search(_line_before(without_fences, m.start()))))
    return list(found.items())


def commands_in(text: str) -> list[str]:
    return [cmd for cmd, _ in steps_in(text)]


def skill_step_calls(
    platform: str, pending: CanonicalCall, store: str | None = None
) -> list[CanonicalCall]:
    """The commands a self-edit writes into a skill, as exec calls; `store` is the self-edit's `store`. A save to
    another store (memory) is never read, whatever its tool; an unknown store is read only for a skill tool."""
    if store != "skills" and (store not in (None, "other") or pending.tool not in SKILL_TOOLS):
        return []
    steps: dict[str, bool] = {}
    for text in written_texts(pending.raw):
        for cmd, negated in steps_in(text):
            steps[cmd] = steps.get(cmd, True) and negated
    ordered = sorted(steps.items(), key=lambda kv: not _RISKY.search(kv[0]))[:MAX_COMMANDS]
    return [
        canonicalise(
            platform,
            source="resolved",
            tool="terminal",
            tool_kind=ToolKind.EXEC,
            provider=Provider(kind=ProviderKind.HOST),
            arguments={"command": cmd},
            call_id=f"{CALL_ID_PREFIX}{i}{NEGATED_SUFFIX if negated else ''}",
            step=pending.step,
        )
        for i, (cmd, negated) in enumerate(ordered, start=1)
    ]
