"""The commands a saved skill tells the agent to run.

A skill is a procedure the agent follows in later sessions, so the shell commands it holds are future exec calls. For
a declared self-edit that writes a skill, the commands in the written text (fenced code blocks and inline code spans
that read as commands) become synthetic exec calls with source `resolved`, so the rule-based probe judges them as it
would judge the agent running them now: fetching code into a shell, sending local data off the host, reading credential
stores, and so on. Only text the save writes is read (`content`, `file_content`, `new_string`, also inside
`operations`), never the text it replaces.
"""

from __future__ import annotations

import re
from typing import Any

from ..planir.canonical import CanonicalCall, canonicalise
from ..planir.models import Provider, ProviderKind, ToolKind

SKILL_TOOLS = frozenset({"skill_manage"})
WRITTEN_KEYS = ("content", "file_content", "new_string")
MAX_COMMANDS = 20
MAX_COMMAND_CHARS = 2000

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_INLINE = re.compile(r"`([^`\n]{4,})`")
#: A command starts with a program name or path and has at least one argument.
_COMMANDISH = re.compile(r"^(?:sudo\s+)?(?:[\w.~/-]+=\S+\s+)*[./~]?[\w./-]+\s+\S")
_PROMPT = re.compile(r"^\s*\$\s+")


def written_texts(arguments: Any) -> list[str]:
    """The text a skill save writes."""
    out: list[str] = []

    def take(obj: Any) -> None:
        if isinstance(obj, dict):
            for k in WRITTEN_KEYS:
                if isinstance(obj.get(k), str):
                    out.append(obj[k])
            ops = obj.get("operations")
            if isinstance(ops, list):
                for op in ops:
                    take(op)

    take(arguments)
    return out


def commands_in(text: str) -> list[str]:
    """Shell commands in a skill's text: every non-comment line of a fenced block, and inline code that reads as a
    command."""
    found: list[str] = []
    for block in _FENCE.findall(text):
        for line in block.splitlines():
            line = _PROMPT.sub("", line).strip()
            if line and not line.startswith("#") and _COMMANDISH.match(line):
                found.append(line)
    without_fences = _FENCE.sub(" ", text)
    for span in _INLINE.findall(without_fences):
        span = _PROMPT.sub("", span).strip()
        if _COMMANDISH.match(span):
            found.append(span)
    return [c[:MAX_COMMAND_CHARS] for c in dict.fromkeys(found)][:MAX_COMMANDS]


def skill_step_calls(platform: str, pending: CanonicalCall) -> list[CanonicalCall]:
    if pending.tool not in SKILL_TOOLS:
        return []
    commands: list[str] = []
    for text in written_texts(pending.raw):
        commands.extend(c for c in commands_in(text) if c not in commands)
    return [
        canonicalise(
            platform,
            source="resolved",
            tool="terminal",
            tool_kind=ToolKind.EXEC,
            provider=Provider(kind=ProviderKind.HOST),
            arguments={"command": cmd},
            call_id=f"skill_step:{i}",
            step=pending.step,
        )
        for i, cmd in enumerate(commands[:MAX_COMMANDS], start=1)
    ]
