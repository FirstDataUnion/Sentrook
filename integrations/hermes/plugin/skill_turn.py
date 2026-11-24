"""Turns whose user message Hermes built around one or more skills.

A skill's slash command, and a cron job that lists skills, make Hermes put each skill's whole text into the user
message: `[IMPORTANT: The user has invoked the "<name>" skill, ...]`, a blank line, the skill's text, then the
owner's words after `The user has provided the following instruction alongside the skill invocation: `. On a
cron job those words are Hermes's own cron hint, the run time, any context blocks (the job's previous output,
another job's output, a pre-run script's output, the job's notepad) and, last, the job's prompt.

The scanner reads the request as what the owner asked for. An installed skill's text is the agent's standing
instructions for a service, often written by someone else; sent as the request, every host and command in it
would count as the owner's own words, and a long skill pushes the owner's actual instruction out of what the
judge sees. So the request is the owner's words only:

- a skill's slash command: the instruction after the marker (a skill invoked with none says so);
- a cron job: the cron hint, the run time and the job's prompt, found by the job's own record
  (`_cron_job_prompt`), the last copy of it in the message, since a previous run's output can quote it. Without
  the record, everything after the marker.

What is dropped is only text that is exactly an installed skill's own text, as Hermes loads it
(`installed_text`): the agent's own standing instructions, which the scanner treats like the agent's other own
store. Anything else in the message that is not the owner's words goes to the scanner as untrusted content
(`SkillTurn.content`), never dropped: a context block, text after or around a skill, a runtime note, and a block
that is not an installed skill's text (someone typing the wrapper hides nothing).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

#: Hermes's marker before the owner's words, after the last skill.
INSTRUCTION_MARKER = (
    "The user has provided the following instruction alongside the skill invocation: "
)
_HEADER = re.compile(
    r'\[IMPORTANT: The user has invoked the "([^"\n]{1,128})" skill, indicating they want you to follow its '
    r"instructions\. The full skill content is loaded below\.\]\n\n"
)
_NEXT_HEADER = '\n[IMPORTANT: The user has invoked the "'
#: The notice a cron job's prompt starts with when a skill it lists is not installed: host text.
_MISSING = re.compile(
    r"\[IMPORTANT: The following skill\(s\) were listed for this job but could not be found[^\n]*\]\n*"
)
_CRON_HINT = re.compile(r"\[IMPORTANT: You are running as a scheduled cron job\.[^\n]*\]\n*")
_RUN_TIME = re.compile(r"\[CURRENT RUN TIME: [^\]\n]*\]\n*")
_RUNTIME_NOTE = re.compile(r"\n\n\[Runtime note: [^\n]*\]\s*\Z")


@dataclass
class SkillTurn:
    #: The owner's words: the request every call of the turn carries.
    request: str
    #: What is neither the owner's words nor an installed skill's text, as one untrusted input; None if empty.
    content: str | None
    #: The skills the message invoked, in order.
    skills: list[str] = field(default_factory=list)


def installed_text(name: str) -> str | None:
    """The installed skill's text as Hermes puts it into the message (`skill_view` without preprocessing), or
    None when Hermes cannot say (not installed, no such module in this Hermes)."""
    try:
        from tools.skills_tool import skill_view

        out = json.loads(skill_view(name, preprocess=False))
    except Exception:  # noqa: BLE001 - no skill text to compare: the block is content
        return None
    content = out.get("content") if isinstance(out, dict) and out.get("success") else None
    return content.strip() if isinstance(content, str) and content.strip() else None


def split(
    text: str,
    *,
    job_prompt: str | None = None,
    installed: Callable[[str], str | None] | None = None,
) -> SkillTurn | None:
    """The request and the untrusted content of a message Hermes built around skills; None for any other
    message. The message must start with a complete skill header (after a missing-skills notice, if any)."""
    lookup = installed or installed_text
    if not isinstance(text, str):
        return None
    pos = 0
    if m := _MISSING.match(text):
        pos = m.end()
    if not _HEADER.match(text, pos):
        return None
    skills: list[str] = []
    content: list[str] = []
    instruction: str | None = None
    while (m := _HEADER.match(text, pos)) is not None:
        name, start = m.group(1), m.end()
        skills.append(name)
        own = lookup(name)
        own = own.strip() if isinstance(own, str) else None
        # An installed skill's own text is skipped whole, so nothing inside it can end the block early.
        verified = bool(own) and text.startswith(own, start)
        search_from = start + len(own) if verified and own else start
        nxt = text.find(_NEXT_HEADER, search_from)
        marker = text.find("\n" + INSTRUCTION_MARKER, search_from)
        ends = [i for i in (nxt, marker) if i >= 0]
        end = min(ends) if ends else len(text)
        rest = text[search_from:end] if verified else text[start:end]
        if rest.strip():
            content.append(rest.strip())
        if end == marker:
            instruction = text[marker + 1 + len(INSTRUCTION_MARKER) :]
            break
        pos = end + 1
        while pos < len(text) and text[pos] == "\n":
            pos += 1
        if end == len(text) or not _HEADER.match(text, pos):
            if text[pos:].strip():
                content.append(text[pos:].strip())
            break
    request, extra = _owner_words(instruction or "", job_prompt)
    content.extend(extra)
    if not _without_host_lines(request).strip():
        names = ", ".join(skills)
        noun = "skill" if len(skills) == 1 else "skills"
        request = request + f"The owner invoked the {names} {noun} with no further instruction."
    body = "\n\n".join(c for c in content if c.strip())
    return SkillTurn(request=request, content=body or None, skills=skills)


def _owner_words(instruction: str, job_prompt: str | None) -> tuple[str, list[str]]:
    """(the request, content) from the text after the marker."""
    extra: list[str] = []
    if m := _RUNTIME_NOTE.search(instruction):
        extra.append(instruction[m.start() :].strip())
        instruction = instruction[: m.start()]
    host = ""
    rest = instruction
    if m := _CRON_HINT.match(rest):
        host, rest = rest[: m.end()], rest[m.end() :]
        if m := _RUN_TIME.match(rest):
            host, rest = host + rest[: m.end()], rest[m.end() :]
    prompt = (job_prompt or "").strip()
    if host and prompt:
        at = rest.rfind(prompt)
        if at >= 0:
            before, after = rest[:at], rest[at + len(prompt) :]
            extra.extend(p.strip() for p in (before, after) if p.strip())
            return host + prompt, extra
    return instruction.strip() if not host else host + rest.strip(), extra


def _without_host_lines(request: str) -> str:
    rest = request
    if m := _CRON_HINT.match(rest):
        rest = rest[m.end() :]
    if m := _RUN_TIME.match(rest):
        rest = rest[m.end() :]
    return rest
