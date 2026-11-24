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

- a cron job with no prompt (it only runs its skills): the cron hint and the run time; what follows is context.

What is dropped is only an installed skill's own text, as Hermes loads it (`installed_text`, with the
`${HERMES_SKILL_DIR}` and `${HERMES_SESSION_ID}` tokens Hermes fills in matched as one line each), and the header
Hermes put in front of it: the agent's own standing instructions, which the scanner treats like the agent's other
own store. Anything else in the message that is not the owner's words goes to the scanner as untrusted content
(`SkillTurn.content`), never dropped: a context block, text after or around a skill, a runtime note, a
missing-skills notice line, a skill bundle, and a block that is not an installed skill's text with its header
(someone typing the wrapper hides nothing, and a name they typed is never the request). A skill whose text Hermes
ran inline shell in (off by default, never for a hub skill) does not match, and goes as content too.

Limits: the owner's words begin at the first marker after the last matched skill; a block that does not match an
installed skill and itself holds the marker hands what follows it to the request, as the whole message was before.
A cron job's prompt that Hermes changed while assembling it (Hermes strips invisible characters from a cron prompt)
is not found, and the split falls back to everything after the marker.
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


#: The template tokens Hermes fills in when it loads a skill into the message (`skills.template_vars`, on by
#: default). Each matches one line of any text; a token Hermes could not fill stays as written, and matches too.
_TEMPLATE_TOKEN = re.compile(r"\\\$\\\{(?:HERMES_SKILL_DIR|HERMES_SESSION_ID)\\\}")


def installed_text(name: str) -> str | None:
    """The installed skill's text before Hermes fills in its template tokens (`skill_view` without
    preprocessing), or None when Hermes cannot say (not installed, no such module in this Hermes)."""
    try:
        from tools.skills_tool import skill_view

        try:
            from agent.skill_utils import normalize_skill_lookup_name

            lookup = normalize_skill_lookup_name(name)
        except Exception:  # noqa: BLE001 - an older Hermes: its plain form
            lookup = name.strip().lstrip("/")
        out = json.loads(skill_view(lookup, preprocess=False))
    except Exception:  # noqa: BLE001 - no skill text to compare: the block is content
        return None
    content = out.get("content") if isinstance(out, dict) and out.get("success") else None
    return content.strip() if isinstance(content, str) and content.strip() else None


def _installed_end(text: str, start: int, own: str | None) -> int | None:
    """Where an installed skill's text ends when `text` holds it at `start`, its template tokens filled in or not;
    None when the text there is not that skill's. Inline shell output (off by default in Hermes, and never for a
    hub skill) is not matched: such a block stays content."""
    if not isinstance(own, str) or not own.strip():
        return None
    own = own.strip()
    if "${HERMES_" not in own:
        return start + len(own) if text.startswith(own, start) else None
    pattern = _TEMPLATE_TOKEN.sub(lambda _m: r"[^\n]*?", re.escape(own))
    m = re.compile(pattern).match(text, start)
    return m.end() if m else None


def _marker_at(text: str, start: int) -> int | None:
    at = text.find("\n" + INSTRUCTION_MARKER, start)
    return at if at >= 0 else None


def split(
    text: str,
    *,
    job_prompt: str | None = None,
    installed: Callable[[str], str | None] | None = None,
) -> SkillTurn | None:
    """The request and the untrusted content of a message Hermes built around skills; None for any other
    message. The message must start with a complete skill header (after a missing-skills notice, if any).

    `job_prompt` is the running cron job's prompt from its record: None when there is no record, "" when the
    job has none (a job that only runs its skills)."""
    lookup = installed or installed_text
    if not isinstance(text, str):
        return None
    pos = 0
    content: list[str] = []
    if m := _MISSING.match(text):
        # Hermes's own notice, but its line is free text to whoever typed it: content, never dropped.
        content.append(m.group(0).strip())
        pos = m.end()
    if not _HEADER.match(text, pos):
        return None
    skills: list[str] = []
    named: list[str] = []
    marker: int | None = None
    while True:
        m = _HEADER.match(text, pos)
        if m is None:
            # Not a skill block in the form known here (a bundle, or text): content up to the owner's words.
            marker = _marker_at(text, pos)
            end = len(text) if marker is None else marker
            if text[pos:end].strip():
                content.append(text[pos:end].strip())
            break
        name, start = m.group(1), m.end()
        skills.append(name)
        own_end = _installed_end(text, start, lookup(name))
        if own_end is not None:
            # An installed skill's own text is skipped whole, so nothing inside it can end the block early.
            named.append(name)
            search_from = own_end
        else:
            # Not the installed skill's text: the block, its header with it, is content.
            content.append(m.group(0).strip())
            search_from = start
        nxt = text.find(_NEXT_HEADER, search_from)
        marker = _marker_at(text, search_from)
        ends = [i for i in (nxt if nxt >= 0 else None, marker) if i is not None]
        end = min(ends) if ends else len(text)
        if text[search_from:end].strip():
            content.append(text[search_from:end].strip())
        if marker is not None and end == marker:
            break
        marker = None
        if end == len(text):
            break
        pos = end + 1
        while pos < len(text) and text[pos] == "\n":
            pos += 1
    instruction = "" if marker is None else text[marker + 1 + len(INSTRUCTION_MARKER) :]
    request, extra = _owner_words(instruction, job_prompt)
    content.extend(extra)
    if not _without_host_lines(request).strip():
        if named:
            noun = "skill was" if len(named) == 1 else "skills were"
            request += f"The {', '.join(named)} {noun} invoked with no further instruction."
        else:
            request += "A skill was invoked with no further instruction."
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
    if host and job_prompt is not None:
        prompt = job_prompt.strip()
        if not prompt:
            # The job runs its skills with no prompt: whatever follows the host lines is context.
            if rest.strip():
                extra.append(rest.strip())
            return host, extra
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
