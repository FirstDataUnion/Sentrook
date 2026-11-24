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

What is dropped is only an installed skill's own text, as Hermes loads it (`installed_skills`, with the
`${HERMES_SKILL_DIR}` and `${HERMES_SESSION_ID}` tokens filled in with the values Hermes had, exactly), and the header
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

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

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
#: default); a token Hermes has no value for stays as written.
_SKILL_DIR = "${HERMES_SKILL_DIR}"
_SESSION_ID = "${HERMES_SESSION_ID}"


@dataclass(frozen=True)
class InstalledSkill:
    #: The skill's text before Hermes fills in its template tokens.
    text: str
    #: The skill's directory, the value Hermes gives `${HERMES_SKILL_DIR}`; None when Hermes did not say.
    skill_dir: str | None = None


#: A skill name as a slash command or a cron job writes it: one or more path segments, no glob or traversal.
_SKILL_NAME = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def installed_skills(home: Path, name: str) -> list[InstalledSkill]:
    """The installed skills a header name can mean, read from Hermes's skills directory as Hermes reads them
    (`<home>/skills/[<category>/[<sub>/]]<name>/SKILL.md`, UTF-8 with an optional BOM): the text before Hermes
    fills in its template tokens, and the skill's directory. Read from disk, not through Hermes's skill tool,
    which counts every view as use. A name Hermes resolves elsewhere (an external or plugin skill directory)
    is not found here, and its block stays content."""
    clean = name.strip().lstrip("/")
    if not _SKILL_NAME.fullmatch(clean) or any(
        part in ("", ".", "..") for part in clean.split("/")
    ):
        return []
    root = home / "skills"
    out: list[InstalledSkill] = []
    try:
        found = {root / clean / "SKILL.md"}
        found.update(root.glob(f"*/{clean}/SKILL.md"))
        found.update(root.glob(f"*/*/{clean}/SKILL.md"))
        for path in sorted(found):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8-sig", errors="replace").strip()
            if text:
                out.append(InstalledSkill(text, str(path.parent)))
    except OSError:
        return out
    return out


def _forms(own: InstalledSkill, session_ids: tuple[str, ...]) -> list[str]:
    """The installed skill's text as Hermes can have put it into the message: each template token filled in
    with the value Hermes had, or left as written when it had none. Exact text only: nothing else on a token's
    line can match (a cron job loads its skills with no session id; a slash command with the session's)."""
    base = own.text.strip()
    if "${HERMES_" not in base:
        return [base]
    dirs = [own.skill_dir, None] if own.skill_dir else [None]
    sessions = [None, *(s for s in session_ids if s)]
    out: list[str] = []
    for d in dirs:
        for sid in sessions:
            form = base.replace(_SKILL_DIR, d) if d else base
            form = form.replace(_SESSION_ID, sid) if sid else form
            if form not in out:
                out.append(form)
    return out


def _installed_end(
    text: str,
    start: int,
    own: InstalledSkill | str | list[InstalledSkill | str] | None,
    session_ids: tuple[str, ...] = (),
) -> int | None:
    """Where an installed skill's text ends when `text` holds it, exactly, at `start`; None when the text there
    is not that skill's. Inline shell output (off by default in Hermes, and never for a hub skill) is not
    matched: such a block stays content."""
    candidates = own if isinstance(own, list) else [own]
    for one in candidates:
        if isinstance(one, str):
            one = InstalledSkill(one)
        if not isinstance(one, InstalledSkill) or not one.text.strip():
            continue
        for form in _forms(one, session_ids):
            if text.startswith(form, start):
                return start + len(form)
    return None


def _marker_at(text: str, start: int) -> int | None:
    at = text.find("\n" + INSTRUCTION_MARKER, start)
    return at if at >= 0 else None


def split(
    text: str,
    *,
    job_prompt: str | None = None,
    installed: Callable[[str], InstalledSkill | str | list[InstalledSkill] | None],
    session_ids: tuple[str, ...] = (),
) -> SkillTurn | None:
    """The request and the untrusted content of a message Hermes built around skills; None for any other
    message. The message must start with a complete skill header (after a missing-skills notice, if any).

    `job_prompt` is the running cron job's prompt from its record: None when there is no record, "" when the
    job has none (a job that only runs its skills). `session_ids` are the values Hermes may have given
    `${HERMES_SESSION_ID}` (the turn's session and task ids)."""
    lookup = installed
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
        own_end = _installed_end(text, start, lookup(name), session_ids)
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
