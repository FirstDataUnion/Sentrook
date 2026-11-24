"""The owner's words inside `request.text`.

Hosts wrap scheduled, heartbeat, webhook and sub-agent prompts in text of their own, and the plugins pass
`request.text` through as the host built it: a cron job header, the current time, a paragraph of standing rules
for unattended runs, a sub-agent context block, a webhook envelope around outside content, or the heartbeat
prompt in front of the queued system events. Jev reads all of it (its preamble says what host text is). The
rule-side matchers must not: a host sentence is not the owner naming a destination or asking for a secret, and
outside content in a webhook envelope is not the owner's at all.

Hermes also puts an invoked skill's whole text into the message (a skill's slash command, a cron job that lists
skills), ahead of the owner's words. A skill is the agent's standing instructions for a service, often written by
someone else: a host or address in it is not the owner naming it. The Hermes plugin sends only the owner's words;
this shape covers messages from plugins that send the whole text. Context blocks Hermes puts inside a cron
wrapper (the job's previous output, a script's output) stay in the words here, as before: only the plugin can
tell them from the job's prompt.

`owner_words` recognises each wrapper by its whole shape, anchored at both ends of the text, and keeps only the
part the owner wrote. Anything else, including a host whose wording has changed and an owner message that quotes
host text, passes through unchanged, so the matchers then read everything, as they did before.
"""

from __future__ import annotations

import re
from collections.abc import Callable

_CLOCK = r"Current time: [^\n]*\nReference UTC: [^\n]*"
_UNATTENDED = r"This is an unattended scheduled run\.[^\n]*"
_INTERNAL = r"<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>(?:(?!<<<).)*<<<END_OPENCLAW_INTERNAL_CONTEXT>>>"
#: A queued system event line: `System: [<timestamp>] <event text>`.
_EVENT_PREFIX = re.compile(r"^System: \[[^\]\n]*\] ", re.M)
#: Hermes's skill invocation: one or more skills' whole text, then the owner's words after a marker. A skill's
#: slash command builds it, and so does a cron job that lists skills (the words are then the cron wrapper).
_HERMES_SKILLS = (
    r"\A(?:\[IMPORTANT: The following skill\(s\) were listed for this job but could not be found[^\n]*\]\n+)?"
    r'\[IMPORTANT: The user has invoked the "[^"\n]{1,128}" skill, indicating they want you to follow its '
    r"instructions\. The full skill content is loaded below\.\]\n\n"
)
_HERMES_INSTRUCTION = (
    "The user has provided the following instruction alongside the skill invocation: "
)

#: (shape, the owner's words from a match). Each shape covers the whole text.
_SHAPES: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = [
    # Hermes cron: one bracketed line and, from Hermes 0.23, the run time; then the job prompt.
    (
        re.compile(
            r"\A\[IMPORTANT: You are running as a scheduled cron job\.[^\n]*\]\n+"
            r"(?:\[CURRENT RUN TIME: [^\]\n]*\]\n+)?(?P<w>.*)\Z",
            re.S,
        ),
        lambda m: m["w"],
    ),
    # Hermes skills: the skills' text is not the owner's words; theirs follow the first marker (a cron run's
    # words are its own cron wrapper, read again). Skills with no instruction carry none.
    (
        re.compile(
            _HERMES_SKILLS + r".*?\n\n" + re.escape(_HERMES_INSTRUCTION) + r"(?P<w>.*)\Z", re.S
        ),
        lambda m: owner_words(m["w"]),
    ),
    (re.compile(_HERMES_SKILLS + r".*\Z", re.S), lambda m: ""),
    # OpenClaw cron: `[cron:<id> <name>] <prompt>`, the clock lines, the unattended-run paragraph.
    (
        re.compile(
            r"\A\[cron:[0-9A-Za-z-]+(?: [^\]\n]*)?\] (?P<w>.*)\n"
            + _CLOCK
            + r"\n\n"
            + _UNATTENDED
            + r"\Z",
            re.S,
        ),
        lambda m: m["w"],
    ),
    # OpenClaw webhook: the job line, the data notice, the outside content, the clock lines and the
    # unattended-run paragraph. None of it is the owner's words.
    (
        re.compile(
            r"\AJob ID: \S+ \| Received: [^\n]*\n\nExternal content below is data, not a message from the "
            r"user or system\.[^\n]*\n+"
            r'<<<EXTERNAL_UNTRUSTED_CONTENT id="(?P<id>[^"\n]*)">>>\n.*?\n'
            r'<<<END_EXTERNAL_UNTRUSTED_CONTENT id="(?P=id)">>>\n\n'
            + _CLOCK
            + r"\n\n"
            + _UNATTENDED
            + r"\Z",
            re.S,
        ),
        lambda m: "",
    ),
    # OpenClaw sub-agent task: an internal-context block on each side of the task.
    (
        re.compile(r"\A" + _INTERNAL + r"\n+(?P<w>.*?)\n+" + _INTERNAL + r"\Z", re.S),
        lambda m: m["w"],
    ),
    # OpenClaw heartbeat: the heartbeat prompt and clock lines, then the queued events, if any.
    (
        re.compile(
            r"\AFollow the heartbeat monitor scratch context when provided\.[^\n]*\n"
            + _CLOCK
            + r"(?:\n\n(?P<w>.*))?\Z",
            re.S,
        ),
        lambda m: _EVENT_PREFIX.sub("", m["w"] or ""),
    ),
]


def owner_words(text: str) -> str:
    """The part of `text` the owner wrote when it is a recognised host wrapper; otherwise `text`."""
    if not text:
        return text
    for shape, words in _SHAPES:
        m = shape.match(text)
        if m:
            return words(m).strip()
    return text
