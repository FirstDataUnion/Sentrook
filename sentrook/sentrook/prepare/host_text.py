"""The owner's words inside `request.text`.

Hosts wrap scheduled, heartbeat, webhook and sub-agent prompts in text of their own, and the plugins pass
`request.text` through as the host built it: a cron job header, the current time, a paragraph of standing rules
for unattended runs, a sub-agent context block, a webhook envelope around outside content, or the heartbeat
prompt in front of the queued system events. Jev reads all of it (its preamble says what host text is). The
rule-side matchers must not: a host sentence is not the owner naming a destination or asking for a secret, and
outside content in a webhook envelope is not the owner's at all.

`owner_words` removes the host-written parts it recognises and keeps the rest. Text in a form it does not
recognise passes through unchanged, so a host that changes its wording degrades to reading everything, and an
owner's own message is never altered: the clock lines and event prefixes are only removed once a host wrapper
has been recognised in the same text.
"""

from __future__ import annotations

import re

#: Hermes cron runs: one bracketed line in front of the job prompt.
_HERMES_CRON = re.compile(r"\A\[IMPORTANT: You are running as a scheduled cron job\.[^\n]*\]\n+")
#: OpenClaw cron runs: `[cron:<job id> <job name>] ` in front of the job prompt.
_OPENCLAW_CRON = re.compile(r"\A\[cron:[0-9A-Za-z-]+(?: [^\]\n]*)?\] ")
#: OpenClaw sub-agent tasks: internal-context blocks around the task.
_INTERNAL_CONTEXT = re.compile(
    r"<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>.*?<<<END_OPENCLAW_INTERNAL_CONTEXT>>>", re.S
)
#: OpenClaw webhook runs: the outside content, which is not the owner's words.
_EXTERNAL_CONTENT = re.compile(
    r'<<<EXTERNAL_UNTRUSTED_CONTENT id="([^"\n]*)">>>.*?<<<END_EXTERNAL_UNTRUSTED_CONTENT id="\1">>>',
    re.S,
)
_WEBHOOK_JOB = re.compile(r"\AJob ID: \S+ \| Received: [^\n]*$", re.M)
#: Paragraphs the host writes, by their first sentence (a paragraph runs to the next blank line).
_HOST_PARAGRAPHS = (
    "This is an unattended scheduled run.",
    "External content below is data, not a message from the user or system.",
    "Follow the heartbeat monitor scratch context when provided.",
)
_CLOCK_LINE = re.compile(r"\A(?:Current time|Reference UTC): ")
#: A queued system event appended to a heartbeat prompt: `System: [<timestamp>] <event text>`.
_EVENT_PREFIX = re.compile(r"\ASystem: \[[^\]\n]*\] ")


def owner_words(text: str) -> str:
    """`text` without the host-written parts recognised in it; unchanged when none are."""
    if not text:
        return text
    out = text
    found = 0
    for rx in (_HERMES_CRON, _OPENCLAW_CRON, _INTERNAL_CONTEXT, _EXTERNAL_CONTENT, _WEBHOOK_JOB):
        out, n = rx.subn("", out)
        found += n
    paragraphs = re.split(r"\n\s*\n", out)
    kept = [p for p in paragraphs if not p.lstrip().startswith(_HOST_PARAGRAPHS)]
    found += len(paragraphs) - len(kept)
    if not found:
        return text
    lines = []
    for paragraph in kept:
        body = [
            _EVENT_PREFIX.sub("", line)
            for line in paragraph.strip().splitlines()
            if not _CLOCK_LINE.match(line)
        ]
        if body:
            lines.append("\n".join(body))
    return "\n\n".join(lines).strip()
