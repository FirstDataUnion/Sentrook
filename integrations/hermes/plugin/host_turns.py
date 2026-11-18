"""Turns Hermes starts itself, with a user message it wrote.

Hermes delivers its own events into a chat as a new turn whose user message is the host's text: a finished
asynchronous sub-agent, a background process that finished, matched a watch or is still running, a kanban
event, a recurring heartbeat or `/loop` wakeup, a standing goal's next step. `pre_llm_call` fires for them
like for any message, from the chat they were delivered to, so the turn looks like the owner's. None of
them is the owner speaking now.

Two classes:
- **Event notices** (a sub-agent's or a process's result or watch notice, a kanban event or a kanban
  goal-mode step with the judge's reason, anything with Hermes's internal notification footer, and the
  gateway's note on its own when it resumes a turn a restart or shutdown cut off). The text is the host's and a sub-agent's or program's output: it goes as an untrusted
  new input (`subagent_reply` for a sub-agent, `other` for the rest), and the turn's calls carry the
  session's last request with `carried_from_turn`. For the resume note that is the interrupted turn's
  request: the note asks the agent to carry on with it, and is host context, not a request of its own.
- **Standing instructions** (a heartbeat, a `/loop` wakeup, a goal continuation). The text wraps an
  instruction the owner set earlier, so it stays the request, as a scheduled job's prompt does. A goal step
  after a failed quality gate keeps the goal and command as the request and sends the command's output as
  content (`parts`).

Either way the turn is not an owner message: when the sender reads as the owner, the trigger becomes
`system` (`heartbeat` for a heartbeat or `/loop` wakeup) with an unknown sender. Senders can type these
forms too, so nothing changes for any other sender: their trigger and sender stay, their text still goes as
an untrusted input, and they never get an earlier request in its place (`carries`).

A form is recognised at the start of the message, or after one `[name] ` speaker prefix (Hermes names the
speaker in shared group and thread sessions), once the one-shot notes the gateway puts in front of the next
message (a model switch or reset, a skills reload, a system note) are taken off (`strip_notes`). Those notes
are host context: an owner's message behind them is their request without the notes. A message ending with Hermes's internal notification footer is
an event notice whatever its start.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: The request a call on an event-notice turn carries when no earlier request may be carried.
REQUEST_TEXT = (
    "No owner request: Hermes delivered a background task's result or event, "
    "and the agent continued on its own."
)
#: The same for the gateway's resume note.
RESUME_REQUEST_TEXT = (
    "No owner request: Hermes resumed a turn a gateway restart or shutdown interrupted, "
    "and the agent continued on its own."
)


@dataclass(frozen=True)
class HostTurn:
    form: str
    #: The new input kind the text goes as; None for a standing instruction (the text is the request).
    input_kind: str | None
    #: The trigger kind the turn gets in a chat when the sender reads as the owner.
    trigger: str
    #: The text (or the part `parts` keeps) is the run's request: a standing instruction the owner set.
    own_request: bool = False
    #: The request an event notice's calls carry when no earlier request may be carried.
    no_request: str = REQUEST_TEXT


FORMS = {
    t.form: t
    for t in (
        HostTurn("async_delegation", "subagent_reply", "system"),
        HostTurn("process", "other", "system"),
        HostTurn("kanban", "other", "system"),
        HostTurn("kanban_goal", "other", "system"),
        HostTurn("internal_notification", "other", "system"),
        HostTurn("resume", "other", "system", no_request=RESUME_REQUEST_TEXT),
        HostTurn("heartbeat", None, "heartbeat", own_request=True),
        HostTurn("loop", None, "heartbeat", own_request=True),
        HostTurn("goal", None, "system", own_request=True),
        # A goal step after a failed quality gate: the goal and command are the request, the command's
        # output is content.
        HostTurn("goal_gate", "other", "system", own_request=True),
    )
}

_STARTS = (
    # A sub-agent's result: complete, batch complete, task failed; several delivered as one batch.
    (
        "async_delegation",
        re.compile(
            r"\[ASYNC DELEGATION |\[IMPORTANT: \d+ background subagent delegations completed"
        ),
    ),
    # A background process: finished, matched a watch pattern, still running; several in one batch.
    (
        "process",
        re.compile(
            r"\[IMPORTANT: Background process |\[Background process \S+ heartbeat #"
            r"|\[IMPORTANT: \d+ background process(?:es completed| results arrived)"
            r"|\[IMPORTANT: Watch(?: patterns disabled for process |-pattern overflow"
            r"|-pattern notifications resumed)"
        ),
    ),
    # A kanban task's wake (any locale), and a kanban goal-mode worker's next step after the judge.
    ("kanban", re.compile(r"\[kanban\] ")),
    (
        "kanban_goal",
        re.compile(
            r"\[Continuing toward this kanban task — |\[The work looks complete, but the task is still open\]"
        ),
    ),
    ("goal_gate", re.compile(r"\[Continuing toward your standing goal — a quality gate failed\]")),
    ("kanban", re.compile(r"(?:✔|⏸|✖|⏱|🔄) (?:\[[^\]\n]+\] )?(?:@\S+ )?Kanban \S")),
    ("heartbeat", re.compile(r"\[Heartbeat — recurring instruction")),
    ("loop", re.compile(r"\[/loop wakeup #")),
    # The gateway resuming a turn a restart or shutdown cut off, with no message of the owner's behind it
    # (one behind it is the owner's request, `strip_notes`).
    ("resume", re.compile(r"\[System note: The previous turn was interrupted by ")),
    ("goal", re.compile(r"\[Continuing toward your standing goal")),
)
#: One speaker prefix Hermes adds in shared group and thread sessions.
_SPEAKER = re.compile(r"\[[^\]\n]{1,256}\] ")
#: The start of the footer Hermes appends to the process and watch notices it delivers.
FOOTER = "[INTERNAL NOTIFICATION — generated by the Hermes gateway"

#: Who wrote a host turn's message, in the conversation a background save is judged against.
SENDER = {"relation": "unknown", "basis": ["none"]}


def message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        return "\n".join(
            p if isinstance(p, str) else str(p.get("text") or "")
            for p in message
            if isinstance(p, str | dict)
        )
    return ""


def _footer(text: str) -> bool:
    at = text.rfind(FOOTER)
    return at >= 0 and "\n" not in text[at:] and text.endswith("]")


#: One-shot notes the gateway puts in front of the next message in a session (a model switch or reset, a
#: skills reload, a system note), each followed by a blank line. Host context, never the request.
_NOTE = re.compile(
    r"(?:\[Note: (?:model was just switched|the session model override was cleared)[^\n]*\]"
    r"|\[System note: [^\n]*\]"
    r"|\[USER INITIATED SKILLS RELOAD:\n.*?\nUse skills_list to see the updated catalog\.\])\n\n",
    re.DOTALL,
)


def strip_notes(message: Any) -> str:
    """The message without the host notes in front of it. A message that is only notes is returned as it
    was (a resume note on its own)."""
    text = message_text(message)
    rest = text.lstrip()
    while m := _NOTE.match(rest):
        rest = rest[m.end() :].lstrip()
    return rest if rest.strip() and rest != text.lstrip() else text


def classify(message: Any) -> HostTurn | None:
    """The host turn a user message is (after any host notes in front of it), or None for a message someone
    sent."""
    text = strip_notes(message).strip()
    bodies = [text]
    if m := _SPEAKER.match(text):
        bodies.append(text[m.end() :])
    for body in bodies:
        for form, pattern in _STARTS:
            if pattern.match(body):
                return FORMS[form]
    return FORMS["internal_notification"] if _footer(text) else None


_GATE_OUTPUT = "\nOutput (tail):\n"
#: The fixed text after the output's closing fence; anything else there is content.
GATE_TRAILER = (
    "\n\nFix the underlying problem so this gate passes, then re-run it to confirm. Do not declare "
    "the goal complete while any gate fails. If the gate itself is wrong or cannot pass, say so "
    "clearly and stop."
)
#: What the request of a failed-gate goal step says in place of the command's output.
GATE_OUTPUT_NOTE = "\nOutput (tail): sent as content, not part of the request."


def parts(host: HostTurn, message: Any) -> tuple[str | None, str | None]:
    """A host turn's request text (None when it has none of its own) and the text it sends as content, both
    without the host notes in front of it."""
    text = strip_notes(message)
    if not host.own_request:
        return None, text
    if host.form != "goal_gate":
        return text, None
    start = text.find(_GATE_OUTPUT)
    if start < 0:
        # Not the shape expected: none of it can be told apart from the output, so all of it is content.
        return None, text
    if text.endswith("\n```" + GATE_TRAILER):
        end = len(text) - len(GATE_TRAILER)
        return text[:start] + GATE_OUTPUT_NOTE + GATE_TRAILER, text[start:end]
    # No fixed trailer right after the closing fence: everything from the output on is content.
    return text[:start] + GATE_OUTPUT_NOTE, text[start:]


def is_owner(trigger: dict[str, Any]) -> bool:
    sender = trigger.get("sender") or {}
    return sender.get("relation") == "owner" or "host_allowlist_dm" in (sender.get("basis") or [])


def carries(trigger: dict[str, Any]) -> bool:
    """A host turn's calls may carry the session's last request: the sender reads as the owner, or the run
    is not a chat message (a scheduled job, an API call) where the session's requests are the run's own."""
    return is_owner(trigger) or trigger.get("kind") != "message"


def trigger_for(trigger: dict[str, Any], kind: str) -> dict[str, Any]:
    """The trigger of a host turn (or of a turn whose start was never seen): an owner sender becomes unknown
    and a chat message becomes `kind`. Any other sender's trigger is left exactly as it was."""
    if not is_owner(trigger):
        return trigger
    return {
        "kind": kind if trigger.get("kind") == "message" else trigger.get("kind"),
        "channel": trigger.get("channel"),
        "sender": dict(SENDER, basis=list(SENDER["basis"])),
    }
