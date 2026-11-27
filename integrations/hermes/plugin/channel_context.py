"""Other people's words Hermes puts in front of a new message in a chat: channel history and a reply quote.

In a channel, Hermes's gateway prepends recent channel history to the message that started the turn (Discord's
history backfill and reply context, Slack's thread context, relayed channels):

    [Recent channel messages]
    [Alice] ...
    [Bob] ...

    [New message]
    [Owner] the message itself

The lines before `[New message]` are other people's words (Hermes tags the ones from senders off its allowlist
`[unverified]`, but an allowlisted member's lines are not tagged). In front of that block Hermes may add notes about
the sender's attachments, the message being replied to (`[Replying to: "<its text>"]`, someone else's words too) and,
outermost on Discord, the triggering message's id. None of it is the sender's request: `split` returns it apart, and
the plugin sends it as an untrusted input. A reply quote is split off in a group chat only: in a direct chat the
quoted message is the owner's own or the agent's.

Hermes may also append content after the message: the files and pages an `@` reference names, after
`--- Attached Context ---` (and its warnings after `--- Context Warnings ---`). That is content too.

Other people control the text before the message and fetched content controls the text after it, and either can type
Hermes's separators. So the message is taken only when every separator Hermes used appears exactly once, in order
(reply quote end, `[New message]`, appended content); anything else cannot be told apart, and none of it is the
sender's request. Channel history and reply quotes only come in group chats, so `split` reads nothing in a direct
chat.
"""

from __future__ import annotations

import re

#: How the gateway starts the block it prepends (`MessageEvent.channel_context`).
HEADERS = (
    "[Recent channel messages]",
    "[Context around the replied-to message]",
    "[Messages prefixed with [unverified]",
    "[Thread context",
)
#: What the gateway puts between that block and the message itself.
MARKER = "\n\n[New message]\n"
#: The request when the history cannot be told apart from the message (no marker).
NO_REQUEST = "No request of the sender's own: Hermes sent other people's messages that could not be told apart from it."
#: Discord's triggering-message note, the outermost prefix.
_TRIGGER = re.compile(r"\[Triggering message id: `[^`\n]*`[^\n]*\]\n\n")
#: The start of the reply quote, and the end it closes with.
_REPLY = re.compile(r"\[Replying to(?: your previous message)?: \"")
_REPLY_END = '"]\n\n'


#: Where Hermes appends expanded `@` references (and their warnings) after the message.
_TAILS = ("\n\n--- Context Warnings ---\n", "\n\n--- Attached Context ---\n\n")


def _has_history(text: str) -> bool:
    return any(text.startswith(h) or ("\n\n" + h) in text for h in HEADERS)


def split(text: str, *, group: bool) -> tuple[str, str] | None:
    """(everything that is not the sender's message: host notes, other people's text and appended content, the
    message) for a group-chat message Hermes prefixed with channel history or a reply quote; None for any other
    message, and for any message in a direct chat. The message is "" when the separators cannot be told apart."""
    if not group or not isinstance(text, str):
        return None
    body = text.lstrip()
    if m := _TRIGGER.match(body):
        body = body[m.end() :]
    reply = _REPLY.match(body) is not None
    history = _has_history(body)
    if not reply and not history:
        return None
    # (where the text before the message ends, where the message starts), in the order Hermes writes them
    seps: list[tuple[int, int]] = []
    for used, sep, keep in ((reply, _REPLY_END, 2), (history, MARKER, 0)):
        if not used:
            continue
        if text.count(sep) != 1:
            return text, ""
        at = text.find(sep)
        seps.append((at + keep, at + len(sep)))
    if any(a[1] > b[0] for a, b in zip(seps, seps[1:], strict=False)):
        return text, ""
    before, start = seps[-1]
    end = len(text)
    for tail in _TAILS:
        n = text.count(tail)
        if n > 1:
            return text, ""
        if n == 1:
            at = text.find(tail)
            if at < start:
                return text, ""
            end = min(end, at)
    return (text[:before].rstrip("\n") + "\n\n" + text[end:].lstrip("\n")).rstrip("\n"), text[
        start:end
    ]
