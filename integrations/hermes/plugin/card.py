"""The review card: what a person reads when Sentrook asks before a tool call.

One fact per line, in this order:
- the header: Sentrook's mark, the kind of question and the risk (`🪶 Sentrook security check · risk 62/100`);
- what the call does, from the scan's tool description (`Sends ~/notes/q3-plan.md to paste.example.net.`);
- why, in plain words: the first two reasons whose `text` the scanner filled, or the block category when none has;
- what an answer does, only where the host's buttons would not say it: a suggested grant, a block a snooze turned
  into a question, a call that would run without a scan;
- where to read more (`Details: /sentrook why 3f9c2a1b`), when the traffic log is on.

Every line is a sentence, so a surface that joins lines (the OpenClaw terminal UI) still reads. The text is plain:
no markdown, which some surfaces escape and others render.

Each host bounds the text, and a card over the bound is cut by the host (Hermes on Discord, at 300 characters) or
refused (OpenClaw, over 80 for the title or 512 for the description, which blocks the call). The card is fitted
to the host's budget, measured the way the strictest surface measures it. When it does not fit, what the call
does gives way first (long files and addresses are shortened in the middle, then the line is cut or dropped), then
the second reason, then a suggested grant's command (pointing to `why`, which lists it). The header and what an
answer does are kept.

Values the agent can influence (entity displays, the tool name, scanner reason text) lose characters that some host
escapes into visible codes or that would start a new line, and chat markup that would make a link or a mention.

The OpenClaw plugin builds the same card (`card.ts`); `integrations/fixtures/review-card/cases.json` holds both.
"""

from __future__ import annotations

import html
import math
import re
import unicodedata
from typing import Any

from . import grants
from .decision import BLOCK_CATEGORIES, block_category

MARK = "🪶 Sentrook"
GRANT_DAYS = 30

#: Per host: the budget, how commands are typed, and the host's word for the approve-always button.
HOSTS: dict[str, dict[str, Any]] = {
    "hermes": {"budget": 300, "cmd": "/sentrook {}", "always": '"Always"'},
    "openclaw": {"budget": 500, "title_max": 80, "cmd": "/sentrook-{}", "always": '"Always allow"'},
}

#: Entity displays are shortened to these lengths in turn before the line about what the call does gives way.
ENTITY_CAPS = (60, 40, 24, 12)
#: (reasons shown, entity length) in the order tried: down to 24 characters with two reasons, then with one.
FIT_STEPS = ((2, 60), (2, 40), (2, 24), (1, 60), (1, 40), (1, 24), (1, 12))
#: Shortest cut of what the call does worth showing; with less room the line is dropped.
WHAT_MIN = 16
#: A reason's text and the tool name are capped at these lengths before anything else.
REASON_MAX = 120
TOOL_MAX = 40

# What OpenClaw replaces with a visible `\u{..}` code: control, format, surrogate and separator characters, and
# spaces that do not look like spaces.
_ODD_SPACES = frozenset("    　ᅟᅠㅤﾠ") | frozenset(chr(c) for c in range(0x2000, 0x200B))
_MARKUP = re.compile(r"[\[\]<>|`]")
_PLACEHOLDER = re.compile(r"\{(E\d+)\}")
#: Mentions that notify everyone in a chat, written without markup (Mattermost and Slack read them as typed).
_BROADCAST = re.compile(r"@(everyone|here|channel|all)\b", re.IGNORECASE)


def _odd(c: str) -> bool:
    return c in _ODD_SPACES or unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp")


def clean(s: Any) -> str:
    """One line of plain text: odd characters become spaces, runs of spaces one space."""
    return " ".join(w for w in "".join(" " if _odd(c) else c for c in str(s)).split(" ") if w)


def inert(s: Any) -> str:
    """`clean`, with chat link and code markup taken out and `@` made unable to mention anyone."""
    return clean(_MARKUP.sub("", str(s)).replace("@", "＠"))


def mid(s: str, n: int) -> str:
    """`s` shortened to `n` characters in the middle, so both ends stay readable."""
    if len(s) <= n:
        return s
    if n <= 1:
        return "…"[:n]
    head = math.ceil((n - 1) / 2)
    return s[:head] + "…" + s[len(s) - (n - 1 - head) :]


def clip(s: str, n: int) -> str:
    """`s` cut to `n` characters at the end."""
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def sentence(s: str) -> str:
    return s if not s or s[-1] in ".?!" else s + "."


def risk_number(resp: dict[str, Any]) -> int:
    """`risk` held to 0-100 and rounded half up, as both plugins round it; 0 when it is not a finite number."""
    risk = resp.get("risk")
    if not isinstance(risk, (int, float)) or isinstance(risk, bool) or not math.isfinite(risk):
        return 0
    return int(math.floor(min(max(float(risk), 0.0), 100.0) + 0.5))


def measure(host: str, text: str) -> int:
    """How the host's strictest surface counts `text`. Hermes: UTF-16 units after HTML escaping (Telegram's
    count; Discord's is never more). OpenClaw: code points (its own count, after `clean` left nothing to escape)."""
    if host == "hermes":
        return len(html.escape(text).encode("utf-16-le")) // 2
    return len(text)


def _entities(resp: dict[str, Any]) -> dict[str, str]:
    raw = resp.get("entities") if isinstance(resp.get("entities"), dict) else {}
    return {
        k: inert(v["display"])
        for k, v in raw.items()
        if isinstance(k, str) and isinstance(v, dict) and isinstance(v.get("display"), str)
    }


def _fill(template: str, ents: dict[str, str], cap: int) -> str:
    return _PLACEHOLDER.sub(lambda m: mid(ents.get(m.group(1), m.group(1)), cap), template)


def _what(resp: dict[str, Any], tool: str, ents: dict[str, str], cap: int) -> str:
    desc = resp.get("tool_description") if isinstance(resp.get("tool_description"), dict) else {}
    template = desc.get("template")
    if not isinstance(template, str) or not inert(template):
        return f"Runs {mid(inert(tool), TOOL_MAX) or 'a tool'}."
    return sentence(_fill(inert(template), ents, cap))


def _reason_texts(resp: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for r in resp.get("reasons") or []:
        text = r.get("text") if isinstance(r, dict) else None
        if isinstance(text, str):
            t = clip(inert(text), REASON_MAX)
            if t and t not in seen:
                seen.append(t)
    return seen


def _because(texts: list[str]) -> str:
    return "Because " + ", and ".join(texts) + "."


def _grant_phrase(grant: dict[str, Any], third: bool, cap: int) -> str:
    """What a suggested grant allows, as `trust x` (or `trusts x` with `third`), its pattern at most `cap` long."""
    pattern = mid(inert(grant["pattern"]), cap)
    if grant["kind"] == "credential":
        name, _, host = str(grant["pattern"]).partition("@")
        what = mid(inert(f"{name} to {host}"), cap)
        return f"{'lets' if third else 'let'} the agent send {what}"
    if grant["kind"] == "file":
        allows = list(grant.get("allows") or []) or ["use"]
        verbs = allows[0] if len(allows) == 1 else ", ".join(allows[:-1]) + " and " + allows[-1]
        return f"{'lets' if third else 'let'} the agent {verbs} {pattern}"
    return f"{'trusts' if third else 'trust'} {pattern}"


def command_shown(grant: dict[str, Any]) -> bool:
    """Whether the card may show the grant command as typed: its pattern has nothing a host would escape (which
    could take the card over OpenClaw's limit), no chat markup and no mention of everyone. A command must be copied
    whole, so it is never cleaned: the card points to `why` instead."""
    pattern = grant["pattern"]
    return not (
        any(_odd(c) for c in pattern) or _MARKUP.search(pattern) or _BROADCAST.search(pattern)
    )


def _answer(
    host: str,
    relaxed: bool,
    hint: dict[str, Any] | None,
    remember: bool,
    why_id: str | None,
    short: bool,
    cap: int,
) -> list[str]:
    h = HOSTS[host]
    lines: list[str] = []
    if hint is not None:
        if remember:
            lines.append(
                f"{h['always']} also {_grant_phrase(hint, True, cap)} for {GRANT_DAYS} days."
            )
        elif short or not command_shown(hint):
            # `why` lists the command, and the details line names it. Without `why` (the traffic log is off) the
            # line is left out rather than cut: a cut command would set a different grant.
            if why_id:
                lines.append(
                    f"To {_grant_phrase(hint, False, cap)} for {GRANT_DAYS} days, see Details."
                )
        else:
            lines.append(
                f"To allow this for {GRANT_DAYS} days: {grants.grant_command(hint, h['cmd'].format)}"
            )
    if relaxed:
        line = "Would be blocked, but a snooze is on."
        if host == "hermes":
            line += " Session and Always cover this action until it ends."
        lines.append(line)
    return lines


def header(resp: dict[str, Any]) -> str:
    kind = "safety rule" if resp.get("enforced") == "review" else "security check"
    return f"{MARK} {kind} · risk {risk_number(resp)}/100"


def review_lines(
    resp: dict[str, Any],
    tool: str,
    host: str,
    *,
    relaxed: bool = False,
    hint: dict[str, Any] | None = None,
    remember: bool = False,
    why_id: str | None = None,
    fixed: str = "",
) -> list[str]:
    """The card's body lines, fitted with `fixed` (text the host shows with them in the same budget, the header
    on Hermes) to the host's budget."""
    budget = HOSTS[host]["budget"]
    sid = why_id[:8] if why_id else None
    ents = _entities(resp)
    texts = _reason_texts(resp) or [BLOCK_CATEGORIES[block_category(resp)]]
    details = [f"Details: {HOSTS[host]['cmd'].format('why')} {sid}"] if sid else []

    def build(
        cap: int, what_room: int | None, n: int, short: bool, why_room: int | None
    ) -> list[str]:
        what = _what(resp, tool, ents, cap)
        if what_room is not None:
            what = clip(what, what_room) if what_room >= WHAT_MIN else ""
        because = _because([_fill(t, ents, max(cap, 24)) for t in texts[:n]])
        if why_room is not None:
            because = clip(because, why_room)
        answer = _answer(host, relaxed, hint, remember, sid, short, max(cap, 24))
        lines = [what, because, *answer, *details]
        return [line for line in lines if line]

    def size(lines: list[str]) -> int:
        return measure(host, "\n".join([fixed, *lines] if fixed else lines))

    def room_for(lines: list[str], index: int) -> int:
        """The characters line `index` may keep so that the whole fits (escaping counted as on the host)."""
        rest = size(lines[:index] + lines[index + 1 :]) + 1
        line = lines[index]
        while line and rest + measure(host, line) > budget:
            line = line[:-1]
        return len(line)

    # Shorten files and addresses (to a length that still reads), then keep one reason, then shorten them further,
    # then cut or drop what the call does, then point to `why` for the grant command, then cut the reason.
    for n, cap in FIT_STEPS:
        lines = build(cap, None, n, False, None)
        if size(lines) <= budget:
            return lines
    cap = ENTITY_CAPS[-1]
    for short in (False, True):
        full = build(cap, None, 1, short, None)
        lines = build(cap, room_for(full, 0), 1, short, None)
        if size(lines) <= budget:
            return lines
    lines = build(cap, 0, 1, True, None)
    i = next(i for i, line in enumerate(lines) if line.startswith("Because "))
    lines = build(cap, 0, 1, True, room_for(lines, i))
    if size(lines) <= budget:
        return lines
    # Only an answer line too long to fit is left: cut the text as a whole.
    text = "\n".join(lines)
    while text and size([text]) > budget:
        text = text[:-1]
    return [text]


def hermes_message(
    resp: dict[str, Any],
    tool: str,
    *,
    relaxed: bool = False,
    hint: dict[str, Any] | None = None,
    remember: bool = False,
    why_id: str | None = None,
) -> str:
    """The approval prompt's text on Hermes (its only field: the host adds its own header and buttons)."""
    head = header(resp)
    body = review_lines(
        resp,
        tool,
        "hermes",
        relaxed=relaxed,
        hint=hint,
        remember=remember,
        why_id=why_id,
        fixed=head,
    )
    return "\n".join([head, *body])


def openclaw_card(
    resp: dict[str, Any],
    tool: str,
    *,
    relaxed: bool = False,
    hint: dict[str, Any] | None = None,
    remember: bool = False,
    why_id: str | None = None,
) -> dict[str, str]:
    """The approval's title and description on OpenClaw (`card.ts` builds it; this one is for the shared tests)."""
    body = review_lines(
        resp, tool, "openclaw", relaxed=relaxed, hint=hint, remember=remember, why_id=why_id
    )
    return {
        "title": clip(header(resp), HOSTS["openclaw"]["title_max"]),
        "description": "\n".join(body),
    }


# ---- a call Sentrook could not scan ----------------------------------------------------------------------

ERROR_HEADER = f"{MARK} could not check this call"
ERROR_CAUSES = {
    "rate_limited": "The scan service is busy and turned this scan away for now.",
    "config": "Sentrook's settings are missing or wrong. This is a setup problem, not a security finding.",
    "auth": "Sentrook could not sign in to its scan service. This is a setup problem, not a security finding.",
    "unreachable": "Its scan service did not answer.",
}
ERROR_RUNS_UNCHECKED = "If you allow it, it runs without a security check."
#: On Hermes, Session and Always answer every scan error in the chat (`error_rule_key` in the plugin).
ERROR_SESSION_NOTE = (
    "Session and Always skip this question in this chat while Sentrook cannot scan."
)


def error_cause(kind: str, auth: bool) -> str:
    if kind == "rate_limited":
        return "rate_limited"
    if kind == "config":
        return "config"
    return "auth" if auth else "unreachable"


def error_lines(cause: str, host: str) -> list[str]:
    lines = [ERROR_CAUSES[cause], ERROR_RUNS_UNCHECKED]
    if host == "hermes":
        lines.append(ERROR_SESSION_NOTE)
    lines.append(f"Status: {HOSTS[host]['cmd'].format('status')}")
    return lines


def hermes_error_message(cause: str) -> str:
    return "\n".join([ERROR_HEADER, *error_lines(cause, "hermes")])
