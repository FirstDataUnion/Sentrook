"""What a self-edit's saved content adds, read by rule from the text it writes (no model).

A declared self-edit (the host's own background process saving to the agent's memory or skills) is reported with the
kinds of thing its saved content adds, for `Response.self_edit.adds`:

- `command`: runnable steps. Commands are read as `skill_steps` reads a skill (fenced blocks and inline code that
  reads as a command), from any store, with three narrower rules that apply to this report only (the judged skill
  steps keep their reading):
  - a fenced block tagged as text, log or output (```` ```text ````, ```` ```log ````, ...) holds no commands, nor
    does a line inside a fence that starts like a log line (a date or time, a bracketed tag such as `[INFO]`, an
    upper-case level such as `ERROR:`, a `{placeholder}`); in a fence where some lines carry a `$ ` prompt, the
    lines without one are output;
  - inline code that is a flag fragment (starts with `-`), a setting (`name = value`, `name: value`), quoted text, or
    plain words starting with a capital or a common English word is prose, not a command;
  - in a memory note, inline code that the sentence only reports on (`` `npm ci` failed ``, "because `npm ci`")
    is quoted, not a step.
  Anything else that reads as a command counts: when in doubt the text is a command.
- `destination`: a host, URL, mail address, recipient or remote a later run reaches or sends to: the roles
  `written_selfmod.future_entities` reads from the text as a skill's prose; every host a saved command contacts; and
  any URL with a network scheme or mail address written anywhere in the saved text, prose included.
- `permission`: a saved command that changes permissions, tool allowlists, host or agent config, plugins, hooks,
  the scheduler, approval or safety settings, or privilege: the self-modification (C4), guardrail (C4*) and
  privilege (C8) rules run on each command candidate, with every rule pack on. The candidates are every command the
  scanner's own skill reading finds (before the narrower rules above), and, for an edit fragment or the lines a
  patch adds (which may sit inside a fence the fragment does not show), each of their lines. On the save's own
  target, which the plugin declares only for the memory or skill store, only a guardrail, an approval file or a
  privilege change counts: every save writes into that store, and a path rule may class a skill folder under the
  host's agent directory as config. More candidates than `MAX_CHECKED_COMMANDS` cannot all be checked, and count as
  a change (and a destination; so do more than `MAX_CODE_SPANS` code spans, around which the prose is read).
- `secret`: a redaction placeholder, a shape the second redaction pass masks, or a secret-like value
  (`secret_like.secret_carried`) in the saved text.

Only text the save writes is read (`skill_steps.written_texts`; for a patch, its new side with the context lines, so
a fence the hunk shows stays a fence). A save through a tool whose written text sits under other argument names is
read through every string argument but the replaced text. A save made by running a command or a program is read as
that command: it adds `command`, and its own text is read for the rest. A rule that fails counts its kind as added,
since the scanner cannot vouch for what it did not read. Nothing here changes a score.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..planir.canonical import CanonicalCall, canonicalise
from ..planir.models import Provider, ProviderKind, ToolKind
from .entities import _EMAIL_RE
from .skill_steps import (
    _COMMANDISH,
    _FENCE,
    _INLINE,
    _PROMPT,
    MAX_COMMAND_CHARS,
    NESTED_KEYS,
    PATCH_KEY,
    WRITTEN_KEYS,
    _fence_lines,
)

COMMAND, DESTINATION, PERMISSION, SECRET = "command", "destination", "permission", "secret"
ADDS: tuple[str, ...] = (COMMAND, DESTINATION, PERMISSION, SECRET)
#: The most command candidates the permission and destination rules run on per save; a save with more counts as a
#: change of both kinds.
MAX_CHECKED_COMMANDS = 200
#: The most fenced blocks and inline code spans the destination rule reads a save's prose around; more count as a
#: destination, since the prose reading's cost grows with them.
MAX_CODE_SPANS = 400
#: Keys whose text is a fragment of a larger file (an edit's new text), which may sit inside a fence it does not show.
FRAGMENT_KEYS = frozenset({"new_string", "new_text", "newText"})
#: Keys that hold the text an edit replaces, never read.
REPLACED_KEYS = frozenset({"old_string", "old_text", "oldText", "old"})
#: Rule classes that change permissions, config, plugins, hooks, the scheduler, approvals or privilege.
PERMISSION_CLASSES = frozenset({"C4", "C4*", "C8"})
#: Self-modification reasons for the store a save writes to (memory, a skill), which every save has.
STORE_REASONS = frozenset({"selfmod.memory", "selfmod.plugin", "selfmod.workspace_skill"})
#: What counts on the save's own target, which the plugin declared to be the memory or skill store.
TARGET_CLASSES = frozenset({"C4*", "C8"})
TARGET_REASONS = frozenset({"selfmod.host_approvals"})

#: Fence tags of text that is shown, not run.
_OUTPUT_TAGS = frozenset(
    {
        "text",
        "txt",
        "plain",
        "plaintext",
        "log",
        "logs",
        "output",
        "out",
        "stdout",
        "stderr",
        "nohighlight",
    }
)
#: A line that starts like a log or output line: a date or time, a bracketed tag, an upper-case level, a placeholder.
_LOG_LINE = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}(?:[T ]|$)|\d{1,2}:\d{2}(?::\d{2})?\b|\[[A-Za-z0-9][^\]\n]*\](?:\s|$)"
    r"|(?:INFO|WARN|WARNING|ERROR|DEBUG|TRACE|FATAL|CRITICAL|NOTICE)\b[:\s\]]|\{\w+\}|<\w[^>\n]*>)"
)
_PROMPTED = re.compile(r"^\s*\$\s+")
#: A fragment line that may be a command inside a fence the fragment does not show: it starts like a program name,
#: a path or an environment assignment, not like a sentence or a list item.
_FRAGMENT_COMMAND = re.compile(r"^(?:[a-z./~]|[A-Z_][A-Z0-9_]*=)")
_PLAIN_WORD = re.compile(r"^[A-Za-z][a-z]*(?:'[a-z]+)?$")
_CAPITALISED = re.compile(r"^[A-Z][a-z]+$")
#: Words that start prose, never a program.
_PROSE_STARTS = frozenset(
    "a an the no not and or but my your our their his her its this that these those all any each every some only "
    "always never please".split()
)
#: Words after inline code that report on it rather than ask for it: "`npm ci` failed", "`make` is slow".
_REPORTED_AFTER = re.compile(
    r"\s*(?:failed|fails|errored|errors|returned|returns|printed|prints|showed|shows|worked|works|succeeded|"
    r"hung|hangs|timed\s+out|crashed|crashes|was|is|were|are|exited|exits|needed|needs|requires|required|"
    r"took|takes|output|outputs|gave|gives|broke|breaks)\b",
    re.I,
)
#: Words right before inline code that report on it: "because `npm ci`", "the output of `ls`".
_REPORTED_BEFORE = re.compile(
    r"\b(?:because|since|when|whenever|after|ran|tried|output\s+of|result\s+of|error\s+from|errors\s+from|"
    r"running)\s*$",
    re.I,
)
#: A URL with a network scheme.
_NET_URL = re.compile(r"\b(?:https?|ftps?|sftp|ssh|git|wss?|rsync|smb|s3|gs)://\S", re.I)


@dataclass(frozen=True)
class SavedText:
    text: str
    #: A fragment of a larger file (an edit's new text, a patch's added lines), whose fence may not be shown.
    fragment: bool = False


def patch_new_side(patch: str) -> str:
    """A patch's new side as the hunks show it: context and added lines, without their prefix."""
    out: list[str] = []
    for line in patch.splitlines():
        if line.startswith(("+++", "---", "***", "@@")):
            continue
        if line.startswith(("+", " ")):
            out.append(line[1:])
    return "\n".join(out)


def _patch_added(patch: str) -> str:
    return "\n".join(
        line[1:]
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def saved_texts(arguments: Any) -> list[SavedText]:
    """The text a save writes (as `skill_steps.written_texts` reads it, a patch with its context), each marked when
    it is a fragment of a larger file."""
    out: list[SavedText] = []

    def take(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for k in WRITTEN_KEYS:
            if isinstance(obj.get(k), str):
                out.append(SavedText(obj[k], fragment=k in FRAGMENT_KEYS))
        patch = obj.get(PATCH_KEY)
        if isinstance(patch, str) and "\n+" in patch:
            new_side = patch_new_side(patch)
            if new_side:
                out.append(SavedText(new_side))
            added = _patch_added(patch)
            if added:
                out.append(SavedText(added, fragment=True))
        for key in NESTED_KEYS:
            ops = obj.get(key)
            if isinstance(ops, list):
                for op in ops:
                    take(op)

    take(arguments)
    return out


def _all_strings(obj: Any, key: str | None = None) -> list[str]:
    """Every string in the arguments but the text an edit replaces."""
    if key in REPLACED_KEYS:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in _all_strings(v, str(k))]
    if isinstance(obj, list):
        return [s for v in obj for s in _all_strings(v)]
    return []


# ---- commands ---------------------------------------------------------------------------------------------------


def _fence_tag(fence: str) -> str:
    opener = fence.split("\n", 1)[0].strip().lstrip("`~").strip()
    return opener.split(None, 1)[0].lower() if opener else ""


def _fence_commands(block: str) -> list[str]:
    """A fenced block's commands for the report: output and log lines left out."""
    lines = block.splitlines()
    if any(_PROMPTED.match(line) for line in lines):
        # a console transcript: the prompted lines (and their continuations) are commands, the rest is output
        kept: list[str] = []
        carrying = False
        for line in lines:
            if _PROMPTED.match(line) or carrying:
                kept.append(line)
                carrying = line.rstrip().endswith("\\")
        lines = kept
    return [line for line in _fence_lines("\n".join(lines)) if not _LOG_LINE.match(line)]


def _prose_span(span: str) -> bool:
    """Inline code that is a flag fragment, a setting, quoted text or plain prose rather than a command."""
    tokens = span.split()
    if not tokens:
        return True
    first = tokens[0]
    if first.startswith("-"):
        return True
    if len(span) >= 2 and span[0] == span[-1] and span[0] in "\"'":
        return True
    if len(tokens) > 1 and (tokens[1] in ("=", ":") or first.endswith(":")):
        return True
    if all(_PLAIN_WORD.match(t) for t in tokens) and (
        _CAPITALISED.match(first) or first.lower() in _PROSE_STARTS
    ):
        return True
    return False


#: How far around inline code the reporting words are looked for.
_REPORT_WINDOW = 40


def _reported(text: str, start: int, end: int) -> bool:
    """Inline code at `start:end` that the sentence reports on rather than asks for."""
    after = text[end : end + _REPORT_WINDOW]
    before = text[max(0, start - _REPORT_WINDOW) : start]
    return bool(_REPORTED_AFTER.match(after) or _REPORTED_BEFORE.search(before))


def saved_commands(text: str, store: str) -> list[str]:
    """The commands a saved text adds, for the report: `skill_steps.steps_in`'s reading less output and log lines,
    prose in backticks and, in a memory note, commands the note only reports on."""
    found: dict[str, None] = {}

    def add(cmd: str) -> None:
        cmd = cmd[:MAX_COMMAND_CHARS]
        if _COMMANDISH.match(cmd):
            found.setdefault(cmd, None)

    for m in _FENCE.finditer(text):
        if _fence_tag(m.group(0)) in _OUTPUT_TAGS:
            continue
        for line in _fence_commands(m.group(2)):
            add(line)
    without_fences = _FENCE.sub(lambda m: " " * len(m.group(0)), text)
    for m in _INLINE.finditer(without_fences):
        raw = m.group(1)
        prompted = bool(_PROMPT.match(raw))
        span = _PROMPT.sub("", raw).strip()
        if _prose_span(span):
            continue
        if store == "memory" and not prompted and _reported(without_fences, m.start(), m.end()):
            continue
        add(span)
    return list(found)


def _raw_commands(text: str) -> list[str]:
    """The commands `skill_steps.steps_in` reads (fenced lines and inline code that reads as a command), without its
    negation check, in one pass."""
    out: dict[str, None] = {}
    for m in _FENCE.finditer(text):
        for line in _fence_lines(m.group(2)):
            if _COMMANDISH.match(line):
                out.setdefault(line[:MAX_COMMAND_CHARS], None)
    without_fences = _FENCE.sub(lambda m: " " * len(m.group(0)), text)
    for m in _INLINE.finditer(without_fences):
        span = _PROMPT.sub("", m.group(1)).strip()
        if _COMMANDISH.match(span):
            out.setdefault(span[:MAX_COMMAND_CHARS], None)
    return list(out)


def _candidates(texts: Iterable[SavedText]) -> list[str]:
    """Every command candidate the permission rules check: the scanner's own skill reading, and each line of a
    fragment that starts like a command."""
    out: dict[str, None] = {}
    for st in texts:
        for cmd in _raw_commands(st.text):
            out.setdefault(cmd, None)
        if st.fragment:
            for line in st.text.splitlines():
                line = _PROMPT.sub("", line).strip().strip("`").strip()
                if _FRAGMENT_COMMAND.match(line) and _COMMANDISH.match(line):
                    out.setdefault(line[:MAX_COMMAND_CHARS], None)
    return list(out)


def _code_spans(texts: Iterable[str], limit: int) -> int:
    """The fenced blocks and inline code spans in the texts, counted up to `limit`."""
    n = 0
    for t in texts:
        for _ in _FENCE.finditer(t):
            n += 1
            if n >= limit:
                return n
        for _ in _INLINE.finditer(t):
            n += 1
            if n >= limit:
                return n
    return n


# ---- the rules --------------------------------------------------------------------------------------------------


def _exec_call(platform: str, command: str, step: int | None) -> CanonicalCall:
    return canonicalise(
        platform,
        source="resolved",
        tool="terminal",
        tool_kind=ToolKind.EXEC,
        provider=Provider(kind=ProviderKind.HOST),
        arguments={"command": command},
        call_id="self_edit_save",
        step=step,
    )


def _permission(prepared: Any, candidates: list[str], *, exec_save: bool) -> bool:
    from ..aira.analysis import analyse
    from ..aira.detectors import PACK_HOST_GATED, PACK_TIER1, Context, run_detectors
    from ..aira.lists import load_lists

    if len(candidates) > MAX_CHECKED_COMMANDS:
        return True
    lists = load_lists()
    ctx = Context(prepared=prepared, lists=lists, packs=frozenset({PACK_TIER1, PACK_HOST_GATED}))
    pending = prepared.pending
    # The save itself. The plugin declares a save only for a target in the agent's memory or skill store, which a
    # path rule may still class as agent config (a skill folder under the host's agent directory): only a guardrail,
    # an approval file or a privilege change counts there. A save made by running a command is read as a command,
    # less the write into the store.
    findings, _ = run_detectors(analyse(pending, prepared, lists), ctx)
    if exec_save:
        if any(f.cls in PERMISSION_CLASSES and f.reason not in STORE_REASONS for f in findings):
            return True
    elif any(f.cls in TARGET_CLASSES or f.reason in TARGET_REASONS for f in findings):
        return True
    for cmd in candidates:
        call = _exec_call(prepared.platform, cmd, pending.step)
        findings, _ = run_detectors(analyse(call, prepared, lists), ctx)
        if any(f.cls in PERMISSION_CLASSES for f in findings):
            return True
    return False


def _destination(prepared: Any, texts: list[str], commands: list[str]) -> bool:
    from .written_selfmod import Form, WrittenText, future_entities

    if any(_NET_URL.search(t) or _EMAIL_RE.search(t) for t in texts):
        return True
    if len(commands) > MAX_CHECKED_COMMANDS or _code_spans(texts, MAX_CODE_SPANS) >= MAX_CODE_SPANS:
        return True  # more than the prose reading is run on: not vouched for
    home, ws = prepared.home, prepared.workspace_root
    written = [WrittenText(t, Form.PROSE, host_run=False) for t in texts]
    if commands:
        # every host a saved command contacts, not only a send: a later run reaches it with nobody asked
        written.append(WrittenText("\n".join(commands), Form.SHELL, host_run=True))
    return bool(future_entities(written, home=home, workspace_root=ws))


def _secret(texts: list[str]) -> bool:
    from ..aira.lists import load_lists
    from .secret_like import secret_carried

    placeholder = str(load_lists().get("egress", "placeholder", "open", default="⟦secret"))
    return any(secret_carried(t, placeholder) for t in texts)


def save_adds(prepared: Any) -> tuple[str, ...]:
    """What a declared self-edit's saved content adds, sorted (`ADDS`)."""
    planir = prepared.planir
    store = planir.self_edit.store.value if planir.self_edit is not None else "other"
    pending: CanonicalCall = prepared.pending
    adds: set[str] = set()
    exec_save = pending.tool_kind is ToolKind.EXEC and isinstance(pending.command, str)
    try:
        texts = saved_texts(pending.raw)
        if exec_save:
            # a save made by running a command or a program: its text is what runs
            texts = [SavedText(pending.command or "")]
            adds.add(COMMAND)
        elif not texts:
            texts = [SavedText(s, fragment=True) for s in _all_strings(pending.raw) if s.strip()]
    except Exception:  # noqa: BLE001 (odd arguments: nothing can be vouched for)
        return ADDS
    plain = [st.text for st in texts]

    def rule(kind: str, check) -> None:
        try:
            if check():
                adds.add(kind)
        except Exception:  # noqa: BLE001 (a rule that fails cannot vouch for the text)
            adds.add(kind)

    rule(COMMAND, lambda: any(saved_commands(st.text, store) for st in texts))
    candidates: list[str] = []
    try:
        candidates = _candidates(texts)
    except Exception:  # noqa: BLE001
        adds.update((PERMISSION, DESTINATION))
    # the command an exec save runs is the pending call itself, which the permission rules read as the target
    rule(PERMISSION, lambda: _permission(prepared, candidates, exec_save=exec_save))
    shell = [pending.command or "", *candidates] if exec_save else candidates
    rule(DESTINATION, lambda: _destination(prepared, plain, shell))
    rule(SECRET, lambda: _secret(plain))
    return tuple(k for k in ADDS if k in adds)
