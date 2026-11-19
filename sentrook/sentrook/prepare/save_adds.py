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
  Every line of a script (a file the save writes whose path is not instruction text, or text starting `#!`) is a
  command, and so is a line outside a recognised fence that starts like a command (a program name, a path, an
  environment assignment; not a sentence or a list item): an edit fragment inside a fence it does not show, an
  indented block, a longer or unclosed fence. A `<pre>` block is read as a fence, and a fence or script line that
  starts a subshell, a group, a command substitution or a variable (`(`, `{ `, `$(`, `$VAR`) is a command too.
  Anything else that reads as a command counts: when in doubt the text is a command.
- `destination`: a host, URL, mail address, recipient or remote a later run reaches or sends to: the roles
  `written_selfmod.future_entities` reads from the text as a skill's prose; every host a saved command contacts; a
  remote a copy or sync command names (`scp`, `rsync`, `sftp`, `rclone`: `host:path`, `remote:path`); a `git push`
  to a remote other than `origin` or `upstream`; any mail address written anywhere in the saved text or another
  string argument; and any URL with a network scheme in code, in another string argument, or in prose. A URL in a
  saved text's prose that is only a pointer to reading matter (right after "see", "docs at", "reference:", and in a
  sentence with no send or run verb) is not one. A recipient named without an address (a chat id, a channel) and a
  step written only in prose are left to the self-edit judge.
- `permission`: a saved command that changes permissions, tool allowlists, host or agent config, plugins, hooks,
  the scheduler, approval or safety settings, or privilege: the self-modification (C4), guardrail (C4*) and
  privilege (C8) rules run on each command candidate, with every rule pack on, and a `chmod` that makes a file
  world-writable or setuid (or changes the mode of a credential or system folder), an ACL grant, an attribute
  change or a `crontab` that installs a table counts too. The candidates are every command the scanner's own skill reading finds (before the narrower
  rules above), every line of a saved text that reads as a command on its own (a script's lines, and lines anywhere
  that start like a command), and list items that read as code (a known program, or shell syntax). On the save's
  own target, which the plugin declares only for the memory or skill store, only a guardrail, an approval file or a
  privilege change counts: every save writes into that store, and a path rule may class a skill folder under the
  host's agent directory as config. More candidates than `MAX_CHECKED_COMMANDS` cannot all be checked, and count as
  a change (and a destination; so do more than `MAX_CODE_SPANS` code spans, around which the prose is read).
- `secret`: a redaction placeholder, a shape the second redaction pass masks, a secret-like value
  (`secret_like.secret_carried`), or a sign-in pair (`login is admin / <passphrase>`) in the saved text or any other
  string argument.

Besides what it adds, the reading says why it cannot vouch for a save (`SaveReading.held`), which rules out lenient
handling whatever it adds:

- `nothing_written`: the save writes no content the reading examined: no non-blank text under a written-text key
  (`content`, `file_content`, `new_string`, `new_text`, `newText`, also inside `operations` and `edits`, and a
  patch's added lines), and it is not a command the save runs. A restore of an older version, an archive, a delete
  or a support-file removal brings in or takes out content the scan never saw.
- `removes`: the save removes existing content and writes nothing in its place, as far as the request shows it: a
  delete, remove or archive action (a skill, a support file, a memory entry), an edit whose replaced text has a word
  the save does not write again and whose new text is empty, a patch's removed lines likewise, or a save made by
  running a command that deletes, moves, truncates or edits a file in place. An edit that replaces text with new text
  and drops a word of it is a rewording (`SaveReading.rewrites`): not held here, but lenient only while the judge's
  loosened-oversight answer is low. A replaced text every word of which the save writes again (an insertion, a
  reorder, an edit that only adds) is neither. A whole-file write shows no old content and is neither.
- `risky_step`: a rule of any class fired on a command the save tells the agent to run (the narrower reading
  above, script lines, list items that read as code), which the rule-based probe does not judge for a memory note.
- `unread`: the save holds code the rules cannot read: a command whose program is a variable (`$C config set`), a
  PowerShell or batch command (a fence tagged as one, or a `Verb-Noun` cmdlet), more skill steps than the rule-based
  probe judges (`skill_steps.MAX_COMMANDS`), or a command longer than it reads (`skill_steps.MAX_COMMAND_CHARS`).
- `outside_store`: a file write, edit or command whose target is not plainly inside the declared store (a path
  under the store's own folder group, or inside the workspace with no other agent, credential or system group), or
  whose target cannot be seen. The host's own memory and skill tools name their store themselves.

Only text the save writes is read (`skill_steps.written_texts`; for a patch, its new side with the context lines, so
a fence the hunk shows stays a fence); every other string argument but the replaced text (a description, a prompt
field) is read for destinations and secrets too, and for commands when the call has no written text. A save made by
running a command or a program is read as that command: it adds `command`, and its own text is read for the rest. A
rule that fails counts its kind as added (or the save as held), since the scanner cannot vouch for what it did not
read. The reading's cost grows linearly with the text: fences and `<pre>` blocks are found in one pass over the
lines, sentence bounds once per text (each sentence is read at most twice for links), heredocs in one pass, and every
pattern bounds its runs of spaces and repeats. Text is read as a reader would take it (`normalise`: compatibility
forms folded, invisible characters dropped, entities decoded, defanged addresses restored). Nothing here changes a
score.
"""

from __future__ import annotations

import html
import re
import shlex
import unicodedata
from bisect import bisect_right
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ..planir.canonical import CanonicalCall, canonicalise
from ..planir.models import Provider, ProviderKind, ToolKind
from .entities import _EMAIL_RE, _FILE_EXTENSIONS
from .skill_steps import (
    _COMMANDISH,
    _INLINE,
    _PROMPT,
    MAX_COMMAND_CHARS,
    MAX_COMMANDS,
    NESTED_KEYS,
    PATCH_KEY,
    SKILL_TOOLS,
    WRITTEN_KEYS,
    _fence_lines,
)

COMMAND, DESTINATION, PERMISSION, SECRET = "command", "destination", "permission", "secret"
ADDS: tuple[str, ...] = (COMMAND, DESTINATION, PERMISSION, SECRET)
#: Why the reading cannot vouch for a save, beyond what it adds.
NOTHING_WRITTEN, REMOVES, RISKY_STEP, UNREAD, OUTSIDE_STORE = (
    "nothing_written",
    "removes",
    "risky_step",
    "unread",
    "outside_store",
)
HELD: tuple[str, ...] = (NOTHING_WRITTEN, REMOVES, RISKY_STEP, UNREAD, OUTSIDE_STORE)
#: The most command candidates the permission and destination rules run on per save; a save with more counts as a
#: change of both kinds.
MAX_CHECKED_COMMANDS = 200
#: The most fenced blocks and inline code spans the destination rule reads a save's prose around; more count as a
#: destination, since the prose reading's cost grows with them.
MAX_CODE_SPANS = 400
#: Keys whose text is a fragment of a larger file (an edit's new text), which may sit inside a fence it does not show.
FRAGMENT_KEYS = frozenset({"new_string", "new_text", "newText"})
#: Keys that hold the text an edit replaces, never read as written text.
REPLACED_KEYS = frozenset({"old_string", "old_text", "oldText", "old"})
#: Actions that remove a skill, a support file or a memory entry.
REMOVING_ACTIONS = frozenset(
    {"delete", "remove", "remove_file", "delete_file", "archive", "uninstall", "discard"}
)
#: Rule classes that change permissions, config, plugins, hooks, the scheduler, approvals or privilege.
PERMISSION_CLASSES = frozenset({"C4", "C4*", "C8"})
#: Self-modification reasons for the store a save writes to (memory, a skill), which every save has.
STORE_REASONS = frozenset({"selfmod.memory", "selfmod.plugin", "selfmod.workspace_skill"})
#: What counts on the save's own target, which the plugin declared to be the memory or skill store.
TARGET_CLASSES = frozenset({"C4*", "C8"})
TARGET_REASONS = frozenset({"selfmod.host_approvals"})
#: Each declared store's own path group.
STORE_GROUPS = {"memory": "agent_memory", "skills": "agent_plugins"}
#: Path groups a target inside the workspace must not be in, unless it is also in the store's own group.
FOREIGN_GROUPS = frozenset(
    {
        "agent_config",
        "agent_plugins",
        "agent_memory",
        "agent_scheduler",
        "hooks",
        "startup",
        "host_scheduler",
        "credential_store",
        "credential_bearing_config",
        "browser_profile",
        "pii_store",
        "sensitive",
    }
)

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
#: Fence tags of a language the rules do not read.
_UNREAD_TAGS = frozenset({"powershell", "pwsh", "ps1", "ps", "posh", "bat", "batch", "cmd"})
#: A PowerShell cmdlet (`Set-Content`, `Invoke-WebRequest`) at the start of a command.
_CMDLET = re.compile(r"^[A-Z][a-z]+-[A-Z][A-Za-z]+(?=\s|$)")
#: A command (or a segment of one) whose program is a variable's value: `$C config set ...`.
_VAR_PROGRAM = re.compile(
    r"(?:^|[;&|]\s*|\$\(\s*|\(\s*|\{\s+)(?:[A-Za-z_]\w*=\S*\s+)*\$\{?[A-Za-z_]\w*\}?(?=\s|$|;)"
)
#: A line that starts a subshell, a group, a command substitution or a variable: shell, not prose.
_SHELL_START = re.compile(
    r"^(?:\(\s*\S|\{\s+\S|\$\(|\$\{?[A-Za-z_]|[A-Za-z_]\w*=\S*\s*;|\\\w|([\"'])[\w./-]+\1\s+\S|\w+\s*\(\)\s*\{)"
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
#: A Markdown list item's marker.
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d{1,3}[.)])\s+")
#: Shell syntax in a list item, which makes it read as code: a pipe, a redirect, a separator, a variable, quotes, an
#: assignment, a path, a flag.
_CODEISH = re.compile(r"[|;&<>$'\"=/~]|\s--?[A-Za-z]")
#: Programs a list item that starts with one reads as a command.
_KNOWN_PROGRAMS = frozenset(
    "openclaw hermes git npm npx pnpm yarn pip pip3 pipx uv python python3 node bun deno curl wget ssh scp rsync "
    "sftp rclone nc ncat sudo su doas chmod chown chgrp chattr setfacl crontab systemctl launchctl docker podman "
    "kubectl helm terraform aws gcloud az gh rm mv cp ln cat tee echo printf sed awk perl ruby make bash sh zsh "
    "eval source export env kill pkill killall brew apt apt-get dnf yum".split()
)
_PLAIN_WORD = re.compile(r"^[A-Za-z][a-z]*(?:'[a-z]+)?$")
_CAPITALISED = re.compile(r"^[A-Z][a-z]+$")
#: Words that start prose, never a program.
_PROSE_STARTS = frozenset(
    "a an the no not and or but my your our their his her its this that these those all any each every some only "
    "always never please".split()
)
#: Words after inline code that report what it did rather than ask for it: "`npm ci` failed", "`make` took 4 min".
_REPORTED_AFTER = re.compile(
    r"\s*(?:failed|fails|errored|returned|printed|showed|worked|succeeded|hung|timed\s+out|crashed|exited|took|"
    r"gave|broke)\b",
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
#: A sign-in pair the redactors and the secret-like detector leave raw: "login is admin / <passphrase>",
#: "credentials: root:<value>", "user admin pass <value>". The value must hold a digit, a capital or a symbol, or be
#: long, so "account: home/work" is not one.
_CREDENTIAL_PAIR = re.compile(
    r"(?i:\b(?:log[ -]?in|sign[ -]?in|credentials?|creds|user(?:name)?|account)\b)"
    r"[ \t]{0,4}(?:(?:is|are|was)\b[ \t]{0,4})?[:=]?[ \t]{0,4}"
    r"[\w.@+-]{1,64}[ \t]{0,4}(?:/|:|[ \t](?i:pass(?:word|phrase)?|pw|pwd)[ \t]{0,4}[:=]?)[ \t]{0,4}"
    r"(?P<v>[^\s/,;]{4,128})"
)
#: A sign-in pair's value counts when it is this long, or holds a digit, a capital or a symbol.
_PAIR_PLAIN_CHARS = 12
_PAIR_MIXED = re.compile(r"[0-9A-Z]|[^\w]")
#: "the password is <word>", "Wifi passphrase: <word>", "PIN is <digits>" in any case. Words that say where a secret
#: is kept or what happened to it are not values.
_SECRET_IS = re.compile(
    r"(?i:\b(?P<cue>password|passwd|passphrase|passcode|pass\s?code|pin|pwd)\b)[ \t]{0,4}(?i:is|was|:|=)[ \t]{0,4}"
    r"[\"'`]?(?P<v>[^\s\"'`,;]{3,128})"
)
_NOT_VALUES = frozenset(
    """the a an in on at set stored saved kept not empty required changed same different there here below above
    managed rotated unknown missing none null secret redacted hidden available needed""".split()
)
#: A card number: 13 to 19 digits, single spaces or dashes allowed between them (checked with the Luhn sum).
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
#: A base32 seed after a 2FA, OTP or TOTP cue.
_OTP_SEED = re.compile(
    r"(?i:\b(?:2fa|mfa|otp|totp|authenticator|seed)\b)[^\n]{0,24}?(?<![A-Za-z0-9])([A-Z2-7]{16,64})(?![A-Za-z0-9])"
)
#: A recovery phrase: twelve or more short lower-case words after a seed, recovery or mnemonic cue.
_RECOVERY = re.compile(
    r"(?i:\b(?:seed|recovery|mnemonic)\b)[^\n]{0,24}?(?:\b[a-z]{3,8}\b[ \t,]{1,3}){11,23}\b[a-z]{3,8}\b"
)
#: Vendor token prefixes, read in a run of spaced characters once joined.
_PREFIXED_TOKEN = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_\w{20,}|sk-[A-Za-z0-9_-]{16,}|xox[abprs]-[\w-]{10,}"
    r"|AKIA[0-9A-Z]{12,}|glpat-[\w-]{16,}|AIza[\w-]{30,})"
)
#: A run of single characters separated by single spaces ("g h p _ a b c ..."), joined before the vendor shapes run.
_SPACED = re.compile(r"(?<!\S)(?:\S ){11,}\S(?!\S)")


@dataclass(frozen=True)
class SavedText:
    text: str
    #: A fragment of a larger file (an edit's new text, a patch's added lines), whose fence may not be shown.
    fragment: bool = False
    #: A file that is not instruction text (a skill's script or data file, by its path, or text starting `#!`): every
    #: line is read as it would run.
    script: bool = False


@dataclass(frozen=True)
class SaveReading:
    """What a save adds (`ADDS`, sorted), and why the reading cannot vouch for it (`HELD`, sorted; empty when it
    can). Only `adds` reaches the response; `held` rules out lenient handling. `rewrites`: an edit replaces text with
    new text and drops a word of it (`removes`), so lenient handling also needs a low loosened-oversight answer."""

    adds: tuple[str, ...] = ()
    held: tuple[str, ...] = ()
    rewrites: bool = False


#: The reading of a save the reading could not finish: every kind counted as added, every hold set.
UNREAD_SAVE = SaveReading(ADDS, HELD)

#: Suffixes of instruction text, whose commands are its fenced and inline code.
PROSE_SUFFIXES = (".md", ".markdown", ".txt", ".rst")
#: The arguments that name the file a save writes.
PATH_KEYS = ("file_path", "path")


def _script(path: str | None, text: str) -> bool:
    if text.lstrip().startswith("#!"):
        return True
    return (
        isinstance(path, str) and bool(path.strip()) and not path.lower().endswith(PROSE_SUFFIXES)
    )


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


def _patch_removed(patch: str) -> str:
    return "\n".join(
        line[1:]
        for line in patch.splitlines()
        if line.startswith("-") and not line.startswith("---")
    )


def _ops(arguments: Any) -> list[dict[str, Any]]:
    """The call's own arguments and every nested edit (`operations`, `edits`), depth first."""
    out: list[dict[str, Any]] = []

    def take(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        out.append(obj)
        for key in NESTED_KEYS:
            ops = obj.get(key)
            if isinstance(ops, list):
                for op in ops:
                    take(op)

    take(arguments)
    return out


def saved_texts(arguments: Any) -> list[SavedText]:
    """The text a save writes (as `skill_steps.written_texts` reads it, a patch with its context), each marked when
    it is a fragment of a larger file."""
    out: list[SavedText] = []

    def take(obj: Any, path: str | None = None) -> None:
        if not isinstance(obj, dict):
            return
        path = next((obj[k] for k in PATH_KEYS if isinstance(obj.get(k), str)), path)
        for k in (*WRITTEN_KEYS, *_EXTRA_NEW_KEYS):
            if isinstance(obj.get(k), str):
                text = obj[k]
                fragment = k in FRAGMENT_KEYS or k in _EXTRA_NEW_KEYS
                out.append(SavedText(text, fragment=fragment, script=_script(path, text)))
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
                    take(op, path)

    take(arguments)
    return out


def _all_strings(obj: Any, key: str | None = None) -> list[str]:
    """Every string in the arguments but the text an edit replaces and a raw patch (read by its new side)."""
    if key in REPLACED_KEYS or key in _EXTRA_OLD_KEYS or key == PATCH_KEY:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in _all_strings(v, str(k))]
    if isinstance(obj, list):
        return [s for v in obj for s in _all_strings(v)]
    return []


# ---- fences, in one pass --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Fence:
    """A fenced block (or a `<pre>` block) at `start:end` of its text; `body` is its inner text."""

    start: int
    end: int
    body: str
    tag: str
    pre: bool = False


_OPENER = re.compile(r"[ \t]*(```|~~~)")
_CLOSER = re.compile(r"[ \t]*(```|~~~)[ \t]*\Z")


def _fence_tag(opener: str) -> str:
    rest = opener.strip().lstrip("`~").strip()
    return rest.split(None, 1)[0].lower() if rest else ""


def markdown_fences(text: str) -> list[Fence]:
    """The fenced blocks `skill_steps._FENCE` finds (an opener line of ``` or ~~~, closed by the next line that is
    exactly the same marker), found in one pass: each opener looks up its closer among the closer lines, instead of
    scanning the rest of the text, so many unclosed openers cost no more than many lines."""
    starts = [0, *(m.end() for m in re.finditer("\n", text))]
    n = len(starts)

    def line(i: int) -> str:
        end = starts[i + 1] - 1 if i + 1 < n else len(text)
        return text[starts[i] : end]

    closers: dict[str, list[int]] = {"```": [], "~~~": []}
    openers: list[tuple[int, str]] = []
    for i in range(n):
        ln = line(i)
        m = _OPENER.match(ln)
        if not m:
            continue
        marker = m.group(1)
        if _CLOSER.match(ln):
            closers[marker].append(i)
        if i + 1 < n:  # an opener needs a line break after it
            openers.append((i, marker))
    out: list[Fence] = []
    resume = 0
    for i, marker in openers:
        if i < resume:
            continue
        cl = closers[marker]
        k = bisect_right(cl, i)
        if k == len(cl):
            continue
        j = cl[k]
        end = starts[j] + len(line(j))
        out.append(Fence(starts[i], end, text[starts[i + 1] : starts[j]], _fence_tag(line(i))))
        resume = j + 1
    return out


_PRE_OPEN = re.compile(r"<pre\b[^>\n]*>", re.I)
_PRE_CLOSE = re.compile(r"</pre\s*>", re.I)
_TAG = re.compile(r"<[^>\n]*>")


def pre_blocks(text: str) -> list[Fence]:
    """`<pre>` blocks, each opener paired with the next closer after it, tags inside dropped and entities decoded."""
    closes = [m for m in _PRE_CLOSE.finditer(text)]
    out: list[Fence] = []
    k = 0
    for m in _PRE_OPEN.finditer(text):
        if out and m.start() < out[-1].end:
            continue
        while k < len(closes) and closes[k].start() < m.end():
            k += 1
        if k == len(closes):
            break
        c = closes[k]
        body = html.unescape(_TAG.sub("", text[m.end() : c.start()]))
        out.append(Fence(m.start(), c.end(), body, "", pre=True))
    return out


def fences(text: str) -> list[Fence]:
    """Fenced blocks and `<pre>` blocks outside them, in order."""
    md = markdown_fences(text)
    if "<" not in text:
        return md
    starts = [f.start for f in md]
    pres = []
    for p in pre_blocks(text):
        i = bisect_right(starts, p.end - 1) - 1
        if i >= 0 and md[i].end > p.start:
            continue  # overlaps a fence: the fence reading has it
        pres.append(p)
    return sorted([*md, *pres], key=lambda f: f.start)


def _blank(text: str, spans: Iterable[Fence], *, keep_lines: bool = False) -> str:
    """`text` with each span replaced by spaces (or by its line breaks, with `keep_lines`), offsets kept."""
    parts: list[str] = []
    at = 0
    for f in spans:
        parts.append(text[at : f.start])
        chunk = text[f.start : f.end]
        parts.append(re.sub(r"[^\n]", "", chunk) if keep_lines else " " * len(chunk))
        at = f.end
    parts.append(text[at:])
    return "".join(parts)


# ---- commands ---------------------------------------------------------------------------------------------------


def _is_command(line: str) -> bool:
    return bool(_COMMANDISH.match(line) or _SHELL_START.match(line))


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


def saved_commands(text: str, store: str, found_fences: list[Fence] | None = None) -> list[str]:
    """The commands a saved text adds, for the report: `skill_steps.steps_in`'s reading less output and log lines,
    prose in backticks and, in a memory note, commands the note only reports on."""
    found: dict[str, None] = {}
    blocks = fences(text) if found_fences is None else found_fences

    def add(cmd: str) -> None:
        cmd = cmd[:MAX_COMMAND_CHARS]
        if _is_command(cmd):
            found.setdefault(cmd, None)

    for f in blocks:
        if f.tag in _OUTPUT_TAGS:
            continue
        for line in _fence_commands(f.body):
            add(line)
    without_fences = _blank(text, blocks)
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


def _raw_commands(text: str, found_fences: list[Fence] | None = None) -> list[str]:
    """The commands `skill_steps.steps_in` reads (fenced lines and inline code that reads as a command), without its
    negation check, in one pass; also `<pre>` lines and lines that start a subshell, a group or a variable."""
    out: dict[str, None] = {}
    blocks = fences(text) if found_fences is None else found_fences
    for f in blocks:
        for line in _fence_lines(f.body):
            if _is_command(line):
                out.setdefault(line[:MAX_COMMAND_CHARS], None)
    without_fences = _blank(text, blocks)
    for m in _INLINE.finditer(without_fences):
        span = _PROMPT.sub("", m.group(1)).strip()
        if _is_command(span):
            out.setdefault(span[:MAX_COMMAND_CHARS], None)
    return list(out)


def line_commands(
    st: SavedText, *, outside_fences: bool = False, found_fences: list[Fence] | None = None
) -> list[str]:
    """The lines of a saved text read as commands on their own: every line of a script (but comments), and each line
    that starts like a command (a program name, a path, an environment assignment, a subshell or a group), not like a
    sentence or a list item (inline code is left to the inline reading). These catch code the fence reading misses:
    an edit fragment inside a fence it does not show, an indented block, a longer or unclosed fence. With
    `outside_fences`, lines of a fence the fence reading recognised are left to it."""
    text = st.text
    if outside_fences and not st.script:
        text = _blank(text, fences(text) if found_fences is None else found_fences, keep_lines=True)
    out: list[str] = []
    for raw in text.splitlines():
        line = _PROMPT.sub("", raw).strip()
        if not line or line.startswith("#"):
            continue
        if (st.script or _FRAGMENT_COMMAND.match(line) or _SHELL_START.match(line)) and _is_command(
            line
        ):
            out.append(line[:MAX_COMMAND_CHARS])
    return out


def list_commands(text: str, found_fences: list[Fence] | None = None) -> list[str]:
    """List items outside fences that read as code: they start with a known program, or start like a command and hold
    shell syntax. "1. openclaw config set ..." is a step even with no backticks around it."""
    text = _blank(text, fences(text) if found_fences is None else found_fences, keep_lines=True)
    out: list[str] = []
    for raw in text.splitlines():
        m = _LIST_ITEM.match(raw)
        if not m:
            continue
        line = _PROMPT.sub("", raw[m.end() :]).strip().strip("`").strip()
        if not line or not _is_command(line):
            continue
        head = line.split(None, 1)[0].rsplit("/", 1)[-1]
        if head in _KNOWN_PROGRAMS or (
            (_FRAGMENT_COMMAND.match(line) or _SHELL_START.match(line)) and _CODEISH.search(line)
        ):
            out.append(line[:MAX_COMMAND_CHARS])
    return out


@dataclass
class _Read:
    """One saved text, read once."""

    st: SavedText
    fences: list[Fence]
    raw: list[str]
    lines: list[str]
    listed: list[str]


def _read(st: SavedText) -> _Read:
    fs = fences(st.text)
    return _Read(
        st,
        fs,
        _raw_commands(st.text, fs),
        line_commands(st, found_fences=fs),
        list_commands(st.text, fs) if not st.script else [],
    )


def _candidates(reads: Iterable[_Read]) -> list[str]:
    """Every command candidate the permission rules check: the scanner's own skill reading, each line read as a
    command on its own (`line_commands`), and list items that read as code."""
    out: dict[str, None] = {}
    for r in reads:
        for cmd in (*r.raw, *r.lines, *r.listed):
            out.setdefault(cmd, None)
            for v in program_variants(cmd):
                out.setdefault(v, None)
    return list(out)


def _code_spans(reads: Iterable[_Read], others: Iterable[str], limit: int) -> int:
    """The fenced blocks and inline code spans in the texts, counted up to `limit`."""
    n = 0
    for r in reads:
        n += len(r.fences)
        if n >= limit:
            return n
        for _ in _INLINE.finditer(r.st.text):
            n += 1
            if n >= limit:
                return n
    for t in others:
        n += len(fences(t))
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


_OCTAL = re.compile(r"^[0-7]{3,4}$")
_SYMBOLIC = re.compile(r"^([ugoa]*)([+=-])([rwxXst]*)$")
#: Folders whose mode is the system's or the owner's credentials': any `chmod` on them counts.
_GUARDED_MODE_PATHS = re.compile(
    r"^(?:~|\$HOME|\$\{HOME\})?/?(?:\.ssh|\.gnupg|\.aws|\.config/gcloud|\.kube|\.docker|\.netrc)\b"
    r"|^/(?:etc|usr|bin|sbin|var|root|boot|lib)?(?:/|$)|^~/?$|^\$HOME/?$"
)


def _segments(command: str) -> list[list[str]]:
    """A command's simple commands, split on `;`, `&&`, `||`, `|` and newlines, each as words (shell-quoted where the
    quoting parses, by whitespace where it does not), with a leading `sudo`, `(` or `{` dropped."""
    out: list[list[str]] = []
    for seg in re.split(r"\|\||&&|[;|\n]", command):
        seg = seg.strip().lstrip("({").strip()
        if not seg:
            continue
        try:
            words = shlex.split(seg, comments=True)
        except ValueError:
            words = seg.split()
        while words and words[0] in ("sudo", "doas", "env", "nohup", "exec", "command"):
            words = words[1:]
        if words:
            out.append(words)
    return out


def _loosens(command: str) -> bool:
    """What the permission rules leave to this reading: a `chmod` that makes a file world-writable, setuid or setgid,
    or changes the mode of a credential or system folder; an ACL grant (`setfacl -m`, `icacls /grant`); an attribute
    change (`chattr`); a `crontab` that installs a table (from a file or standard input), not one that only lists."""
    for words in _segments(command):
        head = words[0].rsplit("/", 1)[-1].lower()
        args = words[1:]
        if head in ("setfacl", "chattr"):
            return True
        if head == "crontab" and any(a != "-l" for a in args):
            return True
        if head == "icacls" and any(a.lower().startswith("/grant") for a in args):
            return True
        if head != "chmod":
            continue
        operands = [a for a in args if not (a.startswith("-") and not _SYMBOLIC.match(a))]
        if not operands:
            continue
        mode, targets = operands[0], operands[1:]
        if any(_GUARDED_MODE_PATHS.match(t) for t in targets):
            return True
        if _OCTAL.match(mode):
            digits = mode.zfill(4)
            if int(digits[0]) & 6 or int(digits[3]) & 2:
                return True
            continue
        for part in mode.split(","):
            m = _SYMBOLIC.match(part)
            if not m:
                return True  # a mode the rule cannot read
            who, op, perms = m.groups()
            if op == "-":
                continue
            if "s" in perms or (
                "w" in perms and (set(who) & {"o", "a"} or (not who and op == "="))
            ):
                return True
    return False


def _rule_findings(prepared: Any, commands: list[str]) -> dict[str, list[Any]]:
    from ..aira.analysis import analyse
    from ..aira.detectors import PACK_HOST_GATED, PACK_TIER1, Context, run_detectors
    from ..aira.lists import load_lists

    lists = load_lists()
    ctx = Context(prepared=prepared, lists=lists, packs=frozenset({PACK_TIER1, PACK_HOST_GATED}))
    out: dict[str, list[Any]] = {}
    for cmd in commands:
        call = _exec_call(prepared.platform, cmd, prepared.pending.step)
        out[cmd] = run_detectors(analyse(call, prepared, lists), ctx)[0]
    return out


def _target_findings(prepared: Any) -> list[Any]:
    from ..aira.analysis import analyse
    from ..aira.detectors import PACK_HOST_GATED, PACK_TIER1, Context, run_detectors
    from ..aira.lists import load_lists

    lists = load_lists()
    ctx = Context(prepared=prepared, lists=lists, packs=frozenset({PACK_TIER1, PACK_HOST_GATED}))
    return run_detectors(analyse(prepared.pending, prepared, lists), ctx)[0]


def _permission(
    prepared: Any, candidates: list[str], findings: dict[str, list[Any]], *, exec_save: bool
) -> bool:
    if len(candidates) > MAX_CHECKED_COMMANDS:
        return True
    # The save itself. The plugin declares a save only for a target in the agent's memory or skill store, which a
    # path rule may still class as agent config (a skill folder under the host's agent directory): only a guardrail,
    # an approval file or a privilege change counts there. A save made by running a command is read as a command,
    # less the write into the store.
    target = _target_findings(prepared)
    if exec_save:
        if any(f.cls in PERMISSION_CLASSES and f.reason not in STORE_REASONS for f in target):
            return True
        if _loosens(prepared.pending.command or ""):
            return True
    elif any(f.cls in TARGET_CLASSES or f.reason in TARGET_REASONS for f in target):
        return True
    for cmd in candidates:
        if any(f.cls in PERMISSION_CLASSES for f in findings.get(cmd, ())) or _loosens(cmd):
            return True
    return False


#: Remote copy and sync programs, whose `host:path` (or `remote:path`) operands are destinations.
_REMOTE_COPY = frozenset({"scp", "rsync", "sftp", "rclone"})
_REMOTE_OPERAND = re.compile(r"^(?:[^\s@/:]+@)?[A-Za-z0-9][\w.-]+:(?!//)")
#: Remotes a `git push` may name without adding a destination: the clone's own.
_OWN_REMOTES = frozenset({"origin", "upstream"})


def _remote_destination(command: str) -> bool:
    """A copy or sync to a `host:path` or `remote:path`, or a `git push` to a remote other than the clone's own."""
    for words in _segments(command):
        head = words[0].rsplit("/", 1)[-1].lower()
        args = [a for a in words[1:] if not a.startswith("-")]
        if head in _REMOTE_COPY and any(_REMOTE_OPERAND.match(a) for a in args):
            return True
        if head == "git" and args[:1] == ["push"] and len(args) > 1:
            remote = args[1]
            if remote not in _OWN_REMOTES:
                return True
    return False


#: A pointer to reading matter directly before a URL: "see the docs at", "docs:", "reference:", "handbook:".
_REF_LEAD = re.compile(
    r"(?:\b(?:see(?:\s+(?:the\s+)?(?:docs?|documentation|reference|guide|details|notes))?|docs?|documentation"
    r"|reference|details|read\s+more|learn\s+more|more\s+info|source)(?:\s+(?:at|on|in|here))?"
    r"|\b(?:handbook|guide|manual|wiki|runbook)\s*:)\s*[:(<\[]?\s*$",
    re.I,
)
#: Words that make a sentence more than a pointer to reading: a send, a run, a fetch, following what the page says,
#: or naming an endpoint.
_REF_SPOILERS = re.compile(
    r"\b(?:post|send|upload|forward|submit|transmit|exfiltrate|beacon|deliver|push|leak|report|share|sync|mirror|"
    r"copy|ping|e-?mail|mail|back\s?up|run|execute|exec|install|source|eval|launch|bash|sh|follow|obey|apply|"
    r"open|fetch|load|download|curl|wget|import|retrieve|endpoint|webhook|callback)(?:s|es|ed|d|ing)?\b|\bdo\s+what\b",
    re.I,
)
#: A later sentence that points back at the page ("there", "that page", "it").
_REFERS_BACK = re.compile(
    r"\b(?:there|it|them|that|this)(?:\s+(?:page|url|link|site|address|endpoint))?\b", re.I
)
_SENTENCE_END = re.compile(r"\n|[.!?](?=\s|$)")
#: How far before a URL its pointer phrase is looked for.
_LEAD_WINDOW = 80


def _sentence_spans(prose: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    at = 0
    for m in _SENTENCE_END.finditer(prose):
        spans.append((at, m.start()))
        at = m.end()
    spans.append((at, len(prose)))
    return spans


def _prose_urls(reads: Iterable[_Read]) -> bool:
    """A network URL in a saved text's prose (outside fences, `<pre>` blocks and inline code) that is not only a
    pointer to reading matter: one with a pointer phrase directly before it, in a sentence with no send, run, fetch
    or follow word, and not pointed back at by the next sentence with such a word. Sentence bounds are found once per
    text and each sentence is read at most twice, so the cost grows linearly with the text."""
    for r in reads:
        if r.st.script:
            if _NET_URL.search(r.st.text):
                return True
            continue
        prose = re.sub(r"`[^`\n]+`", lambda m: " " * len(m.group(0)), _blank(r.st.text, r.fences))
        if _NET_URL.search(prose) and _unreferenced_url(prose):
            return True
    return False


def _unreferenced_url(prose: str) -> bool:
    spans = _sentence_spans(prose)
    ends = [e for _, e in spans]
    spoiled: dict[tuple[int, bool], bool] = {}

    def spoils(i: int, back: bool) -> bool:
        if (i, back) not in spoiled:
            text = prose[spans[i][0] : spans[i][1]]
            hit = bool(_REF_SPOILERS.search(text))
            spoiled[(i, back)] = hit and bool(_REFERS_BACK.search(text)) if back else hit
        return spoiled[(i, back)]

    for m in _NET_URL.finditer(prose):
        i = min(bisect_right(ends, m.start()), len(spans) - 1)
        before = prose[max(spans[i][0], m.start() - _LEAD_WINDOW) : m.start()]
        if not _REF_LEAD.search(before) or spoils(i, False):
            return True
        if i + 1 < len(spans) and spoils(i + 1, True):
            return True
    return False


def _code_urls(reads: Iterable[_Read]) -> bool:
    """A network URL inside a saved text's fences, `<pre>` blocks or inline code."""
    for r in reads:
        if any(_NET_URL.search(f.body) for f in r.fences):
            return True
        without = _blank(r.st.text, r.fences)
        if any(_NET_URL.search(m.group(0)) for m in re.finditer(r"`[^`\n]+`", without)):
            return True
    return False


#: A host-shaped token (two to nine labels and an alphabetic top-level label) or an IPv4 address, with an optional
#: port and path.
_HOSTISH = re.compile(
    r"(?<![\w@/.:+-])((?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3})"
    r"(:\d{2,5})?(/[^\s<>()\[\]'\"`]*)?(?![\w-]|\.[\w-])"
)
#: Top-level labels a host-shaped token without a path or a port is taken for a host by: the generic ones, the
#: country codes in wide use, and cheap ones often used to host collectors. A token with a path or a port only needs
#: a top-level label that is not a file extension; a dotted field name (`text.link.url`) has neither.
_COMMON_TLDS = frozenset(
    """com net org edu gov mil int io dev ai app co me info biz xyz site online tech cloud page sh gg tv us uk de
    fr nl eu ru cn jp in br ca au ch se no es it pl cz at be dk fi ie il kr mx nz pt ro sg tw ua za ar cl id my ph th
    tr vn hk ir pk ng ke eg sa ae gr hu sk si lt lv ee bg hr rs by kz uz is lu li mc mt cy ly to ws cc su pw tk ml ga
    cf gq st vc la fm am nu tel mobi name pro top zip mov click link live store shop club fun icu cyou buzz rest cfd
    sbs lol space website digital network systems services email run host hosting media news blog wiki tools world
    today one social chat bot dog ninja rocks zone lat example test""".split()
)
#: Words before a host that send to it, or name it as an address to reach: "post the summary to", "url", "webhook".
_HOST_CUE = re.compile(
    r"\b(?:post|send|upload|forward|submit|transmit|exfiltrate|beacon|deliver|push|leak|report|share|sync|mirror|"
    r"copy|ping|e-?mail|mail|notify|back\s?up|url|endpoint|webhook|callback)(?:s|es|ed|d|ing)?\b",
    re.I,
)
_FROM_BEFORE = re.compile(r"\b(?:from|of|off)\s*$", re.I)
_CLAUSE_BREAK = re.compile(r"[.;!?\n]")
#: "name at host dot tld": a mail address written out.
_SPELLED_MAIL = re.compile(
    r"(?<![\w.+-])[\w.+-]{1,64}\s{1,3}at\s{1,3}(?P<d>[A-Za-z0-9-]{1,63}(?:\s{1,3}dot\s{1,3}[A-Za-z0-9-]{1,63}){1,4})\b",
    re.I,
)
_HOST_WINDOW = 80


def _hostish(token: str) -> bool:
    """A host-shaped token whose top-level label is not a file extension (`notes.md`, `config.yaml`), and not
    `e.g` or a version."""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
        return all(int(p) < 256 for p in token.split("."))
    tld = token.rsplit(".", 1)[-1].lower()
    if tld in _FILE_EXTENSIONS and tld != "example":
        return False
    return token.lower() not in ("e.g", "i.e", "etc.etc")


def _known_tld(token: str) -> bool:
    """An address, or a host on a top-level label in `_COMMON_TLDS`."""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
        return _hostish(token)
    return token.rsplit(".", 1)[-1].lower() in _COMMON_TLDS


def _prose_hosts(texts: Iterable[str]) -> bool:
    """A host or address a sentence sends to or names as an address to reach ("post the summary to
    hooks.example.io/ingest", "back up to 203.0.113.7", a host in inline code after such a word), or a mail address
    spelled out ("name at host dot tld")."""
    for t in texts:
        for m in _HOSTISH.finditer(t):
            if not _hostish(m.group(1)) or not (m.group(2) or m.group(3) or _known_tld(m.group(1))):
                continue
            window = t[max(0, m.start() - _HOST_WINDOW) : m.start()]
            clause = _CLAUSE_BREAK.split(window)[-1]
            if _HOST_CUE.search(clause) and not _FROM_BEFORE.search(clause):
                return True
        for m in _SPELLED_MAIL.finditer(t):
            if _known_tld(re.sub(r"\s+dot\s+", ".", m.group("d"), flags=re.I)):
                return True
    return False


def _quoted_code_hosts(reads: Iterable[_Read]) -> bool:
    """A quoted string in code (a fence, a `<pre>` block, inline code, a script) that is a host with a path or a port,
    or a host on a common top-level label: `requests.post('hooks.example.io/ingest', ...)`."""
    for r in reads:
        code = [f.body for f in r.fences]
        if r.st.script:
            code.append(r.st.text)
        without = _blank(r.st.text, r.fences)
        code += [m.group(0) for m in re.finditer(r"`[^`\n]+`", without)]
        for c in code:
            for q in re.finditer(r"([\"'])(?:[a-z]{2,8}://)?([^\"'\s]{4,256})\1", c):
                m = _HOSTISH.match(q.group(2))
                if not m or not _hostish(m.group(1)):
                    continue
                if m.group(2) or (m.group(3) and len(m.group(3)) > 1) or _known_tld(m.group(1)):
                    return True
    return False


#: The longest sentence the prose reading gets: a longer one is broken at a space (the reading's own host and link
#: rules above have already read it whole).
_PROSE_SENTENCE_CHARS = 400


def _bounded_sentences(text: str) -> str:
    out: list[str] = []
    run = 0
    for piece in re.split(r"(\s+)", text):
        if not piece:
            continue
        if piece.isspace():
            if "\n" in piece or re.search(r"[.!?]$", out[-1] if out else ""):
                run = 0
            elif run > _PROSE_SENTENCE_CHARS:
                out.append("\n")
                run = 0
                continue
        else:
            run += len(piece)
        out.append(piece)
    return "".join(out)


def _destination(prepared: Any, reads: list[_Read], others: list[str], commands: list[str]) -> bool:
    from .written_selfmod import Form, WrittenText, future_entities

    if any(_EMAIL_RE.search(r.st.text) for r in reads) or any(
        _NET_URL.search(t) or _EMAIL_RE.search(t) for t in others
    ):
        return True
    if _code_urls(reads) or _prose_urls(reads) or _quoted_code_hosts(reads):
        return True
    # hosts and addresses with no scheme, in prose and inline code (fences are read as shell below)
    if _prose_hosts(
        [_blank(r.st.text, r.fences).replace("`", " ") for r in reads if not r.st.script]
    ):
        return True
    if _prose_hosts(others):
        return True
    if (
        len(commands) > MAX_CHECKED_COMMANDS
        or _code_spans(reads, others, MAX_CODE_SPANS) >= MAX_CODE_SPANS
    ):
        return True  # more than the prose reading is run on: not vouched for
    if any(_remote_destination(c) for c in commands):
        return True
    home, ws = prepared.home, prepared.workspace_root

    # The prose is read with its code blanked out (every code line is read below as shell a later run contacts
    # from), with any marker run left by an unclosed fence blanked too, and with no sentence longer than
    # `_PROSE_SENTENCE_CHARS` (the prose reading looks around each host within its sentence), so it stays linear.
    def prose(t: str) -> str:
        return _bounded_sentences(re.sub(r"`{3,}|~{3,}", lambda m: " " * len(m.group(0)), t))

    written = [
        WrittenText(
            prose(
                re.sub(r"`[^`\n]+`", lambda m: " " * len(m.group(0)), _blank(r.st.text, r.fences))
            ),
            Form.PROSE,
            host_run=False,
        )
        for r in reads
        if not r.st.script
    ]
    written += [WrittenText(prose(t), Form.PROSE, False) for t in others]
    code = [*commands, *(f.body for r in reads for f in r.fences)]
    code += [r.st.text for r in reads if r.st.script]
    if code:
        # every host a saved command contacts, not only a send: a later run reaches it with nobody asked
        written.append(WrittenText("\n".join(code), Form.SHELL, host_run=True))
    return bool(future_entities(written, home=home, workspace_root=ws))


def _secret(texts: list[str]) -> bool:
    from ..aira.lists import load_lists
    from .secret_like import secret_carried

    placeholder = str(load_lists().get("egress", "placeholder", "open", default="⟦secret"))
    if any(secret_carried(t, placeholder) for t in texts):
        return True
    for t in texts:
        for m in _CREDENTIAL_PAIR.finditer(t):
            v = m.group("v").rstrip(".")
            if len(v) >= _PAIR_PLAIN_CHARS or _PAIR_MIXED.search(v):
                return True
        for m in _SECRET_IS.finditer(t):
            v = m.group("v").rstrip(".")
            if m.group("cue").lower() == "pin":
                if re.fullmatch(r"\d{4,12}", v):  # a version pin is not a PIN
                    return True
            elif len(v) >= 3 and v.lower() not in _NOT_VALUES:
                return True
        if any(_luhn(m.group(0)) for m in _CARD.finditer(t)):
            return True
        if _OTP_SEED.search(t) or _RECOVERY.search(t):
            return True
        joined = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), t)
        if joined != t and (secret_carried(joined, placeholder) or _PREFIXED_TOKEN.search(joined)):
            return True
    return False


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


# ---- what the reading cannot vouch for --------------------------------------------------------------------------

_WORD = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_'./-]*[A-Za-z0-9_])?")
#: A command a save made by running a command uses to delete, move, truncate, empty or edit a file in place.
_EXEC_REMOVAL = re.compile(
    r"(?:^|[\s;&|(])(?:rm|rmdir|unlink|shred|truncate|mv)\s"
    r"|\b(?:sed|perl|ruby)\s+(?:-\w*\s+)*-i"
    r"|(?<![>&\d])>(?!>)\s*(?!/dev/null\b)[^\s&]"
    r"|\bcp\s+(?:-\w+\s+)*/dev/null\b"
    r"|\bfind\b[^\n;|&]*\s-delete\b"
    r"|\brsync\b[^\n;|&]*\s--delete"
    r"|\btee\b(?![^\n;|&]*\s-(?:a|-append)\b)"
    r"|\bos\.(?:remove|unlink|rmdir)\b|\bshutil\.rmtree\b|\.unlink\(|\bfs\.(?:unlink|rm)\w*\("
    r"|\bgit\s+(?:checkout\s+--|restore\b|reset\s+--hard|clean\b)"
)
#: Lines of a patch that remove or move a whole file: an `apply_patch` delete or move, a unified diff to /dev/null,
#: a git rename.
_PATCH_FILE_REMOVAL = re.compile(
    r"^(?:\*\*\* (?:Delete File|Move to):|\+\+\+ /dev/null\s*$|rename from )", re.M
)
#: Actions that replace a file's whole content without showing the old text.
OVERWRITE_ACTIONS = frozenset({"edit", "update", "replace", "overwrite", "rewrite"})
#: Words that make a sentence an oversight rule: any change to a sentence holding one is a rewording, even when no
#: word is dropped ("No need to always ask ...", a reorder).
OVERSIGHT_WORDS = frozenset(
    """never always ask asks asking asked approve approves approved approval approvals confirm confirms confirmed
    confirmation not no without before permission permissions don't dont must unless only""".split()
)
#: Keys of an edit's replaced and new text beside those the skill reading knows.
_EXTRA_OLD_KEYS = ("old_str", "oldString")
_EXTRA_NEW_KEYS = ("new_str", "newString")


def _words(text: str) -> set[str]:
    return {w.lower() for w in _WORD.findall(text)}


def _oversight_sentences(text: str) -> set[str]:
    return {
        " ".join(sent.lower().split())
        for sent in re.split(r"[.!?\n]+", text)
        if _words(sent) & OVERSIGHT_WORDS
    }


def _all_sentences(text: str) -> set[str]:
    return {" ".join(sent.lower().split()) for sent in re.split(r"[.!?\n]+", text) if sent.strip()}


def removes(arguments: Any, *, exec_command: str | None = None) -> tuple[bool, bool]:
    """Whether the save removes existing content, as far as the request shows it: `(removes, rewrites)`.

    `removes`: a pure removal, which nothing the save writes stands in for: a removing action, a patch that deletes or
    moves a file, a replaced text or a patch's removed lines with no new words in the same edit, or a command that
    deletes, moves, truncates, empties or edits a file in place. `rewrites`: an edit that replaces text with new text
    and drops a word of what it replaces (that edit's own new text counts, not the rest of the save), or changes a
    sentence holding an oversight word (`OVERSIGHT_WORDS`) in any way, or adds one; or an action that replaces a whole
    file without showing the old text (`OVERWRITE_ACTIONS`, a `patch` carrying whole content). Its lenient handling
    rests on the judge's loosened-oversight answer. An edit that keeps every word and every oversight sentence of what
    it replaces is neither."""
    if exec_command is not None:
        return bool(_EXEC_REMOVAL.search(exec_command)), False
    pure = rewrites = False
    for op in _ops(arguments):
        action = op.get("action")
        action = action.strip().lower() if isinstance(action, str) else ""
        if action in REMOVING_ACTIONS:
            pure = True
        replaced = [op[k] for k in (*REPLACED_KEYS, *_EXTRA_OLD_KEYS) if isinstance(op.get(k), str)]
        new = "\n".join(
            op[k] for k in (*WRITTEN_KEYS, *_EXTRA_NEW_KEYS) if isinstance(op.get(k), str)
        )
        patch = op.get(PATCH_KEY)
        if isinstance(patch, str):
            if _PATCH_FILE_REMOVAL.search(patch):
                pure = True
            removed = _patch_removed(patch)
            if removed.strip():
                replaced.append(removed)
            new += "\n" + _patch_added(patch)
        replaced = [old for old in replaced if old.strip()]
        if not replaced:
            if new.strip() and (action in OVERWRITE_ACTIONS or action == "patch"):
                rewrites = True  # the whole content replaced, the old text not shown
            continue
        if not _words(new):
            pure = True  # nothing written in its place
            continue
        new_words = _words(new)
        new_sentences = _all_sentences(new)
        for old in replaced:
            if _words(old) - new_words:
                rewrites = True
            elif not _oversight_sentences(old) <= new_sentences:
                rewrites = True
            elif _oversight_sentences(new) - _all_sentences(old):
                rewrites = True
    return pure, rewrites


def _unread(reads: list[_Read], store: str, tool: str | None) -> bool:
    """Code the rules cannot read: a program named by a variable, PowerShell or batch, more skill steps than the
    rule-based probe judges, or a step longer than it reads."""
    for r in reads:
        if any(f.tag in _UNREAD_TAGS for f in r.fences):
            return True
        for cmd in (*r.raw, *r.lines, *r.listed):
            if _VAR_PROGRAM.search(cmd) or _CMDLET.match(cmd):
                return True
    if store == "skills" or tool in SKILL_TOOLS:
        steps = {c for r in reads for c in r.raw}
        if len(steps) > MAX_COMMANDS:
            return True
        for r in reads:
            for f in r.fences:
                if any(len(line) > MAX_COMMAND_CHARS for line in _fence_lines(f.body)):
                    return True
            without = _blank(r.st.text, r.fences)
            if any(len(m.group(1)) > MAX_COMMAND_CHARS for m in _INLINE.finditer(without)):
                return True
    return False


def _escapes(value: str) -> bool:
    """A store-relative name or path that is absolute, home-relative, or climbs out with `..`."""
    v = value.strip().replace("\\", "/")
    return v.startswith(("/", "~", "$")) or ".." in v.split("/")


def _inside(path: str, workspace_root: str | None) -> bool:
    if path.startswith("~") or path.startswith("$"):
        return False
    parts = path.replace("\\", "/").split("/")
    if ".." in parts:
        return False
    if not path.startswith("/"):
        return True  # relative: the host resolves it against the workspace
    if not workspace_root:
        return False
    root = workspace_root.rstrip("/")
    return path == root or path.startswith(root + "/")


def outside_store(prepared: Any, store: str) -> bool:
    """A file write, edit or command whose target is not plainly inside the declared store: every written path must
    be in the store's own path group, or inside the workspace with no other agent, credential or system group. The
    host's own memory and skill tools name their store themselves. A write whose target cannot be seen is outside."""
    from ..aira.analysis import analyse
    from ..aira.lists import load_lists

    pending = prepared.pending
    if pending.tool in SKILL_TOOLS or pending.tool_kind is ToolKind.MEMORY_WRITE:
        # the host's own tools name their store; a name or a file path that climbs out of it, or is absolute, does not
        return any(
            isinstance(op.get(k), str) and _escapes(op[k])
            for op in _ops(pending.raw)
            for k in ("name", "file_path", "path", "category")
        )
    named = isinstance(pending.raw, dict) and any(
        isinstance(pending.raw.get(k), str) for k in PATH_KEYS
    )
    if (
        pending.tool_kind not in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT, ToolKind.EXEC)
        and not named
    ):
        return False
    own = STORE_GROUPS.get(store)
    if own is None:
        return True
    dests = [p for p in analyse(pending, prepared, load_lists()).paths if p.is_destination]
    if not dests:
        return True
    for p in dests:
        if own in p.groups:
            continue
        if _inside(p.value, prepared.workspace_root) and not FOREIGN_GROUPS & set(p.groups):
            continue
        return True
    return False


# ---- normalising what is read ---------------------------------------------------------------------------------

#: Characters that hide a word's letters: zero-width spaces and joiners, the word joiner, a byte-order mark, a soft
#: hyphen.
_INVISIBLE = re.compile("[​‌‍⁠﻿­]")
#: Defanged addresses: `hxxp`, `[:]`, `[.]`, `(dot)`, `[at]`.
_DEFANG = (
    (re.compile(r"\bhxxp(s?)(?=\s*(?:\[:\]|:))", re.I), r"http\1"),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|\{dot\}", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)|\{at\}", re.I), "@"),
)


def normalise(text: str) -> str:
    """The text as a reader would take it: compatibility forms folded (fullwidth letters and colons, no-break spaces;
    NFKC), invisible characters dropped, HTML entities decoded, defanged addresses restored, and backslash-newline
    continuations joined as the shell joins them. Only this reading uses it; no scored view changes."""
    if (
        text.isascii()
        and "&" not in text
        and "\\\n" not in text
        and not re.search(r"hxxp|[\[({]", text, re.I)
    ):
        return text
    t = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    if "&" in t:
        t = html.unescape(t)
    for rx, to in _DEFANG:
        t = rx.sub(to, t)
    return t.replace("\\\n", "")


_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")


def heredoc_bodies(command: str) -> list[str]:
    """The heredoc bodies a command writes (`cat >> SKILL.md <<'EOF' ... EOF`), in one pass over its lines."""
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        words = [m.group(2) for m in _HEREDOC.finditer(lines[i])]
        i += 1
        for word in words:
            body: list[str] = []
            while i < len(lines) and lines[i].strip() != word:
                body.append(lines[i])
                i += 1
            i += 1
            out.append("\n".join(body))
    return out


#: A program word written quoted or escaped (`"hermes" config ...`, `\hermes config ...`), at the start of a command
#: or after a separator.
_QUOTED_PROGRAM = re.compile(r"(^|[;&|(]\s*)\\?([\"'])?([\w./-]+)(?(2)\2)(?=\s)")
#: A shell function's body: `f() { ...; }`.
_FUNCTION_BODY = re.compile(r"\b\w+\s*\(\)\s*\{([^{}]{1,2000})\}")
#: Programs a description or a reason field may name a command by, outside code.
_PROGRAM_IN_PROSE = re.compile(
    r"\b(?:openclaw|hermes|sudo|crontab|systemctl|launchctl|chmod|chown|setfacl|curl|wget|scp|rsync|ssh|nc|"
    r"git\s+(?:push|remote|config)|pip3?\s+install|npm\s+install)\s"
)


def program_variants(command: str) -> list[str]:
    """The command as the shell reads it, where the reading would miss it: the program word unquoted and unescaped,
    and each shell function's body."""
    out = []
    plain = _QUOTED_PROGRAM.sub(lambda m: m.group(1) + m.group(3), command)
    if plain != command:
        out.append(plain)
    out += [m.group(1).strip() for m in _FUNCTION_BODY.finditer(plain) if m.group(1).strip()]
    return out


def prose_commands(text: str) -> list[str]:
    """Commands a description or reason field names in prose ("Run hermes config set ... first"): the text from each
    known program word to the end of its sentence."""
    out = []
    for m in _PROGRAM_IN_PROSE.finditer(text):
        end = _CLAUSE_END_RE.search(text, m.start())
        out.append(text[m.start() : end.start() if end else len(text)][:MAX_COMMAND_CHARS].strip())
    return out


_CLAUSE_END_RE = re.compile(r"[.!?](?=\s|$)|\n")
_FRONT_MATTER_DESCRIPTION = re.compile(r"^description:\s*(.+)$", re.M)


def front_matter_description(text: str) -> str | None:
    """A skill file's front-matter description, which the host shows the agent to choose the skill by."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    m = _FRONT_MATTER_DESCRIPTION.search(text, 4, end if end != -1 else min(len(text), 4000))
    return m.group(1) if m else None


# ---- the reading ------------------------------------------------------------------------------------------------


def save_adds(prepared: Any) -> SaveReading:
    """What a declared self-edit's saved content adds (`ADDS`), and why the reading cannot vouch for it (`HELD`)."""
    planir = prepared.planir
    store = planir.self_edit.store.value if planir.self_edit is not None else "other"
    pending: CanonicalCall = prepared.pending
    adds: set[str] = set()
    held: set[str] = set()
    exec_save = pending.tool_kind is ToolKind.EXEC and isinstance(pending.command, str)
    command = normalise(pending.command or "") if exec_save else ""
    try:
        texts = [
            SavedText(normalise(st.text), st.fragment, st.script) for st in saved_texts(pending.raw)
        ]
        if exec_save:
            # a save made by running a command or a program: its text is what runs, and its heredocs are what it
            # writes, read as any saved text is
            texts = [SavedText(command), *(SavedText(b) for b in heredoc_bodies(command))]
            adds.add(COMMAND)
        elif not any(_WORD.search(st.text) for st in texts):
            # nothing written the reading can examine (a restore, an archive, a delete, a file emptied to a dot):
            # read what the call names, but it is not vouched for
            held.add(NOTHING_WRITTEN)
            texts = [
                SavedText(normalise(s), fragment=True)
                for s in _all_strings(pending.raw)
                if s.strip()
            ]
        reads = [_read(st) for st in texts]
    except Exception:  # noqa: BLE001 (odd arguments: nothing can be vouched for)
        return UNREAD_SAVE
    # every other string the call writes or names (a description, a prompt field) is read for hosts and secrets too
    written = {st.text for st in texts}
    raw_written = {st.text for st in saved_texts(pending.raw)}
    others = list(
        dict.fromkeys(
            normalise(s)
            for s in _all_strings(pending.raw)
            if s.strip() and s not in raw_written and normalise(s) not in written
        )
    )
    plain = list(dict.fromkeys([*written, *others]))

    def rule(kind: str, check: Callable[[], bool], into: set[str] = adds) -> None:
        try:
            if check():
                into.add(kind)
        except Exception:  # noqa: BLE001 (a rule that fails cannot vouch for the text)
            into.add(kind)

    # fenced and inline code as narrowed for the report, every line of a script, and lines outside a recognised fence
    # that start like a command (an edit fragment's, or code the fence reading misses)
    steps: list[str] = []
    try:
        for r in reads:
            steps += saved_commands(r.st.text, store, r.fences)
            if not (
                exec_save and r is reads[0]
            ):  # an exec save's own command is the save, judged as the call
                steps += line_commands(r.st, outside_fences=True, found_fences=r.fences)
    except Exception:  # noqa: BLE001
        adds.add(COMMAND)
        held.add(RISKY_STEP)
    if steps:
        adds.add(COMMAND)
    candidates: list[str] = []
    findings: dict[str, list[Any]] = {}
    try:
        # an exec save's own command is the save itself, read as the target below; only code inside it is a step
        if exec_save and reads:
            candidates = list(dict.fromkeys([*reads[0].raw, *_candidates(reads[1:])]))
        else:
            candidates = _candidates(reads)
        # a description or a reason field, and a skill's front-matter description, naming a command in prose
        described = [front_matter_description(r.st.text) or "" for r in reads]
        for t in [*others, *described]:
            for c in prose_commands(t):
                if c not in candidates:
                    candidates.append(c)
        if len(candidates) <= MAX_CHECKED_COMMANDS:
            findings = _rule_findings(prepared, candidates)
    except Exception:  # noqa: BLE001
        adds.update((PERMISSION, DESTINATION))
        held.add(RISKY_STEP)
    # the command an exec save runs is the pending call itself, which the permission rules read as the target
    rule(PERMISSION, lambda: _permission(prepared, candidates, findings, exec_save=exec_save))
    shell = [command, *candidates] if exec_save else candidates
    rule(DESTINATION, lambda: _destination(prepared, reads, others, shell))
    rule(SECRET, lambda: _secret(plain))
    # a rule of any class on a step the save tells the agent to run (the skill steps' own findings are the rule-based
    # probe's; a memory note's steps and the lines that reading misses are checked here)
    told = list(dict.fromkeys([*steps, *(c for r in reads for c in r.listed)]))

    def risky() -> bool:
        if len(told) > MAX_CHECKED_COMMANDS:
            return True
        missing = [c for c in told if c not in findings]
        extra = _rule_findings(prepared, missing) if missing else {}
        return any(findings.get(c) or extra.get(c) for c in told)

    rule(RISKY_STEP, risky, held)
    rewrites = False
    try:
        pure, rewrites = removes(pending.raw, exec_command=command if exec_save else None)
        if pure:
            held.add(REMOVES)
    except Exception:  # noqa: BLE001
        held.add(REMOVES)
    rule(UNREAD, lambda: _unread(reads, store, pending.tool), held)
    rule(OUTSIDE_STORE, lambda: outside_store(prepared, store), held)
    return SaveReading(
        tuple(k for k in ADDS if k in adds), tuple(k for k in HELD if k in held), rewrites
    )
