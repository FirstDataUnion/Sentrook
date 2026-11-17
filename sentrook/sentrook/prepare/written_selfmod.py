"""Hosts in written self-modification content: where a later run that this call sets up sends to or runs code from.

A call that writes a cron line, a hook script, a startup file, a skill, a scheduled job's prompt or an automation
does not send or run anything itself, but the content it writes runs later, often with nobody watching: a host that
content fetches code from or sends to is a code source or a destination of that later run. Those roles are recorded
on the entity apart from its own roles (`Entity.future_roles`), so the call itself is never read as a send or a run;
the oracle and the context probe score them as the roles of a run the call schedules.

What counts as written self-modification content:

- a file write or edit into the agent's scheduler, skill, hook or config folders, a repository hook folder
  (`.git/hooks`, `.husky`, `.githooks`), or a host scheduler or startup file (the `agent_scheduler`, `agent_plugins`,
  `hooks`, `agent_config`, `host_scheduler` and `startup` path groups); a JSON or YAML file is read by key (command
  keys as shell, prompt and message keys as instructions); a `package.json` by its install lifecycle scripts; only
  the text the call writes, never the text an edit replaces;
- a scheduler, skill or config tool (the self-modification tool names) with a changing action: its command, script
  and argv fields as shell, its prompt, message, content and instruction fields as instructions;
- a shell command that installs a crontab, a systemd or launchd job, or writes into one of those files (a redirect,
  `tee`, an in-place `sed`), or that adds a job with the host's own cron or automation command: its quoted strings,
  heredoc bodies and unquoted `echo` text.

How the roles are read:

- shell text the host or the shell runs (a cron line, a hook or startup script, a unit, a job's command): a host the
  text fetches code from and runs (piped to a shell, downloaded then run, cloned then built, run through a command
  or process substitution, an inline `python -c` or `node -e` program that fetches and evaluates, PowerShell's
  download-and-invoke, or base64 decoded into a shell) is a code source; any other host a network client contacts
  (`curl`, `wget`, `ssh`, `nc`, ...) is a destination. Nobody scans that run, so a plain request counts. Cron
  schedule fields (and a system cron table's user field) are dropped first, comments are ignored, and a variable
  an earlier line sets is read where it is used.
- program text the host runs (a hook written in another language): every host its code names is a destination;
  hosts in its comments are not. A `hooks/` folder of the workspace's own code (a web app's hooks) is not a host
  hook.
- what the agent runs later through its own tools (a skill's commands and scripts): a fetch-and-run is a code source
  and a send of local data a destination: a file or standard input, a variable's value or a command substitution in
  a web client's arguments, an httpie file field, a copy, an `ssh` fed by a pipe, a `git push` to a URL, a raw
  socket. An API call with a literal body (a query, a POST with a key in its header) is a lookup, not charged now,
  since each command is scanned when the agent runs it.
- instruction text (a skill, a job prompt, an agent instruction file): its commands (fenced or inline code) as above,
  less those it tells the agent not to run, where the negated verb's object is the command itself ("do not run
  this:"); a negation of something else ("never run as root:") hides nothing. A sentence that tells the agent to
  fetch and run something, or to read or load something and follow or apply it, names a code source; one with a
  send verb (post, send, upload, report, share, copy, back up, sync, mail) before the host, or after it ("upload the
  logs there"), names a destination, and a mail address after such a verb a recipient. A host something comes from,
  and a pointer to reading matter right before the host ("see ... at", "docs at"), take no role.

Whether the owner's naming, a grant or the owner's configuration sanctions a later role is decided by relief, as for
the call's own roles (`converge.relief`): naming sanctions sending to a host, never running code from it.
"""

from __future__ import annotations

import json
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..aira.lists import Lists, load_lists
from ..planir.canonical import CanonicalCall
from ..planir.models import ToolKind
from .entities import (
    _EMAIL_RE,
    EntityKind,
    Found,
    Role,
    _hosts_in,
    extract_exec,
    normalise_path,
    normalise_recipient,
    pipes_into_code,
    shell_segments,
    shell_segments_sep,
)
from .skill_steps import (
    _COMMANDISH,
    _FENCE,
    _INLINE,
    _PROMPT,
    _fence_lines,
    patch_added_text,
    written_texts,
)


class Form(StrEnum):
    SHELL = "shell"
    PROGRAM = "program"
    PROSE = "prose"


@dataclass(frozen=True)
class WrittenText:
    text: str
    form: Form
    #: The host or the shell runs it (a cron line, a hook, a startup file), outside the agent's own scanned tool
    #: calls: every host it contacts is a destination. Otherwise (a skill's commands or scripts, which the agent runs
    #: through its tools) only a fetch-and-run is a code source and only a send (an upload, a POST, a raw socket) a
    #: destination.
    host_run: bool = True
    #: A system cron table (`/etc/crontab`, `/etc/cron.d/*`): each line names the user it runs as after the schedule.
    cron_user: bool = False


#: Path groups whose files hold content that runs or is followed later.
SELFMOD_GROUPS = (
    "agent_scheduler",
    "host_scheduler",
    "hooks",
    "startup",
    "agent_plugins",
    "agent_config",
)
#: Groups whose files are run by the host or the shell when not instruction text or a program.
_SHELL_GROUPS = frozenset({"agent_scheduler", "host_scheduler", "hooks", "startup"})
#: Suffixes of instruction text (skills, agent instruction files, hook descriptions).
_PROSE_SUFFIXES = (".md", ".markdown", ".txt", ".rst")
#: Suffixes of program text that is not shell.
_PROGRAM_SUFFIXES = (
    ".ts",
    ".js",
    ".mjs",
    ".cjs",
    ".py",
    ".rb",
    ".pl",
    ".go",
    ".rs",
    ".lua",
    ".php",
)
#: Suffixes of structured files whose string values are walked.
_STRUCTURED_SUFFIXES = (".json", ".jsonl", ".json5")
_YAML_SUFFIXES = (".yaml", ".yml")
#: System cron tables, whose lines carry a user field.
_SYSTEM_CRON = re.compile(r"^/etc/(?:crontab$|cron\.d/)")
#: Git hook folders a hook manager keeps in the repository, run by git like `.git/hooks`.
_REPO_HOOKS = re.compile(r"(?:^|/)\.(?:husky|githooks)/")
#: npm lifecycle scripts, which run on install with nobody asked.
_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

#: Arguments (and structured-file keys) that hold a command the job runs.
COMMAND_KEYS = frozenset({"command", "cmd", "script", "exec", "run", "shell", "execstart", "argv"})
#: Arguments (and structured-file keys) that hold instructions the agent follows later.
PROSE_KEYS = frozenset(
    {
        "prompt",
        "message",
        "text",
        "content",
        "instructions",
        "instruction",
        "task",
        "body",
        "description",
        "file_content",
        "new_text",
        "newtext",
        "new_string",
        "system_prompt",
        "payload",
    }
)
#: Self-modification reasons whose tool or command writes content that runs later. A memory note is not in scope.
_TOOL_REASONS = frozenset(
    {"selfmod.scheduler", "selfmod.plugin", "selfmod.config", "selfmod.hooks"}
)

#: Clients that contact the host named in their arguments.
NET_HEADS = frozenset(
    "curl wget http https xh httpie aria2c nc ncat netcat socat ssh scp sftp rsync ftp telnet git".split()
)
#: A cron line's schedule: five time fields, or a `@` nickname.
_CRON_SCHEDULE = re.compile(
    r"^\s*(?:@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    r"(?:[\d*?LW#/,-]+|[A-Za-z]{3}(?:[-,][A-Za-z]{3})*)(?:\s+(?:[\d*?LW#/,-]+|[A-Za-z]{3}(?:[-,][A-Za-z]{3})*)){4})"
    r"\s+"
)
#: A unit file's command line (`ExecStart=...`).
_UNIT_EXEC = re.compile(r"^\s*Exec\w*\s*=\s*[-@:+!]*", re.IGNORECASE)
#: A heredoc opener: `<<WORD`, `<<-WORD`, `<<'WORD'`, `<<"WORD"`.
_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
_WORD = re.compile(r"\w+")


def _heredocs(text: str) -> list[tuple[int, int, str]]:
    """Each heredoc in `text` as (start, end, body): what
    `<<-?\\s*(['"]?)(\\w+)\\1[^\\n]*\\n(.*?)\\n\\s*\\2\\s*(?:\\n|$)` (dot matching newlines) finds with
    `finditer`, in one pass. The body runs from the line after the opener to the first line that holds only the word
    (blank lines before it are not part of the body); an unquoted word with no such line falls back to its longest
    prefix that has one. The heredoc ends after the last newline before the next non-blank line."""
    if "<<" not in text:
        return []
    lines = text.split("\n")
    starts: list[int] = []
    at = 0
    for line in lines:
        starts.append(at)
        at += len(line) + 1
    blank = [not line.strip() for line in lines]
    prev_text: list[int] = []
    last = -1
    for i, empty in enumerate(blank):
        prev_text.append(last)
        if not empty:
            last = i
    next_text = [len(lines)] * len(lines)
    following = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        next_text[i] = following
        if not blank[i]:
            following = i
    ends: dict[str, list[int]] = {}
    for i, line in enumerate(lines):
        word = line.strip()
        if word and _WORD.fullmatch(word):
            ends.setdefault(word, []).append(i)
    lengths = sorted({len(w) for w in ends}, reverse=True)

    out: list[tuple[int, int, str]] = []
    pos = 0
    newline = -1
    while True:
        m = _HEREDOC_OPEN.search(text, pos)
        if m is None:
            break
        if newline < m.end():
            newline = text.find("\n", m.end())
        if newline < 0:
            break  # no line after this opener, nor after any later one
        first = bisect_left(starts, newline + 1)  # the body's first line
        quote, word = m.group(1), m.group(2)
        words = [word] if quote else [word[:n] for n in lengths if n <= len(word)]
        found: int | None = None
        for w in words:
            rows = ends.get(w)
            if rows:
                i = bisect_right(rows, first)
                if i < len(rows):
                    found = rows[i]
                    break
        if found is None:
            pos = m.start() + 1
            continue
        cut = max(prev_text[found], first)  # the body ends at the newline closing this line
        body = text[newline + 1 : starts[cut] + len(lines[cut])]
        after = next_text[found]
        end = len(text) if after >= len(lines) else starts[after]
        out.append((m.start(), end, body))
        pos = end
    return out


def _without_heredocs(text: str) -> str:
    parts: list[str] = []
    at = 0
    for start, end, _ in _heredocs(text):
        parts.append(text[at:start])
        parts.append(" ")
        at = end
    parts.append(text[at:])
    return "".join(parts)


_QUOTED = re.compile(r"'([^']*)'|\"((?:[^\"\\]|\\.)*)\"", re.S)

_CODE = re.compile(r"(?ms)^[ \t]*(```|~~~)[^\n]*\n.*?^[ \t]*\1[ \t]*$|`[^`\n]+`")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=\S)|\n+")


def written_selfmod_texts(
    call: CanonicalCall, *, home: str | None, workspace_root: str | None, lists: Lists | None = None
) -> list[WrittenText]:
    """The self-modification content `call` writes, each piece with how it is read. Empty for any other call."""
    lists = lists or load_lists()
    kind = call.tool_kind
    if kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT):
        return _file_texts(call, home=home, workspace_root=workspace_root, lists=lists)
    if kind in (ToolKind.MCP, ToolKind.OTHER):
        return _tool_texts(call, lists)
    if kind is ToolKind.EXEC:
        return _exec_texts(
            call.command or "", home=home, workspace_root=workspace_root, lists=lists
        )
    return []


def _groups(path: str, lists: Lists) -> list[str]:
    groups = [g for g in SELFMOD_GROUPS if g in lists.path_groups and lists.group(g).search(path)]
    if _REPO_HOOKS.search(path) and "hooks" not in groups:
        groups.append("hooks")
    return groups


def _form_of(path: str, groups: list[str]) -> Form | None:
    low = path.lower()
    if low.endswith(_PROSE_SUFFIXES):
        return Form.PROSE
    if low.endswith(_PROGRAM_SUFFIXES):
        return Form.PROGRAM
    if "agent_plugins" in groups and not low.endswith((".sh", ".bash", ".zsh")):
        if "." in low.rsplit("/", 1)[-1]:
            return None  # a skill's data or config file
    if _SHELL_GROUPS & set(groups):
        return Form.SHELL
    if "agent_plugins" in groups:
        # a script in a skill folder runs when the skill is used
        return Form.SHELL
    return None


def _file_texts(
    call: CanonicalCall, *, home: str | None, workspace_root: str | None, lists: Lists
) -> list[WrittenText]:
    path = call.path
    if not path:
        return []
    norm = normalise_path(path, home=home, workspace_root=workspace_root)
    texts = written_texts(call.raw)
    if not texts and isinstance(call.get("content"), str):
        texts = [call.get("content")]
    if not texts:
        return []
    if norm.rsplit("/", 1)[-1] == "package.json":
        return [w for t in texts for w in _lifecycle_scripts(t)]
    groups = _groups(norm, lists) or _groups(path, lists)
    if not groups:
        return []
    if norm.lower().endswith(_STRUCTURED_SUFFIXES + _YAML_SUFFIXES):
        out: list[WrittenText] = []
        for text in texts:
            out.extend(_structured(text, yaml_text=norm.lower().endswith(_YAML_SUFFIXES)))
        return out
    form = _form_of(norm, groups)
    if form is None:
        return []
    if (
        form is Form.PROGRAM
        and set(groups) <= {"hooks"}
        and _project_file(norm, home, workspace_root)
    ):
        return []  # a `hooks/` folder of a project's own code (a web app's hooks), not a host hook
    host_run = bool(_SHELL_GROUPS & set(groups))
    cron_user = bool(_SYSTEM_CRON.search(norm))
    return [WrittenText(t, form, host_run, cron_user) for t in texts if t.strip()]


def _lifecycle_scripts(text: str) -> list[WrittenText]:
    """npm lifecycle scripts a `package.json` sets: they run on the next install, as shell."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    scripts = doc.get("scripts") if isinstance(doc, dict) else None
    if not isinstance(scripts, dict):
        return []
    return [
        WrittenText(v, Form.SHELL)
        for k in _LIFECYCLE_SCRIPTS
        if isinstance(v := scripts.get(k), str) and v.strip()
    ]


def _project_file(path: str, home: str | None, workspace_root: str | None) -> bool:
    """Under the workspace and not in a host's or git's own hook folder."""
    if re.search(r"(?:^|/)\.(?:git|openclaw|hermes)/", path):
        return False
    ws = normalise_path(workspace_root, home=home, workspace_root=None) if workspace_root else None
    return bool(ws) and path.startswith(ws.rstrip("/") + "/")


def _structured(text: str, *, yaml_text: bool = False) -> list[WrittenText]:
    """The string values of a JSON or YAML document: command keys as shell, instruction keys as prose. A document
    that does not parse is read as instructions."""
    try:
        if yaml_text:
            import yaml

            doc = yaml.safe_load(text)
        else:
            doc = json.loads(text)
    except Exception:  # noqa: BLE001 (a fragment or a broken file is still text)
        return [WrittenText(text, Form.PROSE)] if text.strip() else []
    out: list[WrittenText] = []
    _walk(doc, None, out)
    return out


def _walk(node: Any, key: str | None, out: list[WrittenText]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, str(k), out)
    elif isinstance(node, list):
        if (
            key is not None
            and key.lower() in COMMAND_KEYS
            and all(isinstance(v, str) for v in node)
        ):
            out.append(WrittenText(_join_argv(node), Form.SHELL))
            return
        for v in node:
            _walk(v, key, out)
    elif isinstance(node, str) and node.strip() and key is not None:
        k = key.lower().replace("-", "_")
        if k in COMMAND_KEYS:
            out.append(WrittenText(node, Form.SHELL))
        elif k in PROSE_KEYS:
            out.append(WrittenText(node, Form.PROSE))


def _join_argv(argv: list[str]) -> str:
    """An argument vector as one shell command; `sh -c CODE` is the code it runs."""
    import shlex

    if (
        len(argv) >= 3
        and argv[0].rsplit("/", 1)[-1] in ("sh", "bash", "zsh", "dash")
        and argv[1] == "-c"
    ):
        return argv[2]
    return shlex.join(argv)


def _tool_reason(call: CanonicalCall, lists: Lists) -> str | None:
    action = call.raw.get("action")
    if isinstance(action, str) and action.strip().lower() in {
        a.lower() for a in lists.strings("selfmod", "read_actions")
    }:
        return None
    prefix = str(lists.get("selfmod", "tool_name_prefix", default=r"(?:\A|__|[.:/])"))
    for rule in lists.rules("selfmod", "tool_names"):
        if re.search(prefix + rule.regex.pattern, call.tool or "", re.IGNORECASE):
            return str(rule.get("reason"))
    return None


def _tool_texts(call: CanonicalCall, lists: Lists) -> list[WrittenText]:
    if _tool_reason(call, lists) not in _TOOL_REASONS:
        return []
    out: list[WrittenText] = []
    seen: set[tuple[str, Form]] = set()

    def add(text: str, form: Form) -> None:
        if text.strip() and (text, form) not in seen:
            seen.add((text, form))
            out.append(WrittenText(text, form))

    def take(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            key = str(k).lower().replace("-", "_")
            if isinstance(v, str):
                if key in COMMAND_KEYS:
                    add(v, Form.SHELL)
                elif key in PROSE_KEYS:
                    add(v, Form.PROSE)
                elif key == "input" and "\n+" in v:
                    add(patch_added_text(v), Form.PROSE)
            elif isinstance(v, dict):
                take(v)
            elif isinstance(v, list):
                if key in COMMAND_KEYS and v and all(isinstance(i, str) for i in v):
                    add(_join_argv(v), Form.SHELL)
                    continue
                for item in v:
                    take(item)

    take(call.raw)
    for text in written_texts(call.raw):
        add(text, Form.PROSE)
    return out


#: Host persistence commands whose input is a cron table or a unit (read as shell).
_HOST_JOB_CLI = re.compile(r"\b(?:crontab|systemctl|launchctl|at|batch)\b")
#: A cron table read from standard input (`... | crontab -`, `crontab - <<EOF`).
_CRONTAB_STDIN = re.compile(r"\|\s*(?:sudo\s+)?crontab\b|\bcrontab\s+-(?=\s|$|[;&|)])")
#: The host's own job commands, whose quoted text is the job's prompt or message (read as instructions).
_AGENT_JOB_CLI = re.compile(
    r"\b(?:openclaw|hermes)\s+(?:cron|automations?|schedules?|jobs?|heartbeats?|hooks?)\s+"
    r"(?:add|create|new|set|enable|update|edit)\b"
)


def _exec_texts(
    command: str, *, home: str | None, workspace_root: str | None, lists: Lists
) -> list[WrittenText]:
    if not command.strip():
        return []
    form: Form | None = None
    rest = _without_heredocs(command)
    cli = [str(r.get("reason")) for r in lists.rules("selfmod", "cli") if r.regex.search(rest)]
    if _AGENT_JOB_CLI.search(rest):
        form = Form.PROSE
    elif ("selfmod.scheduler" in cli and _HOST_JOB_CLI.search(rest)) or _CRONTAB_STDIN.search(rest):
        form = Form.SHELL
    host_run = True
    if form is None:
        targets = _write_targets(rest)
        for t in targets:
            groups = _groups(normalise_path(t, home=home, workspace_root=workspace_root), lists)
            if groups:
                form = _form_of(t, groups) or Form.SHELL
                host_run = bool(_SHELL_GROUPS & set(groups))
                break
    if form is None:
        return []
    bodies = [body for _, _, body in _heredocs(command)]
    for m in _QUOTED.finditer(rest):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if body and _hosts_in(body):
            bodies.append(_SED_APPEND.sub("", body.replace('\\"', '"'), count=1))
    for m in _UNQUOTED_ECHO.finditer(rest):
        if _hosts_in(m.group(1)):
            bodies.append(m.group(1))
    cron_user = any(_SYSTEM_CRON.search(t) for t in _write_targets(rest))
    return [WrittenText(b, form, host_run, cron_user) for b in dict.fromkeys(bodies) if b.strip()]


#: A sed script that appends or inserts a line (`$a text`, `1i\ text`): the line is the text.
_SED_APPEND = re.compile(r"^\s*(?:(?:\$|\d+|/[^/]*/)\s*[aic]\\?\s*|[aic]\\\s*)")
#: An unquoted `echo` or `printf` redirected into a file: what it writes.
_UNQUOTED_ECHO = re.compile(r"\b(?:echo|printf)\s+(?:-[neE]+\s+)?([^'\"<>|;&\n]+?)\s*>>?\s*\S+")


_REDIRECT = re.compile(r"(?<![<>&\d])>{1,2}\s*([^\s;&|<>]+)")


def _write_targets(command: str) -> list[str]:
    """Files a command writes by redirect, `tee` or an in-place `sed`."""
    out = [m.group(1).strip("'\"") for m in _REDIRECT.finditer(command)]
    for tokens in shell_segments(command):
        if tokens[0] == "tee":
            out.extend(t for t in tokens[1:] if not t.startswith("-"))
    for m in _SED_IN_PLACE.finditer(command):
        # the file is the last word of the command: the script before it may hold a `|` the split above cuts at
        out.append(m.group(1).strip("'\""))
    return out


_SED_IN_PLACE = re.compile(
    r"\bsed\s+(?:-\w+\s+)*(?:-i\S*|--in-place\S*)\s.*\s(\S+)\s*(?:$|[;&])", re.S
)


# --------------------------------------------------------------------------- roles


def future_entities(
    texts: list[WrittenText], *, home: str | None, workspace_root: str | None
) -> list[Found]:
    """The hosts and repositories the written content's later run sends to (`data_destination`) or runs code from
    (`code_source`)."""
    out: dict[tuple[EntityKind, str, Role], Found] = {}

    def add(found: list[Found]) -> None:
        for f in found:
            if f.role is not None:
                out.setdefault((f.kind, f.value, f.role), f)

    for wt in texts:
        if wt.form is Form.SHELL:
            add(
                _shell_roles(
                    wt.text,
                    home=home,
                    workspace_root=workspace_root,
                    contacts=wt.host_run,
                    cron_user=wt.cron_user,
                )
            )
        elif wt.form is Form.PROGRAM:
            code = _strip_comments(wt.text)
            program_lines = (
                [code] if wt.host_run else [ln for ln in code.splitlines() if _sends_local(ln)]
            )
            add(
                [
                    Found(EntityKind.HOST, h, h, Role.DATA_DESTINATION)
                    for line in program_lines
                    for h in _hosts_in(line, inline_program=True, emails=False)
                    if not _local(h)
                ]
            )
        else:
            add(_prose_roles(wt.text, home=home, workspace_root=workspace_root))
    return list(out.values())


def _local(host: str) -> bool:
    from ..oracle.client import is_local_host

    return is_local_host(host)


_COMMENTS = re.compile(r"/\*.*?\*/|(?:^|(?<=\s))(?://|#(?!!))[^\n]*", re.S | re.M)


def _strip_comments(code: str) -> str:
    """Program text without its comments (`/* */`, `//` and `#` to the end of a line; never a `://` in a URL)."""
    return _COMMENTS.sub(" ", code)


def _shell_lines(text: str, *, cron_user: bool = False) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = pending + line
        pending = ""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _UNIT_EXEC.match(stripped):
            stripped = _UNIT_EXEC.sub("", stripped, count=1)
        elif (
            re.match(r"^[A-Z_][A-Z0-9_]*=", stripped)
            and " " not in stripped.split("=", 1)[1].strip()
            and "/" not in stripped.split("=", 1)[1]
        ):
            continue  # a variable line of a cron table (`MAILTO=...`)
        else:
            m = _CRON_SCHEDULE.match(stripped)
            if m:
                stripped = stripped[m.end() :]
                if cron_user:
                    # a system cron table names the user next: exactly one field
                    stripped = stripped.split(None, 1)[1] if " " in stripped.strip() else ""
                elif re.match(r"root\s+\S", stripped):
                    stripped = stripped[4:].lstrip()  # a system line written into a user's table
        if stripped:
            lines.append(stripped)
    if pending.strip():
        lines.append(pending.strip())
    return lines


_VAR_LINE = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=(['\"]?)([^\s'\"]+)\2\s*;?\s*$"
)


def _resolve_vars(lines: list[str]) -> list[str]:
    """Lines with the values of variables an earlier line sets (`U=https://...`) written in where they are used."""
    values: dict[str, str] = {}
    out: list[str] = []
    for line in lines:
        m = _VAR_LINE.match(line)
        if m:
            values[m.group(1)] = m.group(3)
            out.append(line)
            continue
        for name, value in values.items():
            line = re.sub(r"\$\{" + name + r"\}|\$" + name + r"\b", lambda _m, v=value: v, line)
        out.append(line)
    return out


#: A fetch whose output a shell runs through a substitution: `sh -c "$(curl ...)"`, `bash <(curl ...)`,
#: `eval "$(wget -qO- ...)"`, `source <(curl ...)`.
_SUBST_RUN = re.compile(
    r"(?:\b(?:ba|z|k|da|fi)?sh|\beval|\bsource|(?:^|[\s;&|(])\.)\s+(?:-\w+\s+)*[\"']?(?:\$\(|`|<\()\s*"
    r"(?:\S+/)?(?:curl|wget|fetch)\b"
)
#: An inline program (`python3 -c`, `node -e`, ...) that both fetches and runs what it fetched.
_INLINE_PROGRAM = re.compile(
    r"\b(?:python[23]?|node|deno|bun|perl|ruby|php)\s+(?:-\w+\s+)*(?:-c|-e|-E|-r|--eval)\b", re.I
)
_PROGRAM_FETCH = re.compile(
    r"\b(?:urlopen|urllib|requests\.get|http\.get|https\.get|fetch\(|LWP|open-uri|Net::HTTP|file_get_contents"
    r"|httpx\.get)",
    re.I,
)
_PROGRAM_RUN = re.compile(r"\b(?:exec|eval|Function|system|spawn|execSync|import\()", re.I)
#: PowerShell's download-and-run: `iwr URL | iex`, `IEX (New-Object Net.WebClient).DownloadString(URL)`.
_PWSH_FETCH = re.compile(
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient)\b",
    re.I,
)
_PWSH_RUN = re.compile(r"\b(?:iex|invoke-expression|start-process)\b", re.I)


def _runs_fetched(line: str) -> bool:
    """The line fetches code and runs it by a route the pipe check does not read."""
    if _SUBST_RUN.search(line):
        return True
    if _INLINE_PROGRAM.search(line) and _PROGRAM_FETCH.search(line) and _PROGRAM_RUN.search(line):
        return True
    return bool(_PWSH_FETCH.search(line) and _PWSH_RUN.search(line))


#: A send that carries local data: a file or standard input (`@file`, `@-`, `-T`, `<`), a variable's value in the
#: request body, or a file-copy or raw-socket client. A request whose body is a literal (an API query) is a lookup.
_LOCAL_SEND = re.compile(
    r"(?:\s|^)(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?|--json|-F|--form(?:-string)?|--post-data|--body-data)"
    r"(?:\s+|=)[^\s]*?(?:@|\$|<)"
    r"|(?:\s|^)(?:-T|--upload-file|--post-file|--body-file)(?:\s|=)"
    r"|(?:\s|^)<\s*[~/$.\w]"
    r"|\b(?:scp|rsync|sftp|nc|ncat|netcat|socat)\b|/dev/(?:tcp|udp)/"
    r"|requests\.(?:post|put|patch)\([^)]*(?:open\(|environ|getenv)|readFileSync|process\.env",
    re.I,
)


#: wget's combined short flags ending in `O` (`-qO FILE`), split so the download parser reads the file.
_WGET_COMBINED_O = re.compile(r"\bwget\s+((?:-\S+\s+)*?)-([A-Za-z]+)O(?=\s)")


def _sends_local(text: str) -> bool:
    return bool(_LOCAL_SEND.search(text))


#: httpie's file fields: `file@path` (a form upload) and `key=@path` / `key:=@path` (a field read from a file).
_HTTPIE_FILE = re.compile(r"^[\w.-]+(?::?=)?@\S")
_HTTP_HEADS = frozenset({"curl", "wget", "http", "https", "xh", "httpie"})


def _segment_sends_local(sep: str, tokens: list[str], seg: str) -> bool:
    """A segment of shell text sends local data: `_sends_local`, a command substitution in a web client's arguments
    (a header, a query or a body built from local output), an httpie file field, an `ssh` fed by a pipe, or a
    `git push` to a remote written as a URL."""
    head = tokens[0].rsplit("/", 1)[-1]
    if _sends_local(seg):
        return True
    if head in _HTTP_HEADS and re.search(r"\$\(|`", seg):
        return True
    if head in ("http", "https", "xh", "httpie") and any(_HTTPIE_FILE.match(t) for t in tokens[1:]):
        return True
    if head == "ssh" and sep == "|":
        return True
    return head == "git" and "push" in tokens[1:] and bool(_hosts_in(seg, emails=False))


def _shell_roles(
    text: str,
    *,
    home: str | None,
    workspace_root: str | None,
    contacts: bool = True,
    cron_user: bool = False,
) -> list[Found]:
    """Code sources and destinations of shell text. With `contacts`, every host a network client contacts is a
    destination; without it, only a host the text sends local data to (a file, standard input, a variable's value,
    a copy or a raw socket). Base64 the text decodes is read too."""
    from ..aira.normalize import normalise_text

    lines = [
        _WGET_COMBINED_O.sub(r"wget \1-\2 -O ", line)
        for line in _resolve_vars(_shell_lines(text, cron_user=cron_user))
    ]
    if not lines:
        return []
    decoded = [d for d in (normalise_text(line) for line in lines) if d not in lines]
    lines = lines + decoded
    whole = "\n".join(lines)
    out: list[Found] = []
    try:
        found = extract_exec(whole, home=home, workspace_root=workspace_root, cwd=None)
    except Exception:  # noqa: BLE001 (an odd script must not fail the scan)
        found = []
    code = {f.value for f in found if f.role is Role.CODE_SOURCE and f.kind is EntityKind.HOST}
    for f in found:
        if f.role is Role.CODE_SOURCE and f.kind in (EntityKind.HOST, EntityKind.REPO):
            out.append(f)
    for line in decoded:
        # encoded text decoded and handed to a shell or interpreter runs what it fetches
        if pipes_into_code(line):
            for h in _hosts_in(line, emails=False):
                if h not in code and not _local(h):
                    code.add(h)
                    out.append(Found(EntityKind.HOST, h, h, Role.CODE_SOURCE))
    for line in lines:
        if _runs_fetched(line):
            for h in _hosts_in(line, inline_program=True, emails=False):
                if h not in code and not _local(h):
                    code.add(h)
                    out.append(Found(EntityKind.HOST, h, h, Role.CODE_SOURCE))
    contacted: set[str] = set()
    for line in lines:
        for sep, tokens in shell_segments_sep(line):
            seg = " ".join(tokens)
            if not contacts and not _segment_sends_local(sep.strip(), tokens, seg):
                continue
            if (
                tokens[0].rsplit("/", 1)[-1] in NET_HEADS
                or "/dev/tcp/" in seg
                or "/dev/udp/" in seg
            ):
                contacted.update(_hosts_in(seg, emails=False))
    for h in sorted(contacted - code):
        if not _local(h):
            out.append(Found(EntityKind.HOST, h, h, Role.DATA_DESTINATION))
    return out


#: An explicit instruction not to run or send: a warning word alone ("never skip", "to avoid", "not installed")
#: never hides a command.
_DONT = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|mustn'?t|should\s+not|shouldn'?t)\s+(?:ever\s+)?(?:\w+\s+)??"
    r"(?:run|execute|exec|use|type|paste|call|invoke|install|source|eval|download|fetch|curl|wget|post|send|"
    r"upload|forward|submit|push|ping|pipe|share|report)\b",
    re.I,
)


#: A negation whose object is the command that follows: "do not run this:", "never paste the following". Only words
#: that point at the command may come between the verb and the end of the clause.
_DONT_THIS = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|mustn'?t|should\s+not|shouldn'?t)\s+(?:ever\s+)?"
    r"(?:run|execute|exec|use|type|paste|call|invoke|try|copy)"
    r"(?:\s+(?:this|these|that|those|it|them|the|following|below|above|command|commands|line|lines|snippet|script|"
    r"anything|like|one))*\s*:?\s*$",
    re.I,
)
#: Where a clause ends for a negation: punctuation or "instead".
_CLAUSE_BREAK = re.compile(r"[,.;!?]|\binstead\b", re.I)


def _clause_before(text: str, at: int) -> str:
    """The clause that introduces a command at `at`: the text before it on its line, or the last non-empty line
    before it when the command starts its own line, cut after the last clause break."""
    start = text.rfind("\n", 0, at) + 1
    same = text[start:at]
    if not same.strip():
        prev = text[:start].rstrip()
        same = prev[prev.rfind("\n") + 1 :]
    colon = same.rstrip().endswith(":")
    tail = _CLAUSE_BREAK.split(same.rstrip().rstrip(":"))[-1]
    return tail + (":" if colon else "")


def _commands(text: str) -> list[str]:
    """The commands in instruction text (fenced blocks and inline code that reads as a command), less those the
    text tells the agent not to run: only a negation whose object is the command itself drops one."""
    found: dict[str, None] = {}

    def add(cmd: str, before: str) -> None:
        if _COMMANDISH.match(cmd) and not _DONT_THIS.search(before):
            found.setdefault(cmd, None)

    for m in _FENCE.finditer(text):
        before = _clause_before(text, m.start())
        for line in _fence_lines(m.group(2)):
            add(line, before)
    without_fences = _FENCE.sub(lambda m: " " * len(m.group(0)), text)
    for m in _INLINE.finditer(without_fences):
        add(_PROMPT.sub("", m.group(1)).strip(), _clause_before(without_fences, m.start()))
    return list(found)


_SEND_VERB = (
    r"(?:post|send|upload|forward|submit|transmit|exfiltrate|beacon|deliver|push|leak|report|share|sync|mirror|"
    r"copy|ping|e-?mail|mail)(?:s|ed|ing)?|back(?:s|ed|ing)?[\s-]?up"
)
_SEND = re.compile(rf"\b(?:{_SEND_VERB})\b", re.I)
#: The host is where something comes from, not where it goes ("copy the example from URL").
_FROM_HOST = re.compile(r"\b(?:from|of|off)\s*$", re.I)
#: "URL ...: upload the logs there": the host first, the send after.
_SEND_THERE = re.compile(rf"\b(?:{_SEND_VERB})\b[^.]*\b(?:there|to\s+it|to\s+that\b)", re.I)
#: A pointer to reading matter right before the host: "see ... at URL", "docs at URL", "reference: URL".
_DOC_LEAD = re.compile(
    r"\b(?:see|docs?|documentation|reference|guide|details|read\s+more|learn\s+more)\b[^.]{0,60}?"
    r"\b(?:at|on|in|here)\s*[:(]?\s*$"
    r"|\b(?:see|docs?|documentation|reference|guide|details)\s*[:(\[]?\s*$",
    re.I,
)
#: Fetching and running, before or around the host.
_FETCH_VERB = r"(?:download|fetch|get|grab|pull|retrieve|curl|wget|read|open|visit|load|check)"
_RUN_VERB = r"(?:run|execute|exec|install|source|eval|launch|bash|sh)"
_RUN_FROM = re.compile(
    rf"\b{_RUN_VERB}\b[^.]*\b(?:from|at|hosted\s+(?:at|on))\s*$"
    rf"|\b(?:pipe|feed)\b.*\b(?:to|into)\s+(?:a\s+)?(?:shell|bash|sh|python|node)\b",
    re.I,
)
_RUN_AFTER = re.compile(
    rf"\b(?:and|then|&&)\b[^.]*\b{_RUN_VERB}\b"
    r"|\b(?:and|then)\b[^.]*\b(?:follow|obey|apply|carry\s+out|do\s+what)\b",
    re.I,
)


def _prose_roles(text: str, *, home: str | None, workspace_root: str | None) -> list[Found]:
    out: list[Found] = []
    commands = _commands(text)
    if commands:
        out.extend(
            _shell_roles(
                "\n".join(commands), home=home, workspace_root=workspace_root, contacts=False
            )
        )
    # the commands were read above: the sentences are the words around them
    words = _CODE.sub(lambda m: " " * len(m.group(0)), text)
    for sentence in _SENTENCE.split(words):
        if not sentence.strip():
            continue
        for host in _hosts_in(sentence, emails=False):
            if _local(host):
                continue
            at = _position(sentence, host)
            if at < 0:
                continue
            # the words before the token that names the host (a URL's scheme is part of that token)
            before = re.sub(r"\S*$", "", sentence[:at])
            after = sentence[at:].split(None, 1)[1] if " " in sentence[at:] else ""
            if _DONT.search(_CLAUSE_BREAK.split(before)[-1]):
                continue
            fetch_before = re.search(rf"\b{_FETCH_VERB}\b", before, re.I)
            if _RUN_FROM.search(before) or (fetch_before and _RUN_AFTER.search(after)):
                out.append(Found(EntityKind.HOST, host, host, Role.CODE_SOURCE))
            elif (
                not _DOC_LEAD.search(before)
                and not _FROM_HOST.search(before)
                and (_SEND.search(before) or (not before.strip() and _SEND_THERE.search(after)))
            ):
                out.append(Found(EntityKind.HOST, host, host, Role.DATA_DESTINATION))
        # mail to an address the text names: the address is a recipient of the later run
        for m in _EMAIL_RE.finditer(sentence):
            before = sentence[: m.start()]
            if _SEND.search(before) and not _DONT.search(_CLAUSE_BREAK.split(before)[-1]):
                addr = normalise_recipient(m.group(1))
                out.append(Found(EntityKind.RECIPIENT, addr, addr, Role.RECIPIENT))
    return out


def _position(text: str, host: str) -> int:
    m = re.search(r"(?<![\w-])" + re.escape(host) + r"(?![\w-])", text, re.IGNORECASE)
    return m.start() if m else -1
