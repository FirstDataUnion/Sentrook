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
  heredoc bodies and unquoted `echo` text;
- a Python program the command runs (`python3 -c`, or a heredoc fed to `python3 -`) that writes one of those files
  (`open(..., "w"|"a")`, `Path.write_text`): its string literals, read as that file's content;
- a config field set with the host's `config set` command or a config tool (`{key, value}`): a command field as
  shell, a prompt or message field as instructions, a JSON value walked by its keys;
- a git setting git runs later (an alias or a credential helper with a leading `!`, `core.fsmonitor`,
  `core.sshCommand`, `core.pager`), set with `git config` or written into a git config file;
- the command a `systemd-run` timer (`--on-calendar` and the like) runs;
- a file an earlier step that ran (or a sibling call in the batch) wrote, put into one of those files by `cp`, `mv`,
  `install`, `rsync` or `cat >`, installed with `crontab FILE`, or run by shell content the host runs
  (`sh /tmp/x.sh`): read as that content, with the origin of the call that wrote it. A scheduler tool naming such a
  script is read as running it now (`prepare._scheduled_scripts`), not again here.

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

import ast
import json
import re
import shlex
from bisect import bisect_left, bisect_right
from collections.abc import Callable
from dataclasses import dataclass, replace
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
    #: The text is a file another call wrote, which this call puts in place or runs (`PlantedFile`).
    planted: PlantedFile | None = None


@dataclass(frozen=True)
class PlantedFile:
    """A file an earlier step that ran, or a sibling call in the batch, wrote: its content and which call wrote it
    (`ref`: `step:N` for a step, the call id for a sibling)."""

    content: str
    ref: str | None
    sibling: bool = False


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
        "markdown",
        "skill_md",
        "file_text",
    }
)
#: Self-modification reasons whose tool or command writes content that runs later. A memory note is not in scope.
_TOOL_REASONS = frozenset(
    {"selfmod.scheduler", "selfmod.plugin", "selfmod.config", "selfmod.hooks"}
)

#: Clients that contact the host named in their arguments.
NET_HEADS = frozenset(
    "curl wget http https xh httpie aria2c nc ncat netcat socat ssh scp sftp rsync ftp telnet git "
    "iwr irm invoke-webrequest invoke-restmethod".split()
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


#: What an earlier call of the session (or a sibling in the batch) wrote at a normalised path, or None.
Planted = Callable[[str], "PlantedFile | None"]
#: Planted files read for one call at most.
MAX_PLANTED = 8


def written_selfmod_texts(
    call: CanonicalCall,
    *,
    home: str | None,
    workspace_root: str | None,
    lists: Lists | None = None,
    planted: Planted | None = None,
) -> list[WrittenText]:
    """The self-modification content `call` writes, each piece with how it is read. Empty for any other call.

    `planted` gives the content another call wrote at a path: a copy of that file into a hook or startup file, a
    crontab installed from it, and shell content the host runs that runs it are read through it."""
    lists = lists or load_lists()
    kind = call.tool_kind
    if kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT):
        texts = _file_texts(call, home=home, workspace_root=workspace_root, lists=lists)
    elif kind in (ToolKind.MCP, ToolKind.OTHER):
        texts = _tool_texts(call, lists)
    elif kind is ToolKind.EXEC:
        texts = _exec_texts(
            call.command or "",
            home=home,
            workspace_root=workspace_root,
            lists=lists,
            planted=planted,
        )
    else:
        return []
    # A scheduler tool that names a script the agent wrote already runs that file in this call's lineage (its hosts
    # take the roles of a run now), so it is not read again as a later run.
    scheduler = (
        kind in (ToolKind.MCP, ToolKind.OTHER) and _tool_reason(call, lists) == "selfmod.scheduler"
    )
    if planted is not None and texts and not scheduler:
        texts = texts + _planted_runs(
            texts, home=home, workspace_root=workspace_root, planted=planted
        )
    return texts


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
    return [
        w
        for t in texts
        for w in _path_texts(
            norm, t, home=home, workspace_root=workspace_root, lists=lists, raw=path
        )
    ]


def _path_texts(
    norm: str,
    text: str,
    *,
    home: str | None,
    workspace_root: str | None,
    lists: Lists,
    raw: str | None = None,
) -> list[WrittenText]:
    """How `text` written to the file at `norm` (a normalised path; `raw` as the call spells it) is read: empty for
    a file that holds no self-modification content."""
    if not text.strip():
        return []
    if norm.rsplit("/", 1)[-1] == "package.json":
        return _lifecycle_scripts(text)
    if _GITCONFIG.search(norm):
        return _gitconfig_texts(text)
    groups = _groups(norm, lists) or (_groups(raw, lists) if raw else [])
    if not groups:
        return []
    low = norm.lower()
    if low.endswith(_STRUCTURED_SUFFIXES + _YAML_SUFFIXES):
        return _structured(text, yaml_text=low.endswith(_YAML_SUFFIXES))
    if low.endswith(".pth"):
        return _pth_texts(text)
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
    return [WrittenText(text, form, host_run, cron_user)]


#: git's own configuration files, whose aliases and command settings git runs later.
_GITCONFIG = re.compile(r"(?:^|/)(?:\.gitconfig(?:\.local)?|\.git/config|\.config/git/config)$")
#: git settings whose value is a command git runs; an alias or a credential helper only with a leading `!`.
_GIT_COMMAND_KEY = re.compile(
    r"^(?:core\.(?:fsmonitor|sshcommand|pager)|filter\..+\.(?:smudge|clean|process))$"
)
_GIT_BANG_KEY = re.compile(r"^(?:alias\..+|credential\.(?:.+\.)?helper)$")


def _git_value(key: str, value: str) -> list[WrittenText]:
    """A git setting's value as shell when git runs it: an alias or a credential helper with a leading `!`,
    `core.fsmonitor`, `core.sshCommand`, `core.pager`, a filter's `smudge`, `clean` or `process` command."""
    key, value = key.strip().lower(), value.strip()
    if _GIT_BANG_KEY.match(key):
        return (
            [WrittenText(value[1:], Form.SHELL)]
            if value.startswith("!") and value[1:].strip()
            else []
        )
    if _GIT_COMMAND_KEY.match(key) and value:
        return [WrittenText(value, Form.SHELL)]
    return []


_GIT_SECTION = re.compile(r'^\[\s*([^\]\s"]+)(?:\s+"([^"]*)")?\s*\]')


def _gitconfig_texts(text: str) -> list[WrittenText]:
    """The command settings (`_git_value`) of a git configuration file."""
    out: list[WrittenText] = []
    section = ""
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        m = _GIT_SECTION.match(s)
        if m:
            section = m.group(1).lower() + (f".{m.group(2)}" if m.group(2) else "")
            continue
        if "=" in s and section:
            k, v = s.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
            out.extend(_git_value(f"{section}.{k.strip()}", v))
    return out


def _selfmod_file(norm: str, raw: str, lists: Lists) -> bool:
    """Whether a write to the file can hold self-modification content (`_path_texts` may read it)."""
    return bool(
        norm.rsplit("/", 1)[-1] == "package.json"
        or _GITCONFIG.search(norm)
        or _groups(norm, lists)
        or _groups(raw, lists)
    )


def _pth_texts(text: str) -> list[WrittenText]:
    """A `.pth` file in a Python package folder: its `import` lines run as Python whenever an interpreter starts; its
    other lines are paths."""
    code = [ln for ln in text.splitlines() if re.match(r"import[ \t]", ln)]
    return [WrittenText("\n".join(code), Form.PROGRAM)] if code else []


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


def _snake(name: str) -> str:
    """A key in snake case: `systemPrompt` and `system-prompt` read as `system_prompt`."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower().replace("-", "_")


def _walk(node: Any, key: str | None, out: list[WrittenText]) -> None:
    if isinstance(node, dict):
        cmd, args = node.get("command"), node.get("args")
        if (
            isinstance(cmd, str)
            and isinstance(args, list)
            and all(isinstance(a, str) for a in args)
        ):
            # a server or job started as `command` with `args` (an MCP stdio server): one command line
            out.append(WrittenText(_join_argv([cmd, *args]), Form.SHELL))
            node = {k: v for k, v in node.items() if k not in ("command", "args")}
        for k, v in node.items():
            _walk(v, str(k), out)
    elif isinstance(node, list):
        k = _snake(key) if key is not None else None
        if k is not None and all(isinstance(v, str) for v in node):
            if k in COMMAND_KEYS:
                out.append(WrittenText(_join_argv(node), Form.SHELL))
                return
            if k == "args" and "-c" in node[:-1]:
                # a shell's arguments on their own: the program after `-c`
                out.append(WrittenText(node[node.index("-c") + 1], Form.SHELL))
                return
        for v in node:
            _walk(v, key, out)
    elif isinstance(node, str) and node.strip() and key is not None:
        k = _snake(key)
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
        # a config tool's `{key: "a.b.command", value: ...}`: the value is read by the field the key names
        name = next((obj[k] for k in _CONFIG_NAME_KEYS if isinstance(obj.get(k), str)), None)
        if name is not None and "value" in obj:
            for w in _config_value(name, obj["value"]):
                add(w.text, w.form)
        for k, v in obj.items():
            key = _snake(str(k))
            if isinstance(v, str) and key in NESTED_JSON_KEYS:
                try:
                    v = json.loads(v)  # a list of edits passed as a JSON string
                except ValueError:
                    continue
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


#: A config tool's argument that names the field it sets.
_CONFIG_NAME_KEYS = ("key", "path", "setting", "field", "name")
#: Arguments that hold a list of edits, which a tool may take as a JSON string.
NESTED_JSON_KEYS = frozenset({"operations", "edits"})


def _field_name(path: str) -> str:
    """The last field of a dotted config path (`mcp.servers.x.command`, `hooks[0].systemPrompt`), in snake case."""
    parts = [p for p in re.split(r"[.\[\]/]+", path) if p and not p.isdigit()]
    return _snake(parts[-1]) if parts else ""


def _config_value(path: str, value: Any) -> list[WrittenText]:
    """A config field's new value: shell when the field holds a command, instructions when it holds a prompt or a
    message; a JSON object or list is walked by its own keys."""
    leaf = _field_name(path)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in '[{"':
            try:
                value = json.loads(stripped)
            except ValueError:
                pass
    out: list[WrittenText] = []
    if isinstance(value, (dict, list)):
        _walk(value, leaf, out)
    elif isinstance(value, str) and value.strip():
        if leaf in COMMAND_KEYS:
            out.append(WrittenText(value, Form.SHELL))
        elif leaf in _CONFIG_PROSE_KEYS:
            out.append(WrittenText(value, Form.PROSE))
    return out


#: Config fields whose text the agent follows: a prompt or a job's message. A description or a label is shown, not
#: followed.
_CONFIG_PROSE_KEYS = frozenset(
    {"prompt", "system_prompt", "instructions", "instruction", "message", "task", "persona"}
)


#: Launchers that run the command after them: `sudo`, `env`, `npx`, `uv run`, `pnpm exec` and the like.
_LAUNCHERS = frozenset({"sudo", "env", "exec", "nohup", "npx", "bunx"})
_LAUNCHER_PAIRS = frozenset(
    {("uv", "run"), ("poetry", "run"), ("pnpm", "exec"), ("pnpm", "dlx"), ("npm", "exec")}
)


def _argv_pipeline(command: str) -> list[tuple[str, list[str]]]:
    """The simple commands of shell text as argument vectors, each with the separator before it (`""` for the
    first): quotes removed and kept whole (a quoted program or value is one argument), split at `;`, `&`, `|` and
    newlines; a leading launcher (`sudo`, `env`, `npx`, `uv run`, ...) or variable assignment is dropped. Empty when
    the text does not split (an unclosed quote)."""
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        return []
    out: list[tuple[str, list[str]]] = []
    cur: list[str] = []
    sep = ""
    for tok in tokens:
        if tok and all(c in ";&|\n" for c in tok):
            if cur:
                out.append((sep, cur))
            cur = []
            sep = tok
        else:
            cur.append(tok)
    if cur:
        out.append((sep, cur))
    cleaned: list[tuple[str, list[str]]] = []
    for sep, argv in out:
        argv = [
            t.lstrip("(") if i == 0 else t.rstrip(")") if i == len(argv) - 1 else t
            for i, t in enumerate(argv)
        ]
        argv = [t for t in argv if t]
        while argv:
            if re.match(r"^[A-Za-z_]\w*=", argv[0]):
                argv = argv[1:]
            elif argv[0] in _LAUNCHERS or tuple(argv[:2]) in _LAUNCHER_PAIRS:
                argv = argv[1:] if argv[0] in _LAUNCHERS else argv[2:]
                while argv and argv[0].startswith("-"):
                    argv = argv[2:] if argv[0] in ("-u", "-g", "-C", "--with", "-p") else argv[1:]
            else:
                break
        if argv:
            cleaned.append((sep, argv))
    return cleaned


def _argv_segments(command: str) -> list[list[str]]:
    """The simple commands of shell text as argument vectors (`_argv_pipeline` without the separators)."""
    return [argv for _, argv in _argv_pipeline(command)]


def _head(argv: list[str]) -> str:
    return argv[0].rsplit("/", 1)[-1]


_PYTHON_HEAD = re.compile(r"^python(?:\d+(?:\.\d+)?)?$")
#: A Python program writing a file: `open(..., "w"|"a"|"x")`, `Path.write_text`, `Path.open("a")`.
_PY_WRITE = re.compile(
    r"\bopen\((?:[^()]|\([^()]*\))*?,\s*(?:mode\s*=\s*)?[rRbBuU]?['\"][^'\"]*[wax]"
    r"|\.write_(?:text|bytes)\("
    r"|\.open\(\s*(?:mode\s*=\s*)?['\"][^'\"]*[wax]"
)
_PY_LITERAL = re.compile(
    r"(?<![\w'\"])[rRbBuU]{0,2}(?:'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\")"
)
#: `Path.home() / ".bashrc"`: a path under the home folder.
_PY_HOME_JOIN = re.compile(r"Path\.home\(\)\s*/\s*[rRuU]?(['\"])([^'\"]+)\1")


def _python_programs(command: str) -> list[str]:
    """The Python programs a command runs: the code after `python3 -c`, and heredoc bodies fed to an interpreter
    that reads its program from standard input."""
    rest = _without_heredocs(command)
    progs: list[str] = []
    stdin = False
    for argv in _argv_segments(rest):
        if not _PYTHON_HEAD.match(_head(argv)):
            continue
        if "-c" in argv[1:]:
            i = argv.index("-c", 1)
            if i + 1 < len(argv):
                progs.append(argv[i + 1])
        elif all(t.startswith("-") for t in argv[1:]):
            stdin = True  # `python3`, `python3 -`, `python3 -u -`
    if stdin:
        progs.extend(body for _, _, body in _heredocs(command))
    return progs


def _py_statements(prog: str) -> list[str]:
    """A Python program's statements (split at newlines and `;` outside strings); the whole program when it does not
    tokenise."""
    import io
    import tokenize

    try:
        toks = list(tokenize.generate_tokens(io.StringIO(prog).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return [prog]
    lines = prog.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))

    def offset(pos: tuple[int, int]) -> int:
        row, col = pos
        return starts[row - 1] + col if row - 1 < len(starts) else len(prog)

    out: list[str] = []
    at = 0
    for tok in toks:
        if tok.type == tokenize.NEWLINE or (tok.type == tokenize.OP and tok.string == ";"):
            end = offset(tok.start)
            if prog[at:end].strip():
                out.append(prog[at:end])
            at = offset(tok.end)
    if prog[at:].strip():
        out.append(prog[at:])
    return out


#: The file a write call writes: the arguments of `open(..., "w"|"a"|"x")`, or the receiver of `.write_text(`,
#: `.write_bytes(` or `.open("a")`.
_PY_OPEN_WRITE = re.compile(
    r"\bopen\(((?:[^()]|\([^()]*\))*?),\s*(?:mode\s*=\s*)?[rRbBuU]?['\"][^'\"]*[wax]"
)
_PY_RECEIVER_WRITE = re.compile(
    r"\.\s*(?:write_(?:text|bytes)\(|open\(\s*(?:mode\s*=\s*)?['\"][^'\"]*[wax])"
)
_PY_ASSIGN = re.compile(r"^\s*(?:with\s+.*\bas\s+)?([A-Za-z_]\w*)\s*=\s*(.+)$", re.S)


def _py_literals(code: str) -> list[str]:
    out: list[str] = []
    for m in _PY_LITERAL.finditer(code):
        try:
            value = ast.literal_eval(m.group(0))
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if isinstance(value, str):
            out.append(value)
    return out


def _py_paths(expr: str) -> list[str]:
    """The paths a Python expression spells: a path literal, or `Path.home() / "..."`."""
    paths = [f"~/{m.group(2).lstrip('/')}" for m in _PY_HOME_JOIN.finditer(expr)]
    return paths + [v for v in _py_literals(expr) if v.startswith(("/", "~/"))]


def _python_texts(
    command: str, *, home: str | None, workspace_root: str | None, lists: Lists
) -> list[WrittenText]:
    """What a Python program a command runs writes into a self-modification file: its string literals, read as that
    file's content. The file is the one a write call names (`open(PATH, "w")`, `PATH.write_text(...)`, through a
    variable an earlier statement set); a file the program only reads is not written."""
    out: list[WrittenText] = []
    for prog in _python_programs(command):
        if not _PY_WRITE.search(prog):
            continue
        names: dict[str, str] = {}
        targets: list[str] = []
        for stmt in _py_statements(prog):
            exprs = [m.group(1) for m in _PY_OPEN_WRITE.finditer(stmt)]
            m = _PY_RECEIVER_WRITE.search(stmt)
            if m:
                exprs.append(stmt[: m.start()])
            for expr in exprs:
                for name, value in names.items():
                    expr = re.sub(rf"\b{name}\b", lambda _m, v=value: f"({v})", expr)
                targets.extend(_py_paths(expr))
            a = _PY_ASSIGN.match(stmt)
            if a:
                names[a.group(1)] = a.group(2)
        for path in targets:
            norm = normalise_path(path, home=home, workspace_root=workspace_root)
            if not _selfmod_file(norm, path, lists):
                continue
            for value in _py_literals(prog):
                if value != path and not value.startswith(("/", "~/")):
                    out.extend(
                        _path_texts(
                            norm,
                            value,
                            home=home,
                            workspace_root=workspace_root,
                            lists=lists,
                            raw=path,
                        )
                    )
            break
    return out


#: `openclaw config set PATH VALUE`, `hermes config set PATH VALUE` (and `add`, `append`).
_CONFIG_CLI_HEADS = frozenset({"openclaw", "hermes"})
_CONFIG_CLI_VERBS = frozenset({"set", "add", "append"})


def _config_cli_texts(command: str) -> list[WrittenText]:
    """A config field the host's own `config set` command sets: read by the field it names (`_config_value`)."""
    out: list[WrittenText] = []
    for argv in _argv_segments(command):
        if (
            _head(argv) in _CONFIG_CLI_HEADS
            and len(argv) >= 3
            and argv[1] == "config"
            and argv[2] in _CONFIG_CLI_VERBS
        ):
            operands = [t for t in argv[3:] if not t.startswith("--")]
            if len(operands) == 1 and "=" in operands[0]:
                operands = operands[0].split("=", 1)  # `config set path=value`
            if len(operands) >= 2:
                out.extend(_config_value(operands[0], operands[1]))
    return out


#: `git config` options that take a value of their own.
_GIT_VALUE_OPTS = frozenset(
    {"-f", "--file", "--blob", "--type", "--default", "--comment", "--value"}
)


def _git_config_texts(command: str) -> list[WrittenText]:
    """A git setting the command sets whose value git runs later (`_git_value`)."""
    out: list[WrittenText] = []
    for argv in _argv_segments(command):
        if _head(argv) != "git":
            continue
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            i += 2 if argv[i] in ("-C", "-c") else 1
        if i >= len(argv) or argv[i] != "config":
            continue
        if any(t.startswith("--unset") for t in argv[i + 1 :]) or argv[i + 1 : i + 2] in (
            ["unset"],
            ["get"],
        ):
            continue  # removing or reading a setting: a value after it is a pattern, not a command
        operands: list[str] = []
        j = i + 1
        while j < len(argv):
            tok = argv[j]
            if tok in _GIT_VALUE_OPTS:
                j += 2
                continue
            if not tok.startswith("-"):
                operands.append(tok)
            j += 1
        if operands[:1] == ["set"]:
            operands = operands[1:]
        if len(operands) >= 2:
            out.extend(_git_value(operands[0], operands[1]))
    return out


#: `systemd-run` options that set up a timer: the command runs later, not now.
_SDRUN_TIMER = re.compile(
    r"^--on-(?:active|boot|startup|unit-active|unit-inactive|calendar|clock-change|timezone-change)\b"
)
#: `systemd-run` options that take a value of their own when not written `--opt=value`.
_SDRUN_VALUE_OPTS = frozenset(
    "-u --unit -p --property --description --slice --uid --gid -E --setenv --working-directory -M --machine "
    "-H --host --nice --service-type --on-active --on-boot --on-startup --on-unit-active --on-unit-inactive "
    "--on-calendar --timer-property --path-property --socket-property".split()
)


def _systemd_run_texts(command: str) -> list[WrittenText]:
    """The command a `systemd-run` timer runs later (one with an `--on-...` option)."""
    out: list[WrittenText] = []
    for argv in _argv_segments(command):
        if _head(argv) != "systemd-run" or not any(_SDRUN_TIMER.match(t) for t in argv[1:]):
            continue
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            i += 2 if argv[i] in _SDRUN_VALUE_OPTS else 1
        if i < len(argv):
            out.append(WrittenText(_join_argv(argv[i:]), Form.SHELL))
    return out


#: Copies and links whose last operand is the destination; options of theirs that take a value.
_COPY_HEADS = frozenset({"cp", "mv", "install", "rsync", "ln"})
_COPY_VALUE_OPTS = frozenset({"-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix"})


def _operands(
    argv: list[str], value_opts: frozenset[str] = frozenset()
) -> tuple[list[str], list[str], list[str]]:
    """A command's operands, the files it redirects its output to (`>`, `>>`) and the files it reads its input
    from (`<`), skipping options and the values of `value_opts`."""
    operands: list[str] = []
    outputs: list[str] = []
    inputs: list[str] = []
    i = 1
    while i < len(argv):
        tok = argv[i]
        m = re.match(r"^(\d?>>?|<)(.*)$", tok)
        if m:
            target = m.group(2) or (argv[i + 1] if i + 1 < len(argv) else "")
            i += 1 if m.group(2) else 2
            if target and not target.startswith("&"):
                (inputs if m.group(1) == "<" else outputs).append(target)
            continue
        if tok in value_opts:
            i += 2
            continue
        if not tok.startswith("-") or tok == "-":
            operands.append(tok)
        i += 1
    return operands, outputs, inputs


def _planted_copies(
    command: str,
    *,
    home: str | None,
    workspace_root: str | None,
    lists: Lists,
    planted: Planted,
) -> list[WrittenText]:
    """A file another call wrote, put into a self-modification file (read as that file's content): copied, moved,
    installed or linked there, written there by `cat` (a redirect, or a pipe into `tee`), or installed as a crontab
    (`crontab FILE`, `crontab < FILE`, `cat FILE | crontab -`). A relative path is resolved against the folder an
    earlier `cd` in the command moved to."""
    out: list[WrittenText] = []
    cwd: str | None = None

    def norm(p: str) -> str:
        if not p.startswith(("/", "~", "$HOME", "./")):
            p = "./" + p  # relative to the folder the command is in
        return normalise_path(p, home=home, workspace_root=workspace_root, cwd=cwd)

    def put(src: str, dest: str) -> None:
        found = planted(norm(src))
        if found is None:
            return
        # a destination with no file name of its own may be a folder: the file keeps its name there
        candidates = [dest]
        if dest.endswith("/") or "." not in dest.rstrip("/").rsplit("/", 1)[-1]:
            candidates.insert(0, dest.rstrip("/") + "/" + src.rsplit("/", 1)[-1])
        for cand in candidates:
            if cand.endswith("/"):
                continue
            texts = _path_texts(
                norm(cand),
                found.content,
                home=home,
                workspace_root=workspace_root,
                lists=lists,
                raw=cand,
            )
            if texts:
                out.extend(replace(w, planted=found) for w in texts)
                return

    piped: list[str] = []  # what the previous command of a pipeline read (`cat FILE | ...`)
    for sep, argv in _argv_pipeline(command):
        head = _head(argv)
        stdin = piped if sep == "|" else []
        piped = []
        if head == "cd":
            operands, _, _ = _operands(argv)
            cwd = norm(operands[0]) if operands else cwd
            continue
        if head in _COPY_HEADS:
            target: str | None = None
            if "-t" in argv or "--target-directory" in argv:
                k = argv.index("-t") if "-t" in argv else argv.index("--target-directory")
                target = argv[k + 1] + "/" if k + 1 < len(argv) else None
                argv = argv[:k] + argv[k + 2 :]
            operands, _, _ = _operands(argv, _COPY_VALUE_OPTS)
            if target is None and len(operands) >= 2:
                target = operands.pop()
            for src in operands if target else []:
                put(src, target)
        elif head == "cat":
            operands, outputs, inputs = _operands(argv)
            srcs = [o for o in operands if o != "-"] + inputs
            for dest in outputs:
                for src in srcs:
                    put(src, dest)
            piped = srcs
        elif head == "tee":
            operands, _, _ = _operands(argv)
            for dest in operands:
                for src in stdin:
                    put(src, dest)
        elif head == "crontab":
            operands, _, inputs = _operands(argv, frozenset({"-u"}))
            files = (
                [o for o in operands if o != "-"][:1]
                or inputs
                or (stdin if operands in ([], ["-"]) else [])
            )
            for src in files:
                found = planted(norm(src))
                if found is not None and found.content.strip():
                    out.append(WrittenText(found.content, Form.SHELL, planted=found))
    return out


#: Heads that run their first operand as a script.
_SCRIPT_RUNNERS = frozenset(
    "sh bash zsh dash ksh fish source . python python3 node perl ruby pwsh powershell".split()
)


def _planted_runs(
    texts: list[WrittenText], *, home: str | None, workspace_root: str | None, planted: Planted
) -> list[WrittenText]:
    """Files another call wrote that shell content the host runs (a hook, a cron line, a startup file, a job's
    command) runs in turn (`sh /tmp/x.sh`, `/tmp/x.sh`): read as content the host runs. One level, at most
    `MAX_PLANTED` files."""
    out: list[WrittenText] = []
    seen: set[str] = set()
    for wt in texts:
        if wt.form is not Form.SHELL or not wt.host_run:
            continue
        for line in _shell_lines(wt.text, cron_user=wt.cron_user):
            for argv in _argv_segments(line):
                head = _head(argv)
                if head in _SCRIPT_RUNNERS or _PYTHON_HEAD.match(head):
                    operands = [t for t in argv[1:] if not t.startswith("-")]
                    if "-c" in argv[1:] or not operands:
                        continue
                    path = operands[0]
                elif argv[0].startswith(("/", "~/", "./", "$HOME/")):
                    path = argv[0]
                else:
                    continue
                norm = normalise_path(path, home=home, workspace_root=workspace_root)
                if norm in seen or len(seen) >= MAX_PLANTED:
                    continue
                seen.add(norm)
                found = planted(norm)
                if found is not None and found.content.strip():
                    form = Form.PROGRAM if norm.lower().endswith(_PROGRAM_SUFFIXES) else Form.SHELL
                    out.append(WrittenText(found.content, form, planted=found))
    return out


def _exec_texts(
    command: str,
    *,
    home: str | None,
    workspace_root: str | None,
    lists: Lists,
    planted: Planted | None = None,
) -> list[WrittenText]:
    if not command.strip():
        return []
    routes = _python_texts(command, home=home, workspace_root=workspace_root, lists=lists)
    rest = _without_heredocs(command)
    routes += _config_cli_texts(rest) + _git_config_texts(rest) + _systemd_run_texts(rest)
    if planted is not None:
        routes += _planted_copies(
            rest, home=home, workspace_root=workspace_root, lists=lists, planted=planted
        )
    return routes + _exec_written(command, home=home, workspace_root=workspace_root, lists=lists)


def _exec_written(
    command: str, *, home: str | None, workspace_root: str | None, lists: Lists
) -> list[WrittenText]:
    """Text a shell command writes into a self-modification file or a job by a redirect, `tee`, `sed`, a heredoc,
    `crontab -` or the host's job commands."""
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
    # Every body is kept, not only one that names a host: a line that runs a file another call wrote
    # (`sh /tmp/x.sh`) names none (`_planted_runs`).
    for m in _QUOTED.finditer(rest):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if body:
            bodies.append(_SED_APPEND.sub("", body.replace('\\"', '"'), count=1))
    for m in _UNQUOTED_ECHO.finditer(rest):
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
            if wt.host_run:
                # every host the code names is a destination; one a line fetches from and evaluates is a code source
                runs = {
                    h
                    for line in code.splitlines()
                    if _PROGRAM_FETCH.search(line) and _PROGRAM_RUN.search(line)
                    for h in _hosts_in(line, inline_program=True, emails=False)
                }
                program_lines = [code]
            else:
                runs = set()
                program_lines = [ln for ln in code.splitlines() if _sends_local(ln)]
            add(
                [
                    Found(
                        EntityKind.HOST,
                        h,
                        h,
                        Role.CODE_SOURCE if h in runs else Role.DATA_DESTINATION,
                    )
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


#: A fetch piped into the current shell (fish's `curl ... | source`, `curl ... | . /dev/stdin`).
_PIPE_SOURCE = re.compile(r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:source|\.)(?=\s|$)")


def _runs_fetched(line: str) -> bool:
    """The line fetches code and runs it by a route the pipe check does not read."""
    if _SUBST_RUN.search(line) or _PIPE_SOURCE.search(line):
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
                tokens[0].rsplit("/", 1)[-1].lower() in NET_HEADS
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
