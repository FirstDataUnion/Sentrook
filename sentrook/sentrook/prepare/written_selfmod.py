"""Hosts in written self-modification content: where a later run that this call sets up sends to or runs code from.

A call that writes a cron line, a hook script, a startup file, a skill, a scheduled job's prompt or an automation
does not send or run anything itself, but the content it writes runs later, often with nobody watching: a host that
content fetches code from or sends to is a code source or a destination of that later run. Those roles are recorded
on the entity apart from its own roles (`Entity.future_roles`), so the call itself is never read as a send or a run;
the oracle and the context probe score them as the roles of a run the call schedules.

What counts as written self-modification content:

- a file write or edit into the agent's scheduler, skill, hook or config folders, or into a host scheduler or
  startup file (the `agent_scheduler`, `agent_plugins`, `hooks`, `agent_config`, `host_scheduler` and `startup`
  path groups); only the text the call writes, never the text an edit replaces;
- a scheduler, skill or config tool (the self-modification tool names) with a changing action: its command and
  script fields as shell, its prompt, message, content and instruction fields as instructions;
- a shell command that installs a crontab, a systemd or launchd job, or writes into one of those files (a redirect,
  `tee`), or that adds a job with the host's own cron or automation command: its quoted strings and heredoc bodies.

How the roles are read:

- shell text the host or the shell runs (a cron line, a hook or startup script, a unit, a job's command): a host the
  text fetches code from and runs (piped to a shell, downloaded then run, cloned then built) is a code source; any
  other host a network client in the text contacts (`curl`, `wget`, `ssh`, `nc`, ...) is a destination. Nobody scans
  that run, so a plain request to a host counts. Cron schedule fields are dropped first and comments are ignored.
- program text the host runs (a hook written in another language): every host it names is a destination. A
  `hooks/` folder of the workspace's own code (a web app's hooks) is not a host hook.
- what the agent runs later through its own tools (a skill's commands and scripts): a fetch-and-run is a code source
  and a send (an upload, a POST, a raw socket) a destination; a plain lookup is not charged now, since each command
  is scanned when the agent runs it.
- instruction text (a skill, a job prompt, an agent instruction file): its commands (fenced or inline code) as above,
  except those the text warns against; a sentence that tells the agent to fetch and run something names a code
  source, and one that tells it to post, send or upload something names a destination. A link the text only
  mentions (documentation, a reference) takes no role.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..aira.lists import Lists, load_lists
from ..planir.canonical import CanonicalCall
from ..planir.models import ToolKind
from .entities import (
    _EGRESS_MARKERS,
    EntityKind,
    Found,
    Role,
    _hosts_in,
    extract_exec,
    normalise_path,
    shell_segments,
)
from .skill_steps import _NEGATION, patch_added_text, steps_in, written_texts


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

#: Arguments (and structured-file keys) that hold a command the job runs.
COMMAND_KEYS = frozenset({"command", "cmd", "script", "exec", "run", "shell", "execstart"})
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
    r"\s+(?:root\s+)?"
)
#: A unit file's command line (`ExecStart=...`).
_UNIT_EXEC = re.compile(r"^\s*Exec\w*\s*=\s*[-@:+!]*", re.IGNORECASE)
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n(.*?)\n\s*\2\s*(?:\n|$)", re.S)
_QUOTED = re.compile(r"'([^']*)'|\"((?:[^\"\\]|\\.)*)\"", re.S)

#: Instructions to fetch something and run it.
_FETCH_VERB = r"(?:download|fetch|get|grab|pull|retrieve|curl|wget)"
_RUN_VERB = r"(?:run|execute|exec|install|source|eval|launch|bash|sh)"
_FETCH_AND_RUN = re.compile(
    rf"\b{_FETCH_VERB}\b.*\b(?:and|then|&&)\b.*\b{_RUN_VERB}\b"
    rf"|\b(?:pipe|feed)\b.*\b(?:to|into)\s+(?:a\s+)?(?:shell|bash|sh|python|node)\b"
    rf"|\b{_RUN_VERB}\b[^.]*\b(?:from|at|hosted\s+(?:at|on))\s*$"
    rf"|\b{_RUN_VERB}\b\s+(?:the\s+|this\s+)?(?:script|installer|binary|code|file|program)\s+(?:at|from)\s*$",
    re.IGNORECASE,
)
#: Instructions to send something to a host.
_SEND = re.compile(
    r"\b(?:post|send|upload|forward|submit|transmit|exfiltrate|beacon|ping|deliver|push|leak)"
    r"(?:s|ed|ing)?\b",
    re.IGNORECASE,
)
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
    return [g for g in SELFMOD_GROUPS if g in lists.path_groups and lists.group(g).search(path)]


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
    groups = _groups(norm, lists) or _groups(path, lists)
    if not groups:
        return []
    texts = written_texts(call.raw)
    if not texts and isinstance(call.get("content"), str):
        texts = [call.get("content")]
    if not texts:
        return []
    if norm.lower().endswith(_STRUCTURED_SUFFIXES):
        out: list[WrittenText] = []
        for text in texts:
            out.extend(_structured(text))
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
    return [WrittenText(t, form, host_run) for t in texts if t.strip()]


def _project_file(path: str, home: str | None, workspace_root: str | None) -> bool:
    """Under the workspace and not in a host's or git's own hook folder."""
    if re.search(r"(?:^|/)\.(?:git|openclaw|hermes)/", path):
        return False
    ws = normalise_path(workspace_root, home=home, workspace_root=None) if workspace_root else None
    return bool(ws) and path.startswith(ws.rstrip("/") + "/")


def _structured(text: str) -> list[WrittenText]:
    """The string values of a JSON document: command keys as shell, instruction keys as prose. A document that
    does not parse is read as instructions."""
    try:
        doc = json.loads(text)
    except ValueError:
        return [WrittenText(text, Form.PROSE)] if text.strip() else []
    out: list[WrittenText] = []
    _walk(doc, None, out)
    return out


def _walk(node: Any, key: str | None, out: list[WrittenText]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, str(k), out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, key, out)
    elif isinstance(node, str) and node.strip() and key is not None:
        k = key.lower().replace("-", "_")
        if k in COMMAND_KEYS:
            out.append(WrittenText(node, Form.SHELL))
        elif k in PROSE_KEYS:
            out.append(WrittenText(node, Form.PROSE))


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
    rest = _HEREDOC.sub(" ", command)
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
    bodies = [m.group(3) for m in _HEREDOC.finditer(command)]
    for m in _QUOTED.finditer(rest):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if body and _hosts_in(body):
            bodies.append(body.replace('\\"', '"'))
    return [WrittenText(b, form, host_run) for b in dict.fromkeys(bodies) if b.strip()]


_REDIRECT = re.compile(r"(?<![<>&\d])>{1,2}\s*([^\s;&|<>]+)")


def _write_targets(command: str) -> list[str]:
    """Files a command writes by redirect or `tee`."""
    out = [m.group(1).strip("'\"") for m in _REDIRECT.finditer(command)]
    for tokens in shell_segments(command):
        if tokens[0] == "tee":
            out.extend(t for t in tokens[1:] if not t.startswith("-"))
    return out


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
                    wt.text, home=home, workspace_root=workspace_root, contacts=wt.host_run
                )
            )
        elif wt.form is Form.PROGRAM:
            program_lines = (
                [wt.text]
                if wt.host_run
                else [line for line in wt.text.splitlines() if _EGRESS_MARKERS.search(line)]
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


def _shell_lines(text: str) -> list[str]:
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
        ):
            continue  # a variable line of a cron table (`MAILTO=...`)
        else:
            stripped = _CRON_SCHEDULE.sub("", stripped, count=1)
        if stripped:
            lines.append(stripped)
    if pending.strip():
        lines.append(pending.strip())
    return lines


def _shell_roles(
    text: str, *, home: str | None, workspace_root: str | None, contacts: bool = True
) -> list[Found]:
    """Code sources and destinations of shell text. With `contacts`, every host a network client contacts is a
    destination; without it, only a host the text sends to (an upload, a POST, a raw socket)."""
    lines = _shell_lines(text)
    if not lines:
        return []
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
    contacted: set[str] = set()
    for line in lines:
        for tokens in shell_segments(line):
            seg = " ".join(tokens)
            if not contacts and not _EGRESS_MARKERS.search(seg):
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


def _prose_roles(text: str, *, home: str | None, workspace_root: str | None) -> list[Found]:
    out: list[Found] = []
    commands = [cmd for cmd, negated in steps_in(text) if not negated]
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
            # the words before the token that names the host (a URL's scheme is part of that token)
            before = re.sub(r"\S*$", "", sentence[:at]) if at >= 0 else sentence
            if _NEGATION.search(before):
                continue
            if _FETCH_AND_RUN.search(before) or (
                at >= 0
                and _FETCH_AND_RUN.search(sentence)
                and re.search(rf"\b{_FETCH_VERB}\b", before, re.I)
            ):
                out.append(Found(EntityKind.HOST, host, host, Role.CODE_SOURCE))
            elif _SEND.search(before):
                out.append(Found(EntityKind.HOST, host, host, Role.DATA_DESTINATION))
    return out


def _position(text: str, host: str) -> int:
    m = re.search(r"(?<![\w-])" + re.escape(host) + r"(?![\w-])", text, re.IGNORECASE)
    return m.start() if m else -1
