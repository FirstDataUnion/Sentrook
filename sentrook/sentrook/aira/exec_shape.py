"""Deterministic structure for shell commands (ported from 1.x `layers/exec_shape`).

Derived for every exec call AIRA looks at. Fail closed: a command that does not parse gets
``parse_ok=False`` and no ``segments``, so nothing that *relieves* can build on a structure we did
not understand. ``heads`` is still populated where it can be — tree-sitter is error-tolerant and a
command with one damaged fragment often still yields correct heads, which is useful for the
detectors that *score* (a class we can still see is a reason to score, never a reason to relieve).

Derivation runs on the redacted command (what the plugin sent). 1.x measured that redaction is
parser-safe, including marker-bearing forms (``[REDACTED:a3f19c]``, ``sk-ant-[REDACTED]``).
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .path_classes import (
    ExecPath,
    derive_path_roles,
    derive_paths,
    derive_url_hosts,
    roll_up_path_classes,
)
from .sensitive_paths import PathList

#: Commands longer than this are not parsed at all (``parse_ok=False``). History arguments are
#: capped by the plugin at about 4 KB, so this bounds worst-case parser cost rather than being a
#: real limit.
MAX_PARSE_CHARS = 16_000

#: Stripped before the head is taken, recursively. ``sudo`` is recorded but is deliberately in this
#: list: a detector that wants to know about elevation reads ``wrappers`` / ``privileged``, and a
#: detector matching on ``heads`` should see the real binary rather than silently failing to match
#: because sudo was in front of it.
WRAPPERS = frozenset(
    {
        "timeout",
        "time",
        "nice",
        "nohup",
        "stdbuf",
        "env",
        "command",
        "builtin",
        "noglob",
        "xargs",
        "sudo",
        "doas",
        "run0",
        "pkexec",
    }
)

#: Wrappers that **elevate privilege**. Stripped like any other so detectors still see the real
#: binary — but recorded separately, because stripping alone makes elevation invisible:
#:
#:     cat /etc/passwd       -> heads ['cat']
#:     sudo cat /etc/shadow  -> heads ['cat']
#:
#: This is a known failure mode in the wild: one agent tool lists `timeout`/`nohup`/`nice`/`env`
#: among its safe command prefixes, so `timeout rm -rf /` prefix-matches as safe; another strips
#: sudo with a blind `command[1..]`, so `sudo -u root rm -rf /` is re-examined as `-u root rm -rf /`
#: with `-u` never modelled as consuming `root`.
PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas", "run0", "pkexec"})

#: Wrapper flags that take a value, for wrapper stripping only. When a wrapper is followed by one
#: of these we must skip the flag *and* its argument before the real binary. Kept narrow on
#: purpose: guessing wrongly makes the head wrong, which is worse than treating the wrapper as the
#: head.
WRAPPER_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "xargs": frozenset({"-n", "-P", "-I", "-d", "-s", "-a", "-E"}),
    # `sudo -u root bash -c …` otherwise yields a head of `root`.
    "sudo": frozenset(
        {
            "-u",
            "--user",
            "-g",
            "--group",
            "-p",
            "--prompt",
            "-C",
            "-h",
            "--host",
            "-U",
            "-r",
            "--role",
            "-t",
            "--type",
        }
    ),
    "doas": frozenset({"-u", "-C", "-a"}),
    "time": frozenset({"-o", "--output", "-f", "--format"}),
}

#: Wrappers that take a leading *positional* before the real command, which a flag-skipping loop
#: would otherwise mistake for the binary (``timeout 30 nice python3 …`` yielding a head of ``30``).
#: Each entry is a predicate over the token: it is only consumed when it actually looks like that
#: wrapper's argument, so an unusual form leaves the head alone rather than eating it.
DURATION_RE = re.compile(r"\A\d+(?:\.\d+)?[smhd]?\Z")
ENV_ASSIGN_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*=")

_WRAPPER_POSITIONAL: dict[str, tuple[re.Pattern[str], bool]] = {
    # (predicate, repeats) — `timeout` takes exactly one duration; `env` and `sudo` take any
    # number of KEY=VALUE assignments.
    "timeout": (DURATION_RE, False),
    "env": (ENV_ASSIGN_RE, True),
    # `sudo` interprets `VAR=value` arguments as environment settings, so without this the
    # assignment is taken for the binary: `sudo LD_PRELOAD=/tmp/x.so python3 -c '…'` gave heads
    # ['x.so'], inline_eval False and no env assignment — the head, the flag and the prefix lost in
    # one go. Only `sudo` is listed: `timeout 5 FOO=1 ls` really would exec a binary named `FOO=1`
    # and fail, so reporting that head is correct, and `doas`/`pkexec` take no assignments.
    "sudo": (ENV_ASSIGN_RE, True),
}

#: Interpreter flags that mean "the next thing is code, not a path".
_INLINE_EVAL_FLAGS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c", "-m"}),
    "python2": frozenset({"-c", "-m"}),
    "python3": frozenset({"-c", "-m"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"eval"}),
    "bun": frozenset({"-e", "--eval"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
    "bash": frozenset({"-c"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
    "dash": frozenset({"-c"}),
    "ksh": frozenset({"-c"}),
    "fish": frozenset({"-c"}),
}

#: Bare builtins that evaluate their argument as code with no flag at all.
_INLINE_EVAL_HEADS = frozenset({"eval", "source", "."})

#: Heads that read a shell script from a pipe or execute fetched content.
_SHELL_HEADS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"})
_INTERPRETER_HEADS = frozenset(
    {"python", "python2", "python3", "node", "deno", "bun", "perl", "ruby", "php", "osascript"}
)
_NET_HEADS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "http", "httpie"})

#: Redirect operators that actually write somewhere. `<` reads, and `>&` / `<&` duplicate a file
#: descriptor rather than naming a path.
_WRITE_REDIRECT_OPS = frozenset({">", ">>", "&>", "&>>", ">|"})

#: Destinations that discard rather than store. Writing here is not a sink.
_NULL_SINKS = frozenset({"/dev/null", "/dev/zero"})


@dataclass(slots=True)
class ExecSegment:
    """One simple command inside a compound command."""

    head: str
    argv: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    positional: list[str] = field(default_factory=list)
    #: Write-redirect targets attached to this segment (`> path`, `>> path`, `&> path`).
    redirects: list[str] = field(default_factory=list)
    #: Wrappers stripped from this segment and whether one of them elevates.
    wrappers: list[str] = field(default_factory=list)
    env_assignments: list[str] = field(default_factory=list)

    @property
    def privileged(self) -> bool:
        return any(w in PRIVILEGE_WRAPPERS for w in self.wrappers)

    def has_flag_letter(self, letter: str) -> bool:
        """Whether a short-flag bundle carries `letter` (`-rf` carries `r` and `f`)."""
        return any(
            f.startswith("-") and not f.startswith("--") and letter in f[1:] for f in self.flags
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "head": self.head,
            "argv": list(self.argv),
            "flags": list(self.flags),
            "positional": list(self.positional),
            "redirects": list(self.redirects),
            "wrappers": list(self.wrappers),
            "env_assignments": list(self.env_assignments),
        }


@dataclass(slots=True)
class ExecShape:
    parse_ok: bool = False
    heads: list[str] = field(default_factory=list)
    wrappers: list[str] = field(default_factory=list)
    inline_eval: bool = False
    sinks: list[str] = field(default_factory=list)
    substitution: bool = False
    #: A privilege-elevation wrapper was stripped (sudo/doas/run0/pkexec). Separate from
    #: `wrappers` so a detector can ask about elevation with one field.
    privileged: bool = False
    #: Every path class the command touches (roles in group order, then locations). Derived
    #: whole-command, so it survives a `cd` rebase and a parse failure — unlike `segments`, it is
    #: **not** dropped when `parse_ok` is false, because a class we can still see is a reason to
    #: score and never a reason to relieve.
    path_classes: list[str] = field(default_factory=list)
    #: `KEY=VALUE` assignments prefixed to a command, from either form — `LD_PRELOAD=x ls` or
    #: `env LD_PRELOAD=x ls`. The assignment is its own tree-sitter node that a naive collector
    #: discards, and the `env` form is eaten by wrapper stripping; without this field
    #: `LD_PRELOAD=/tmp/evil.so ls` produced a shape identical to a bare `ls`.
    env_assignments: list[str] = field(default_factory=list)
    #: Path groups referenced anywhere in the command text — the whole-command defence, which sees
    #: bare basenames, redirect targets and quoted references that the per-path view cannot.
    path_roles: list[str] = field(default_factory=list)
    #: Every path the command references, classified on both axes. This is what detectors read;
    #: `path_classes` is the roll-up, derived from this list so the two cannot disagree.
    paths: list[ExecPath] = field(default_factory=list)
    #: Lowercased hostnames of every http(s) URL in the command.
    url_hosts: list[str] = field(default_factory=list)
    segments: list[ExecSegment] = field(default_factory=list)
    #: Heads written as a **path** rather than a bare name, as written: `./ls`, `bin/ls`, `../ls`,
    #: `~/ls`, `/usr/bin/ls`. `heads` is the basename, lowercased, which is right for a detector
    #: hunting `curl` and exactly backwards for one asking "is this the system `ls`": `/usr/bin/ls`
    #: is, `./ls` is a file in the workspace the agent may have written a moment ago.
    head_paths: list[str] = field(default_factory=list)
    #: Each segment as ``head arg1 arg2 …``, one per line — the **parsed** command, matchable by a
    #: regex. An argv guard written against the raw ``command`` text and a head clause written
    #: against the parse can disagree about what the command is (``"git" push --force`` has no
    #: `git ` to match in the text); the tokenizer resolves quoting, so nothing here can be tricked
    #: by it.
    argv: str = ""
    #: Write-redirect targets anywhere in the command (`> path`, `>> path`), in source order.
    redirect_targets: list[str] = field(default_factory=list)
    #: Pipelines as lists of segment indices, in stage order (`[[0, 1]]` for `curl … | bash`).
    pipelines: list[list[int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parse_ok": self.parse_ok,
            "heads": list(self.heads),
            "wrappers": list(self.wrappers),
            "inline_eval": self.inline_eval,
            "sinks": list(self.sinks),
            "substitution": self.substitution,
            "privileged": self.privileged,
            "env_assignments": list(self.env_assignments),
            "path_classes": list(self.path_classes),
            "path_roles": list(self.path_roles),
            "paths": [p.to_dict() for p in self.paths],
            "url_hosts": list(self.url_hosts),
            "segments": [s.to_dict() for s in self.segments],
            "head_paths": list(self.head_paths),
            "argv": self.argv,
            "redirect_targets": list(self.redirect_targets),
            "pipelines": [list(p) for p in self.pipelines],
        }

    def summary(self) -> dict[str, Any]:
        """The compact form recorded in probe evidence."""
        return {
            "parse_ok": self.parse_ok,
            "heads": list(self.heads),
            "wrappers": list(self.wrappers),
            "privileged": self.privileged,
            "inline_eval": self.inline_eval,
            "substitution": self.substitution,
            "sinks": list(self.sinks),
            "env_assignments": list(self.env_assignments),
            "path_classes": list(self.path_classes),
            "url_hosts": list(self.url_hosts),
            "redirect_targets": list(self.redirect_targets),
            "pipelines": [[self.segments[i].head for i in p] for p in self.pipelines],
        }

    def segments_with_head(self, heads: set[str] | frozenset[str]) -> list[ExecSegment]:
        return [s for s in self.segments if s.head in heads]


class ParserUnavailableError(RuntimeError):
    """tree-sitter or the bash grammar could not be loaded."""


@lru_cache(maxsize=1)
def _parser() -> Any:
    """Build the parser once. Cold init is ~0.1 ms, so this is cheap insurance."""
    try:
        import tree_sitter_bash
        from tree_sitter import Language, Parser
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise ParserUnavailableError(f"tree-sitter-bash unavailable: {exc}") from exc
    return Parser(Language(tree_sitter_bash.language()))


def parser_available() -> bool:
    """Whether shape derivation can run in this process."""
    try:
        _parser()
    except ParserUnavailableError:
        return False
    return True


def _default_groups() -> Mapping[str, PathList]:
    from .lists import load_lists

    return load_lists().path_groups


def derive_exec_shape(
    command: str | None,
    groups: Mapping[str, PathList] | None = None,
    *,
    workspace_root: str | None = None,
    home: str | None = None,
) -> ExecShape:
    """Derive the shape of one exec command. Never raises."""
    if not command or not command.strip():
        return ExecShape()
    if len(command) > MAX_PARSE_CHARS:
        return ExecShape()
    if groups is None:
        groups = _default_groups()

    try:
        parser = _parser()
    except ParserUnavailableError:
        return ExecShape()

    source = command.encode("utf-8", "surrogateescape")
    try:
        tree = parser.parse(source)
    except Exception:  # pragma: no cover - defensive; parser is total in practice
        return ExecShape()

    root = tree.root_node
    shape = ExecShape(parse_ok=not root.has_error)

    raw_segments: list[_RawSegment] = []
    _collect_commands(root, source, raw_segments)

    wrappers: list[str] = []
    assignments: list[str] = []
    head_paths: list[str] = []
    index_by_start: dict[int, int] = {}
    for raw in raw_segments:
        assignments.extend(raw.assignments)
        head, argv, stripped, wrapped_assignments = _strip_wrappers(raw.head, raw.argv)
        wrappers.extend(stripped)
        assignments.extend(wrapped_assignments)
        # Record the head *as written* before the basename erases it.
        written = _unquote(head)
        if "/" in written:
            head_paths.append(written)
        head = _basename(head)
        if not head:
            continue
        flags = [a for a in argv if a.startswith("-") and a != "-"]
        positional = [a for a in argv if not a.startswith("-") or a == "-"]
        index_by_start[raw.start] = len(shape.segments)
        shape.segments.append(
            ExecSegment(
                head=head,
                argv=list(argv),
                flags=flags,
                positional=positional,
                redirects=list(raw.redirects),
                wrappers=list(stripped),
                env_assignments=[*raw.assignments, *wrapped_assignments],
            )
        )
        shape.heads.append(head)
        if _segment_is_inline_eval(head, argv):
            shape.inline_eval = True

    shape.head_paths = _dedupe(head_paths)
    shape.wrappers = _dedupe(wrappers)
    shape.env_assignments = _dedupe(assignments)
    shape.privileged = any(w in PRIVILEGE_WRAPPERS for w in shape.wrappers)
    shape.substitution = _has_substitution(root)
    shape.sinks, shape.redirect_targets = _derive_sinks(root, source)
    shape.pipelines = _derive_pipelines(root, source, index_by_start)
    # One role scan, shared by the per-path view and the roll-up: the group regexes dominate the
    # cost, so computing them per consumer would run several scans.
    shape.path_roles = derive_path_roles(command, groups)
    shape.paths = derive_paths(
        command,
        [s.argv for s in shape.segments],
        groups,
        shape.path_roles,
        workspace_root=workspace_root,
        home=home,
    )
    shape.path_classes = roll_up_path_classes(shape.path_roles, shape.paths, groups)
    shape.argv = "\n".join(" ".join([seg.head, *seg.argv]).strip() for seg in shape.segments)
    shape.url_hosts = derive_url_hosts(command)
    if not shape.parse_ok:
        # Heads stay for diagnostics; segments do not, so nothing can build a constraint out of a
        # structure we are not confident in.
        shape.segments = []
        shape.pipelines = []
    return shape


@dataclass(slots=True)
class _RawSegment:
    head: str
    argv: list[str]
    assignments: list[str]
    redirects: list[str]
    start: int


def _collect_commands(
    node: Any, source: bytes, out: list[_RawSegment], redirects: list[str] | None = None
) -> None:
    """Depth-first, source order: one raw segment per simple command.

    `assignments` is the `KEY=VALUE` prefix (its own tree-sitter node type, see `env_assignments`).
    A `redirected_statement` wraps its body with the redirects as siblings; the write targets are
    attached to the last simple command of the body.
    """
    if node.type == "redirected_statement":
        targets: list[str] = []
        body = None
        for child in node.children:
            if child.type == "file_redirect":
                target = _write_target(child, source)
                if target is not None:
                    targets.append(target)
            elif child.type == "heredoc_redirect":
                continue
            elif body is None and child.is_named:
                body = child
        if body is not None:
            before = len(out)
            _collect_commands(body, source, out)
            if targets and len(out) > before:
                out[-1].redirects.extend(targets)
        return
    if node.type == "command":
        head = ""
        argv: list[str] = []
        assignments: list[str] = []
        for child in node.children:
            text = source[child.start_byte : child.end_byte].decode("utf-8", "replace")
            if child.type == "command_name":
                head = text
            elif child.type == "variable_assignment":
                assignments.append(text)
            elif child.type in ("word", "string", "raw_string", "concatenation", "number"):
                argv.append(_unquote(text))
            elif child.type in ("simple_expansion", "expansion"):
                argv.append(text)
        if head:
            out.append(
                _RawSegment(
                    head=head,
                    argv=argv,
                    assignments=assignments,
                    redirects=list(redirects or []),
                    start=node.start_byte,
                )
            )
    for child in node.children:
        _collect_commands(child, source, out)


def _strip_wrappers(head: str, argv: list[str]) -> tuple[str, list[str], list[str], list[str]]:
    """Peel ``timeout 30 nice python3 …`` down to ``python3``, recording wrappers.

    Recursive by loop, because wrappers stack in real traffic. Stops at the first token that is not
    a wrapper, and never strips past the end — a bare ``sudo`` with no command stays ``sudo``
    rather than becoming an empty head.
    """
    stripped: list[str] = []
    assignments: list[str] = []
    guard = 0
    while _basename(head) in WRAPPERS and argv and guard < 8:
        guard += 1
        wrapper = _basename(head)
        stripped.append(wrapper)
        value_flags = WRAPPER_VALUE_FLAGS.get(wrapper, frozenset())
        rest = list(argv)
        while rest:
            token = rest[0]
            if not token.startswith("-") or token == "-":
                break
            rest.pop(0)
            # `-s SIGNAL` style: the value is a separate token, not `-s=SIGNAL`.
            if token in value_flags and rest:
                rest.pop(0)
        positional = _WRAPPER_POSITIONAL.get(wrapper)
        if positional is not None:
            predicate, repeats = positional
            while rest and predicate.match(rest[0]):
                consumed = rest.pop(0)
                if predicate is ENV_ASSIGN_RE:
                    # `env LD_PRELOAD=x ls` hides the assignment in the wrapper's own argv;
                    # stripping it silently would lose exactly what a bare `LD_PRELOAD=x ls` was
                    # already losing.
                    assignments.append(consumed)
                if not repeats:
                    break
        if not rest:
            # Wrapper with no command after it (e.g. `timeout --help`). Keep the wrapper as the
            # head rather than inventing one.
            stripped.pop()
            break
        head, argv = rest[0], rest[1:]
    return head, argv, stripped, assignments


def _segment_is_inline_eval(head: str, argv: list[str]) -> bool:
    if head in _INLINE_EVAL_HEADS:
        return True
    flags = _INLINE_EVAL_FLAGS.get(head)
    if not flags:
        return False
    return any(a in flags or a.split("=", 1)[0] in flags for a in argv)


def _has_substitution(node: Any) -> bool:
    if node.type in ("command_substitution", "process_substitution"):
        return True
    return any(_has_substitution(child) for child in node.children)


def _derive_sinks(node: Any, source: bytes) -> tuple[list[str], list[str]]:
    """Where data flows *out* of, or executable content *into*, this command — plus every
    write-redirect target."""
    sinks: list[str] = []
    targets: list[str] = []

    def walk(n: Any) -> None:
        if n.type == "pipeline":
            _pipeline_sinks(n, source, sinks)
        elif n.type == "file_redirect":
            target = _write_target(n, source)
            if target is not None:
                sinks.append("redirect_to_path")
                targets.append(target)
        elif n.type == "heredoc_redirect":
            sinks.append("heredoc")
        for child in n.children:
            walk(child)

    walk(node)
    return _dedupe(sinks), _dedupe(targets)


def _write_target(node: Any, source: bytes) -> str | None:
    """The path a ``file_redirect`` writes to, or None when it does not write to a path.

    Measured on the 1.x corpus, a naive "any file_redirect is a sink" rule fired on **52% of all
    commands** — every one sampled being ``2>/dev/null`` (discarding stderr) or ``2>&1`` (a
    descriptor dup with no path at all).
    """
    operator = None
    destination = None
    for child in node.children:
        text = source[child.start_byte : child.end_byte].decode("utf-8", "replace")
        if child.type == "file_descriptor":
            continue
        if operator is None and not text.strip().startswith(("/", "~", ".", "$")):
            # First non-fd token is the operator (`>`, `>>`, `>&`, `&>`, `<`).
            if text.strip() in _WRITE_REDIRECT_OPS or text.strip() in ("<", ">&", "<&", "<<<"):
                operator = text.strip()
                continue
        if operator is not None and destination is None:
            destination = _unquote(text.strip())
    if operator not in _WRITE_REDIRECT_OPS or destination is None:
        return None
    # `2>&1` parses as operator `>&` (rejected above), but be defensive: a bare number destination
    # is a descriptor, not a path.
    if destination.isdigit() or destination in _NULL_SINKS:
        return None
    return destination


def _pipeline_sinks(node: Any, source: bytes, sinks: list[str]) -> None:
    """Classify each stage a pipeline feeds *into* by that stage's head."""
    stages = [c for c in node.children if c.is_named]
    for stage in stages[1:]:
        head = _basename(_first_head(stage, source))
        if head in _SHELL_HEADS:
            sinks.append("pipe_to_shell")
        elif head in _INTERPRETER_HEADS:
            sinks.append("pipe_to_interpreter")
        elif head in _NET_HEADS:
            sinks.append("pipe_to_net")


def _derive_pipelines(node: Any, source: bytes, index_by_start: dict[int, int]) -> list[list[int]]:
    """Each pipeline as the segment indices of its stages, in order."""
    pipelines: list[list[int]] = []

    def walk(n: Any) -> None:
        if n.type == "pipeline":
            stages: list[int] = []
            for stage in (c for c in n.children if c.is_named):
                found: list[_RawSegment] = []
                _collect_commands(stage, source, found)
                if found and found[0].start in index_by_start:
                    stages.append(index_by_start[found[0].start])
            if len(stages) >= 2:
                pipelines.append(stages)
        for child in n.children:
            walk(child)

    walk(node)
    return pipelines


def _first_head(node: Any, source: bytes) -> str:
    found: list[_RawSegment] = []
    _collect_commands(node, source, found)
    if not found:
        return ""
    head, _argv, _stripped, _assign = _strip_wrappers(found[0].head, found[0].argv)
    return head


def _basename(token: str) -> str:
    """``/usr/bin/python3`` → ``python3``. Lowercased."""
    if not token:
        return ""
    return os.path.basename(_unquote(token)).lower()


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    return token


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving unique — these lists are matched in order, so order is API."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
