"""Deterministic structure for shell commands — Phase 1, §1.1.

Derived at normalisation for every step whose tool is ``exec``. Never stored on
the PlanIR wire: the shape is attached to the in-memory step (an excluded field)
and echoed into ``ScanResult`` for traces.

Fail closed. A command that does not parse gets ``parse_ok=False`` and no
``segments``, so an allow rule requiring ``_shape.parse_ok: "^true$"`` can never
fire on something we did not understand. ``heads`` is still populated where it
can be — tree-sitter is error-tolerant and a command with one damaged fragment
often still yields correct heads, which is useful for diagnostics even when the
command is not eligible to be allowed.

Derivation runs on the **redacted** command (what rules see). F11/F16 measured
that redaction is parser-safe, including the marker-bearing forms slice 1A
introduced (``[REDACTED:a3f19c]``, ``sk-ant-[REDACTED]``).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from sentrook.layers.path_classes import (
    ExecPath,
    derive_path_roles,
    derive_paths,
    derive_url_hosts,
    roll_up_path_classes,
)
from sentrook.sanitize.signal_excerpt import _SEP as _PACK_SEPARATOR

#: Commands longer than this are not parsed at all (``parse_ok=False``). The
#: command budget is 4000 (D1), so this only catches a caller that bypassed
#: sanitize; it bounds worst-case parser cost rather than being a real limit.
MAX_PARSE_CHARS = 16_000

#: Stripped before the head is taken, recursively. ``sudo`` is recorded but is
#: deliberately in this list: a rule that wants to know about sudo reads
#: ``wrappers``, and a rule matching on ``heads`` should see the real binary
#: rather than silently failing to match because sudo was in front of it.
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

#: Wrappers that **elevate privilege**. Stripped like any other so detection
#: rules still see the real binary — but recorded separately, because stripping
#: alone makes elevation invisible to exactly the field allow rules key on:
#:
#:     cat /etc/passwd       -> heads ['cat']
#:     sudo cat /etc/shadow  -> heads ['cat']
#:
#: An allow rule matching ``_shape.heads: "^(ls|cat|wc)$"`` would fire on both.
#: This is a known failure mode in the wild, not a hypothetical: charmbracelet's
#: crush lists `timeout`/`nohup`/`nice`/`env` among its safe command prefixes, so
#: `timeout rm -rf /` prefix-matches as safe; and Codex's POSIX safety check
#: strips sudo with a blind `command[1..]`, so `sudo -u root rm -rf /` is
#: re-examined as `-u root rm -rf /` with `-u` never modelled as consuming
#: `root`. Phase 3b must require `_shape.privileged: "^false$"` on every allow
#: rule, enforced at rule compile time (slice 1B-3) rather than by convention.
PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas", "run0", "pkexec"})

#: ``head -c`` style flags that take a value, for wrapper stripping only. When a
#: wrapper is followed by one of these we must skip the flag *and* its argument
#: before the real binary. Keeping this narrow is deliberate — guessing wrongly
#: makes the head wrong, which is worse than treating the wrapper as the head.
#:
#: Public, along with ``WRAPPERS``, ``DURATION_RE`` and ``ENV_ASSIGN_RE``,
#: because the skeleton twin (``serve/skeleton.py``) strips wrappers the same way
#: and imports these rather than re-declaring them — and the TypeScript plugin
#: mirrors the same semantics, checked by ``fixtures/exec_shape_golden.jsonl``.
#: One definition is what stops the three drifting on this axis.
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

#: Wrappers that take a leading *positional* before the real command, which a
#: flag-skipping loop would otherwise mistake for the binary (``timeout 30 nice
#: python3 …`` yielding a head of ``30``). Each entry is a predicate over the
#: token: it is only consumed when it actually looks like that wrapper's
#: argument, so an unusual form leaves the head alone rather than eating it.
DURATION_RE = re.compile(r"\A\d+(?:\.\d+)?[smhd]?\Z")
ENV_ASSIGN_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*=")

_WRAPPER_POSITIONAL: dict[str, tuple[re.Pattern[str], bool]] = {
    # (predicate, repeats) — `timeout` takes exactly one duration; `env` and
    # `sudo` take any number of KEY=VALUE assignments.
    "timeout": (DURATION_RE, False),
    "env": (ENV_ASSIGN_RE, True),
    # `sudo` interprets `VAR=value` arguments as environment settings, so
    # without this the assignment is taken for the binary:
    #
    #     sudo LD_PRELOAD=/tmp/x.so python3 -c '…'
    #       -> heads ['x.so'], inline_eval False, env_assignments []
    #
    # which loses the head, the inline-eval flag and the prefix in one go. F18
    # and F30 a third time: a construct in front of the command hiding what
    # rules key on. Only `sudo` is listed — `timeout 5 FOO=1 ls` really would
    # exec a binary named `FOO=1` and fail, so reporting that head is correct,
    # and `doas`/`pkexec` do not take assignments as arguments at all.
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
_SHELL_HEADS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish", "ash"})
_INTERPRETER_HEADS = frozenset(
    {"python", "python2", "python3", "node", "deno", "bun", "perl", "ruby", "php", "osascript"}
)
_NET_HEADS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "http", "httpie"})


@dataclass(slots=True)
class ExecSegment:
    """One simple command inside a compound command."""

    head: str
    argv: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    positional: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "head": self.head,
            "argv": list(self.argv),
            "flags": list(self.flags),
            "positional": list(self.positional),
        }


@dataclass(slots=True)
class ExecShape:
    """§1.1, complete: Phase 2 added ``path_classes`` and ``url_hosts``."""

    parse_ok: bool = False
    heads: list[str] = field(default_factory=list)
    wrappers: list[str] = field(default_factory=list)
    inline_eval: bool = False
    sinks: list[str] = field(default_factory=list)
    substitution: bool = False
    packed: bool = False
    #: A privilege-elevation wrapper was stripped (sudo/doas/run0/pkexec).
    #: Separate from `wrappers` so an allow rule can refuse elevation with one
    #: constraint that cannot be forgotten — see PRIVILEGE_WRAPPERS.
    privileged: bool = False
    #: Every path class the command touches, in `PATH_CLASSES` order (§1.1).
    #: A *set*, not one winning label: allow eligibility is a property of the
    #: whole path set, and a single label cannot say "touches nothing
    #: sensitive". Derived whole-command, so it survives a `cd` rebase and a
    #: parse failure — unlike `segments`, it is **not** dropped when
    #: `parse_ok` is false, because a class we can still see is a reason to
    #: refuse and never a reason to allow.
    path_classes: list[str] = field(default_factory=list)
    #: `KEY=VALUE` assignments prefixed to a command, from either form —
    #: `LD_PRELOAD=x ls` or `env LD_PRELOAD=x ls`.
    #:
    #: This is F18 a second time. Wrapper stripping made `sudo` invisible to
    #: `heads`, so `privileged` was added to let an allow rule refuse it. An
    #: environment assignment was invisible in the *whole shape*: it is its own
    #: tree-sitter node that `_collect_commands` discarded, and the `env` form
    #: was eaten by wrapper stripping. `LD_PRELOAD=/tmp/evil.so ls` therefore
    #: produced a shape identical to a bare `ls` — and Phase 3b's Listing
    #: family, written to the plan's stated constraints, allowed it.
    env_assignments: list[str] = field(default_factory=list)
    #: Roles referenced anywhere in the command text — the §1.3 whole-command
    #: defence, which sees bare basenames, redirect targets and quoted
    #: references that the per-path view structurally cannot. A property of the
    #: command, so no quantifier is implied and a rule may match it directly.
    path_roles: list[str] = field(default_factory=list)
    #: Every path the command references, classified on both axes (§1.1).
    #: **This is what rules read**, through the `paths:` condition; the flat
    #: `path_classes` roll-up above is for metrics only and is derived from
    #: this list, so the two cannot disagree.
    paths: list[ExecPath] = field(default_factory=list)
    #: Lowercased hostnames of every http(s) URL in the command.
    url_hosts: list[str] = field(default_factory=list)
    segments: list[ExecSegment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parse_ok": self.parse_ok,
            "heads": list(self.heads),
            "wrappers": list(self.wrappers),
            "inline_eval": self.inline_eval,
            "sinks": list(self.sinks),
            "substitution": self.substitution,
            "packed": self.packed,
            "privileged": self.privileged,
            "env_assignments": list(self.env_assignments),
            "path_classes": list(self.path_classes),
            "path_roles": list(self.path_roles),
            "paths": [p.to_dict() for p in self.paths],
            "url_hosts": list(self.url_hosts),
            "segments": [s.to_dict() for s in self.segments],
        }


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


def is_packed(command: str) -> bool:
    """True if ``command`` is a signal-packed excerpt rather than valid shell.

    Bound to the packer's own separator rather than a copy of it: a packed
    excerpt preferentially keeps command-ish lines, so it can parse *successfully*
    into misleading heads. That is worse than failing, which is why this check
    runs before the parser and forces ``parse_ok=False``.
    """
    return _PACK_SEPARATOR in command


def derive_exec_shape(command: str | None) -> ExecShape:
    """Derive the shape of one exec command. Never raises."""
    if not command or not command.strip():
        return ExecShape()
    if is_packed(command):
        return ExecShape(packed=True)
    if len(command) > MAX_PARSE_CHARS:
        return ExecShape()

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

    raw_segments: list[tuple[str, list[str], list[str]]] = []
    _collect_commands(root, source, raw_segments)

    wrappers: list[str] = []
    assignments: list[str] = []
    for raw_head, raw_argv, raw_assignments in raw_segments:
        assignments.extend(raw_assignments)
        head, argv, stripped, wrapped_assignments = _strip_wrappers(raw_head, raw_argv)
        wrappers.extend(stripped)
        assignments.extend(wrapped_assignments)
        head = _basename(head)
        if not head:
            continue
        flags = [a for a in argv if a.startswith("-") and a != "-"]
        positional = [a for a in argv if not a.startswith("-")]
        shape.segments.append(
            ExecSegment(head=head, argv=list(argv), flags=flags, positional=positional)
        )
        shape.heads.append(head)
        if _segment_is_inline_eval(head, argv):
            shape.inline_eval = True

    shape.wrappers = _dedupe(wrappers)
    shape.env_assignments = _dedupe(assignments)
    shape.privileged = any(w in PRIVILEGE_WRAPPERS for w in shape.wrappers)
    shape.substitution = _has_substitution(root)
    shape.sinks = _derive_sinks(root, source, shape)
    # Derived here, before `segments` is dropped on a parse failure: the
    # per-path view needs the tokens the parse found, while `path_roles` is
    # whole-command and survives a failed parse on its own.
    #
    # One role scan, shared by all three views. The group regexes dominate the
    # cost, so computing them per consumer would run four scans.
    shape.path_roles = derive_path_roles(command)
    shape.paths = derive_paths(command, [s.argv for s in shape.segments], shape.path_roles)
    shape.path_classes = roll_up_path_classes(shape.path_roles, shape.paths)
    shape.url_hosts = derive_url_hosts(command)
    if not shape.parse_ok:
        # Heads stay for diagnostics; segments do not, so no allow rule can build
        # a constraint out of a structure we are not confident in.
        shape.segments = []
    return shape


#: Arg keys that carry a shell command, in adapter-normalised PlanIR.
COMMAND_ARG_KEYS = ("command", "cmd")

#: Tools whose steps carry a shell command. Process-run-like arms are folded
#: onto ``exec`` by adapters before this point (§1.1).
EXEC_TOOLS = frozenset({"exec"})


def command_of(step: Any) -> str | None:
    """The shell command on an exec step, or None if this is not one."""
    if getattr(step, "tool", None) not in EXEC_TOOLS:
        return None
    args = getattr(step, "args", None) or {}
    for key in COMMAND_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str):
            return value
    return None


#: Separator between the tool name and a head in an `exec:<head>` tool pattern.
TOOL_HEAD_SEPARATOR = ":"

#: Reserved namespace for derived shape fields in YAIRA `args_match` (§1.2).
#: Defined here rather than in `l2_match` so the rule compiler can validate
#: `_shape.*` keys without importing the matcher — that direction closes a cycle
#: (compiler -> l2_match -> rules.models -> rules.loader -> compiler).
SHAPE_KEY_PREFIX = "_shape."


def step_tool_tokens(step: Any) -> frozenset[str]:
    """Every tool token a YAIRA pattern may match against for this step.

    The plain tool name, plus one ``exec:<head>`` token per head on the step's
    shape. **L1 candidacy and L2 matching must both go through this function.**

    That is not tidiness. L1 decides candidacy from a set of tool strings while
    L2 matches against a step, so if the two computed tokens differently a rule
    could pass L1 and never match at L2 (wasted evaluation) or — the dangerous
    direction — be skipped at L1 despite matching at L2, which is a detection
    silently lost with nothing in the trace to show for it. One function makes
    that class of divergence unrepresentable.
    """
    tool = getattr(step, "tool", None)
    if not tool:
        return frozenset()
    tokens = {tool}
    shape = getattr(step, "exec_shape", None)
    for head in getattr(shape, "heads", ()) or ():
        if head:
            tokens.add(f"{tool}{TOOL_HEAD_SEPARATOR}{head}")
    return frozenset(tokens)


def plan_tool_tokens(plan: Any) -> set[str]:
    """Union of :func:`step_tool_tokens` over a plan — the L1 candidacy set."""
    tokens: set[str] = set()
    for step in getattr(plan, "steps", []):
        tokens |= step_tool_tokens(step)
    return tokens


def attach_exec_shapes(plan: Any) -> None:
    """Attach ``exec_shape`` to every exec step of ``plan``, in place.

    Called once per scan on the redacted plan. Non-exec steps keep ``None`` so
    ``_shape.*`` keys are *absent* rather than empty for them, which is what
    makes a rule requiring a shape fail closed on a non-exec step (§1.2).
    """
    for step in getattr(plan, "steps", []):
        command = command_of(step)
        if command is None:
            continue
        step.exec_shape = derive_exec_shape(command)


def _collect_commands(
    node: Any, source: bytes, out: list[tuple[str, list[str], list[str]]]
) -> None:
    """Depth-first, source order: one (head, argv, assignments) per simple command.

    ``assignments`` is the ``KEY=VALUE`` prefix. tree-sitter gives it its own
    node type, and dropping it is how ``LD_PRELOAD=/tmp/evil.so ls`` used to
    produce a shape identical to a bare ``ls`` — see ``env_assignments``.
    """
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
            elif child.type == "simple_expansion" or child.type == "expansion":
                argv.append(text)
        if head:
            out.append((head, argv, assignments))
    for child in node.children:
        _collect_commands(child, source, out)


def _strip_wrappers(head: str, argv: list[str]) -> tuple[str, list[str], list[str], list[str]]:
    """Peel ``timeout 30 nice python3 …`` down to ``python3``, recording wrappers.

    Recursive by loop, because wrappers stack in real traffic. Stops at the first
    token that is not a wrapper, and never strips past the end — a bare ``sudo``
    with no command stays ``sudo`` rather than becoming an empty head.
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
                    # `env LD_PRELOAD=x ls` hides the assignment in the wrapper's
                    # own argv; stripping it silently would lose exactly what a
                    # bare `LD_PRELOAD=x ls` was already losing.
                    assignments.append(consumed)
                if not repeats:
                    break
        if not rest:
            # Wrapper with no command after it (e.g. `timeout --help`). Keep the
            # wrapper as the head rather than inventing one.
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


def _derive_sinks(node: Any, source: bytes, shape: ExecShape) -> list[str]:
    """Where does data flow *out* of, or executable content *into*, this command."""
    sinks: list[str] = []

    def walk(n: Any) -> None:
        if n.type == "pipeline":
            _pipeline_sinks(n, source, sinks)
        elif n.type == "file_redirect":
            if _is_write_to_path(n, source):
                sinks.append("redirect_to_path")
        elif n.type == "heredoc_redirect":
            sinks.append("heredoc")
        for child in n.children:
            walk(child)

    walk(node)
    if shape.heads and shape.heads[0] in _NET_HEADS and "redirect_to_path" not in sinks:
        # A fetch that writes nowhere is still a fetch; `pipe_to_net` covers the
        # outbound case and is added by the pipeline walk.
        pass
    return _dedupe(sinks)


#: Redirect operators that actually write somewhere. `<` reads, and `>&` / `<&`
#: duplicate a file descriptor rather than naming a path.
_WRITE_REDIRECT_OPS = frozenset({">", ">>", "&>", "&>>", ">|"})

#: Destinations that discard rather than store. Writing here is not a sink in
#: any sense Phase 3b cares about.
_NULL_SINKS = frozenset({"/dev/null", "/dev/zero"})


def _is_write_to_path(node: Any, source: bytes) -> bool:
    """Whether a ``file_redirect`` actually writes data to a filesystem path.

    Measured on the corpus, a naive "any file_redirect is a sink" rule fired on
    **52% of all commands** — and every one sampled was either ``2>/dev/null``
    (discarding stderr) or ``2>&1`` (a descriptor dup with no path at all).

    That matters far more than it looks. Every allow rule requires
    ``_shape.sinks: "^$"``, and ``2>/dev/null`` is ubiquitous in exactly the
    benign listing commands Phase 3b exists to approve — so this would have
    silently suppressed most of the fatigue relief while every test still passed.
    """
    operator = None
    destination = None
    for child in node.children:
        text = source[child.start_byte : child.end_byte].decode("utf-8", "replace")
        if child.type in ("file_descriptor",):
            continue
        if operator is None and not text.strip().startswith(("/", "~", ".", "$")):
            # First non-fd token is the operator (`>`, `>>`, `>&`, `&>`, `<`).
            if text.strip() in _WRITE_REDIRECT_OPS or text.strip() in ("<", ">&", "<&", "<<<"):
                operator = text.strip()
                continue
        if operator is not None and destination is None:
            destination = _unquote(text.strip())
    if operator not in _WRITE_REDIRECT_OPS:
        return False
    if destination is None:
        return False
    # `2>&1` parses as operator `>&` (rejected above), but be defensive: a bare
    # number destination is a descriptor, not a path.
    if destination.isdigit():
        return False
    return destination not in _NULL_SINKS


def _pipeline_sinks(node: Any, source: bytes, sinks: list[str]) -> None:
    """Classify each stage a pipeline feeds *into* by that stage's head."""
    stages = [c for c in node.children if c.type in ("command", "pipeline", "subshell")]
    for stage in stages[1:]:
        head = _basename(_first_head(stage, source))
        if head in _SHELL_HEADS:
            sinks.append("pipe_to_shell")
        elif head in _INTERPRETER_HEADS:
            sinks.append("pipe_to_interpreter")
        elif head in _NET_HEADS:
            sinks.append("pipe_to_net")


def _first_head(node: Any, source: bytes) -> str:
    found: list[tuple[str, list[str], list[str]]] = []
    _collect_commands(node, source, found)
    return found[0][0] if found else ""


def _basename(token: str) -> str:
    """``/usr/bin/python3`` → ``python3``. Lowercased, per §1.1."""
    if not token:
        return ""
    return os.path.basename(_unquote(token)).lower()


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    return token


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving unique — these lists are matched by regex, so order is API."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
