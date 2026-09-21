"""Command skeletonisation — Python twin of ``plugin/localAllowlist.ts``.

The OpenClaw plugin owns the *local allowlist* lane: an operator picks "allow
every time" and the plugin stores a skeleton of the command so later matching
invocations skip the review UI on that host. Nothing about that lane reaches
Rookery, so the engine never needed the same logic.

Phase 0's three-lane counterfactual does: to ask "would an allowlist entry have
skipped this review?" offline, the fatigue report must skeletonise exactly the
way the plugin does. Phase 3b needs it again to keep ``localAllowlist.ts`` and
the shipped allow families from disagreeing about what a command *is*.

**This module and ``localAllowlist.ts`` must stay in lockstep.** Both load
``fixtures/skeleton_golden.jsonl`` and assert identical output for every case
there; add a fixture row before changing either side. Same contract as
``sanitize/*.py`` <-> ``plugin/sanitize.ts``.

Deliberate fidelity notes, where JS and Python regex semantics differ:

- JS ``\\d`` is ASCII-only; Python ``\\d`` also matches Unicode digits. Every
  digit class here is written ``[0-9]`` so ``١٢٣`` is not silently an ``<int>``.
- JS ``\\s`` and Python ``\\s`` both match Unicode whitespace, so the tokenizer
  needs no special handling.
- ``URL.origin`` drops the default port and lowercases the host; :func:`pin_http_url`
  reproduces that rather than using a naive scheme+netloc join.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from sentrook.layers.exec_shape import (
    DURATION_RE as _DURATION_RE,
)
from sentrook.layers.exec_shape import (
    ENV_ASSIGN_RE as _ENV_ASSIGN_RE,
)
from sentrook.layers.exec_shape import (
    WRAPPER_VALUE_FLAGS as _WRAPPER_VALUE_FLAGS_SRC,
)
from sentrook.layers.exec_shape import (
    WRAPPERS as _WRAPPERS,
)
from sentrook.sanitize.core import apply_secret_patterns
from sentrook.sanitize.rules import SanitizeRules, load_rules

INTERPRETER_RE = re.compile(
    r"^(python3(?:\.[0-9]+)?|python|node|nodejs|bash|sh|zsh)$", re.IGNORECASE
)
SCRIPT_EXT_RE = re.compile(r"\.(py|sh|bash|zsh|js|mjs|cjs)$", re.IGNORECASE)

INLINE_EVAL_FLAGS = frozenset({"-c", "-e", "-p", "-r", "-E", "--eval", "--print"})

#: Bare builtins that execute their argument as code with no flag at all.
INLINE_EVAL_HEADS = frozenset({"eval", "source", "."})

#: Inline-eval flags **bound to the interpreter that gives them meaning**.
#: Mirrors `INLINE_EVAL_FLAGS_BY_HEAD` in `localAllowlist.ts`. The flat scan this
#: replaces was wrong in both directions: it refused `ls -r`, `cp -r`, `grep -e`,
#: `du -c`, `sort -r`, `tar -c`, `uniq -c` as high risk, and passed
#: `python3 -m <module>`, which executes arbitrary code.
INLINE_EVAL_FLAGS_BY_HEAD: dict[str, frozenset[str]] = {
    "python": frozenset({"-c", "-m"}),
    "python2": frozenset({"-c", "-m"}),
    "python3": frozenset({"-c", "-m"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"eval"}),
    "bun": frozenset({"-e", "--eval"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
    "bash": frozenset({"-c"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
    "dash": frozenset({"-c"}),
    "ksh": frozenset({"-c"}),
    "fish": frozenset({"-c"}),
    "osascript": frozenset({"-e"}),
}

#: Heads whose flags are known *not* to mean "evaluate this as code". The
#: conservative fallback still applies to anything unrecognised, so an omission
#: here costs allowlist eligibility, never safety.
NON_EVAL_FLAG_BINS = frozenset(
    {
        "ls",
        "cp",
        "mv",
        "rm",
        "ln",
        "mkdir",
        "rmdir",
        "touch",
        "stat",
        "file",
        "cat",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "cut",
        "tr",
        "tee",
        "split",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "ack",
        "find",
        "fd",
        "locate",
        "du",
        "df",
        "ps",
        "top",
        "kill",
        "pgrep",
        "pkill",
        "uptime",
        "free",
        "tar",
        "zip",
        "unzip",
        "gzip",
        "gunzip",
        "bzip2",
        "xz",
        "zstd",
        "diff",
        "patch",
        "cmp",
        "md5sum",
        "sha256sum",
        "base64",
        "date",
        "whoami",
        "id",
        "pwd",
        "which",
        "whereis",
        "echo",
        "printf",
        "seq",
        "chmod",
        "chown",
        "readlink",
        "realpath",
        "dirname",
        "basename",
        "git",
        "docker",
        "kubectl",
        "npm",
        "pnpm",
        "yarn",
        "make",
        "cargo",
        "go",
        "jq",
        "yq",
        "xmllint",
        "column",
        "less",
        "more",
        "man",
        "openclaw",
        "gog",
    }
)

#: The packer's separator. A packed excerpt is not valid shell (§1.1).
PACK_SEPARATOR = " \u2026 "

#: Wrapper stripping is defined once, in the engine's `exec_shape`, and reused
#: here. The twin mirrors the TypeScript plugin, and both mirror `exec_shape` —
#: importing rather than re-declaring means the three cannot drift on this axis.
WRAPPER_BINS = _WRAPPERS
WRAPPER_VALUE_FLAGS = _WRAPPER_VALUE_FLAGS_SRC
DURATION_RE = _DURATION_RE
ENV_ASSIGN_RE = _ENV_ASSIGN_RE

#: Substitution, process substitution and redirects. ``;``, ``&&``, ``||`` and
#: ``|`` used to be here, which made *every* compound command unallowlistable
#: — a blunt instrument that worked because the alternative was reasoning
#: about what a compound command does. §3b's per-segment matching is that
#: reasoning, so the separators come out and the things a segment split cannot
#: make safe stay:
#:
#: * substitution, because ``ls $(curl evil)`` is one segment and the shape
#:   cannot say what the substitution evaluated to;
#: * a pipe into an interpreter, because ``echo hi | sh`` is two individually
#:   harmless segments — see :func:`pipes_into_interpreter`;
#: * a redirect, because ``ls > ~/.bashrc`` is one segment whose skeleton
#:   differs from a recorded ``ls`` only by tokens the skeletonizer happens to
#:   keep, and relying on that is relying on an accident.
#:
#: **Mirrored in ``localAllowlist.ts``** and pinned by
#: ``fixtures/skeleton_golden.jsonl``, which both sides read.
HIGH_RISK_SHELL_RE = re.compile(r"(?:`|\$\(|<\(|>\(|>>?|<)")

#: Heads that turn their standard input into code. A pipe *into* one of these
#: is the shape per-segment matching cannot see.
PIPE_SINK_INTERPRETERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "python",
        "python2",
        "python3",
        "node",
        "nodejs",
        "perl",
        "ruby",
        "php",
        "eval",
        "source",
        ".",
        "xargs",
        "env",
    }
)

URL_RE = re.compile(r"^https?://|^[a-z0-9.-]+:[0-9]+$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
ISO_DATE_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?$"
)
INT_RE = re.compile(r"^-?[0-9]+$")
LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)

BARE_DANGEROUS_BINS = frozenset(
    {
        "curl",
        "wget",
        "bash",
        "sh",
        "zsh",
        "python",
        "python3",
        "node",
        "nodejs",
        "perl",
        "ruby",
        "php",
        "lua",
        "osascript",
    }
)

#: Fetch bins whose URL is the identity of the action, not a volatile.
FETCH_BINS = frozenset({"curl", "wget"})

_WS_RE = re.compile(r"\s")
_WS_RUN_RE = re.compile(r"\s+")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def tokenize_argv(command: str) -> list[str]:
    """Split on unquoted whitespace, dropping quote characters themselves.

    Mirrors the plugin exactly, including that adjacent quoted runs concatenate
    (``"cu""rl"`` -> ``curl``) and that an unterminated quote swallows the rest.
    This is not a shell parser and is not trying to be — Phase 1 ``exec_shape``
    is where real parsing lands.
    """
    tokens: list[str] = []
    current = ""
    quote: str | None = None
    for ch in command:
        if quote is not None:
            if ch == quote:
                quote = None
            else:
                current += ch
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if _WS_RE.match(ch):
            if current:
                tokens.append(current)
                current = ""
            continue
        current += ch
    if current:
        tokens.append(current)
    return tokens


def basename_of(token: str) -> str:
    parts = token.replace("\\", "/").split("/")
    return parts[-1] or token


def normalize_interpreter(token: str) -> str | None:
    base = basename_of(token)
    if not INTERPRETER_RE.match(base):
        return None
    lower = base.lower()
    if lower.startswith("python"):
        return "python"
    if lower in ("nodejs", "node"):
        return "node"
    if lower in ("bash", "zsh"):
        return lower
    if lower == "sh":
        return "sh"
    return lower


def is_path_like(token: str) -> bool:
    return (
        token.startswith("/")
        or token.startswith("./")
        or token.startswith("../")
        or token.startswith("~/")
        or bool(_WINDOWS_DRIVE_RE.match(token))
    )


def looks_like_script_path(token: str) -> bool:
    if not token or token.startswith("-"):
        return False
    if URL_RE.search(token):
        return False
    return bool(SCRIPT_EXT_RE.search(token)) or token.startswith("./") or token.startswith("../")


def is_packed_excerpt(command: str) -> bool:
    """True when the text is a signal-packed excerpt rather than a real command."""
    return PACK_SEPARATOR in command


def split_segments(command: str) -> list[list[str]]:
    """Split a command into simple commands, mirroring the TS twin."""
    segments: list[list[str]] = []
    current: list[str] = []
    for raw in tokenize_argv(command):
        token = raw
        broke = False
        while token.endswith((";", "|", "&")):
            token = token[:-1]
            broke = True
        if token in ("&&", "||", ";", "|"):
            if current:
                segments.append(current)
            current = []
            continue
        if token:
            current.append(token)
        if broke:
            if current:
                segments.append(current)
            current = []
    if current:
        segments.append(current)
    return segments


def segment_head(tokens: list[str]) -> str:
    """Peel wrappers and leading env assignments off one segment."""
    rest = list(tokens)
    while rest and ENV_ASSIGN_RE.match(rest[0]):
        rest = rest[1:]
    if not rest:
        return ""
    guard = 0
    while guard < 8:
        guard += 1
        head = basename_of(rest[0]).lower()
        if head not in WRAPPER_BINS or len(rest) < 2:
            return head
        value_flags = WRAPPER_VALUE_FLAGS.get(head, frozenset())
        i = 1
        while i < len(rest) and rest[i].startswith("-") and rest[i] != "-":
            flag = rest[i]
            i += 1
            if flag in value_flags and i < len(rest):
                i += 1
        if head == "timeout" and i < len(rest) and DURATION_RE.match(rest[i]):
            i += 1
        if head == "env":
            while i < len(rest) and ENV_ASSIGN_RE.match(rest[i]):
                i += 1
        if i >= len(rest):
            return head
        rest = rest[i:]
    return basename_of(rest[0]).lower()


def segment_is_inline_eval(tokens: list[str]) -> bool:
    """True when this segment executes its argument as code (§1.1)."""
    head = segment_head(tokens)
    if not head:
        return False
    if head in INLINE_EVAL_HEADS:
        return True
    bound = INLINE_EVAL_FLAGS_BY_HEAD.get(head)
    if bound is not None:
        return any(t in bound or t.split("=")[0] in bound for t in tokens)
    if head in NON_EVAL_FLAG_BINS:
        return False
    # Unknown binary: fall back to the blunt check. Cost of being wrong here is
    # only that the command cannot be added to a host allowlist.
    return any(t in INLINE_EVAL_FLAGS for t in tokens)


def shell_significant(command: str) -> str | None:
    """The command with quoted content blanked out.

    An argument character must not be readable as shell syntax. ``grep
    '<html>' page.txt`` and ``grep "=>" src.js`` are routine, and a raw regex
    looking for ``<`` or ``>`` calls both of them redirects — the same
    text-versus-parse mistake that let ``"git" push`` past the engine's argv
    guards, in the other direction.

    Single-quoted spans are fully literal in shell and are blanked entirely.
    Double-quoted spans keep ``$``, ``(``, ``)`` and a backtick, because
    substitution still happens inside them.

    **An unbalanced quote returns ``None``**, and every caller treats that as
    high risk. Guessing where the span ends would blank the rest of the
    command, which is the one direction this must not fail in.

    **Mirrored in ``localAllowlist.ts``.**
    """
    out: list[str] = []
    quote: str | None = None
    for ch in command:
        if quote is None:
            if ch in ("'", '"'):
                quote = ch
                out.append(" ")
                continue
            out.append(ch)
            continue
        if ch == quote:
            quote = None
            out.append(" ")
            continue
        out.append(ch if quote == '"' and ch in "$()`" else " ")
    return "".join(out) if quote is None else None


def pipes_into_interpreter(command: str) -> bool:
    """Whether any ``|`` in the command feeds a head that executes its stdin.

    The hole per-segment matching opens, closed in the same change. ``echo
    hi`` and ``sh`` are each an unremarkable segment that an operator might
    well have allowlisted; ``echo hi | sh`` is arbitrary code and nothing
    about either half says so.

    Split on the **masked** text rather than on tokens: ``echo hi|sh`` has no
    whitespace around the pipe, so the tokenizer yields one token ``hi|sh``
    and a token-level scan missed it entirely. A ``|`` inside quotes is
    already blanked, so ``grep 'a|b' f`` is not a pipe here.

    **Mirrored in ``localAllowlist.ts``.**
    """
    masked = shell_significant(command.strip())
    if masked is None:
        return True
    for part in masked.split("|")[1:]:
        # `|&` pipes stderr too and leaves a leading `&`; `||` leaves an empty
        # part and then the next command, which is not a pipe but does still
        # run the interpreter, so treating it the same way is the
        # conservative reading rather than a mistake.
        first = part.lstrip("&|").strip().split()
        if not first:
            continue
        if basename_of(first[0]).lower() in PIPE_SINK_INTERPRETERS:
            return True
    return False


def is_high_risk_command(command: str) -> bool:
    """True when a command must never be skeletonised for allowlist matching.

    Fails closed: an empty command, an untokenisable one, shell metacharacters,
    inline-eval flags, or a fetch binary co-occurring with a shell are all
    high risk. ``skeletonize_command`` returns ``None`` for these.
    """
    trimmed = command.strip()
    if not trimmed:
        return True
    if is_packed_excerpt(trimmed):
        return True
    masked = shell_significant(trimmed)
    if masked is None:  # unbalanced quote: we cannot say what this is
        return True
    if HIGH_RISK_SHELL_RE.search(masked):
        return True
    if pipes_into_interpreter(trimmed):
        return True

    tokens = tokenize_argv(trimmed)
    if not tokens:
        return True

    for segment in split_segments(trimmed):
        if segment_is_inline_eval(segment):
            return True

    joined = " ".join(tokens).lower()
    if re.search(r"\b(curl|wget)\b", joined) and re.search(r"\b(bash|sh|zsh)\b", joined):
        return True
    return False


def pin_http_url(token: str) -> str | None:
    """Reproduce JS ``${url.origin}${url.pathname || "/"}``.

    ``URL.origin`` lowercases the host and omits the port when it is the scheme
    default, so ``http://Example.com:80/x`` pins to ``http://example.com/x``.
    """
    if not re.match(r"^https?://", token, re.IGNORECASE):
        return None
    try:
        parts = urlsplit(token)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    netloc = host if port is None or port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path or '/'}"


def skeletonize_general_token(token: str, *, pin_http_urls: bool = False) -> str:
    if pin_http_urls:
        pinned = pin_http_url(token)
        if pinned:
            return pinned
    if token.startswith("-") and not ISO_DATE_RE.match(token):
        return token
    if URL_RE.search(token):
        return "<url>" if token.startswith("http") else token
    if EMAIL_RE.match(token):
        return "<email>"
    if UUID_RE.match(token):
        return "<uuid>"
    if ISO_DATE_RE.match(token):
        return "<date>"
    if INT_RE.match(token):
        return "<int>"
    if LONG_HEX_RE.match(token):
        return "<hex>"
    if is_path_like(token):
        normalized = token.replace("\\", "/")
        parts = normalized.split("/")
        leaf = parts[-1] if parts else ""
        if (
            UUID_RE.match(leaf)
            or ISO_DATE_RE.match(leaf)
            or INT_RE.match(leaf)
            or LONG_HEX_RE.match(leaf)
        ):
            parts[-1] = "<file>"
            return "/".join(parts)
        return token
    return token


def skeletonize_command(command: str) -> str | None:
    """Volatile-stripped identity of a command, or ``None`` when not skeletonisable.

    Dangerous binaries and interpreters must retain *literal* structure after
    volatiles are replaced — ``curl <url>`` alone carries no identity worth
    trusting, so it returns ``None`` rather than a skeleton that would match any
    fetch at all.
    """
    if is_high_risk_command(command):
        return None

    tokens = tokenize_argv(command.strip())
    if not tokens:
        return None

    bin_name = basename_of(tokens[0]).lower()
    pin_http_urls = bin_name in FETCH_BINS

    if bin_name in BARE_DANGEROUS_BINS or normalize_interpreter(tokens[0]):
        rest = [skeletonize_general_token(t, pin_http_urls=pin_http_urls) for t in tokens[1:]]
        literal_rest = [
            t for t in rest if not t.startswith("<") and not t.endswith(">") and t != "<file>"
        ]
        if not literal_rest:
            return None
        return " ".join([tokens[0], *rest])

    return " ".join(skeletonize_general_token(t) for t in tokens)


def allowlist_command_skeleton(command: str, rules: SanitizeRules | None = None) -> str | None:
    """Skeleton used for allowlist record + match: secrets scrubbed, whitespace collapsed."""
    skeleton = skeletonize_command(command)
    if skeleton is None:
        return None
    rules = rules or load_rules()
    fingerprint = _WS_RUN_RE.sub(" ", apply_secret_patterns(skeleton, rules)).strip()
    return fingerprint or None


@dataclass(frozen=True)
class BindableScript:
    """Interpreter + single local script form, for the ``script_bind`` lane."""

    interpreter: str
    script_path: str
    trailing_args: tuple[str, ...]


def parse_bindable_script(command: str) -> BindableScript | None:
    """Detect ``interpreter + one local script`` forms; ``None`` when not bindable.

    Pure — no filesystem access. The plugin binds such commands to a content
    hash of the script so an edit invalidates the allowlist entry; this twin only
    needs the *shape* decision, which is the part that must not drift.
    """
    if is_high_risk_command(command):
        return None

    tokens = tokenize_argv(command.strip())
    if not tokens:
        return None

    # Direct script: ./foo.py or /path/foo.sh
    if looks_like_script_path(tokens[0]) and SCRIPT_EXT_RE.search(tokens[0]):
        ext = tokens[0].lower()
        interpreter = "sh"
        if ext.endswith(".py"):
            interpreter = "python"
        elif ext.endswith((".js", ".mjs", ".cjs")):
            interpreter = "node"
        elif ext.endswith(".bash"):
            interpreter = "bash"
        elif ext.endswith(".zsh"):
            interpreter = "zsh"
        return BindableScript(interpreter, tokens[0], tuple(tokens[1:]))

    interpreter = normalize_interpreter(tokens[0])
    if not interpreter:
        return None

    # Skip leading interpreter flags that are not inline-eval (e.g. -u, -O).
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in INLINE_EVAL_FLAGS:
            return None
        if token.startswith("-"):
            i += 1
            continue
        break

    if i >= len(tokens):
        return None
    script_path = tokens[i]
    if not looks_like_script_path(script_path) and not SCRIPT_EXT_RE.search(script_path):
        # Extensionless only when it carries a path separator (./bin/helper);
        # otherwise it could be a module name.
        if "/" not in script_path and "\\" not in script_path:
            return None
    if script_path.startswith("-"):
        return None

    return BindableScript(interpreter, script_path, tuple(tokens[i + 1 :]))
