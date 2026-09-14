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

from sentrook.sanitize.core import apply_secret_patterns
from sentrook.sanitize.rules import SanitizeRules, load_rules

INTERPRETER_RE = re.compile(
    r"^(python3(?:\.[0-9]+)?|python|node|nodejs|bash|sh|zsh)$", re.IGNORECASE
)
SCRIPT_EXT_RE = re.compile(r"\.(py|sh|bash|zsh|js|mjs|cjs)$", re.IGNORECASE)

INLINE_EVAL_FLAGS = frozenset({"-c", "-e", "-p", "-r", "-E", "--eval", "--print"})

HIGH_RISK_SHELL_RE = re.compile(r"(?:\|\||&&|;|`|\$\(|<\(|>\(|\|)")

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


def is_high_risk_command(command: str) -> bool:
    """True when a command must never be skeletonised for allowlist matching.

    Fails closed: an empty command, an untokenisable one, shell metacharacters,
    inline-eval flags, or a fetch binary co-occurring with a shell are all
    high risk. ``skeletonize_command`` returns ``None`` for these.
    """
    trimmed = command.strip()
    if not trimmed:
        return True
    if HIGH_RISK_SHELL_RE.search(trimmed):
        return True

    tokens = tokenize_argv(trimmed)
    if not tokens:
        return True

    for i, token in enumerate(tokens):
        base = basename_of(token).lower()
        if token in INLINE_EVAL_FLAGS or base in INLINE_EVAL_FLAGS:
            return True
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if normalize_interpreter(token) and nxt and nxt in INLINE_EVAL_FLAGS:
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
