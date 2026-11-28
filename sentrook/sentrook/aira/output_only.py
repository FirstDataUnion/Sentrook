"""Whether a shell read of an env file can only hand back masked values, names or a listing.

A credential read whose only way into the session is the output the call returns holds nothing when that output
shows no value (`state.token.PendingMarks.output_only`, `prepare.shown_output`). This module answers the first half
for the pending call. It recognises a few exact shapes of exec command and nothing else: anything it does not
recognise keeps the session flag, as before. Code programs are never recognised, because what a program prints
cannot be read reliably from its text.

A command is a sequence of statements joined by `;`, `&&` or `||`. Besides the pipelines below, a statement may
only be `set -a` / `set +a`, `echo` of fixed text (no `-n` or `-e`), `test` / `[ … ]` /
`[[ … ]]`, `true` or `:`. The pipelines:

- masked (`shell`): whole-line readers (`cat FILE`, `grep [-EFivwxnHhs] PATTERN [FILE]`, `head`, `tail`) ending in
  a `sed` that is exactly `s<d>=.*<d>=<mask><d>`, so every value after its `=` is replaced by fixed text;
- names (`shell`): whole-line readers, then a names extractor (`grep -o` with an anchored character class without
  `=` such as `'^[A-Z0-9_]*'`, `cut -d= -f1`, `sed 's/=.*//'`), then optionally `tr '\\n'` to a blank or comma;
- listing (`list`): `ls`, then `head`, `tail`, `wc` or `grep` on its output only.

There may be no redirect but to `/dev/null` or of errors into the output (`2>&1`). Sourcing a file is not one of
them: it runs the file, and a shell kept between calls would keep its values. Also ruled out: an input redirect, an
expansion (`$` or a backquote) outside single quotes, a backslash escape, a background job, a subshell, a group,
a newline, and a quoted operator.

Returns `shell`, `list` or None.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from ..planir.models import ToolKind
from ..prepare.entities import is_code_call

SHELL, LIST = "shell", "list"

_OPERATOR_CHARS = frozenset("();<>|&")
_SEPARATORS = frozenset({";", "&&", "||"})
_GREPS = frozenset({"grep", "egrep", "fgrep"})
#: Short grep options that keep every printed line whole.
_GREP_LINE_FLAGS = frozenset("EFivwxnHhs")
_DOTENV = re.compile(r"(?:^|/)(?:[\w.-]*\.env|\.env(?:\.[\w-]+)?)$")
_DIGITS = re.compile(r"\d+")
_COUNT = re.compile(r"[-+]?\d+")
#: `s<d>=.*<d><replacement><d>[g]`: the whole value after `=` replaced by fixed text (no `&`, no back-reference).
_SED_MASK = re.compile(r"s(?P<d>[/|#,:%@])=\.\*(?P=d)(?P<r>(?:(?!(?P=d))[^&\\])*)(?P=d)g?")
#: An anchored character class without `=`: `^[A-Z_]*`, `^[A-Za-z_][A-Za-z0-9_]*`.
_CLASS = r"\[(?:A-Z|a-z|0-9|[A-Za-z0-9_])+\]"
_NAMES_PATTERN = re.compile(rf"\^{_CLASS}[*+]?(?:{_CLASS}[*+])?")
_SINGLE_QUOTED = re.compile(r"'[^']*'")
_DOUBLE_QUOTED = re.compile(r'"[^"]*"')
_COMMENT = re.compile(r"(?:^|[\s;&|()])#")
_QUOTED_OPERATOR = re.compile(r"""(['"])[();<>|&]+\1""")


def _tokens(command: str) -> list[str] | None:
    if not command or "\n" in command or "\r" in command or _QUOTED_OPERATOR.search(command):
        return None
    unquoted = _SINGLE_QUOTED.sub("''", command)
    if "$" in unquoted or "`" in unquoted or "\\" in unquoted:
        return None
    if _COMMENT.search(_DOUBLE_QUOTED.sub('""', unquoted)):
        return None  # the shell ignores the rest of the line from an unquoted `#`
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return None


def _statements(tokens: list[str]) -> list[list[list[str]]] | None:
    """Statements, each a list of pipeline stages (word lists), with the allowed redirects removed; None when an
    operator or redirect is not allowed."""
    statements: list[list[list[str]]] = []
    stages: list[list[str]] = []
    words: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if not t or not set(t) <= _OPERATOR_CHARS:
            if t.startswith("#") and not words:
                return None  # a comment hides the rest of the line from the shell, not from this reading
            words.append(t)
            i += 1
            continue
        if t in _SEPARATORS or t == "|":
            if not words:
                return None
            stages.append(words)
            words = []
            if t != "|":
                statements.append(stages)
                stages = []
            i += 1
            continue
        target = tokens[i + 1] if i + 1 < len(tokens) else None
        fd = words[-1] if words and _DIGITS.fullmatch(words[-1]) else None
        # output thrown away, or errors joined to the output; never the output sent past the next stage
        if (t in (">", ">>") and target == "/dev/null") or (
            t == ">&" and target == "1" and fd == "2"
        ):
            if fd is not None:
                words.pop()  # the redirected stream's number
            i += 2
            continue
        return None
    if not words:
        return None  # a trailing operator
    stages.append(words)
    statements.append(stages)
    return statements


def _plain_statement(words: list[str]) -> bool:
    head, args = words[0], words[1:]
    if head == "set":
        return args in (["-a"], ["+a"])
    if head == "echo":
        # `-e` would read escapes and `-n` would join the next output onto this line
        return not any(re.fullmatch(r"-[neE]+", a) for a in args)
    if head in ("test", "[", "[["):
        return True
    return head in ("true", ":") and not args


def _grep_files(args: list[str]) -> list[str] | None:
    """A whole-line grep's file operands (after its pattern); None for an option that changes the lines."""
    operands: list[str] = []
    pattern_given = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-e" and i + 1 < len(args):
            pattern_given = True
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            if not set(a[1:]) <= _GREP_LINE_FLAGS:
                return None
        else:
            operands.append(a)
        i += 1
    if not pattern_given and not operands:
        return None
    return operands if pattern_given else operands[1:]


def _reader(stage: list[str], first: bool) -> bool:
    """A stage that prints whole lines of its input; it may name files only as the first stage."""
    head, args = stage[0], stage[1:]
    if head == "cat":
        return first and bool(args) and all(not a.startswith("-") for a in args)
    if head in _GREPS:
        files = _grep_files(args)
        return files is not None and (first or not files)
    if head in ("head", "tail"):
        flags = [a for a in args if a.startswith("-") or a.startswith("+")]
        files = [a for a in args if a not in flags and not _COUNT.fullmatch(a)]
        if any(not (_COUNT.fullmatch(f) or f == "-n") for f in flags):
            return False
        return first or not files
    return False


def _masker(stage: list[str]) -> bool:
    """The last stage: `sed` replacing every value after `=` by fixed text, reading only its input."""
    if stage[0] != "sed":
        return False
    args = stage[1:]
    if any(a not in ("-E", "-r") for a in args if a.startswith("-")):
        return False
    scripts = [a for a in args if not a.startswith("-")]
    if len(scripts) != 1:
        return False
    m = _SED_MASK.fullmatch(scripts[0])
    if m is None:
        return False
    replacement = m.group("r")
    return replacement.startswith("=") and "=" not in replacement[1:]


def _extractor(stage: list[str], first: bool) -> bool:
    """A stage that prints only the name before each `=`; it may name a file only as the first stage."""
    head, args = stage[0], stage[1:]
    flags = [a for a in args if a.startswith("-")]
    operands = [a for a in args if not a.startswith("-")]
    if head in _GREPS:
        letters = "".join(f[1:] for f in flags)
        if "o" not in letters or not set(letters) <= set("oEh"):
            return False
        if not operands or not _NAMES_PATTERN.fullmatch(operands[0]):
            return False
        return first or len(operands) == 1
    if head == "cut":
        return sorted(flags) == ["-d=", "-f1"] and (first or not operands)
    if head == "sed":
        return (
            not flags
            and bool(operands)
            and operands[0] in ("s/=.*//", "s|=.*||")
            and (first or len(operands) == 1)
        )
    return False


def _joiner(stage: list[str]) -> bool:
    return (
        stage[0] == "tr" and len(stage) == 3 and stage[1] == "\\n" and stage[2] in (" ", ",", "\t")
    )


def _pipeline_kind(stages: list[list[str]]) -> str | None:
    """`shell` for a masked or names pipeline, `list` for a listing, None for anything else."""
    if stages[0][0] == "ls":
        ok = all(
            ((s[0] in ("head", "tail") or s[0] in _GREPS) and _reader(s, False))
            or (s[0] == "wc" and all(a in ("-l", "-c", "-w", "-m") for a in s[1:]))
            for s in stages[1:]
        )
        return LIST if ok else None
    i = 0
    while i < len(stages) and _reader(stages[i], i == 0):
        i += 1
    if 0 < i == len(stages) - 1 and _masker(stages[i]):
        return SHELL
    if i < len(stages) and _extractor(stages[i], i == 0):
        rest = stages[i + 1 :]
        return SHELL if len(rest) <= 1 and all(_joiner(s) for s in rest) else None
    return None


def only_shows(a: Any) -> str | None:
    """`shell` or `list` when the pending exec command is one of the recognised shapes; None otherwise."""
    call = a.call
    if call.tool_kind is not ToolKind.EXEC or is_code_call(call):
        return None
    tokens = _tokens(call.command or "")
    statements = _statements(tokens) if tokens else None
    if not statements:
        return None
    kinds: list[str] = []
    for stages in statements:
        if len(stages) == 1 and _plain_statement(stages[0]):
            continue
        kind = _pipeline_kind(stages)
        if kind is None:
            return None
        kinds.append(kind)
    if not kinds:
        return None  # nothing but plain statements: not a read of the shapes above
    return SHELL if SHELL in kinds else LIST
