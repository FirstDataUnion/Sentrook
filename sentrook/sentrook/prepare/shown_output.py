"""Whether a shell read's returned output shows a value it read.

The second half of the output-only read (`aira.output_only`, `state.token.PendingMarks.output_only`). The next scan
carries the call's output, and the read holds nothing when that output shows no value. How the output is read
depends on the shape the command was recognised as:

- `shell` (a masked check or a names listing): line by line, by what each line may be. A line must be one of:
  - a masked assignment (`NAME=***`, `NAME=`); a placeholder is a value;
  - a list of env-style names (`DB_HOST OTHER_TOKEN`);
  - exactly the text of one of the command's `echo` statements;
  - an env-file comment with nothing secret-like in it.
  Any other line shows a value.
- `list` (`ls`, `test -f`): the command prints no file content, so only a placeholder or a credential shape counts.

Both read a redaction placeholder or a credential shape anywhere as a value. A host's JSON wrapper
(`{"output": "…", "exit_code": 0}`) is read by its keys and text fields.
"""

from __future__ import annotations

import json
import re
import shlex

from .secret_like import _unescape, secret_carried

SHELL, LIST = "shell", "list"

_MASK_CHARS = frozenset("*•●")
_QUOTES = "\"'`"
#: A `NAME=…` line, the name in one case; the value is checked by `_masked`.
_ASSIGNED = re.compile(r"(?:export\s+)?[A-Z_][A-Z0-9_]{0,80}=(.*)")
#: An env-style name: capitals, digits and underscores, with at least one underscore.
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
#: The `path:` and `12:` prefixes `grep -H` and `grep -n` print.
_GREP_PREFIX = re.compile(r"(?:(?P<path>[^\s:]*):)?(?:\d+:)?")
#: A host's JSON wrapper: the fields that carry the command's output, and the host's own status fields.
_OUTPUT_FIELDS = frozenset({"output", "stdout", "stderr", "error"})
_STATUS_FIELDS = frozenset(
    {
        "exit_code", "returncode", "status", "duration_seconds", "tool_calls_made", "kernel", "stdout_bytes_captured",
        "stdout_bytes_total", "stdout_bytes_omitted",
    }
)  # fmt: skip
_CUT_FIELDS = frozenset({"truncated", "stdout_truncated"})
#: Runs are bounded so a long word is read in linear time.
_CREDENTIAL_KEY = r"(?i:[A-Za-z_\-]{0,40}(?:key|token|secret|passw(?:or)?d|pwd|pw|pass|pin|auth\w{0,20}|credential)[A-Za-z0-9_\-]{0,40})"
_ENV_STYLE = r"[A-Z][A-Z0-9]{0,40}(?:_[A-Z0-9]{1,40})+"
_VALUE = r"""("[^"\n]*"|'[^'\n]*'|[^\s,}\]]+)"""
#: In a comment: a credential-ish or env-style name with a value after `=`, `:`, `,` or `|`, or an env-style name
#: with one after blanks.
_NAMED = re.compile(
    rf"""(?<![\w\-])["']?(?:{_CREDENTIAL_KEY}|{_ENV_STYLE})["']?[ \t]*[=:,|][ \t]*{_VALUE}"""
    rf"""|(?<![\w\-]){_ENV_STYLE}[ \t]+{_VALUE}"""
)
#: In a comment: a token that may be a key: 12+ characters mixing letters and digits, or 24+ hex digits.
_TOKEN = re.compile(r"(?<![\w\-+/=])[A-Za-z0-9_\-+/]{12,}={0,2}(?![\w\-+/=])")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_OPERATOR_CHARS = frozenset("();<>|&")


def _masked(value: str) -> bool:
    v = value.strip().strip(_QUOTES).strip()
    return not v or set(v) <= _MASK_CHARS


def _status_value(v: object) -> bool:
    """A host status field's value: a number, a flag, null, a short plain word or a small object (a kernel's)."""
    if v is None or isinstance(v, (bool, int, float, dict)):
        return True
    return isinstance(v, str) and bool(re.fullmatch(r"[a-z_]{1,20}", v))


def _texts(output: str) -> list[str] | None:
    """The text a host's output carries: the output fields of a host's JSON wrapper (`{"output": "…", "exit_code":
    0}`), anything else as it is. None when the wrapper says the output was cut."""
    try:
        data = json.loads(output)
    except (ValueError, RecursionError):
        return [_unescape(output)]
    if (
        isinstance(data, dict)
        and set(data) & _OUTPUT_FIELDS
        and set(data) <= _OUTPUT_FIELDS | _STATUS_FIELDS | _CUT_FIELDS
        and all(_status_value(data[k]) for k in set(data) & _STATUS_FIELDS)
    ):
        if any(data.get(k) for k in _CUT_FIELDS):
            return None
        out = [data[k] for k in _OUTPUT_FIELDS if isinstance(data.get(k), str)]
        if any(
            data.get(k) is not None and not isinstance(data.get(k), str) for k in _OUTPUT_FIELDS
        ):
            return [output]  # an output field that is not text: read the whole thing
        return out
    return [output]


def _echo_lines(command: str) -> set[str]:
    """What the command's `echo` statements print."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        tokens = list(lex)
    except ValueError:
        return set()
    out: set[str] = set()
    words: list[str] = []
    for t in [*tokens, ";"]:
        if t and set(t) <= _OPERATOR_CHARS:
            if words and words[0] == "echo":
                out.add(" ".join(w for w in words[1:] if w != "-n"))
            words = []
        else:
            words.append(t)
    return out


def _comment_shows(text: str) -> bool:
    if _NAMED.search(text):
        return True
    for t in _TOKEN.finditer(text):
        tok = t.group(0).rstrip("=")
        if tok.startswith(("/", "~/", "./", "../")):
            continue  # a path
        if re.fullmatch(r"[0-9a-fA-F]{24,}", tok.replace("-", "")) or _UUID.fullmatch(tok):
            return True
        if re.search(r"\d", tok) and re.search(r"[A-Za-z]", tok):
            return True
        if re.search(r"[a-z]", tok) and len(re.findall(r"[A-Z]", tok[1:])) >= 2:
            return True  # mixed case inside a word: random, not prose
    return False


def _line_allowed(line: str, echoed: set[str], prefixed: bool) -> bool:
    s = line.strip()
    if not s or s in echoed:
        return True
    m = _GREP_PREFIX.match(s) if prefixed else None
    if (
        m is not None
        and m.end()
        and (
            m.group("path") is None
            or m.group("path").isdigit()
            or re.search(r"[./]", m.group("path"))
        )
    ):
        s = s[m.end() :].strip()
    comment = s.startswith("#")
    if comment:
        s = s.lstrip("#").strip()
    a = _ASSIGNED.fullmatch(s)
    if a is not None:
        return _masked(a.group(1))
    if comment and "=" in s:
        return False  # a comment carrying a value after a name
    words = [w for w in re.split(r"[\s,]+", s) if w]
    if words and all(_ENV_NAME.fullmatch(w) for w in words):
        return True
    return comment and not _comment_shows(s)


def shows_value(output: str, placeholder_open: str, kind: str, command: str = "") -> bool:
    """Whether a call's returned output shows a value, read as `kind` (`shell`, `list`); `command` is the call's own
    command (what its `echo` statements print is not a value)."""
    if not output:
        return False
    texts = _texts(output)
    if texts is None:
        return True
    for t in [output, *texts]:
        if placeholder_open in t or secret_carried(t, placeholder_open) is not None:
            return True
    if kind == LIST:
        return False
    echoed = _echo_lines(command)
    # `grep -H` / `-n` print a `path:` / `12:` prefix; without them a line keeps whatever comes before its colon
    prefixed = bool(re.search(r"(?:^|\s)-[A-Za-z]*[Hn]", command))
    return not all(_line_allowed(line, echoed, prefixed) for t in texts for line in t.splitlines())
