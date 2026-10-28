"""The scanner's second redaction pass over the v2 Jev views (`redact-v4`; `redact-v3` took the
plugins' text rules but their command-line flag rule, `redact-v2` moved the vendor shapes to data,
`redact-v1` came with the v1.1 question-set pass).

The plugin redacts secrets before a PlanIR leaves the host (`options.redaction`, usually `standard`).
This pass catches secrets that slipped through (an older plugin, redaction `off`, another client), so a
model never sees a live key in a view Sentrook builds. Its text rules are the Hermes plugin's
(`integrations/hermes/plugin/redact.py`), kept as a copy with a parity test, plus the vendor shapes in
`redact_shapes.yaml`. Command-line password flags count (`--password X`, `mysql -pX`, `sshpass -p X`),
but a path or URL after a flag stays (`--secret-file PATH`). It is deliberately conservative: recipients, names, hosts and email addresses stay, because
Jev needs them to judge alignment (a URL loses only its password). A replaced value becomes
`⟦secret:scanner⟧`; the preamble already tells Jev that a placeholder still marks a real secret.

Every pattern does bounded work per position: no nested quantifiers, no unbounded repetition followed
by a suffix that can fail (the JWT tail is matched anchored, from where the head ended, and a private
key's body is capped), and the imported vendor shapes have their repetition capped.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .redact_shapes import load_shapes
from .redact_shapes import spans as shape_spans

REDACTION_VERSION = "redact-v4"
PLACEHOLDER = "⟦secret:scanner⟧"
#: Longest private key body searched for its END line; a 4096-bit RSA key is about 3.3k characters.
PEM_MAX_CHARS = 8000

#: Vendor key shapes (fixed prefix, fixed charset, minimum length) are data: `redact_shapes.yaml`,
#: mostly generated from the gitleaks default rules (`prepare.redact_shapes`, `prepare.redact_import`).
#: The shapes below stay in code: they are the catch-all and never depend on the import.

_JWT_HEAD = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}")
_JWT_TAIL = re.compile(r"\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

#: The whole block up to its END line, whatever the body holds (escaped `\n` in a JSON-encoded result,
#: PGP armour headers); a block cut off before its END line runs over the base64 body. The body never
#: holds a run of five dashes, so the search for END stops at the next armour line.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
    rf"(?:(?:[^-]|-(?!----)){{0,{PEM_MAX_CHARS}}}-----END [A-Z ]{{0,40}}PRIVATE KEY(?: BLOCK)?-----"
    rf"|[A-Za-z0-9+/=\\\r\n \t]{{0,{PEM_MAX_CHARS}}})"
)

_KEY_NAMES = (
    r"api[_-]?key|apikey|secret[_-]?key|secret|token|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd"
    r"|passphrase|client[_-]?secret|auth[_-]?token|bearer"
)
#: A key that ends in a credential word: `GITHUB_TOKEN`, `api_key`, `secretAccessKey`, `logintoken`, and
#: `tok`. A key with letters before its credential word starts at a word boundary; a bare credential word
#: may follow `_` (`MY_VERY_LONG_SERVICE_NAME_TOKEN`). A key right after `/` (a URL segment) or `⟦` (a
#: placeholder label) does not count.
_CREDENTIAL_KEY = (
    r"(?:(?<![A-Za-z0-9/⟦_.-])[A-Za-z0-9_.-]{1,40}(?:" + _KEY_NAMES + r")"
    r"|(?<![A-Za-z0-9/⟦])(?:" + _KEY_NAMES + r"|tok))(?![A-Za-z0-9])"
)

#: Words that introduce a secret in prose: "the database password is X", "gateway token X".
_PROSE_CUES = r"password|passwd|passphrase|token|secret|api[ _-]?key|bearer"
#: A prose value: up to 200 characters without spaces or quotes; trailing punctuation is not part of it.
_PROSE_VALUE = (
    r"[\"'`]?(?![0-9]{1,5}(?![0-9A-Za-z]))"
    r"(?P<v>[^\s\"'`⟦⟧$<>\\]{5,199}[^\s\"'`⟦⟧$<>\\.,;:!?)\]])"
)
#: Words, not secrets: one or more words with at most a capital first letter, maybe hyphenated
#: (`required`, `Read-only`, `ENABLED`), an identifier (`accessToken`, `GITHUB_TOKEN`), or a hyphenated
#: name with two or more plain words in it (`gpt-4o-mini`, `min-length-12`).
_ORDINARY_WORD = re.compile(
    r"(?:[A-Za-z][a-z]*(?:-[A-Za-z][a-z]*)*|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"
)
#: What a sentence names: paths, URLs, masks and templates, code, dates, hex addresses, key fingerprints,
#: email addresses, host and file names (a host may carry a port and a path) and relative paths to a file.
_NAMED_THING = re.compile(
    r"^[/~.*{\[(]|://|\(|^[0-9]{4}-[0-9]{2}-[0-9]{2}|^0x[0-9a-fA-F]{40}$|^(?:SHA256|MD5):"
    r"|^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$"
    r"|^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z]{2,24}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?$"
    r"|^(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_-]+\.[a-z0-9]{1,8}$"
)
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def _is_ordinary(v: str) -> bool:
    return bool(_ORDINARY_WORD.fullmatch(v)) or (
        sum(1 for p in v.split("-") if re.fullmatch(r"[a-z]{2,}", p)) >= 2
    )


def _key_value(v: str) -> bool:
    """Not a key's value: a URL (the URL rule takes any password inside it and the host stays) or the
    name of an environment variable (`token: GITHUB_TOKEN`)."""
    return "://" not in v and not _ENV_NAME.fullmatch(v)


def _inner_key_value(v: str) -> bool:
    """An upper-case name with a credential word inside it names many things; only a long value counts."""
    return len(v) >= 12 and _key_value(v)


def _stated_value(v: str) -> bool:
    """After "password is" or "token:": six or more characters that are not words or a number."""
    return (
        len(v) >= 6
        and not _is_ordinary(v)
        and not re.fullmatch(r"[0-9]+", v)
        and not _NAMED_THING.search(v)
    )


def _bare_value(v: str) -> bool:
    """Straight after a cue word ("backup key X"): twelve or more characters with letters and digits."""
    return (
        len(v) >= 12
        and re.search(r"[A-Za-z]", v) is not None
        and re.search(r"[0-9]", v) is not None
        and not _is_ordinary(v)
        and not _NAMED_THING.search(v)
    )


def _flag_value(v: str) -> bool:
    """A command-line value: not a variable reference (`$DB_PASSWORD`) and not something a sentence names
    (a path, URL, mask or template), so `--secret-file PATH` keeps its path."""
    return not v.startswith("$") and not _NAMED_THING.search(v)


def _suffixed_flag_value(v: str) -> bool:
    """After a flag with a suffix, which often names a setting (`--token-ttl 3600`, `--auth-type basic`,
    `--password-file secrets/db`): also not a word, a number or a path."""
    return (
        _flag_value(v)
        and not _is_ordinary(v)
        and not re.fullmatch(r"[0-9]+", v)
        and not re.search(r"[/\\]", v)
    )


def _mysql_password(v: str) -> bool:
    """After a MySQL client's `-p`: also not a word or a port mapping, which belong to another command on
    the line (`find / -name mysql -prune`, `docker run --name mysql -p3306:3306`)."""
    return _flag_value(v) and not _is_ordinary(v) and not re.match(r"[0-9]{1,5}:[0-9]", v)


#: A command-line value, without its quotes: quoted, up to 256 characters (plain, or with escaped quotes
#: as in a JSON-encoded result), or bare up to a quote or the end of the command. A bare value keeps an
#: escaped character but ends at an escaped quote, newline or tab, so the JSON around it stays.
_FLAG_VALUE = (
    r"(?:\\?[\"'])?(?P<v>(?!⟦)(?:(?<=\\\")[^\"\\]{1,256}(?=\\\")|(?<=\")(?<!\\\")(?:[^\"\\]|\\.){1,256}(?=\")"
    r"|(?<=')(?:[^'\\]|\\.){1,256}(?=')|(?<![\\\"'])[^\s;|&⟦\"'\\-](?:[^\s;|&\"'\\]|\\[^\s\"nrt])*))"
)

#: Values found by their context: (pattern, check). Group `v` is replaced and the context stays; with a
#: check, a match counts only when its value passes it.
_CONTEXT: list[tuple[re.Pattern[str], Callable[[str], bool] | None]] = [
    # `Authorization: Bearer <token>` (also as a JSON or header pair) and a bare `Bearer <token>`.
    (
        re.compile(
            r"(?i)(?:authorization[\"']?[ \t]*[:=][ \t]*[\"']?)?bearer[ \t]+"
            r"(?P<v>[^\s\"'⟦\\][^\s\"'\\]{19,})"
        ),
        None,
    ),
    # The password in `scheme://user:PASS@host` (the user may be empty, the password may hold `@`); user
    # and host stay. A host name and port before a list or a fragment (`cache.test:6379,admin@…`) hold
    # no password.
    (
        re.compile(
            r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://"
            r"(?!(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24}:[0-9]{1,5}[,;#])"
            r"[^\s/?#@:\"'<>\\⟦]{0,256}:"
            r"(?P<v>[^\s/?@\"'<>\\⟦$*{][^\s/?\"'<>\\]{0,255})@"
        ),
        None,
    ),
    # A private calendar feed: `…/private-<token>/basic.ics`.
    (
        re.compile(r"/private-(?P<v>[A-Za-z0-9]{16,128})(?![A-Za-z0-9])"),
        lambda v: re.search(r"[0-9]", v) is not None,
    ),
    # `--password x`, `--api-key=x`, `--token "x"`.
    (
        re.compile(
            r"(?i)--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)"
            r"(?:\s*=\s*|\s+)" + _FLAG_VALUE
        ),
        _flag_value,
    ),
    # `--token-value x`. After a suffixed flag a path, URL or setting stays (`--secret-file /etc/app/x`,
    # `--token-url https://…`, `--token-ttl 3600`).
    (
        re.compile(
            r"(?i)--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)"
            r"-\w+(?:\s*=\s*|\s+)" + _FLAG_VALUE
        ),
        _suffixed_flag_value,
    ),
    # `mysql -pX`: MySQL and MariaDB clients take a password only attached to `-p`. The client is a command
    # word (not a directory such as `/var/lib/mysql`, unless under a `bin/`), and the search stops at the end
    # of its command, an escaped newline included.
    (
        re.compile(
            r"(?:(?<![^\s;|&(`\"'])|(?<=bin/)|(?<=\\[nt]))(?:mysql[a-z]{0,8}|mariadb(?:-?[a-z]{1,8})?)"
            r"(?![\w.-])[^\n;|&\\]{0,200}?\s-p" + _FLAG_VALUE
        ),
        _mysql_password,
    ),
    # `sshpass -p X`, after any of sshpass's own options; a `-p` in the command it runs is not its.
    (
        re.compile(
            r"(?<![\w-])sshpass(?:\s+-[fdP][ \t]*[^\s-]\S*|\s+-[ehvV]){0,4}\s+-p[ \t]*"
            + _FLAG_VALUE
        ),
        _flag_value,
    ),
    # `GITHUB_TOKEN=x`, `"api_key": "x"`, `?token=x`. Values that are variable references or masks stay.
    # Quotes may be escaped (JSON inside a JSON-encoded result), and a value ends at a backslash; a port
    # after a host (`x.token:8443/`) is not a value.
    (
        re.compile(
            r"(?i)" + _CREDENTIAL_KEY + r"\\?[\"']?\s*[=:]\s*\\?[\"']?"
            r"(?![0-9]{1,5}(?![0-9A-Za-z]))(?P<v>[^\s\"'⟦$*{\[<%&,;`\\][^\s\"'&,;<>`\\]{7,})"
        ),
        _key_value,
    ),
    # `"password": "words, & symbols"`: in a JSON pair the whole quoted string is the value.
    (
        re.compile(
            r"(?i)"
            + _CREDENTIAL_KEY
            + r"\\?[\"']\s*:\s*\\?\"(?P<v>[^\"\\\n⟦$*{\[<%][^\"\\\n]{7,199})\\?\""
        ),
        _key_value,
    ),
    # An upper-case name with a credential word inside it: `SENTROOK_SECRET_MARKERS=x`. A number or a
    # path is not a value here (`TOKEN_LIMIT=4096`, `GITHUB_TOKEN_PATH=/home/…`).
    (
        re.compile(
            r"(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}"
            r"\\?[\"']?\s*[=:]\s*\\?[\"']?"
            r"(?![0-9]+(?![^\s\"'&,;<>`\\]))(?P<v>[^\s\"'⟦$*{<%&,;`\\/~.][^\s\"'&,;<>`\\]{7,})"
        ),
        _inner_key_value,
    ),
    # "password is X", "the password is now X", "the token for prod: X". The words between cue and value
    # stay inside one clause and one quoted string and never reach into a placeholder; a cue inside a
    # path, host or name (`/token:8443`, `x.secret`) does not count.
    (
        re.compile(
            r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:"
            + _PROSE_CUES
            + r")(?![A-Za-z0-9_])[^\n:.;=\"'`⟦]{0,40}?"
            r"(?:\s(?:is|was)(?:\s+(?:now|still|currently|set\s+to|changed\s+to))?\s+|:[ \t]*)"
            + _PROSE_VALUE
        ),
        _stated_value,
    ),
    # "gateway token X", "secret X".
    (
        re.compile(r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:" + _PROSE_CUES + r"|key)[ \t]+" + _PROSE_VALUE),
        _bare_value,
    ),
]


def _spans(text: str) -> list[tuple[int, int]]:
    spans = [m.span() for m in _PRIVATE_KEY.finditer(text)]
    for m in _JWT_HEAD.finditer(text):
        tail = _JWT_TAIL.match(text, m.end())
        if tail is not None:
            spans.append((m.start(), tail.end()))
    for shape in load_shapes().shapes:
        spans.extend(shape_spans(shape.compiled, text))
    for pattern, check in _CONTEXT:
        for m in pattern.finditer(text):
            s, e = m.span("v")
            if e > s and (check is None or check(text[s:e])):
                spans.append((s, e))
    return spans


def redact_text(text: str) -> tuple[str, int]:
    """Replace every secret in `text`; overlapping matches merge into one placeholder that covers them
    all, so no part of a secret survives a shorter, earlier match."""
    if len(text) < 8:
        return text, 0
    merged: list[list[int]] = []
    for start, end in sorted(_spans(text), key=lambda s: (s[0], -s[1])):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if not merged:
        return text, 0
    out: list[str] = []
    pos = 0
    for start, end in merged:
        out.append(text[pos:start])
        out.append(PLACEHOLDER)
        pos = end
    out.append(text[pos:])
    return "".join(out), len(merged)


def second_pass(obj: Any) -> tuple[Any, int]:
    """Walk dicts, lists and strings; return a redacted copy and the number of replacements. Dict keys
    and non-string scalars are left as they are; `obj` is never mutated."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        total = 0
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            out[k], n = second_pass(v)
            total += n
        return out, total
    if isinstance(obj, list):
        total = 0
        items: list[Any] = []
        for v in obj:
            item, n = second_pass(v)
            items.append(item)
            total += n
        return items, total
    return obj, 0
