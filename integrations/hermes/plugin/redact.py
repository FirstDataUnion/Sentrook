"""Host-side redaction, applied to everything that leaves the host (the PlanIR sent to Sentrook and the
local traffic log). Mirrors the OpenClaw plugin's `redact.ts`.

`standard` replaces secrets with `⟦secret:<kind>:<ref>⟧`. The ref is a keyed hash of the value, so the
same secret gets the same placeholder across steps without the value ever being stored. Recipients,
hosts and email addresses stay: the scanner needs them to judge whether a call matches the request.
Content is capped head and tail, since a payload placed after a cut-off is the obvious evasion.

Every pattern does bounded work per position (no nested quantifiers).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable
from typing import Any

_KEY_NAMES = (
    r"api[_-]?key|apikey|secret[_-]?key|secret|token|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd"
    r"|passphrase|client[_-]?secret|auth[_-]?token|bearer"
)
# A key that ends in a credential word: `GITHUB_TOKEN`, `api_key`, `secretAccessKey`, `logintoken`, and
# `tok`. A key with letters before its credential word starts at a word boundary; a bare credential word may
# follow `_` (`MY_VERY_LONG_SERVICE_NAME_TOKEN`). A key right after `/` (a URL segment) or `⟦` (a
# placeholder label) does not count.
_CREDENTIAL_KEY = (
    r"(?:(?<![A-Za-z0-9/⟦_.-])[A-Za-z0-9_.-]{1,40}(?:" + _KEY_NAMES + r")"
    r"|(?<![A-Za-z0-9/⟦])(?:" + _KEY_NAMES + r"|tok))(?![A-Za-z0-9])"
)

# Words that introduce a secret in prose: "the database password is X", "gateway token X".
_PROSE_CUES = r"password|passwd|passphrase|token|secret|api[ _-]?key|bearer"
# The last character of a value: sentence punctuation after a value is not part of it (`password: X.`,
# `(token=X)`), so one secret gets one placeholder however the sentence around it goes on.
_VALUE_END = r"[^\s\"'&,;<>`\\.:!?)\]]"
# What a command after a value looks like, after `&`, `,`, `;` or `|`: a word with more after it on its line (`curl …`,
# `w x`), maybe straight after it (`curl${IFS}…`, `curl$IFS…`, `reboot)`, `base64|sh`, `sort<x`); a word before `;`,
# `&`, `&&` or `;;` that ends its line or has a command after it (`reboot;`, `reboot;echo …`, `reboot&&echo …`); a word
# with quotes or an escape inside it (`cu''rl`, `c\url`); or a command led by a symbol: a substitution or a variable
# (`$(…)`, `$SHELL`, `${IFS}`, `$'…'`), a subshell or a group (`(…)`, `{ …; }`) or a path (`./run.sh`, `../bin/x`,
# `/bin/sh`, `~/x.sh`). A tail that runs to the end of the line, a lone word included (`TOKEN=<value>|sh`,
# `TOKEN=<value>;make`), is part of the value, as a password's tail would be.
_COMMAND_ENDS = (
    r"[A-Za-z_][A-Za-z0-9_.-]{1,40}(?:[ \t|<>`)]|\\t|\$[{(A-Za-z_]"
    r"|[;&]{1,2}(?:[ \t]|(?![^\n])|[A-Za-z_][A-Za-z0-9_.-]{0,40}[ \t]))"
    r"|[A-Za-z][A-Za-z0-9_.-]{0,40}(?:['\"]{1,2}[A-Za-z]|\\(?![nrtbf]|u[0-9A-Fa-f]{4})[A-Za-z])"
    r"|[A-Za-z_](?:[ \t]|\\t)|\$[(A-Za-z_{'\"]|\(|\{[ \t]|\.\.?/|/[A-Za-z]|~/"
)
# What ends an unquoted value at `|`: a command (`_COMMAND_ENDS`), a word led by a digit before a space (`|7z x`), or a
# brace list (`|{curl,…}`).
_PIPE_ENDS = _COMMAND_ENDS + r"|[0-9][A-Za-z0-9_.-]{0,40}(?:[ \t]|\\t)|\{[^\s,{}|]{1,40},"
# What ends an unquoted value at `&`, `,` or `;`: an HTML entity after `&` (`&amp;`, `&quot;`, `&#39;`), another key,
# maybe with spaces in its name or led by a digit or a symbol (`&page=2`, `,b=2`, `;Initial Catalog=y`, `&ids[]=1`,
# `&9x=1`), a command (`_COMMAND_ENDS`), a word straight before `(` or `{` (`;next()`), `(` or `{` (`;(…)`, `;{…}`), or
# a comment (`;#`). A tail that runs to the end of the line or of the text, or starts with a digit, is part of the value
# (`password=<value>&3`, an `.env` line `PASSWORD=<value>&<rest>`).
_SEPARATOR_ENDS = (
    r"(?<=&)(?:[A-Za-z]{2,8}|#[xX]?[0-9A-Fa-f]{1,6});"
    r"|[A-Za-z_\[%-][A-Za-z0-9_.\[\]%-]{0,40}(?: [A-Za-z][A-Za-z0-9_.-]{0,20}){0,3}[=:]"
    r"|[0-9][A-Za-z0-9_.\[\]%-]{0,40}="
    r"|[A-Za-z_][A-Za-z0-9_.-]{1,40}[({]|[({]|(?<=;)#|" + _COMMAND_ENDS
)
# `|` inside an unquoted value: part of it (`password=<value>|<rest>`) unless what follows is a space, the end, a quote
# or `_PIPE_ENDS`, so a pipe into a command stays visible (`TOKEN=<value>|curl …|sh`). Unlike after `&`, `,` or `;`, a
# key or a word straight before `(` or `{` does not end it, as `|` is common in generated passwords. A value never ends
# in `|`, so `||` or `|&` before a command ends it too (`TOKEN=<value>||curl …`).
_PIPE_CHAR = r"\|(?=[^\s\"'<>`\\])(?!" + _PIPE_ENDS + ")"
# A character of an unquoted value after a key. `&`, `,` and `;` end the value before a space, the end, a quote, `&&` or
# `;;`, or `_SEPARATOR_ENDS`, and after code's closing bracket (`getToken();`); anywhere else they are part of it
# (`password=<value>&<rest>`, `password=<value>,;<rest>`). `|` ends it where `_PIPE_CHAR` says, and a command
# substitution `$(` always does (`TOKEN=<value>$(…)`); a `$` before anything else is part of it (`pa$sword`).
_VALUE_CHAR = (
    r"(?:[^\s\"'&,;<>`\\|$]|\$(?!\()|"
    + _PIPE_CHAR
    + r"|(?<![)\]])[&,;](?=[^\s\"'<>`\\])(?!(?<=&)&|(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
# The last character of an unquoted value: not a pipe and not the `$` of a command substitution, so the command after
# the value is whole (`TOKEN=<value>$(…)`).
_UNQUOTED_END = r"(?!\||\$\()" + _VALUE_END
# After an opening quote that does not close before a space (`password='<value>|<rest> …`), where a shell reads `|` as a
# character: `|` is part of the value, the rest as in `_VALUE_CHAR`.
_QUOTED_RUN_CHAR = (
    r"(?:[^\s\"'&,;<>`\\$]|\$(?!\()|(?<![)\]])[&,;](?=[^\s\"'<>`\\])(?!(?<=&)&|(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
_QUOTED_RUN_END = r"(?!\$\()" + _VALUE_END
# In a link's query, where the key follows `?`, `&` or `#`, `&` always ends the value (`?token=X&debug`): the value
# there, from its first character.
_QUERY_VALUE_CHAR = (
    r"(?:[^\s\"'&,;<>`\\|$]|\$(?!\()|"
    + _PIPE_CHAR
    + r"|(?<![)\]])[,;](?=[^\s\"'&<>`\\])(?!(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
# The rest of a quoted value after its first character: in single quotes anything up to the closing quote; in double
# quotes, where a shell runs a command substitution, not `$(` (`password="<value>;$(…)"` keeps the command visible).
_SQ_CHAR = r"[^\s\"'<>`\\]"
_DQ_CHAR = r"(?:[^\s\"'<>`\\$]|\$(?!\())"
# Digits that start a value: up to five, then the value's end, are a port or a count (`x.token:8443/`), not a value.
_NOT_A_PORT = r"(?![0-9]{1,5}(?![0-9A-Za-z]|[&,;][^\s\"'&,;<>`\\]))"
_QUERY_VALUE = re.compile(
    r"[\s\S](?:"
    + _QUERY_VALUE_CHAR
    + "{6,}"
    + _UNQUOTED_END
    + "|"
    + _QUERY_VALUE_CHAR
    + "{5}"
    + _UNQUOTED_END
    + r"(?=[.:!?)\]]))"
)
# A prose value: up to 200 characters without spaces or quotes; trailing punctuation is not part of it. Unquoted, it
# ends at `&`, `,`, `;` and `|` where an unquoted value after a key does (`token: <value>|curl …`, `password:
# <value>;curl …`); after a quote, they are part of it.
_PROSE_CHAR = (
    r"(?:[^\s\"'`⟦⟧$<>\\|&,;]|"
    + _PIPE_CHAR
    + r"|(?<![)\]])[&,;](?=[^\s\"'<>`\\])(?!(?<=&)&|(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
_PROSE_VALUE = (
    r"[\"'`]?(?![0-9]{1,5}(?![0-9A-Za-z]))"
    r"(?P<v>(?<=[\"'`])[^\s\"'`⟦⟧$<>\\]{5,199}[^\s\"'`⟦⟧$<>\\.,;:!?)\]]|(?<![\"'`])"
    + _PROSE_CHAR
    + r"{5,199}[^\s\"'`⟦⟧$<>\\.,;:!?)\]|&])"
)
# Words, not secrets: one or more words with at most a capital first letter, maybe hyphenated (`required`,
# `Read-only`, `ENABLED`), an identifier (`accessToken`, `GITHUB_TOKEN`), or a hyphenated name with two or
# more plain words in it (`gpt-4o-mini`, `min-length-12`).
_ORDINARY_WORD = re.compile(
    r"(?:[A-Za-z][a-z]*(?:-[A-Za-z][a-z]*)*|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"
)
# What a sentence names: paths, URLs, masks and templates, code, dates, hex addresses, key fingerprints,
# email addresses, host and file names (a host may carry a port and a path) and relative paths to a file.
_NAMED_THING = re.compile(
    r"^[/~.*{\[(]|://|\(|^[0-9]{4}-[0-9]{2}-[0-9]{2}|^0x[0-9a-fA-F]{40}$|^(?:SHA256|MD5):"
    r"|^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$"
    r"|^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z]{2,24}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?$"
    r"|^(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_-]+\.[a-z0-9]{1,8}$"
)
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
# One part of a name in code, read as a word (`token_data`, `getSecret`, `JSON`, `oauth2`, `b64decode`): lower,
# camel, Pascal or upper case, maybe after `_`, with digits at its end or one short run before more letters.
_CODE_PART = (
    r"_?(?:[a-z]+(?:[0-9]{1,3}[a-z]{3,}|[0-9]*)(?:_[a-z]+[0-9]*)*|[a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)+"
    r"|[A-Z][a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)*|[A-Z]+[0-9]*(?:_[A-Z]+[0-9]*)*)"
)
# A name, maybe dotted, called with no or one bare argument, or subscripted with a small number.
_CODE_CHAIN = _CODE_PART + r"(?:\." + _CODE_PART + r"|\(\)|\([a-z_]{1,20}\)|\[[0-9]{1,4}\])*"
# A dotted name whose every part reads as a word of up to 32 characters with no run of four digits
# (`config.token`, `process.env.TOKEN`).
_DOTTED_PART = r"(?=[A-Za-z0-9_]{1,32}(?![A-Za-z0-9_]))(?![A-Za-z0-9_]{0,28}[0-9]{4})" + _CODE_PART
_DOTTED_NAME = _DOTTED_PART + r"(?:\." + _DOTTED_PART + r")+"
# Code that reads a secret from where it is kept, cut where its quoted argument starts: `token_data[` in
# `access_token = token_data['access_token']`, `os.environ[`, `creds.get(`, `getpass(`, `resp.json()[`. A
# name, maybe dotted, called or subscripted, that ends in an open bracket or parenthesis, or a call whose one
# argument is another such read (`base64.b64decode(os.environ[`) or a dotted name (`b64decode(config.secret`).
# A random value that happens to end in a bracket is still a value.
_CODE_READ = re.compile(
    _CODE_CHAIN + r"(?:[\[(]|\((?:" + _CODE_CHAIN + r"[\[(]|" + _DOTTED_NAME + r"\)?))"
)
# A call whose one argument is a bare lower-case name, cut before its closing parenthesis or a comma
# (`os.getenv(name`, `load_token(path`, `getattr(settings`). It is code only when the name called reads as code
# (`is_code_read`): dotted, with `_` or a capital, or called or subscripted itself, or one of `_CODE_READERS`.
# `hunter(abc)` and `mysecret(pw_2024)` are values.
_CODE_NAME_ARG_READ = re.compile(_CODE_CHAIN + r"\([a-z_][a-z0-9_]{0,29}")
_CODE_READERS = frozenset("input getattr getenv getpass open read load get".split())
# A dotted name called with a keyword before a quoted argument (`getpass.getpass(prompt=`) or subscripted with
# a number of one or two digits (`sys.argv[1`, its `]` left out as punctuation). Only a dotted name counts
# (`is_code_read`): `qwerty[99]` and `monkey(prompt='x')` are values.
_CODE_ARG_READ = re.compile(_CODE_CHAIN + r"(?:\[[0-9]{1,2}\]?|\([a-z_][a-z0-9_]{0,29}=)")
# A plain attribute read is code only from one of these receivers (`self.token`, `config.token`), or when it
# reads a credential field (`resp.access_token`); `correct.horse.battery.staple` is a value.
_CODE_RECEIVERS = frozenset(
    "self cls this args opts options config cfg conf settings env process os creds credentials secrets params ctx "
    "app request".split()
)
_DOTTED_READ = re.compile(_DOTTED_NAME)


# A credential field's name, as docs, templates and code write it (`api_secret`, `your_api_key`, `apiSecret`,
# `YOUR_TOKEN_HERE`): words with no digits, lower or upper case joined by `_` or `-`, or camel case with each part
# three or more letters. `_field_name` also wants it to end in a credential word, maybe before `here`.
_FIELD_NAME_VALUE = re.compile(
    r"(?:[a-z]{2,}(?:[_-][a-z]+)*|[A-Z]{2,}(?:[_-][A-Z]+)*|[a-z]{2,}(?:[A-Z][a-z]{2,})+|(?:[A-Z][a-z]{2,}){2,})"
)
# A placeholder that masks a value (`xxxxxxxx`), and a short lower-case word (`changeme`, `required`, `basic`).
_PLACEHOLDER_VALUE = re.compile(r"(?i)x{3,}")
_SHORT_WORD = re.compile(r"[a-z]{1,12}")
# A value that stands in for a secret rather than being one, under any key: the word REDACTED (maybe in brackets), or
# a mask of three or more `*`, `•` or `·`. A run of another symbol, letter or digit may be a password (`!!!!!!!!`).
_REDACTED_WORD = re.compile(r"(?i)[(\[<{]?redacted[)\]>}]?")
_MASK_RUN = re.compile(r"([*•·])\1{2,}")
# A key or cue word that names a password (`password`, `db_pass`, `passphrase`, `pwd`, `pin`): its value is what a
# person typed, so neither a short value before an ellipsis nor a phrase is read as a stand-in under it.
_PASSWORD_KEY = re.compile(r"(?i)pass|pwd|(?<![a-z])pin(?![a-z])")
# A quoted string's content from where a value starts to the closing quote (escaped or not), and a token cut short
# with an ellipsis, as docs abridge one: up to ten token characters, then `...`, `…`, `<...>` or `[...]`
# (`ya29.a0...`, `1//0g…`). A longer start, or a symbol other than `. _ / + -` in it, may be the secret itself.
_QUOTED_REST = re.compile(r"(?<=[\"'])[^\"'\\\n]{1,200}(?=\\{0,8}[\"'])")
_ELIDED = re.compile(r"[A-Za-z0-9._/+-]{0,10}(?:\.{3}|…|<(?:\.{3}|…)>|\[(?:\.{3}|…)\])")
# A phrase that says what a token or key is (`short-lived token`, `your api key`, `paste your key here`): two to four
# plain words (letters, maybe hyphenated, or a short number), no run of twelve or more token characters, and either up
# to three words ending in a credential noun or a placeholder word with a credential noun anywhere in it.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9_+/=.~-]{12}")
_PLAIN_WORD = re.compile(r"[(\[<{\"'~*]*(?:[A-Za-z][A-Za-z'’-]*|[0-9]{1,4})[)\]>}\",.;:!?*]*")
_CREDENTIAL_NOUNS = frozenset("token tokens key keys secret secrets credential credentials".split())
_PLACEHOLDER_WORDS = frozenset("your here example placeholder".split())


def _is_ordinary(v: str) -> bool:
    return bool(_ORDINARY_WORD.fullmatch(v)) or (
        sum(1 for p in v.split("-") if re.fullmatch(r"[a-z]{2,}", p)) >= 2
    )


def _key_value(v: str) -> bool:
    """Not a key's value: a URL (the URL rule takes any password inside it and the host stays) or the
    name of an environment variable (`token: GITHUB_TOKEN`)."""
    return "://" not in v and not _ENV_NAME.fullmatch(v)


def _names_a_field(v: str) -> bool:
    """Plainly not a secret in text: a credential field's name or a placeholder for one (`api_key:api_secret` in
    docs, `password: your_password`, `token: xxxxxxxx`), or a short lower-case word of three or more different
    letters (`password=changeme`). A value with a digit, mixed case or a symbol, a longer word, and a run of one
    letter are still values. A parsed object's value under a credential key is still replaced whole."""
    if _PLACEHOLDER_VALUE.fullmatch(v) or (_SHORT_WORD.fullmatch(v) and len(set(v)) >= 3):
        return True
    if len(v) > 40 or _FIELD_NAME_VALUE.fullmatch(v) is None:
        return False
    return _CREDENTIAL_FIELD.search(re.sub(r"(?i)[_-]?here\Z", "", v)) is not None


def _stands_in(v: str) -> bool:
    """Plainly a stand-in for a secret under any key: the word REDACTED or a mask (`********`)."""
    return _REDACTED_WORD.fullmatch(v) is not None or _MASK_RUN.fullmatch(v) is not None


def _describes_a_credential(v: str) -> bool:
    """A phrase that says what a token or key is rather than being one (`_CREDENTIAL_NOUNS`)."""
    words = v.split()
    if not 2 <= len(words) <= 4 or _TOKEN_RUN.search(v) is not None:
        return False
    if not all(_PLAIN_WORD.fullmatch(w) for w in words):
        return False
    names = [re.sub(r"[^a-z0-9'’-]", "", w.lower()) for w in words]
    if len(names) <= 3 and names[-1] in _CREDENTIAL_NOUNS:
        return True
    return any(n in _PLACEHOLDER_WORDS for n in names) and any(
        n in _CREDENTIAL_NOUNS for n in names
    )


def _text_key_value(v: str) -> bool:
    """A value after a key in text: a key's value that does not name a field or stand in for a secret."""
    return _key_value(v) and not _names_a_field(v) and not _stands_in(v)


def _quoted_stand_in(text: str, key_start: int, start: int, end: int) -> bool:
    """Whether the value at `start`-`end`, after the key or cue word at `key_start`, opens a quoted string that as a
    whole stands in for a secret: REDACTED or a mask under any key; under a key that does not name a password, also a
    token cut short with an ellipsis (`"access_token": "ya29.a0..."`) or a phrase that says what it is
    (`"short-lived token"`). An unquoted value before an ellipsis ("the password is hunter2...") is still a value."""
    m = _QUOTED_REST.match(text, start)
    if m is None or end > m.end():
        return False
    v = m.group()
    if _stands_in(v):
        return True
    if _PASSWORD_KEY.search(text[key_start:start]) is not None:
        return False
    return _ELIDED.fullmatch(v) is not None or _describes_a_credential(v)


def is_code_read(v: str) -> bool:
    """Whether `v` is code that reads a secret from somewhere: called or subscripted and cut where its quoted
    argument starts (`_CODE_READ`), a dotted name with a simple argument (`_CODE_ARG_READ`), a call on a
    bare name (`_CODE_NAME_ARG_READ`), or a plain attribute read from a known receiver or of a credential field
    (`config.token`, `resp.access_token`)."""
    if _CODE_READ.fullmatch(v) is not None:
        return True
    if "." in v and _CODE_ARG_READ.fullmatch(v) is not None:
        return True
    if _CODE_NAME_ARG_READ.fullmatch(v) is not None:
        callee = v[: v.rindex("(")]
        if re.search(r"[._A-Z(\[]", callee) or callee in _CODE_READERS:
            return True
    if _DOTTED_READ.fullmatch(v) is None:
        return False
    return (
        v.split(".", 1)[0] in _CODE_RECEIVERS
        or _CREDENTIAL_FIELD.search(v.rsplit(".", 1)[1]) is not None
    )


def _unquoted_key_value(v: str) -> bool:
    """An unquoted value after a key: also not code that reads the secret from somewhere
    (`token = creds.get('token')`, cut where its quoted argument starts). A quoted value or one under an
    object key is whole, so it is never code cut short."""
    return _text_key_value(v) and not is_code_read(v)


def _inner_key_value(v: str) -> bool:
    """An upper-case name with a credential word inside it names many things; only a long value counts, and not
    code that reads the secret from somewhere (`MY_SECRET_TOKEN = config.token`), as after any other key."""
    return len(v) >= 12 and _text_key_value(v) and not is_code_read(v)


def _inner_quoted_value(v: str) -> bool:
    """The same name with a quoted value: a long value that is not a URL or an environment variable name. A quoted
    value is whole, so code-shaped text in quotes is still a value."""
    return len(v) >= 12 and _text_key_value(v)


def _stated_value(v: str) -> bool:
    """After "password is" or "token:": six or more characters that are not words, a number or code that
    reads the secret from somewhere."""
    return (
        len(v) >= 6
        and not _is_ordinary(v)
        and not re.fullmatch(r"[0-9]+", v)
        and not _NAMED_THING.search(v)
        and not is_code_read(v)
        and not _names_a_field(v)
        and not _stands_in(v)
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


# The checks of the key and sentence rules, whose quoted values may stand in for a secret (`_quoted_stand_in`). A
# command-line value is what the command runs with, so the flag rules are not among them.
_STAND_IN_CHECKS = frozenset(
    {_unquoted_key_value, _text_key_value, _inner_key_value, _inner_quoted_value, _stated_value}
)


# The checks of the rules whose unquoted value may hold `&` (`_VALUE_CHAR`).
_UNQUOTED_CHECKS = frozenset({_unquoted_key_value, _inner_key_value})


def _query_value_end(text: str, key_start: int, start: int, end: int) -> int | None:
    """Where the value at `start`-`end` ends when its key, at `key_start`, is in a link's query (follows `?`, `&` or
    `#`): at its first `&`. None when what is left is too short to be a value."""
    if key_start == 0 or text[key_start - 1] not in "?&#" or "&" not in text[start:end]:
        return end
    m = _QUERY_VALUE.match(text, start)
    return None if m is None else m.end()


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


# A command-line value, without its quotes: quoted, up to 256 characters (plain, or with escaped quotes
# as in a JSON-encoded result), or bare up to a quote or the end of the command. A bare value keeps an
# escaped character but ends at an escaped quote, newline or tab, so the JSON around it stays.
_FLAG_VALUE = (
    r"(?:\\?[\"'])?(?P<v>(?!⟦)(?:(?<=\\\")[^\"\\]{1,256}(?=\\\")|(?<=\")(?<!\\\")(?:[^\"\\]|\\.){1,256}(?=\")"
    r"|(?<=')(?:[^'\\]|\\.){1,256}(?=')|(?<![\\\"'])[^\s;|&⟦\"'\\-](?:[^\s;|&\"'\\]|\\[^\s\"nrt])*))"
)


def _prose_stated(cues: str) -> re.Pattern[str]:
    """ "password is X", "the password is now X", "the token for prod: X". The words between cue and value
    stay inside one clause and one quoted string and never reach into a placeholder; a cue inside a path,
    host or name (`/token:8443`, `x.secret`) does not count."""
    return re.compile(
        r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:" + cues + r")(?![A-Za-z0-9_])[^\n:.;=\"'`⟦]{0,40}?"
        r"(?:\s(?:is|was)(?:\s+(?:now|still|currently|set\s+to|changed\s+to))?\s+|:[ \t]*)"
        + _PROSE_VALUE
    )


def _prose_restated(cues: str) -> re.Pattern[str]:
    """ "the password changed, it's now X", "the token was rotated and it is now X": a second clause of the
    sentence states the value. The words before it stay inside the sentence, as in "password is X"."""
    return re.compile(
        r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:" + cues + r")(?![A-Za-z0-9_])[^\n:.;=\"'`⟦]{0,40}?"
        r"(?:,|\s+and)\s+it(?:(?:['’]|\\{1,8}u2019)s|\s+(?:is|was))(?:\s+(?:now|still|currently|set\s+to|changed\s+to))?\s+"
        + _PROSE_VALUE
    )


def _prose_bare(cues: str) -> re.Pattern[str]:
    """ "gateway token X", "secret X"."""
    return re.compile(r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:" + cues + r")[ \t]+" + _PROSE_VALUE)


# (kind, pattern, group, check): when `group` is set only that group is replaced and the key stays; when
# `check` is set a match counts only when its value passes it. Kinds name a value's own shape (`github`,
# `jwt`, `private_key`). Every rule that finds a value by its context (a key, a header, a sentence, a URL)
# says `credential`, so one value gets one placeholder whichever rule found it.
_SHAPES: list[tuple[str, re.Pattern[str], str | None, Callable[[str], bool] | None]] = [
    (
        # The whole block up to its END line, whatever the body holds (escaped `\n` in a JSON-encoded
        # result, PGP armour headers); a block cut off before its END line runs over the base64 body. The
        # body never holds a run of five dashes, so the search for END stops at the next armour line.
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
            r"(?:(?:[^-]|-(?!----)){0,8000}-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
            r"|[A-Za-z0-9+/=\\\r\n \t]{0,8000})"
        ),
        None,
        None,
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        None,
        None,
    ),
    (
        "openai",
        re.compile(
            r"sk-(?:proj|svcacct|admin|live)-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"
        ),
        None,
        None,
    ),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"), None, None),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"), None, None),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), None, None),
    (
        "slack",
        re.compile(
            r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]+|xapp-\d-[A-Za-z0-9-]+"
        ),
        None,
        None,
    ),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]+"),
        None,
        None,
    ),
    (
        "discord_webhook",
        re.compile(
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
        ),
        None,
        None,
    ),
    ("telegram", re.compile(r"\b\d{5,16}:A[A-Za-z0-9_-]{34}\b"), None, None),
    ("npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), None, None),
    (
        "aws_access_key",
        re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        None,
        None,
    ),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), None, None),
    ("stripe", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"), None, None),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{20,}"), None, None),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{20,}"), None, None),
    (
        "credential",
        re.compile(
            r"(?i)(?:authorization[\"']?[ \t]*[:=][ \t]*[\"']?)?bearer[ \t]+"
            r"(?P<v>[^\s\"'⟦\\][^\s\"'\\]{19,})"
        ),
        "v",
        None,
    ),
    (
        # The password in `scheme://user:PASS@host` (the user may be empty, the password may hold `@`); user
        # and host stay. A host name and port before a list or a fragment (`cache.test:6379,admin@…`) hold
        # no password.
        "credential",
        re.compile(
            r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://"
            r"(?!(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24}:[0-9]{1,5}[,;#])"
            r"[^\s/?#@:\"'<>\\⟦]{0,256}:"
            r"(?P<v>[^\s/?@\"'<>\\⟦$*{][^\s/?\"'<>\\]{0,255})@"
        ),
        "v",
        None,
    ),
    (
        # A private calendar feed: `…/private-<token>/basic.ics`.
        "credential",
        re.compile(r"/private-(?P<v>[A-Za-z0-9]{16,128})(?![A-Za-z0-9])"),
        "v",
        lambda v: re.search(r"[0-9]", v) is not None,
    ),
    (
        # `--password x`, `--api-key=x`, `--token "x"`.
        "credential",
        re.compile(
            r"(?i)--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)"
            r"(?:\s*=\s*|\s+)" + _FLAG_VALUE
        ),
        "v",
        _flag_value,
    ),
    (
        # `--token-value x`. After a suffixed flag a path, URL or setting stays (`--secret-file /etc/app/x`,
        # `--token-url https://…`, `--token-ttl 3600`).
        "credential",
        re.compile(
            r"(?i)--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)"
            r"-\w+(?:\s*=\s*|\s+)" + _FLAG_VALUE
        ),
        "v",
        _suffixed_flag_value,
    ),
    (
        # `mysql -pX`: MySQL and MariaDB clients take a password only attached to `-p`. The client is a command
        # word (not a directory such as `/var/lib/mysql`, unless under a `bin/`), and the search stops at the end
        # of its command, an escaped newline included.
        "credential",
        re.compile(
            r"(?:(?<![^\s;|&(`\"'])|(?<=bin/)|(?<=\\[nt]))(?:mysql[a-z]{0,8}|mariadb(?:-?[a-z]{1,8})?)"
            r"(?![\w.-])[^\n;|&\\]{0,200}?\s-p" + _FLAG_VALUE
        ),
        "v",
        _mysql_password,
    ),
    (
        # `sshpass -p X`, after any of sshpass's own options; a `-p` in the command it runs is not its.
        "credential",
        re.compile(
            r"(?<![\w-])sshpass(?:\s+-[fdP][ \t]*[^\s-]\S*|\s+-[ehvV]){0,4}\s+-p[ \t]*"
            + _FLAG_VALUE
        ),
        "v",
        _flag_value,
    ),
    (
        # `GITHUB_TOKEN=x`, `"api_key": "x"`, `?token=x`. Values that are variable references or masks stay.
        # Quotes may be escaped (JSON inside a JSON-encoded result), and a value ends at a backslash, so an
        # escaped and a plain copy of one value get the same placeholder. Trailing punctuation stays outside, and
        # `&`, `,` and `;` end the value only where `_VALUE_CHAR` says (`password=<value>&3` is one value), and so do
        # `|` and `$(`.
        "credential",
        re.compile(
            r"(?i)"
            + _CREDENTIAL_KEY
            + r"\\?[\"']?\s*[=:]\s*\\?[\"']?"
            + _NOT_A_PORT
            + r"(?P<v>(?<=[\"'])[^\s\"'⟦$*{\[<%&,;`\\](?:"
            + _QUOTED_RUN_CHAR
            + "{6,}"
            + _QUOTED_RUN_END
            + "|"
            + _QUOTED_RUN_CHAR
            + "{5}"
            + _QUOTED_RUN_END
            + r"(?=[.:!?)\]]))|(?<![\"'])(?:[^\s\"'⟦$*{\[<%&,;`\\|]|"
            + _PIPE_CHAR
            + ")(?:"
            + _VALUE_CHAR
            + "{6,}"
            + _UNQUOTED_END
            + "|"
            + _VALUE_CHAR
            + "{5}"
            + _UNQUOTED_END
            + r"(?=[.:!?)\]])))"
        ),
        "v",
        _unquoted_key_value,
    ),
    (
        # `PASSWORD="x!"`: a quoted value is all of it up to its closing quote, trailing punctuation
        # included, as in a JSON pair or under an object key, and so are `&`, `,` and `;` (`PASSWORD='a&b;c'`).
        "credential",
        re.compile(
            r"(?i)"
            + _CREDENTIAL_KEY
            + r"\\?[\"']?\s*[=:]\s*\\?[\"']"
            + _NOT_A_PORT
            + r"(?P<v>[^\s\"'⟦$*{\[<%&,;`\\](?:(?<='.)"
            + _SQ_CHAR
            + "{7,}|"
            + _DQ_CHAR
            + r"{7,}))(?=\\?[\"'])"
        ),
        "v",
        _text_key_value,
    ),
    (
        # `"password": "words, & symbols"`: in a JSON pair the whole quoted string is the value.
        "credential",
        re.compile(
            r"(?i)"
            + _CREDENTIAL_KEY
            + r"\\?[\"']\s*:\s*\\?\"(?P<v>[^\"\\\n⟦$*{\[<%][^\"\\\n]{7,199})\\?\""
        ),
        "v",
        _text_key_value,
    ),
    (
        # An upper-case name with a credential word inside it: `SENTROOK_SECRET_MARKERS=x`. A number or a
        # path is not a value here (`TOKEN_LIMIT=4096`, `GITHUB_TOKEN_PATH=/home/…`), and nor is unquoted
        # code that reads the secret from somewhere (`MY_SECRET_TOKEN = config.token`).
        "credential",
        re.compile(
            r"(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}"
            r"\\?[\"']?\s*[=:]\s*"
            r"(?![0-9]+(?![^\s\"'&,;<>`\\]))(?P<v>(?:[^\s\"'⟦$*{<%&,;`\\/~.|]|"
            + _PIPE_CHAR
            + ")"
            + _VALUE_CHAR
            + "{6,}"
            + _UNQUOTED_END
            + r")"
        ),
        "v",
        _inner_key_value,
    ),
    (
        # The same name with a quoted value (`GITHUB_TOKEN_VALUE="x"`): a quoted value is whole, so one
        # shaped like code is still a value.
        "credential",
        re.compile(
            r"(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}"
            r"\\?[\"']?\s*[=:]\s*\\?[\"']"
            r"(?![0-9]+(?![^\s\"'&,;<>`\\]))(?P<v>[^\s\"'⟦$*{<%&,;`\\/~.](?:(?<='.)"
            + _SQ_CHAR
            + "{6,}"
            + _VALUE_END
            + "|"
            + _DQ_CHAR
            + r"{6,}(?!\$\()"
            + _VALUE_END
            + r"))"
        ),
        "v",
        _inner_quoted_value,
    ),
    ("credential", _prose_stated(_PROSE_CUES), "v", _stated_value),
    ("credential", _prose_restated(_PROSE_CUES), "v", _stated_value),
    ("credential", _prose_bare(_PROSE_CUES + "|key"), "v", _bare_value),
]

# Object keys whose whole value is a credential: any key that ends in a credential word (`password`,
# `secretAccessKey`, `logintoken`). `pass`, `tok` and `credentials` count only as a whole word, so `compass`
# and `passage` stay.
_CREDENTIAL_FIELD = re.compile(
    r"(?i)^(?:.*[_-])?(?:pass|tok|credentials?)\Z|(?:token|password|passwd|passphrase|secret|api[_-]?key"
    r"|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret)\Z"
)


# Access codes, PINs and personal identifiers named by a cue word, and random values under a key or a header.
# A short number is a secret only after a cue word ("the gate code is 861206", "collection PIN for order 441 is
# 6815", `yard_code=090373`): with no cue it stays, and so do ordinary codes (postal, country, status, error,
# product and business-record codes). A random value counts only under a key or a header (`value: <random>`,
# `X-Desk: <random>`), never in prose ("what it says: X"), and never under a key that names an id, a hash, a version
# or data.
# Kinds: `code`, `pin`, `identifier` (a passport number) and `random`; a placeholder says `identifier` for an
# identifier and `credential` for the others (`PLACEHOLDER_KIND`).
CODE, PIN, IDENTIFIER, RANDOM = "code", "pin", "identifier", "random"
PLACEHOLDER_KIND = {
    CODE: "credential",
    PIN: "credential",
    RANDOM: "credential",
    IDENTIFIER: "identifier",
}

# Where a cue word starts: not inside a word, or straight after an escaped newline or tab (`\nAlarm code: …` in
# a JSON-encoded result).
_CUE_START = r"(?:(?<![A-Za-z0-9_\\])|(?<=\\[nrt]))"
# Words before "code" that make it an access or sign-in code: "gate code", "sign-in code", "backup codes". A
# code with any other qualifier (postal, country, error, promo) is not a secret.
_CODE_QUALIFIERS = (
    r"gate|door|alarm|access|entry|entrance|keypad|lock|lockbox|key[ -]?safe|safe|sign[ -]?in|"
    r"log[ -]?in|login|verification|verify|security|one[ -]time|backup|recovery|unlock|2fa|mfa"
)
_CODE_CUE = _CUE_START + r"(?:(?:" + _CODE_QUALIFIERS + r")[ \t]+codes?|pass[ -]?codes?|otp)"
# `PIN` in capitals (a lower-case "pin" is usually the verb), and in any case "pin code" / "pin number" or a pin
# that belongs to someone or something ("my pin", "the card pin", "collection pin").
_PIN_CAPS_CUE = _CUE_START + r"PINs?"
_PIN_WORDS_CUE = (
    _CUE_START + r"(?:pin[ \t]+(?:codes?|numbers?)"
    r"|(?:my|your|his|her|their|our|the|card|collection|door|access|sim|bank|debit|atm)[ \t]+pin)"
)
_PASSPORT_CUE = _CUE_START + r"passport(?:[ \t]+(?:numbers?|no\.?|#))?"
# "for order 441", "on the booking": a short phrase between the cue and the value. When one is present the value
# must follow `is`, `was` or a colon, so a number inside the phrase is never taken as the value. "the gate code,
# it is N" states it in a second clause.
_CUE_CONNECTOR = (
    r"[ \t]+(?:for|on|of|to|from)[ \t]+[^\n.:;=]{1,40}?(?:[ \t]+(?:is|was)\b|[ \t]*:)[ \t]*"
)
_CUE_SEPARATOR = (
    r"[ \t]*(?:(?:is|was|are|were)[ \t]*(?::[ \t]*)?|[:=#-][ \t]*"
    r"|,[ \t]*it(?:['’]s|[ \t]+(?:is|was))(?:[ \t]+now)?[ \t]*(?::[ \t]*)?|)"
)
# A value ends at a character that does not continue it or a number ("6815." ends a sentence; "2026-11-13" and
# "10:30" are not codes).
_CUE_END = r"(?![A-Za-z0-9_-]|[.:,/][0-9])"


def _cue_rule(flags: str, cue: str, value: str) -> re.Pattern[str]:
    return re.compile(
        flags
        + "(?:"
        + cue
        + ")(?:"
        + _CUE_CONNECTOR
        + "|"
        + _CUE_SEPARATOR
        + r")\\{0,8}[\"'`]?"
        + value
        + _CUE_END
    )


def _code_value(v: str) -> bool:
    """A code: four to ten digits, or two groups of letters and digits with a digit in them (`4821-9930`)."""
    return "-" not in v or re.search(r"[0-9]", v) is not None


def _identifier_value(v: str) -> bool:
    """A passport number: capitals and digits, with a digit (`passport renewal` is words)."""
    return re.search(r"[0-9]", v) is not None and re.search(r"[a-z]", v) is None


# (kind, pattern, check): group `v` is replaced; a match counts only when its value passes the check.
_CUES: list[tuple[str, re.Pattern[str], Callable[[str], bool] | None]] = [
    (
        CODE,
        _cue_rule("(?i)", _CODE_CUE, r"(?P<v>[0-9]{4,10}|[A-Za-z0-9]{4,6}-[A-Za-z0-9]{4,6})"),
        _code_value,
    ),
    (PIN, _cue_rule("", _PIN_CAPS_CUE, r"(?P<v>[0-9]{4,10})"), None),
    (PIN, _cue_rule("(?i)", _PIN_WORDS_CUE, r"(?P<v>[0-9]{4,10})"), None),
    (IDENTIFIER, _cue_rule("(?i)", _PASSPORT_CUE, r"(?P<v>[A-Z0-9]{6,12})"), _identifier_value),
    # The value first: "482193 is your verification code".
    (
        CODE,
        re.compile(
            r"(?i)(?:(?<![A-Za-z0-9_.\\-])|(?<=\\[nrt]))(?P<v>[0-9]{4,10})[ \t]+is[ \t]+(?:your|the|my)[ \t]+"
            r"(?:[A-Za-z0-9_-]{1,30}[ \t]+)?" + _CODE_CUE
        ),
        None,
    ),
]

# Where a key starts: not inside a word, a dotted name or a path, or straight after an escaped newline or tab.
_KEY_START = r"(?:(?<![A-Za-z0-9_.\\-])|(?<=\\[nrt]))"
# `yard_code=090373`, `client_pin: 7021`, `gateCode: 4471`, `"passport_number": "PPCDHFZC6"`, `code=006960`.
_CODE_KEY = re.compile(
    _KEY_START
    + r"(?P<k>[A-Za-z][A-Za-z0-9_-]{0,40})\\{0,8}[\"']?[ \t]*(?P<sep>[:=])[ \t]*\\{0,8}[\"']?"
    r"(?P<v>[A-Za-z0-9]{4,12}|[A-Za-z0-9]{4,6}-[A-Za-z0-9]{4,6})" + _CUE_END
)
# The next code in a list after one the rules found: "backup codes: A, B and C", `codes=A,B`.
_CODE_LIST_NEXT = re.compile(
    r"(?:[ \t]*[,;][ \t]*(?:and[ \t]+)?|[ \t]+and[ \t]+)(?P<v>[0-9]{4,10}|[A-Za-z0-9]{4,6}-[A-Za-z0-9]{4,6})"
    + _CUE_END
)
# `value: <random>`, `"X-Desk": "<random>"`, `sig=<random>`: any key or header, a long value.
_RANDOM_KEY = re.compile(
    _KEY_START
    + r"(?P<k>[A-Za-z_][A-Za-z0-9_.-]{0,40})\\{0,8}[\"']?[ \t]*(?P<sep>[:=])[ \t]*\\{0,8}[\"']?"
    r"(?P<v>[A-Za-z0-9+/_-]{12,256}={0,2})(?![A-Za-z0-9+/=_@-]|\.[A-Za-z0-9])"
)
_RANDOM_VALUE = re.compile(r"[A-Za-z0-9+/_-]{12,256}={0,2}")
# Key prefixes that make `*_code` an ordinary value: postal, country, status and error codes, product,
# business-record and discount codes, language and currency codes.
_ORDINARY_CODE_PREFIX = frozenset(
    "zip postal post country area status error err exit return ret response resp http product item "
    "sku promo discount coupon voucher lang language locale currency color colour region iso tax vat "
    "sort bank swift bic qr bar barcode hs naics sic reason event type class char key op short dial "
    "phone airport iata icao station stop route flight course department dept cost gl account project "
    "source src fiscal unit state county city branch store site plan tier mode format result customer "
    "client vendor supplier merchant mcc lot batch location loc ticket run job tariff part model serial "
    "invoice order shipment carrier service category group cpt icd diagnosis procedure exchange "
    "market ticker isin cusip unspsc ref reference hsn sac dialing calling".split()
)
# Keys and headers whose values are identifiers, digests, names, state, data or patterns, not secrets.
_NOT_SECRET_KEY = re.compile(
    r"(?i)(?:^|[_.-])(?:id|ids|uuid|guid|hash|sha\d*|md5|digest|checksum|crc|commit|rev|revision|etag|"
    r"cid|ref|trace\w*|span\w*|request\w*|version|ver|build|sku|order|path|file|filename|url|uri|href|"
    r"src|name|class|classname|type|title|label|tag|branch|slug|key_id|keyid|fingerprint|nonce|"
    r"state|data|content|body|payload|blob|image|attachment|b64|base64|raw|integrity|list|si|"
    r"in-reply-to|references|message-id|thread\w*|customer|payment_intent|charge|invoice|"
    r"subscription|price|product|regex|pattern|glob|"
    r"to|cc|bcc|from|recipients?|host|hostname|domain|bucket|folder|spreadsheet|sheet|doc|document|base|table|"
    r"channel|repo|repository|project|workspace|account|user|username|email|room|chat)$"
)
# camelCase keys ending in an id or name word (`userId`, `fileHash`); case-sensitive, so `sid` and `PHPSESSID`
# (session cookies) still count.
_NOT_SECRET_CAMEL_KEY = re.compile(r"[a-z](?:Id|ID|Ids|Hash|Name|Url|Uri|Path|Version)$")
# A provider's object id (`cus_…`, `pi_…`) and subresource-integrity hashes (`sha384-…`).
_PREFIXED_OBJECT_ID = re.compile(r"[a-z]{1,8}_|(?i:sha(?:1|256|384|512))-")
# A Google Drive, Docs or Sheets file or folder id: `0` or `1`, then 24 to 43 letters, digits, `-` and `_`. It looks
# random, but where Google is named (`_GOOGLE_CONTEXT`) it is the document or folder a call works on, so it stays.
_DRIVE_ID = re.compile(r"[01][A-Za-z0-9_-]{24,43}")
# What names Google in a text, or among a parsed object's own keys and values: a Google host or client library, a
# Drive, Docs or Sheets API name, a Drive query (`'<id>' in parents`, `parents='<id>'`), or a Drive or Docs tool
# (`drive_files_list`, `docs_get`). A word alone ("my parents") does not.
_GOOGLE_CONTEXT = re.compile(
    r"googleapis|googleapiclient|google-apps|gspread|(?:drive|docs|sheets|slides|script)\.google\.com|"
    + _CUE_START
    + r"(?:(?:documentId|spreadsheetId|presentationId|fileId|folderId|driveId|textRun|batchUpdate)(?![A-Za-z0-9_])"
    r"|gapi\.|in[ \t]{1,8}parents(?![A-Za-z0-9_])|parents\\{0,8}[\"']?[ \t]{0,8}="
    r"|g?drive_(?:files?|folders?|permissions?)(?![A-Za-z0-9])"
    r"|(?:g?docs|sheets|slides)_(?:get|create|append|update|batch|export|insert|replace|values))"
)


def _key_words(key: str) -> list[str]:
    """`yard_code` → [yard, code]; `gateCode` → [gate, code]; `alarmPIN` → [alarm, pin]."""
    return [w.lower() for w in re.split(r"[_-]|(?<=[a-z0-9])(?=[A-Z])", key) if w]


def _key_kind(key: str, value: str, sep: str, after_query: bool, prev_word: str = "") -> str | None:
    """The kind of secret under a code, PIN or passport key, or None. A bare `code` key counts only as a form or
    query field with six or more digits (`-d 'code=006960'`): a JSON or YAML `code:` is far more often a status or
    error code, and a link's `?code=` an exchange the scanner needs to see."""
    words = _key_words(key)
    if not words:
        return None
    passport = words[-1] in ("passport", "passportno", "passportnum", "passportnumber") or (
        len(words) > 1 and words[-2] == "passport" and words[-1] in ("no", "num", "number")
    )
    if passport:
        ok = 6 <= len(value) <= 12 and "-" not in value and _identifier_value(value)
        return IDENTIFIER if ok else None
    digits = value.isdigit() and 4 <= len(value) <= 10
    if words[-1] in ("pin", "passcode", "otp"):
        return PIN if digits else None
    if words[-1] not in ("code", "codes") or not (digits or ("-" in value and _code_value(value))):
        return None
    if len(words) > 1:
        return CODE if words[-2] not in _ORDINARY_CODE_PREFIX else None
    ordinary = prev_word.lower() in _ORDINARY_CODE_PREFIX  # "error code=447100"
    return CODE if sep == "=" and len(value) >= 6 and not after_query and not ordinary else None


def _with_lists(
    text: str, found: list[tuple[int, int, int, str]]
) -> list[tuple[int, int, int, str]]:
    """Each further code in a list after a code or PIN the rules found, as its own value: "backup codes: A, B and C"."""
    out = list(found)
    seen: set[int] = set()
    for start, _, e, kind in found:
        if kind not in (CODE, PIN):
            continue
        while e not in seen:
            seen.add(e)
            m = _CODE_LIST_NEXT.match(text, e)
            if m is None or not _code_value(m.group("v")):
                break
            out.append((start, m.start("v"), m.end("v"), kind))
            e = m.end("v")
    return out


def _class(ch: str) -> int:
    return 0 if ch.isdigit() else 1 if ch.isupper() else 2 if ch.islower() else 3


def _looks_random(v: str) -> bool:
    """A value a person did not type: twelve or more characters with upper case, lower case and a digit, not hex
    (a hash, a commit id, a UUID), with frequent changes between character classes, which rules out camelCase
    words (`PrimaryButton2`), and enough distinct characters."""
    core = v.rstrip("=")
    if len(core) < 12 or core[0] in "/-_" or _PREFIXED_OBJECT_ID.match(core):
        return False
    if re.fullmatch(r"[0-9A-Fa-f-]+", core):
        return False
    if not (re.search(r"[A-Z]", core) and re.search(r"[a-z]", core) and re.search(r"[0-9]", core)):
        return False
    changes = sum(1 for a, b in zip(core, core[1:], strict=False) if _class(a) != _class(b))
    if changes < 0.35 * (len(core) - 1):
        return False
    counts: dict[str, int] = {}
    for c in core:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum(n / len(core) * math.log2(n / len(core)) for n in counts.values())
    return entropy >= 3.0


def _random_key(key: str, value: str, after_query: bool) -> bool:
    """A random value under a key or header that does not name an id, a hash, a version or data, outside a link's
    query (`?si=…`, `&list=…` are share links and tracking parameters)."""
    return (
        not _NOT_SECRET_KEY.search(key)
        and not _NOT_SECRET_CAMEL_KEY.search(key)
        and not after_query
        and _looks_random(value)
    )


def _google_id(value: str, google: bool) -> bool:
    """A Drive, Docs or Sheets id where Google is named: the document or folder a call works on, not a secret."""
    return google and _DRIVE_ID.fullmatch(value) is not None


def names_google(obj: dict[Any, Any]) -> bool:
    """Whether a parsed object names Google among its own keys and string values (`_GOOGLE_CONTEXT`)."""
    return any(
        _GOOGLE_CONTEXT.search(str(k)) or (isinstance(v, str) and _GOOGLE_CONTEXT.search(v))
        for k, v in obj.items()
    )


def _prev_word(text: str, start: int) -> str:
    """The word just before `start`, across spaces and tabs (`error` in `error code=`)."""
    m = re.search(
        r"(?:(?<![A-Za-z\\])|(?<=\\[nrt]))([A-Za-z]{1,30})[ \t]{1,8}$",
        text[max(0, start - 40) : start],
    )
    return m.group(1) if m else ""


def _after_query(text: str, start: int) -> bool:
    return start > 0 and text[start - 1] in "?&"


def _starts_entry(text: str, start: int) -> bool:
    """A `key: value` pair stands on its own: its key starts a line (indented or not), follows `{ , ; ( [` or a quote
    (JSON, a dict, a quoted header) or a `-H` / `--header` flag. A word before a colon in a sentence ("what it says:
    X") is prose, not a key."""
    i = start
    while i > 0:
        if text[i - 1] in " \t":
            i -= 1
        elif i > 1 and text[i - 2 : i] == "\\t":
            i -= 2
        else:
            break
    if i == 0 or text[i - 1] in "\n\r{,;([\"'" or text[max(0, i - 2) : i] in ("\\n", "\\r"):
        return True
    return text.endswith(("-H", "--header"), 0, i)


def cue_spans(text: str) -> list[tuple[int, int, int, str]]:
    """Every access code, PIN, identifier and random value the cue and key rules find: (match start, value start,
    value end, kind), unmerged."""
    out: list[tuple[int, int, int, str]] = []
    for kind, pattern, check in _CUES:
        for m in pattern.finditer(text):
            s, e = m.span("v")
            if check is None or check(text[s:e]):
                out.append((m.start(), s, e, kind))
    for m in _CODE_KEY.finditer(text):
        kind = _key_kind(
            m.group("k"),
            m.group("v"),
            m.group("sep"),
            _after_query(text, m.start()),
            _prev_word(text, m.start()),
        )
        if kind is not None:
            out.append((m.start(), m.start("v"), m.end("v"), kind))
    google: bool | None = None  # read once, and only when a value has a Drive id's shape
    for m in _RANDOM_KEY.finditer(text):
        if m.group("sep") == ":" and not _starts_entry(text, m.start()):
            continue
        if _random_key(m.group("k"), m.group("v"), _after_query(text, m.start())):
            if _DRIVE_ID.fullmatch(m.group("v")):
                if google is None:
                    google = _GOOGLE_CONTEXT.search(text) is not None
                if google:
                    continue
            out.append((m.start(), m.start("v"), m.end("v"), RANDOM))
    return _with_lists(text, out)


def object_kind(key: str, value: Any, google: bool = False) -> str | None:
    """The kind of secret a parsed object's value is under its key, or None: a code, PIN or passport number under
    its key (a number counts as its digits), or a random string under any key or header (`{"X-Desk": …}`) unless it
    is a Drive, Docs or Sheets id and its object names Google (`google`, from `names_google`)."""
    if isinstance(value, float) and value.is_integer() and 0 <= value < 2**53:
        value = int(value)  # JSON `4471.0`, as the OpenClaw plugin reads it
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9]{4,12}|[A-Za-z0-9]{4,6}-[A-Za-z0-9]{4,6}", text):
        kind = _key_kind(key, text, ":", False)
        if kind is not None:
            return kind
    if (
        isinstance(value, str)
        and _RANDOM_VALUE.fullmatch(value)
        and _random_key(key, value, False)
        and not _google_id(value, google)
    ):
        return RANDOM
    return None


def _spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for kind, pattern, group, check in _SHAPES:
        for m in pattern.finditer(text):
            s, e = m.span(group) if group else m.span()
            if check in _STAND_IN_CHECKS and _quoted_stand_in(text, m.start(), s, e):
                continue  # a quoted value cut short in docs: `"access_token": "ya29.a0..."`
            if check in _UNQUOTED_CHECKS and (e := _query_value_end(text, m.start(), s, e)) is None:
                continue
            if e > s and (check is None or check(text[s:e])):
                spans.append((s, e, kind))
    spans.extend((s, e, PLACEHOLDER_KIND[kind]) for _, s, e, kind in cue_spans(text))
    spans.sort(key=lambda x: (x[0], -x[1]))
    merged: list[list[Any]] = []
    for s, e, kind in spans:
        if merged and s < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
            continue
        merged.append([s, e, kind])
    return [(s, e, k) for s, e, k in merged]


class Redactor:
    def __init__(self, level: str, salt: str) -> None:
        self.level = level
        self._salt = salt.encode()

    def _placeholder(self, kind: str, value: str) -> str:
        if kind == "private_key":
            # Hashed without its line breaks, plain or escaped, so a key keeps its placeholder however many
            # times the text around it was JSON-encoded.
            value = re.sub(r"\\+[rnt]|\s+", "", value)
        ref = hmac.new(self._salt, value.encode(), hashlib.sha256).hexdigest()[:4]
        return f"⟦secret:{kind}:{ref}⟧"

    def string(self, text: str) -> str:
        if self.level == "off" or not text:
            return text
        spans = _spans(text)
        if not spans:
            return text
        out, pos = [], 0
        for s, e, kind in spans:
            out.append(text[pos:s])
            out.append(self._placeholder(kind, text[s:e]))
            pos = e
        out.append(text[pos:])
        return "".join(out)

    def value(self, value: Any, depth: int = 0) -> Any:
        if isinstance(value, str):
            return self.string(value)
        if depth > 32:
            return value
        if isinstance(value, list):
            return [self.value(v, depth + 1) for v in value]
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            # Read only when one of its values has a Drive id's shape.
            google = any(
                isinstance(v, str) and _DRIVE_ID.fullmatch(v) for v in value.values()
            ) and names_google(value)
            for k, v in value.items():
                if (
                    self.level != "off"
                    and _CREDENTIAL_FIELD.search(str(k))
                    and isinstance(v, str)
                    and v
                    and not v.startswith("⟦")
                    # A URL under a credential key (`forgotPassword`) goes through the text rules, which
                    # keep its host.
                    and _key_value(v)
                ):
                    out[str(k)] = self._placeholder("credential", v)
                elif self.level != "off" and (kind := object_kind(str(k), v, google)) is not None:
                    # A whole-number float is its digits, as the OpenClaw plugin reads JSON `4471.0`.
                    out[str(k)] = self._placeholder(
                        PLACEHOLDER_KIND[kind], str(int(v)) if isinstance(v, float) else str(v)
                    )
                else:
                    out[str(k)] = self.value(v, depth + 1)
            return out
        return value


def cap_head_tail(text: str, cap_bytes: int) -> tuple[str, bool, int]:
    """Cap at `cap_bytes` (UTF-8), keeping two thirds head and one third tail.
    Returns (text, truncated, original size in bytes)."""
    raw = text.encode("utf-8")
    size = len(raw)
    if size <= cap_bytes:
        return text, False, size
    marker = f"\n…[sentrook: {size - cap_bytes} bytes cut]…\n"
    budget = max(0, cap_bytes - len(marker.encode("utf-8")))
    head_n = budget * 2 // 3
    tail_n = budget - head_n
    head = raw[:head_n].decode("utf-8", errors="ignore")
    tail = raw[size - tail_n :].decode("utf-8", errors="ignore") if tail_n else ""
    return head + marker + tail, True, size


def cap_args(value: Any, cap_bytes: int) -> dict[str, Any]:
    """Cap an arguments object at about `cap_bytes` of JSON while keeping it an object: long string leaves
    are cut head and tail to a share of the budget; anything still over collapses to
    `{"_truncated": "<capped JSON>"}`."""
    obj = value if isinstance(value, dict) else {"value": value}
    dumped = json.dumps(obj, ensure_ascii=False, default=str)
    if len(dumped.encode("utf-8")) <= cap_bytes:
        return obj
    leaves = 0

    def count(v: Any, d: int) -> None:
        nonlocal leaves
        if isinstance(v, str):
            leaves += 1
        elif isinstance(v, dict) and d < 32:
            for x in v.values():
                count(x, d + 1)
        elif isinstance(v, list) and d < 32:
            for x in v:
                count(x, d + 1)

    count(obj, 0)
    leaf_cap = max(200, cap_bytes // max(1, leaves))

    def cut(v: Any, d: int) -> Any:
        if isinstance(v, str):
            return cap_head_tail(v, leaf_cap)[0]
        if isinstance(v, list) and d < 32:
            return [cut(x, d + 1) for x in v]
        if isinstance(v, dict) and d < 32:
            return {k: cut(x, d + 1) for k, x in v.items()}
        return v

    shrunk = cut(obj, 0)
    shrunk_json = json.dumps(shrunk, ensure_ascii=False, default=str)
    if len(shrunk_json.encode("utf-8")) <= cap_bytes * 1.25:
        return shrunk
    return {"_truncated": cap_head_tail(shrunk_json, cap_bytes)[0]}
