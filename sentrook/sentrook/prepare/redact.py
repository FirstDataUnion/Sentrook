"""The scanner's second redaction pass over the v2 Jev views (`redact-v16`; `redact-v15` replaced a Google Drive, Docs
or Sheets id under a key as a random value even where the text or object names Google, so the document or folder a call
works on was hidden, `redact-v14` took a pipe or a command
substitution straight after an unquoted value into it (`TOKEN=<value>|curl …|sh`, `TOKEN=<value>$(…)`), and a
sentence's value ran on through `&`, `,`, `;` and `|`, so the command after it was hidden, `redact-v13` ended an unquoted key's value at `&`, `,` or `;` and a quoted one too
(`password=<value>&<rest>`), so the rest of it stayed raw, `redact-v12`
replaced a quoted key's value that stands in for a secret as if it were one (`"access_token": "ya29.a0..."`,
`"token": "REDACTED"`), `redact-v11` replaced a key's value
that names a credential field or stands in for one, or is a short lower-case word, as if it were a secret
(`api_key:api_secret` quoted from docs, `password: your_password`), `redact-v10` left raw an access code
or PIN named by a cue word, a passport number, and a random value under a key or header that gives no hint,
`redact-v9` replaced a call whose
argument is a bare name, `os.getenv(name)`, as if it were a secret, `redact-v8` replaced code that reads a
secret after an upper-case name with a credential word inside it, `MY_SECRET_TOKEN = config.token`, as if it were
one, `redact-v7` replaced code that reads a secret from an attribute or with arguments, `config.token`,
`sys.argv[1]`, `getpass.getpass(prompt='…')`, `redact-v6` replaced code that reads a secret under a credential key,
`access_token = token_data['access_token']`, `redact-v5` kept a key's trailing
punctuation in its value and missed a value restated in a second clause, `redact-v4` took the plugins'
command-line flag rule but not their object-key rule, `redact-v3` took the plugins' text rules but their
command-line flag rule, `redact-v2` moved the vendor shapes to data,
`redact-v1` came with the v1.1 question-set pass).

The plugin redacts secrets before a PlanIR leaves the host (`options.redaction`, usually `standard`).
This pass catches secrets that slipped through (an older plugin, redaction `off`, another client), so a
model never sees a live key in a view Sentrook builds. Its text rules are the Hermes plugin's
(`integrations/hermes/plugin/redact.py`), kept as a copy with a parity test, plus the vendor shapes in
`redact_shapes.yaml`. In a parsed object (a call's `arguments`) a value under a key that names a
credential (`{"password": X}`, `{"env": {"DB_PASS": X}}`), a code, PIN or passport number under its key
(`{"door_code": "4471"}`) and a random value under any key or header (`{"X-Desk": X}`) are replaced whole, as
the plugins do; a URL
or an environment variable name there goes through the text rules instead. Command-line password flags count (`--password X`, `mysql -pX`, `sshpass -p X`),
but a path or URL after a flag stays (`--secret-file PATH`). It is deliberately conservative: recipients, names, hosts and email addresses stay, because
Jev needs them to judge alignment (a URL loses only its password). A replaced value becomes
`⟦secret:scanner⟧`; the preamble already tells Jev that a placeholder still marks a real secret.

Every pattern does bounded work per position: no nested quantifiers, no unbounded repetition followed
by a suffix that can fail (the JWT tail is matched anchored, from where the head ended, and a private
key's body is capped), and the imported vendor shapes have their repetition capped.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from typing import Any

from .redact_shapes import load_shapes
from .redact_shapes import spans as shape_spans

REDACTION_VERSION = "redact-v16"
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
#: The last character of a value: sentence punctuation after a value is not part of it (`password: X.`,
#: `(token=X)`).
_VALUE_END = r"[^\s\"'&,;<>`\\.:!?)\]]"
#: What a command after a value looks like, after `&`, `,`, `;` or `|`: a word with more after it on its line (`curl …`,
#: `w x`), maybe straight after it (`curl${IFS}…`, `curl$IFS…`, `reboot)`, `base64|sh`, `sort<x`); a word before `;`,
#: `&`, `&&` or `;;` that ends its line or has a command after it (`reboot;`, `reboot;echo …`, `reboot&&echo …`); a word
#: with quotes or an escape inside it (`cu''rl`, `c\url`); or a command led by a symbol: a substitution or a variable
#: (`$(…)`, `$SHELL`, `${IFS}`, `$'…'`), a subshell or a group (`(…)`, `{ …; }`) or a path (`./run.sh`, `../bin/x`,
#: `/bin/sh`, `~/x.sh`). A tail that runs to the end of the line, a lone word included (`TOKEN=<value>|sh`,
#: `TOKEN=<value>;make`), is part of the value, as a password's tail would be.
_COMMAND_ENDS = (
    r"[A-Za-z_][A-Za-z0-9_.-]{1,40}(?:[ \t|<>`)]|\\t|\$[{(A-Za-z_]"
    r"|[;&]{1,2}(?:[ \t]|(?![^\n])|[A-Za-z_][A-Za-z0-9_.-]{0,40}[ \t]))"
    r"|[A-Za-z][A-Za-z0-9_.-]{0,40}(?:['\"]{1,2}[A-Za-z]|\\(?![nrtbf]|u[0-9A-Fa-f]{4})[A-Za-z])"
    r"|[A-Za-z_](?:[ \t]|\\t)|\$[(A-Za-z_{'\"]|\(|\{[ \t]|\.\.?/|/[A-Za-z]|~/"
)
#: What ends an unquoted value at `|`: a command (`_COMMAND_ENDS`), a word led by a digit before a space (`|7z x`), or a
#: brace list (`|{curl,…}`).
_PIPE_ENDS = _COMMAND_ENDS + r"|[0-9][A-Za-z0-9_.-]{0,40}(?:[ \t]|\\t)|\{[^\s,{}|]{1,40},"
#: What ends an unquoted value at `&`, `,` or `;`: an HTML entity after `&` (`&amp;`, `&quot;`, `&#39;`), another key,
#: maybe with spaces in its name or led by a digit or a symbol (`&page=2`, `,b=2`, `;Initial Catalog=y`, `&ids[]=1`,
#: `&9x=1`), a command (`_COMMAND_ENDS`), a word straight before `(` or `{` (`;next()`), `(` or `{` (`;(…)`, `;{…}`), or
#: a comment (`;#`). A tail that runs to the end of the line or of the text, or starts with a digit, is part of the
#: value (`password=<value>&3`, an `.env` line `PASSWORD=<value>&<rest>`).
_SEPARATOR_ENDS = (
    r"(?<=&)(?:[A-Za-z]{2,8}|#[xX]?[0-9A-Fa-f]{1,6});"
    r"|[A-Za-z_\[%-][A-Za-z0-9_.\[\]%-]{0,40}(?: [A-Za-z][A-Za-z0-9_.-]{0,20}){0,3}[=:]"
    r"|[0-9][A-Za-z0-9_.\[\]%-]{0,40}="
    r"|[A-Za-z_][A-Za-z0-9_.-]{1,40}[({]|[({]|(?<=;)#|" + _COMMAND_ENDS
)
#: `|` inside an unquoted value: part of it (`password=<value>|<rest>`) unless what follows is a space, the end, a quote
#: or `_PIPE_ENDS`, so a pipe into a command stays visible (`TOKEN=<value>|curl …|sh`). Unlike after `&`, `,` or `;`, a
#: key or a word straight before `(` or `{` does not end it, as `|` is common in generated passwords. A value never ends
#: in `|`, so `||` or `|&` before a command ends it too (`TOKEN=<value>||curl …`).
_PIPE_CHAR = r"\|(?=[^\s\"'<>`\\])(?!" + _PIPE_ENDS + ")"
#: A character of an unquoted value after a key. `&`, `,` and `;` end the value before a space, the end, a quote, `&&`
#: or `;;`, or `_SEPARATOR_ENDS`, and after code's closing bracket (`getToken();`); anywhere else they are part of it
#: (`password=<value>&<rest>`, `password=<value>,;<rest>`). `|` ends it where `_PIPE_CHAR` says, and a command
#: substitution `$(` always does (`TOKEN=<value>$(…)`); a `$` before anything else is part of it (`pa$sword`).
_VALUE_CHAR = (
    r"(?:[^\s\"'&,;<>`\\|$]|\$(?!\()|"
    + _PIPE_CHAR
    + r"|(?<![)\]])[&,;](?=[^\s\"'<>`\\])(?!(?<=&)&|(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
#: The last character of an unquoted value: not a pipe and not the `$` of a command substitution, so the command after
#: the value is whole (`TOKEN=<value>$(…)`).
_UNQUOTED_END = r"(?!\||\$\()" + _VALUE_END
#: After an opening quote that does not close before a space (`password='<value>|<rest> …`), where a shell reads `|` as
#: a character: `|` is part of the value, the rest as in `_VALUE_CHAR`.
_QUOTED_RUN_CHAR = (
    r"(?:[^\s\"'&,;<>`\\$]|\$(?!\()|(?<![)\]])[&,;](?=[^\s\"'<>`\\])(?!(?<=&)&|(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
_QUOTED_RUN_END = r"(?!\$\()" + _VALUE_END
#: In a link's query, where the key follows `?`, `&` or `#`, `&` always ends the value (`?token=X&debug`): the value
#: there, from its first character.
_QUERY_VALUE_CHAR = (
    r"(?:[^\s\"'&,;<>`\\|$]|\$(?!\()|"
    + _PIPE_CHAR
    + r"|(?<![)\]])[,;](?=[^\s\"'&<>`\\])(?!(?<=;);|"
    + _SEPARATOR_ENDS
    + "))"
)
#: The rest of a quoted value after its first character: in single quotes anything up to the closing quote; in double
#: quotes, where a shell runs a command substitution, not `$(` (`password="<value>;$(…)"` keeps the command visible).
_SQ_CHAR = r"[^\s\"'<>`\\]"
_DQ_CHAR = r"(?:[^\s\"'<>`\\$]|\$(?!\())"
#: Digits that start a value: up to five, then the value's end, are a port or a count (`x.token:8443/`), not a value.
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
#: A prose value: up to 200 characters without spaces or quotes; trailing punctuation is not part of it. Unquoted, it
#: ends at `&`, `,`, `;` and `|` where an unquoted value after a key does (`token: <value>|curl …`, `password:
#: <value>;curl …`); after a quote, they are part of it.
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
#: One part of a name in code, read as a word (`token_data`, `getSecret`, `JSON`, `oauth2`, `b64decode`): lower,
#: camel, Pascal or upper case, maybe after `_`, with digits at its end or one short run before more letters.
_CODE_PART = (
    r"_?(?:[a-z]+(?:[0-9]{1,3}[a-z]{3,}|[0-9]*)(?:_[a-z]+[0-9]*)*|[a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)+"
    r"|[A-Z][a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)*|[A-Z]+[0-9]*(?:_[A-Z]+[0-9]*)*)"
)
#: A name, maybe dotted, called with no or one bare argument, or subscripted with a small number.
_CODE_CHAIN = _CODE_PART + r"(?:\." + _CODE_PART + r"|\(\)|\([a-z_]{1,20}\)|\[[0-9]{1,4}\])*"
#: A dotted name whose every part reads as a word of up to 32 characters with no run of four digits
#: (`config.token`, `process.env.TOKEN`).
_DOTTED_PART = r"(?=[A-Za-z0-9_]{1,32}(?![A-Za-z0-9_]))(?![A-Za-z0-9_]{0,28}[0-9]{4})" + _CODE_PART
_DOTTED_NAME = _DOTTED_PART + r"(?:\." + _DOTTED_PART + r")+"
#: Code that reads a secret from where it is kept, cut where its quoted argument starts: `token_data[` in
#: `access_token = token_data['access_token']`, `os.environ[`, `creds.get(`, `getpass(`, `resp.json()[`. A
#: name, maybe dotted, called or subscripted, that ends in an open bracket or parenthesis, or a call whose one
#: argument is another such read (`base64.b64decode(os.environ[`) or a dotted name (`b64decode(config.secret`).
#: A random value that happens to end in a bracket is still a value.
_CODE_READ = re.compile(
    _CODE_CHAIN + r"(?:[\[(]|\((?:" + _CODE_CHAIN + r"[\[(]|" + _DOTTED_NAME + r"\)?))"
)
#: A call whose one argument is a bare lower-case name, cut before its closing parenthesis or a comma
#: (`os.getenv(name`, `load_token(path`, `getattr(settings`). It is code only when the name called reads as code
#: (`is_code_read`): dotted, with `_` or a capital, or called or subscripted itself, or one of `_CODE_READERS`.
#: `hunter(abc)` and `mysecret(pw_2024)` are values.
_CODE_NAME_ARG_READ = re.compile(_CODE_CHAIN + r"\([a-z_][a-z0-9_]{0,29}")
_CODE_READERS = frozenset("input getattr getenv getpass open read load get".split())
#: A dotted name called with a keyword before a quoted argument (`getpass.getpass(prompt=`) or subscripted with
#: a number of one or two digits (`sys.argv[1`, its `]` left out as punctuation). Only a dotted name counts
#: (`is_code_read`): `qwerty[99]` and `monkey(prompt='x')` are values.
_CODE_ARG_READ = re.compile(_CODE_CHAIN + r"(?:\[[0-9]{1,2}\]?|\([a-z_][a-z0-9_]{0,29}=)")
#: A plain attribute read is code only from one of these receivers (`self.token`, `config.token`), or when it
#: reads a credential field (`resp.access_token`); `correct.horse.battery.staple` is a value.
_CODE_RECEIVERS = frozenset(
    "self cls this args opts options config cfg conf settings env process os creds credentials secrets params ctx "
    "app request".split()
)
_DOTTED_READ = re.compile(_DOTTED_NAME)

#: Object keys whose whole value is a credential: any key that ends in a credential word (`password`,
#: `secretAccessKey`, `logintoken`). `pass`, `tok` and `credentials` count only as a whole word, so
#: `compass` and `passage` stay.
_CREDENTIAL_FIELD = re.compile(
    r"(?i)^(?:.*[_-])?(?:pass|tok|credentials?)\Z|(?:token|password|passwd|passphrase|secret|api[_-]?key"
    r"|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret)\Z"
)


def _is_ordinary(v: str) -> bool:
    return bool(_ORDINARY_WORD.fullmatch(v)) or (
        sum(1 for p in v.split("-") if re.fullmatch(r"[a-z]{2,}", p)) >= 2
    )


def _key_value(v: str) -> bool:
    """Not a key's value: a URL (the URL rule takes any password inside it and the host stays) or the
    name of an environment variable (`token: GITHUB_TOKEN`)."""
    return "://" not in v and not _ENV_NAME.fullmatch(v)


#: A credential field's name, as docs, templates and code write it (`api_secret`, `your_api_key`, `apiSecret`,
#: `YOUR_TOKEN_HERE`): words with no digits, lower or upper case joined by `_` or `-`, or camel case with each part
#: three or more letters. `_names_a_field` also wants it to end in a credential word, maybe before `here`.
_FIELD_NAME_VALUE = re.compile(
    r"(?:[a-z]{2,}(?:[_-][a-z]+)*|[A-Z]{2,}(?:[_-][A-Z]+)*|[a-z]{2,}(?:[A-Z][a-z]{2,})+|(?:[A-Z][a-z]{2,}){2,})"
)
#: A placeholder that masks a value (`xxxxxxxx`), and a short lower-case word (`changeme`, `required`, `basic`).
_PLACEHOLDER_VALUE = re.compile(r"(?i)x{3,}")
_SHORT_WORD = re.compile(r"[a-z]{1,12}")
#: A value that stands in for a secret rather than being one, under any key: the word REDACTED (maybe in brackets), or
#: a mask of three or more `*`, `•` or `·`. A run of another symbol, letter or digit may be a password (`!!!!!!!!`).
_REDACTED_WORD = re.compile(r"(?i)[(\[<{]?redacted[)\]>}]?")
_MASK_RUN = re.compile(r"([*•·])\1{2,}")
#: A key or cue word that names a password (`password`, `db_pass`, `passphrase`, `pwd`, `pin`): its value is what a
#: person typed, so neither a short value before an ellipsis nor a phrase is read as a stand-in under it.
_PASSWORD_KEY = re.compile(r"(?i)pass|pwd|(?<![a-z])pin(?![a-z])")
#: A quoted string's content from where a value starts to the closing quote (escaped or not), and a token cut short
#: with an ellipsis, as docs abridge one: up to ten token characters, then `...`, `…`, `<...>` or `[...]`
#: (`ya29.a0...`, `1//0g…`). A longer start, or a symbol other than `. _ / + -` in it, may be the secret itself.
_QUOTED_REST = re.compile(r"(?<=[\"'])[^\"'\\\n]{1,200}(?=\\{0,8}[\"'])")
_ELIDED = re.compile(r"[A-Za-z0-9._/+-]{0,10}(?:\.{3}|…|<(?:\.{3}|…)>|\[(?:\.{3}|…)\])")
#: A phrase that says what a token or key is (`short-lived token`, `your api key`, `paste your key here`): two to four
#: plain words (letters, maybe hyphenated, or a short number), no run of twelve or more token characters, and either up
#: to three words ending in a credential noun or a placeholder word with a credential noun anywhere in it.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9_+/=.~-]{12}")
_PLAIN_WORD = re.compile(r"[(\[<{\"'~*]*(?:[A-Za-z][A-Za-z'’-]*|[0-9]{1,4})[)\]>}\",.;:!?*]*")
_CREDENTIAL_NOUNS = frozenset("token tokens key keys secret secrets credential credentials".split())
_PLACEHOLDER_WORDS = frozenset("your here example placeholder".split())


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
    """After "password is" or "token:": six or more characters that are not words, a number or code
    that reads the secret from somewhere."""
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


#: The checks of the key and sentence rules, whose quoted values may stand in for a secret (`_quoted_stand_in`). A
#: command-line value is what the command runs with, so the flag rules are not among them.
_STAND_IN_CHECKS = frozenset(
    {_unquoted_key_value, _text_key_value, _inner_key_value, _inner_quoted_value, _stated_value}
)


#: The checks of the rules whose unquoted value may hold `&` (`_VALUE_CHAR`).
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
    # after a host (`x.token:8443/`) is not a value. Trailing punctuation stays outside, and `&`, `,` and `;`
    # end the value only where `_VALUE_CHAR` says (`password=<value>&3` is one value), and so do
    # `|` and `$(`.
    (
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
        _unquoted_key_value,
    ),
    # `PASSWORD="x!"`: a quoted value is all of it up to its closing quote, trailing punctuation, `&`, `,` and `;`
    # included.
    (
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
        _text_key_value,
    ),
    # `"password": "words, & symbols"`: in a JSON pair the whole quoted string is the value.
    (
        re.compile(
            r"(?i)"
            + _CREDENTIAL_KEY
            + r"\\?[\"']\s*:\s*\\?\"(?P<v>[^\"\\\n⟦$*{\[<%][^\"\\\n]{7,199})\\?\""
        ),
        _text_key_value,
    ),
    # An upper-case name with a credential word inside it: `SENTROOK_SECRET_MARKERS=x`. A number or a
    # path is not a value here (`TOKEN_LIMIT=4096`, `GITHUB_TOKEN_PATH=/home/…`), and nor is unquoted
    # code that reads the secret from somewhere (`MY_SECRET_TOKEN = config.token`).
    (
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
        _inner_key_value,
    ),
    # The same name with a quoted value (`GITHUB_TOKEN_VALUE="x"`): a quoted value is whole, so one
    # shaped like code is still a value.
    (
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
        _inner_quoted_value,
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
    # "the password changed, it's now X", "the token was rotated and it is now X": a second clause of the
    # sentence states the value.
    (
        re.compile(
            r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:"
            + _PROSE_CUES
            + r")(?![A-Za-z0-9_])[^\n:.;=\"'`⟦]{0,40}?"
            r"(?:,|\s+and)\s+it(?:(?:['’]|\\{1,8}u2019)s|\s+(?:is|was))(?:\s+(?:now|still|currently|set\s+to|changed\s+to))?\s+"
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
# Words in a key that make its value a secret whatever it looks like (`SIGNING_KEY`, `X-Auth`, `sessionid`, `hmac`), and
# the endings that do the same inside one word (`signingkey`): a Drive id's shape under such a key, or under a custom
# `X-` header, is redacted even where Google is named.
_SECRET_KEY_WORDS = frozenset(
    "key keys auth authorization cookie cookies sessionid sid sess phpsessid jsessionid sig signature hmac salt seed "
    "master license licence pwd pw pass passwd credential credentials cred creds access private priv pk sk pat secret "
    "token otp totp mfa jwt csrf xsrf".split()
)
_SECRET_KEY_END = re.compile(r"(?:key|token|secret|auth|sig|pass|pwd)[0-9]*$")
# What names Google in a text, or among a parsed object's own keys and values: a Google host or client library, a
# Drive, Docs or Sheets API name, a Drive query (`'<id>' in parents`, `parents='<id>'`), or a Drive or Docs tool
# (`drive_files_list`, `docs_get`). The word alone ("my parents", "kid in parents", `parents = []`) does not.
_GOOGLE_CONTEXT = re.compile(
    r"googleapis|googleapiclient|google-apps|gspread|(?:drive|docs|sheets|slides|script)\.google\.com"
    r"|[\"'][ \t]{1,8}in[ \t]{1,8}parents(?![A-Za-z0-9_])|"
    + _CUE_START
    + r"(?:(?:documentId|spreadsheetId|presentationId|fileId|folderId|driveId|textRun|batchUpdate)(?![A-Za-z0-9_])"
    r"|gapi\.|parents\\{0,8}[\"']?[ \t]{0,8}=[ \t]{0,8}\\{0,8}[\"'][01][A-Za-z0-9_-]{24}"
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


def _secret_key(key: str) -> bool:
    """A key whose value is a secret whatever it looks like: a credential key (`_CREDENTIAL_FIELD`), a custom `X-`
    header, a key with a secret word in any of its dotted parts (`connect.sid`, `GITHUB_TOKEN2`), or one whose last
    word is `session` (`x_session`, not `sessionPlan`)."""
    if key[:2].lower() == "x-" or _CREDENTIAL_FIELD.search(key):
        return True
    words = [w for part in key.split(".") for w in _key_words(part)]
    return bool(words) and (
        words[-1] == "session"
        or any(w in _SECRET_KEY_WORDS or _SECRET_KEY_END.search(w) for w in words)
    )


def _google_id(key: str, value: str, google: bool) -> bool:
    """A Drive, Docs or Sheets id where Google is named, under a key that does not name a secret: the document or
    folder a call works on."""
    return google and _DRIVE_ID.fullmatch(value) is not None and not _secret_key(key)


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
            if _DRIVE_ID.fullmatch(m.group("v")) and not _secret_key(m.group("k")):
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
        and not _google_id(key, value, google)
    ):
        return RANDOM
    return None


def _spans(text: str, *, cues: bool = True) -> list[tuple[int, int]]:
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
            if check in _STAND_IN_CHECKS and _quoted_stand_in(text, m.start(), s, e):
                continue  # a quoted value cut short in docs: `"access_token": "ya29.a0..."`
            if check in _UNQUOTED_CHECKS and (e := _query_value_end(text, m.start(), s, e)) is None:
                continue
            if e > s and (check is None or check(text[s:e])):
                spans.append((s, e))
    if cues:
        spans.extend((s, e) for _, s, e, _ in cue_spans(text))
    return spans


#: Characters past a context rule's match that a cut must keep with it: a value's closing quote, optionally escaped,
#: which some rules require after the value.
_CONTEXT_TRAIL_CHARS = 2


def protected_spans(text: str) -> list[tuple[int, int]]:
    """The stretches of `text` a cut must not split, merged, sorted and disjoint: every secret `redact_text` would
    replace, widened by what identifies it. A value found by its context keeps the cue word or key before it and its
    closing quote after it, so a cut that keeps the value keeps what makes it recognisable."""
    if len(text) < 8:
        return []
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
            if check in _UNQUOTED_CHECKS and (e := _query_value_end(text, m.start(), s, e)) is None:
                continue
            if (
                e > s
                and not (check in _STAND_IN_CHECKS and _quoted_stand_in(text, m.start(), s, e))
                and (check is None or check(text[s:e]))
            ):
                spans.append((m.start(), min(len(text), max(e, m.end()) + _CONTEXT_TRAIL_CHARS)))
    for start, _, e, _ in cue_spans(text):
        spans.append((start, min(len(text), e + _CONTEXT_TRAIL_CHARS)))
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def secret_spans(text: str, *, cues: bool = True) -> list[tuple[int, int]]:
    """The stretches `redact_text` replaces: every secret's span, overlapping ones merged, sorted. Without `cues`,
    only the credentials: no access code, PIN, identifier or random value found by its cue word or key."""
    if len(text) < 8:
        return []
    merged: list[list[int]] = []
    for start, end in sorted(_spans(text, cues=cues), key=lambda s: (s[0], -s[1])):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def redact_text(text: str) -> tuple[str, int]:
    """Replace every secret in `text`; overlapping matches merge into one placeholder that covers them
    all, so no part of a secret survives a shorter, earlier match."""
    merged = secret_spans(text)
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


def _credential_value(key: Any, value: Any) -> bool:
    """A value replaced whole: a non-empty string under a credential key that is not already a
    placeholder, a URL or an environment variable name."""
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith("⟦")
        and _key_value(value)
        and _CREDENTIAL_FIELD.search(str(key)) is not None
    )


def second_pass(obj: Any) -> tuple[Any, int]:
    """Walk dicts, lists and strings; return a redacted copy and the number of replacements. A string
    under a credential key is replaced whole; other dict values go through the text rules. Dict keys and
    non-string scalars are left as they are; `obj` is never mutated."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        total = 0
        out: dict[Any, Any] = {}
        # Read only when one of its values has a Drive id's shape.
        google = any(
            isinstance(v, str) and _DRIVE_ID.fullmatch(v) for v in obj.values()
        ) and names_google(obj)
        for k, v in obj.items():
            if _credential_value(k, v) or object_kind(str(k), v, google) is not None:
                out[k], n = PLACEHOLDER, 1
            else:
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
