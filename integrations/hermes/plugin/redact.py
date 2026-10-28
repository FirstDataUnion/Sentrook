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
# A prose value: up to 200 characters without spaces or quotes; trailing punctuation is not part of it.
_PROSE_VALUE = (
    r"[\"'`]?(?![0-9]{1,5}(?![0-9A-Za-z]))"
    r"(?P<v>[^\s\"'`⟦⟧$<>\\]{5,199}[^\s\"'`⟦⟧$<>\\.,;:!?)\]])"
)
# Words, not secrets: one or more words with at most a capital first letter, maybe hyphenated (`required`,
# `Read-only`, `ENABLED`), an identifier (`accessToken`, `GITHUB_TOKEN`), or a hyphenated name with two or
# more plain words in it (`gpt-4o-mini`, `min-length-12`).
_ORDINARY_WORD = re.compile(
    r"(?:[A-Za-z][a-z]*(?:-[A-Za-z][a-z]*)*|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"
)
# What a sentence names: paths, URLs, masks and templates, code, dates, hex addresses, key fingerprints.
_NAMED_THING = re.compile(
    r"^[/~.*{\[(]|://|\(|^[0-9]{4}-[0-9]{2}-[0-9]{2}|^0x[0-9a-fA-F]{40}$|^(?:SHA256|MD5):"
)
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def _is_ordinary(v: str) -> bool:
    return bool(_ORDINARY_WORD.fullmatch(v)) or (
        sum(1 for p in v.split("-") if re.fullmatch(r"[a-z]{2,}", p)) >= 2
    )


def _key_value(v: str) -> bool:
    """Not a key's value: a URL (the URL rule takes any password inside it and the host stays) or the name
    of an environment variable (`token: GITHUB_TOKEN`)."""
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


def _prose_stated(cues: str) -> re.Pattern[str]:
    """ "password is X", "the password is now X", "the token for prod: X". The words between cue and value
    stay inside one clause and one quoted string and never reach into a placeholder; a cue inside a path,
    host or name (`/token:8443`, `x.secret`) does not count."""
    return re.compile(
        r"(?i)(?<![A-Za-z0-9_/.⟦-])(?:" + cues + r")(?![A-Za-z0-9_])[^\n:.;=\"'`⟦]{0,40}?"
        r"(?:\s(?:is|was)(?:\s+(?:now|still|currently|set\s+to|changed\s+to))?\s+|:[ \t]*)"
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
        # and host stay.
        "credential",
        re.compile(
            r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s/?#@:\"'<>\\⟦]{0,256}:"
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
        # `--password x`, `--api-key=x`, `--token "x"`
        "credential",
        re.compile(
            r"(?i)--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)"
            r"(?:-\w+)?(?:\s*=\s*|\s+)"
            r"(?P<v>\"[^\"\\]*(?:\\.[^\"\\]*)*\"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&⟦-][^\s;|&]*)"
        ),
        "v",
        None,
    ),
    (
        # `GITHUB_TOKEN=x`, `"api_key": "x"`, `?token=x`. Values that are variable references or masks stay.
        # Quotes may be escaped (JSON inside a JSON-encoded result), and a value ends at a backslash, so an
        # escaped and a plain copy of one value get the same placeholder.
        "credential",
        re.compile(
            r"(?i)" + _CREDENTIAL_KEY + r"\\?[\"']?\s*[=:]\s*\\?[\"']?"
            r"(?![0-9]{1,5}(?![0-9A-Za-z]))(?P<v>[^\s\"'⟦$*{\[<%&,;`\\][^\s\"'&,;<>`\\]{7,})"
        ),
        "v",
        _key_value,
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
        _key_value,
    ),
    (
        # An upper-case name with a credential word inside it: `SENTROOK_SECRET_MARKERS=x`. A number or a
        # path is not a value here (`TOKEN_LIMIT=4096`, `GITHUB_TOKEN_PATH=/home/…`).
        "credential",
        re.compile(
            r"(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}"
            r"\\?[\"']?\s*[=:]\s*\\?[\"']?"
            r"(?![0-9]+(?![^\s\"'&,;<>`\\]))(?P<v>[^\s\"'⟦$*{<%&,;`\\/~.][^\s\"'&,;<>`\\]{7,})"
        ),
        "v",
        _inner_key_value,
    ),
    ("credential", _prose_stated(_PROSE_CUES), "v", _stated_value),
    ("credential", _prose_bare(_PROSE_CUES + "|key"), "v", _bare_value),
]

# Object keys whose whole value is a credential: any key that ends in a credential word (`password`,
# `secretAccessKey`, `logintoken`). `pass`, `tok` and `credentials` count only as a whole word, so `compass`
# and `passage` stay.
_CREDENTIAL_FIELD = re.compile(
    r"(?i)^(?:.*[_-])?(?:pass|tok|credentials?)\Z|(?:token|password|passwd|passphrase|secret|api[_-]?key"
    r"|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret)\Z"
)


def _spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for kind, pattern, group, check in _SHAPES:
        for m in pattern.finditer(text):
            s, e = m.span(group) if group else m.span()
            if e > s and (check is None or check(text[s:e])):
                spans.append((s, e, kind))
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
