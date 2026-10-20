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
from typing import Any

_KEY_NAMES = (
    r"api[_-]?key|apikey|secret|token|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd"
    r"|client[_-]?secret|auth[_-]?token"
)

# (kind, pattern, group): when `group` is set only that group is replaced and the key stays.
_SHAPES: list[tuple[str, re.Pattern[str], str | None]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\r\n \t]{0,8000}"
            r"(?:-----END [A-Z ]{0,40}PRIVATE KEY-----)?"
        ),
        None,
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        None,
    ),
    (
        "openai",
        re.compile(
            r"sk-(?:proj|svcacct|admin|live)-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"
        ),
        None,
    ),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"), None),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"), None),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), None),
    (
        "slack",
        re.compile(
            r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]+|xapp-\d-[A-Za-z0-9-]+"
        ),
        None,
    ),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]+"),
        None,
    ),
    (
        "discord_webhook",
        re.compile(
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
        ),
        None,
    ),
    ("telegram", re.compile(r"\b\d{5,16}:A[A-Za-z0-9_-]{34}\b"), None),
    ("npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), None),
    ("aws_access_key", re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), None),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), None),
    ("stripe", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"), None),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{20,}"), None),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{20,}"), None),
    (
        "bearer",
        re.compile(
            r"(?i)(?:authorization[\"']?[ \t]*[:=][ \t]*[\"']?)?bearer[ \t]+(?P<v>[^\s\"'⟦][^\s\"']{19,})"
        ),
        "v",
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
    ),
    (
        # `GITHUB_TOKEN=x`, `"api_key": "x"`, `?token=x` (`_` is not alphanumeric, so the key's own prefix
        # passes the lookbehind). A key right after `/` or `⟦` does not count; variable references and
        # masks stay.
        "credential",
        re.compile(
            r"(?i)(?<![A-Za-z0-9/⟦])(?:" + _KEY_NAMES + r")(?![A-Za-z0-9])[\"']?\s*[=:]\s*[\"']?"
            r"(?!\d{1,5}(?![0-9A-Za-z]))(?P<v>[^\s\"'⟦$*{<%&,;`][^\s\"'&,;<>`]{7,})"
        ),
        "v",
    ),
]

_CREDENTIAL_FIELD = re.compile(
    r"(?i)^(?:.*[_-])?(?:token|password|passwd|pass|secret|api[_-]?key|apikey|auth[_-]?token|credentials?"
    r"|bearer|private[_-]?key|client[_-]?secret)$"
)


def _spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for kind, pattern, group in _SHAPES:
        for m in pattern.finditer(text):
            s, e = m.span(group) if group else m.span()
            if e > s:
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
                    and _CREDENTIAL_FIELD.match(str(k))
                    and isinstance(v, str)
                    and v
                    and not v.startswith("⟦")
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
