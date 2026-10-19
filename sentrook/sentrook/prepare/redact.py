"""The scanner's second redaction pass over the v2 Jev views (`redact-v1`, added with the v1.1 question-set pass).

The plugin redacts secrets before a PlanIR leaves the host (`options.redaction`, usually `standard`).
This pass catches well-known secret shapes that slipped through, so a model never sees a live key in a
view Sentrook builds. It is deliberately conservative: recipients, names, hosts and email addresses
stay, because Jev needs them to judge alignment. A replaced value becomes `⟦secret:scanner⟧`; the
preamble already tells Jev that a placeholder still marks a real secret.

Every pattern is linear-time: no nested quantifiers, no unbounded repetition followed by a suffix that
can fail (the JWT tail and the PEM end line are matched anchored, from where the head ended).
"""

from __future__ import annotations

import re
from typing import Any

REDACTION_VERSION = "redact-v1"
PLACEHOLDER = "⟦secret:scanner⟧"
#: Longest PEM body searched for its END line; a 4096-bit RSA key is about 3.3k characters.
PEM_MAX_CHARS = 8000

#: Vendor key shapes: fixed prefix, fixed charset, minimum length. The look-behind keeps a prefix inside
#: a longer word (`disk-usage-…`, `task-…`) from matching.
_B = r"(?<![A-Za-z0-9])"
VENDOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(_B + r"AKIA[0-9A-Z]{16}")),
    ("openai_anthropic", re.compile(_B + r"sk-[A-Za-z0-9_-]{20,}")),
    ("stripe", re.compile(_B + r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("github_token", re.compile(_B + r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("github_pat", re.compile(_B + r"github_pat_[A-Za-z0-9_]{22,}")),
    ("slack", re.compile(_B + r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(_B + r"AIza[0-9A-Za-z_-]{35}")),
    ("gitlab_pat", re.compile(_B + r"glpat-[A-Za-z0-9_-]{20}")),
    ("npm_token", re.compile(_B + r"npm_[A-Za-z0-9]{36}")),
    ("huggingface", re.compile(_B + r"hf_[A-Za-z0-9]{30,}")),
)

_JWT_HEAD = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}")
_JWT_TAIL = re.compile(r"\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

_PEM_BEGIN = re.compile(r"-----BEGIN (?P<kind>[A-Z ]{0,40})PRIVATE KEY-----")
#: An unterminated block (the content was cut): the BEGIN line and the base64 lines after it.
_PEM_BODY = re.compile(r"[A-Za-z0-9+/=\r\n \t]{0,8000}")

#: `Authorization: Bearer <token>` (also as a JSON or header pair); the scheme stays.
_BEARER = re.compile(
    r"(?i)(?<![A-Za-z0-9])authorization[\"']?[ \t]*[:=][ \t]*[\"']?bearer[ \t]+"
    r"(?P<v>[^\s\"'⟦][^\s\"']{19,})"
)

#: `key = value` / `key: value` / `"key": "value"` / `?token=value`. The key is bounded by anything but
#: a letter or digit, so `GITHUB_TOKEN=` and `access_token=` match; a key right after `/` (a URL host or
#: path segment) or `⟦` (a placeholder's label) does not, and a port after a host (`x.token:8443/`) is
#: not a value. The value is 8+
#: characters without whitespace or quotes and does not start with a placeholder, a variable reference
#: or a mask.
_KEY_NAMES = (
    r"api[_-]?key|apikey|secret|token|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd"
    r"|client[_-]?secret|auth[_-]?token"
)
_ASSIGN = re.compile(
    r"(?i)(?<![A-Za-z0-9/⟦])(?:" + _KEY_NAMES + r")(?![A-Za-z0-9])"
    r"[\"']?\s*[=:]\s*[\"']?"
    r"(?!\d{1,5}(?![0-9A-Za-z]))"
    r"(?P<v>[^\s\"'⟦$*{<%&,;`][^\s\"'&,;<>`]{7,})"
)


def _spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for m in _PEM_BEGIN.finditer(text):
        end_line = f"-----END {m.group('kind')}PRIVATE KEY-----"
        idx = text.find(end_line, m.end(), m.end() + PEM_MAX_CHARS + len(end_line))
        if idx >= 0:
            spans.append((m.start(), idx + len(end_line)))
        else:
            body = _PEM_BODY.match(text, m.end())
            spans.append((m.start(), body.end() if body else m.end()))
    for m in _JWT_HEAD.finditer(text):
        tail = _JWT_TAIL.match(text, m.end())
        if tail is not None:
            spans.append((m.start(), tail.end()))
    for _name, rx in VENDOR_PATTERNS:
        spans.extend(m.span() for m in rx.finditer(text))
    spans.extend(m.span("v") for m in _BEARER.finditer(text))
    spans.extend(m.span("v") for m in _ASSIGN.finditer(text))
    return spans


def redact_text(text: str) -> tuple[str, int]:
    """Replace every secret shape in `text`; overlapping matches collapse into the earliest, widest."""
    if len(text) < 8:
        return text, 0
    spans = sorted(_spans(text), key=lambda s: (s[0], -s[1]))
    if not spans:
        return text, 0
    out: list[str] = []
    pos = 0
    count = 0
    for start, end in spans:
        if start < pos:
            continue
        out.append(text[pos:start])
        out.append(PLACEHOLDER)
        pos = end
        count += 1
    out.append(text[pos:])
    return "".join(out), count


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
