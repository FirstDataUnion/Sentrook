"""Local data carried out in the URL of a fetch.

A `GET` has no body, but its query string and path reach the server all the same: a fetch whose URL
reproduces text the agent read from a local file is a send of that text, whatever the method. This module
finds that case deterministically, from what one scan request carries:

- the pending call is a web fetch or a browser navigation with no body and a reading method;
- a part of its URL (the query or the path, percent-decoded, and a base64 or hex value decoded once more)
  shares a run of at least `MIN_RUN` characters with the result of a local read delivered in this request
  (a file read, or a command made only of reading heads), compared without case and with whitespace
  collapsed;
- the owner's own words do not hold that run: a note the owner dictated is theirs to pass on.

A link the file itself gave is an address, not data: text of the local read that is a URL on the same host
is left out before comparing, so fetching a bookmark never counts.

Bounds, by design: only reads whose results are in this request are seen (earlier ones are not kept), and
only a verbatim or singly encoded run is matched; text reworded, split across requests or encoded otherwise
is not.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, unquote_plus, urlsplit

from ..planir.canonical import CanonicalCall
from ..planir.models import InputKind, ProviderKind, ToolKind
from .entities import shell_segments
from .session_sets import READ_HEADS

#: The shortest shared run that counts. Long enough that a date, a short name or a version does not match.
MIN_RUN = 16
#: Per URL part and per local read, how much text is compared.
_MAX_PART = 4096
_MAX_CONTENT = 400_000
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
_B64_VALUE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX_VALUE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_SPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class CarriedText:
    """One URL part that reproduces a local read. Never the text itself."""

    input_seq: int
    part: str  # query | path
    encoding: str  # plain | base64 | hex

    def to_evidence(self) -> dict[str, Any]:
        return {"input_seq": self.input_seq, "part": self.part, "encoding": self.encoding}


def _norm(text: str) -> str:
    return _SPACE.sub(" ", text).strip().lower()


def _decoded(value: str) -> list[tuple[str, str]]:
    """A base64 or hex value read as text, when it decodes to printable text."""
    out: list[tuple[str, str]] = []
    if _HEX_VALUE.fullmatch(value):
        try:
            out.append(("hex", bytes.fromhex(value).decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            pass
    if _B64_VALUE.fullmatch(value):
        padded = value + "=" * (-len(value) % 4)
        try:
            text = base64.urlsafe_b64decode(padded.replace("+", "-").replace("/", "_")).decode(
                "utf-8"
            )
        except (binascii.Error, ValueError, UnicodeDecodeError):
            text = ""
        if text:
            out.append(("base64", text))
    return [(enc, t) for enc, t in out if all(c.isprintable() or c in "\n\t" for c in t)]


def _url_parts(url: str) -> list[tuple[str, str, str]]:
    """(part, encoding, text) for everything in the URL that reaches the server besides the host."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return []
    out: list[tuple[str, str, str]] = []
    for name, raw, plain in (
        ("query", parts.query, unquote_plus(parts.query)),
        ("path", parts.path, unquote(parts.path)),
    ):
        if not raw:
            continue
        out.append((name, "plain", plain))
        if unquote(plain) != plain:  # encoded twice
            out.append((name, "plain", unquote(plain)))
        for token in re.split(r"[/&=;,\s]+", plain):
            out.extend((name, enc, text) for enc, text in _decoded(token))
    return [(name, enc, text[:_MAX_PART]) for name, enc, text in out]


def _local_read(call: CanonicalCall | None) -> bool:
    """The history step read local data and did nothing else: a file read, or a command made only of
    reading heads."""
    if call is None or call.provider.kind is not ProviderKind.HOST:
        return False
    if call.tool_kind is ToolKind.FILE_READ:
        return True
    if call.tool_kind is not ToolKind.EXEC:
        return False
    segments = shell_segments(call.command or "")
    return bool(segments) and all(PurePosixPath(seg[0]).name in READ_HEADS for seg in segments)


def _without_links_to(host: str, content: str) -> str:
    """`content` without the URLs it holds on `host`: an address the file gave is not data."""
    link = re.compile(
        r"(?:https?://)?(?:[\w.-]+@)?" + re.escape(host) + r"(?::\d+)?(?:[/?#][^\s\"'<>`)\]]*)?",
        re.IGNORECASE,
    )
    return link.sub(" ", content)


def _shares_run(text: str, content: str, request: str) -> bool:
    for i in range(len(text) - MIN_RUN + 1):
        run = text[i : i + MIN_RUN]
        if run in content and run not in request:
            return True
    return False


def url_carries_local(
    pending: CanonicalCall,
    inputs: list[Any],
    history_by_step: dict[int, CanonicalCall],
    request_words: str,
) -> list[CarriedText]:
    """The parts of the pending fetch's URL that reproduce a local read in this request, text the owner's
    words do not hold. `inputs` are `PreparedInput`s. Empty for a call that already sends a body."""
    if pending.tool_kind not in (ToolKind.WEB_FETCH, ToolKind.BROWSER):
        return []
    url = pending.get("url")
    if not isinstance(url, str) or not url:
        return []
    if str(pending.get("method") or "GET").upper() in _BODY_METHODS or pending.get("body"):
        return []
    parts = [(name, enc, _norm(text)) for name, enc, text in _url_parts(url)]
    parts = [p for p in parts if len(p[2]) >= MIN_RUN]
    if not parts:
        return []
    try:
        host = urlsplit(url.strip()).hostname or ""
    except ValueError:
        host = ""
    request = _norm(request_words or "")
    out: list[CarriedText] = []
    for pi in inputs:
        item = pi.input
        if item.kind is not InputKind.TOOL_RESULT or not item.content:
            continue
        if not _local_read(history_by_step.get(pi.step) if pi.step is not None else None):
            continue
        content = item.content[:_MAX_CONTENT]
        if host:
            content = _without_links_to(host, content)
        content = _norm(content)
        for name, enc, text in parts:
            found = CarriedText(item.input_seq, name, enc)
            if found not in out and _shares_run(text, content, request):
                out.append(found)
    return out
