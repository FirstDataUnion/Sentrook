"""Signal-preserving truncation for long prose args and exec argv.

Prefix-only truncation drops late-payload attacks (e.g. canary sink URLs after
bland MEMORY.md prefs, or a curl at the end of a long shell script). This packer
keeps a short head for context, extracts IOC-like spans (URLs, sensitive paths,
command-ish lines, injection markers), and optionally a short tail — packed into
a fixed char budget.

Used by sanitize (budget 500) and L3 embed briefing (budget 80). Mirrors live in
``integrations/openclaw/plugin/sanitize.ts``.
"""

from __future__ import annotations

import re

# Prose arg keys and exec argv where late malice is common. Long ``command``
# strings used to be replaced with the literal ``[TRUNCATED]``, which hid the
# pending exec from both L2 and operator review copy.
CONTENT_LIKE_KEYS = frozenset({"content", "text", "body", "message", "command", "cmd"})

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"auth-profiles(?:\.json)?"
    r"|openclaw-agent\.sqlite"
    r"|database\.sqlite"
    r"|~?/\.ssh(?:/[^\s\"']*)?"
    r"|MEMORY\.md"
    r"|authorized_keys"
    r"|/etc/[^\s\"']+"
    r")"
)
_COMMANDISH_LINE_RE = re.compile(
    r"(?im)^.*(?:\bcurl\b|\bwget\b|\btar\b.+\||\bPOST\b|\bpip\s+install\b).*$"
)
# Keep in sync with sentrook.adapters.snapshot._INJECTION_MARKERS (subset for windows).
_INJECTION_MARKERS = re.compile(
    r"(?:"
    r"ignore (?:all |the |your )?(?:previous|prior|above|earlier)\b"
    r"|ignore (?:all |the |your )?safety\b"
    r"|(?:system|admin|developer)\s+override"
    r"|disregard (?:all |the |your )?(?:previous|prior|above|earlier|safety)"
    r"|system prompt"
    r"|exfiltrat"
    r"|upload\s+\S*(?:auth-profiles|openclaw-agent\.sqlite|database\.sqlite|"
    r"credentials|secrets|\.ssh)\S*\s+to\s+https?://"
    r"|(?:important|mandatory|required)\s*:\s*before\b.{0,60}\b(?:upload|send|post|transmit)\b"
    r")",
    re.IGNORECASE,
)

_SEP = " … "
_MARKER_PAD = 60


def is_content_like_key(key: str | None) -> bool:
    """True when ``key`` should use signal-preserving truncation."""
    if key is None:
        return False
    return key.lower() in CONTENT_LIKE_KEYS


def pack_signal_excerpt(text: str, limit: int, *, ellipsis: str = "...") -> str:
    """Pack ``text`` into at most ``limit`` chars, preferring security signals.

    If ``text`` already fits, return it unchanged. For tiny limits, return a
    short ellipsis / truncated marker so callers stay within budget.
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= 3:
        return ellipsis[:limit]

    head_budget, tail_budget = _budgets(limit)
    head = text[:head_budget]
    tail = _aligned_tail(text, tail_budget)

    spans = _collect_spans(text)
    signal_bits: list[str] = []
    seen: set[str] = set()
    for _start, _end, snippet in spans:
        snippet = snippet.strip()
        if not snippet or snippet in seen:
            continue
        # Skip only if already fully visible in the packed head.
        if snippet in head:
            continue
        seen.add(snippet)
        signal_bits.append(snippet)

    return _assemble(head, signal_bits, tail, limit, ellipsis)


def _aligned_tail(text: str, budget: int) -> str:
    """Take the last ``budget`` chars, snapping forward to a word boundary."""
    if budget <= 0 or not text:
        return ""
    tail = text[-budget:]
    # Avoid starting mid-token when the cut is near the start of the window.
    for sep in ("\n", " ", "\t"):
        idx = tail.find(sep)
        if 0 <= idx <= min(24, max(0, budget // 4)):
            return tail[idx + 1 :]
    return tail


def _budgets(limit: int) -> tuple[int, int]:
    """Head/tail char budgets as a function of total limit."""
    if limit <= 40:
        head = max(8, limit // 3)
        tail = max(6, limit // 4)
    elif limit <= 100:
        head = max(24, limit // 3)
        tail = max(16, limit // 4)
    else:
        head = min(120, max(40, limit // 4))
        tail = min(80, max(24, limit // 6))
    # Leave room for separators and at least one signal or ellipsis.
    reserved = len(_SEP) * 2 + len("...")
    while head + tail + reserved > limit and (head > 8 or tail > 6):
        if head >= tail and head > 8:
            head -= 1
        elif tail > 6:
            tail -= 1
        else:
            break
    return head, tail


def _collect_spans(text: str) -> list[tuple[int, int, str]]:
    """Return (start, end, snippet) spans sorted by start, non-overlapping prefer."""
    raw: list[tuple[int, int, str]] = []

    for match in _URL_RE.finditer(text):
        raw.append((match.start(), match.end(), match.group(0)))

    for match in _SENSITIVE_PATH_RE.finditer(text):
        raw.append((match.start(), match.end(), match.group(0)))

    for match in _COMMANDISH_LINE_RE.finditer(text):
        snippet = match.group(0).strip()
        # Lines that already contain a URL are covered by URL extraction; keep
        # the compact URL (+ path) rather than a long diagnostic sentence.
        if not snippet or _URL_RE.search(snippet):
            continue
        raw.append((match.start(), match.end(), snippet))

    for match in _INJECTION_MARKERS.finditer(text):
        start = max(0, match.start() - _MARKER_PAD)
        end = min(len(text), match.end() + _MARKER_PAD)
        # Prefer line boundaries when nearby.
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        if line_end < 0:
            line_end = len(text)
        start = min(start, line_start) if line_start >= start - 20 else start
        end = max(end, line_end) if line_end <= end + 20 else end
        raw.append((start, end, text[start:end].strip()))

    raw.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    merged: list[tuple[int, int, str]] = []
    for start, end, snippet in raw:
        if merged and start < merged[-1][1]:
            # Prefer longer / earlier; skip overlaps.
            continue
        merged.append((start, end, snippet))
    return merged


def _assemble(
    head: str,
    signals: list[str],
    tail: str,
    limit: int,
    ellipsis: str,
) -> str:
    """Join head + signals + tail under ``limit``, dropping signals if needed."""
    # Always prefer ending with ellipsis when we dropped the middle.
    parts: list[str] = [head]
    used = len(head)

    def _can_add(piece: str, *, with_sep: bool) -> bool:
        cost = len(piece) + (len(_SEP) if with_sep else 0)
        # Reserve space for optional trailing ellipsis / tail.
        return used + cost <= limit

    for signal in signals:
        # Cap individual signals so one huge blob doesn't blow the budget alone.
        # Never clip through the middle of a URL — keep the URL intact or drop it.
        max_signal = max(24, limit // 2)
        if len(signal) > max_signal:
            url_match = _URL_RE.search(signal)
            if url_match and len(url_match.group(0)) <= max_signal:
                signal = url_match.group(0)
            elif url_match and len(url_match.group(0)) > max_signal:
                signal = url_match.group(0)[: max_signal - 3] + ellipsis
            else:
                signal = signal[: max_signal - 3] + ellipsis
        if not _can_add(signal, with_sep=True):
            break
        # Need room for sep + signal + maybe sep + tail + ellipsis
        remaining_after = limit - (used + len(_SEP) + len(signal))
        need_tail = 1 if tail and tail not in head else 0
        min_tail_room = (len(_SEP) + min(len(tail), 8)) if need_tail else 0
        if remaining_after < min_tail_room and need_tail:
            break
        parts.append(signal)
        used += len(_SEP) + len(signal)

    if tail and tail not in head:
        # Skip tail when a packed signal already covers it (avoid mid-word dups).
        already = any(tail in p or p in tail for p in parts[1:])
        room = limit - used - len(_SEP)
        if not already and room >= 8:
            clipped = tail if len(tail) <= room else tail[-(room - 3) :] + ellipsis
            parts.append(clipped)
            used += len(_SEP) + len(clipped)
        elif not already and room > 3:
            parts.append(ellipsis[:room])

    packed = _SEP.join(parts)
    if len(packed) > limit:
        packed = packed[: limit - 3] + ellipsis
    # Ensure we signal truncation when we omitted middle content.
    if packed == head and len(head) < limit:
        # No signals/tail fit — classic prefix truncate.
        return head[: limit - 3] + ellipsis if limit > 3 else ellipsis[:limit]
    return packed
