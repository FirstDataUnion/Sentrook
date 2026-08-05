"""Lightweight deobfuscation of tool arg text before YAIRA ``args_match``.

Goal: raise the cost of trivial evasion (base64-wrapped curl, ``\\x`` splits)
without pretending to defeat arbitrary interpreters. Matchers should still key
off high-signal structure (hooks/, secret paths); this only restores obvious
literals into a normalized form that L2 also searches.
"""

from __future__ import annotations

import base64
import binascii
import re

# echo B64 | base64 -d / --decode, optionally wrapped in $()
_ECHO_B64_PIPE = re.compile(
    r"(?:\$\(\s*)?echo\s+['\"]?([A-Za-z0-9+/]{8,}={0,2})['\"]?\s*\|\s*base64\s+(?:-d|--decode)\s*\)?",
    re.IGNORECASE,
)

# printf '%s' B64 | base64 -d
_PRINTF_B64_PIPE = re.compile(
    r"(?:\$\(\s*)?printf\s+(?:'%s'|\"%s\")\s+['\"]?([A-Za-z0-9+/]{8,}={0,2})['\"]?\s*\|\s*base64\s+(?:-d|--decode)\s*\)?",
    re.IGNORECASE,
)

_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")

# Adjacent shell/string concatenations: "cu""rl" or 'cu''rl'
_QUOTE_CONCAT = re.compile(r'(["\'])([^"\']*)\1\s*\1([^"\']*)\1')

_MAX_PASSES = 6


def normalize_arg_text_for_match(text: str) -> str:
    """Return a best-effort decoded form of ``text`` for secondary regex search.

    Safe on garbage input: undecodable base64 segments are left unchanged.
    Bounded iteration avoids pathological expansion.
    """
    if not text:
        return text

    out = text
    for _ in range(_MAX_PASSES):
        prev = out
        out = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), out)
        out = _expand_b64_pipes(out, _ECHO_B64_PIPE)
        out = _expand_b64_pipes(out, _PRINTF_B64_PIPE)
        # Collapse a few rounds of "a""b" → "ab"
        for _ in range(4):
            nxt = _QUOTE_CONCAT.sub(r"\1\2\3\1", out)
            if nxt == out:
                break
            out = nxt
        if out == prev:
            break
    return out


def match_text_with_normalization(pattern: str, value: str) -> bool:
    """True if ``pattern`` matches the raw value or its normalized decoded variant."""
    flags = re.IGNORECASE | re.DOTALL
    if re.search(pattern, value, flags):
        return True
    normalized = normalize_arg_text_for_match(value)
    if normalized != value and re.search(pattern, normalized, flags):
        return True
    return False


def _expand_b64_pipes(text: str, pattern: re.Pattern[str]) -> str:
    def _repl(match: re.Match[str]) -> str:
        raw = match.group(1)
        try:
            decoded = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError):
            return match.group(0)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.decode("utf-8", errors="replace")

    return pattern.sub(_repl, text)
