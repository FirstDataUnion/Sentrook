"""Lightweight deobfuscation of tool-argument text before matching (ported from 1.x).

Goal: raise the cost of trivial evasion (base64-wrapped curl, `\\x` splits, `"cu""rl"`) without
pretending to defeat arbitrary interpreters. Detectors still key off high-signal structure (sinks,
secret paths); this only restores obvious literals into a normalised form that is searched beside
the original.

Decoding is canonicalisation, never suspicion on its own. The *difference*
between the raw and the normalised text tells a detector that encoding was present; whether that
matters depends on what the decoded text reaches (a shell: concealment; a URL query: nothing).
"""

from __future__ import annotations

import base64
import binascii
import re

# echo B64 | base64 -d / --decode, optionally wrapped in $()
_ECHO_B64_PIPE = re.compile(
    r"(?:\$\(\s*)?echo\s+(?:-[neE]+\s+)?['\"]?([A-Za-z0-9+/]{8,}={0,2})['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)\s*\)?",
    re.IGNORECASE,
)

# printf '%s' B64 | base64 -d
_PRINTF_B64_PIPE = re.compile(
    r"(?:\$\(\s*)?printf\s+(?:'%s'|\"%s\")\s+['\"]?([A-Za-z0-9+/]{8,}={0,2})['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)\s*\)?",
    re.IGNORECASE,
)

# base64 -d <<< B64
_HERESTRING_B64 = re.compile(
    r"base64\s+(?:-d|--decode|-D)\s*<<<\s*['\"]?([A-Za-z0-9+/]{8,}={0,2})['\"]?", re.IGNORECASE
)

# python-style base64.b64decode('B64') / b64decode("B64")
_B64DECODE_CALL = re.compile(
    r"b64decode\(\s*[bB]?['\"]([A-Za-z0-9+/]{8,}={0,2})['\"]\s*\)", re.IGNORECASE
)

# JavaScript atob('B64')
_ATOB_CALL = re.compile(r"atob\(\s*['\"]([A-Za-z0-9+/]{8,}={0,2})['\"]\s*\)", re.IGNORECASE)

_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")

# Adjacent shell/string concatenations: "cu""rl" or 'cu''rl'
_QUOTE_CONCAT = re.compile(r'(["\'])([^"\']*)\1\s*\1([^"\']*)\1')

_MAX_PASSES = 6


def normalise_text(text: str) -> str:
    """Return a best-effort decoded form of `text` for secondary matching.

    Safe on garbage input: undecodable base64 segments are left unchanged. Bounded iteration
    avoids pathological expansion. Idempotent on already-plain text.
    """
    if not text:
        return text

    out = text
    for _ in range(_MAX_PASSES):
        prev = out
        out = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), out)
        out = _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), out)
        for pattern in (
            _ECHO_B64_PIPE,
            _PRINTF_B64_PIPE,
            _HERESTRING_B64,
            _B64DECODE_CALL,
            _ATOB_CALL,
        ):
            out = _expand_b64(out, pattern)
        # Collapse a few rounds of "a""b" → "ab"
        for _ in range(4):
            nxt = _QUOTE_CONCAT.sub(r"\1\2\3\1", out)
            if nxt == out:
                break
            out = nxt
        if out == prev:
            break
    return out


def encodings_in(text: str) -> set[str]:
    """Which encodings `normalise_text` would undo in `text`: `base64`, `hex`, `quote_concat`.

    The split matters to the detectors: a base64 or hex payload that reaches a shell is the
    obfuscated decode-to-shell arm (a floor); a head split across quotes (`"cu""rl"`) is
    concealment but not an encoded payload.
    """
    kinds: set[str] = set()
    if _HEX_ESCAPE.search(text) or _OCTAL_ESCAPE.search(text):
        kinds.add("hex")
    if (
        _ECHO_B64_PIPE.search(text)
        or _PRINTF_B64_PIPE.search(text)
        or _HERESTRING_B64.search(text)
        or _B64DECODE_CALL.search(text)
        or _ATOB_CALL.search(text)
    ):
        kinds.add("base64")
    if _QUOTE_CONCAT.search(text):
        kinds.add("quote_concat")
    return kinds


def looks_encoded(text: str) -> bool:
    """Whether `text` carries one of the encodings `normalise_text` undoes."""
    return bool(encodings_in(text))


def _expand_b64(text: str, pattern: re.Pattern[str]) -> str:
    def _repl(match: re.Match[str]) -> str:
        raw = match.group(1)
        try:
            decoded = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError):
            return match.group(0)
        try:
            text_out = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return match.group(0)  # binary payload: nothing to match on, leave it
        if not text_out.isprintable() and not all(c.isprintable() or c in "\n\t" for c in text_out):
            return match.group(0)
        return text_out

    return pattern.sub(_repl, text)
