"""Secret-like values found by a cue word or a key, not by a credential word: the rule side's view of them.

The plugins and the scanner's second pass (`prepare.redact`) replace credentials they recognise by a
context word or a vendor shape. Since `redact-v11` they also replace, by the cue and key rules in
`prepare.redact` (`cue_spans`, the plugins' own rules):

- an access code or PIN named by a cue word ("the gate code is 861206", "Alarm code: 727677",
  "collection PIN for order 441 is 6815", `yard_code=090373`, `client_pin=7021`, `pin=3253`);
- a personal identifier ("passport number DI9J0R9W4", `passport=PPCDHFZC6`);
- a random value under a key or header that gives no hint (`value: <20 random letters and digits>`).

Older plugins, redaction `off` and other clients still send them raw. This module finds them in the text
the rules read, so the rules that ask "does this text carry a secret?" (the lineage secret-carried-to-send
rule and AIRA's placeholder source) see them as they see a placeholder; a raw one found only by these
rules is relieved when the owner's request names it (`secret_carried`), and so is its placeholder from a
plugin that redacts it. It changes no view: the second pass does that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .redact import CODE, IDENTIFIER, PIN, RANDOM, cue_spans, secret_spans

__all__ = [
    "CODE",
    "IDENTIFIER",
    "PIN",
    "RANDOM",
    "SecretLike",
    "find_secret_like",
    "secret_carried",
]

#: JSON string escapes (`\n`, `\t`, `\"`, any depth of encoding): read as the character they stand for,
#: padded to the same length so offsets do not move, so a key on a new line of a JSON-encoded result
#: starts its own word (`\nzip_code=` is `zip_code`, not `nzip_code`).
#: A run of backslashes is taken whole, from its first, so a long run is read once.
_ESCAPE = re.compile(r"(?<!\\)\\+([nrt\"'])")


def _unescape(text: str) -> str:
    def pad(m: re.Match[str]) -> str:
        ch = m.group(1)
        return " " * (len(m.group(0)) - 1) + ("\n" if ch in "nrt" else ch)

    return _ESCAPE.sub(pad, text) if "\\" in text else text


@dataclass(frozen=True)
class SecretLike:
    kind: str
    value: str
    start: int
    end: int


def find_secret_like(text: str) -> list[SecretLike]:
    """Every secret-like value in `text`, in order, without overlaps."""
    if not text or len(text) < 6:
        return []
    text = _unescape(text)
    found = sorted(
        (SecretLike(kind, text[s:e], s, e) for _, s, e, kind in cue_spans(text)),
        key=lambda f: (f.start, -f.end),
    )
    out: list[SecretLike] = []
    for f in found:
        if out and f.start < out[-1].end:
            continue
        out.append(f)
    return out


#: What made a text carry a secret: a redaction placeholder, a credential the second redaction pass masks,
#: or a value only the cue and key rules find.
PLACEHOLDER, SHAPE, DETECTED = "placeholder", "shape", "secret_like"

#: A plugin's placeholder (`⟦secret:credential:ab12⟧`, `⟦secret:identifier:ab12⟧`) or a bare one (`⟦secret⟧`).
_PLACEHOLDER_MARK = re.compile(r"⟦secret(?::(?P<kind>[a-z_]{1,32}))?(?::[0-9a-f]{1,16})?⟧")
#: What stands in for a placeholder's value when the cue and key rules read its place: a code or PIN's digits.
_FILL = "000000"


def secret_like_placeholders(text: str) -> bool:
    """Whether `text` holds placeholders and every one stands for a passport number (`identifier`) or sits in a code's
    or a PIN's place, as the cue and key rules read it with digits standing in for the value (`collection PIN
    ⟦secret:credential:ab12⟧`, `pin=⟦…⟧`) and no credential rule does (`token: ⟦…⟧`). Since `redact-v11` the plugins
    send these values as placeholders, which a rule must read as it read the raw value. A random value under a
    generic key is not one of them: as a placeholder it cannot be told from a credential."""
    marks = list(_PLACEHOLDER_MARK.finditer(text))
    if not marks:
        return False
    parts: list[str] = []
    places: list[tuple[int, int]] = []
    pos = size = 0
    for m in marks:
        parts.append(text[pos : m.start()])
        size += m.start() - pos
        places.append((size, size + len(_FILL)))
        parts.append(_FILL)
        size += len(_FILL)
        pos = m.end()
    parts.append(text[pos:])
    filled = _unescape("".join(parts))
    codes = [(s, e) for _, s, e, kind in cue_spans(filled) if kind in (CODE, PIN)]
    credentials = secret_spans(filled, cues=False)

    def within(spans: list[tuple[int, int]], ps: int, pe: int) -> bool:
        return any(s <= ps and pe <= e for s, e in spans)

    return all(
        m.group("kind") == IDENTIFIER or (within(codes, ps, pe) and not within(credentials, ps, pe))
        for m, (ps, pe) in zip(marks, places, strict=True)
    )


def secret_carried(text: str, placeholder_open: str, *, owner_asked: bool = False) -> str | None:
    """Why `text` carries a secret, or None. A value only the cue and key rules find does not count when the
    owner's request asked for a secret to go (`owner_asked`): the benign twin that sends the gate code
    where the owner said is the same text as the attack. That holds whether the value arrives raw or, from a
    plugin with `redact-v11`, as its placeholder (`secret_like_placeholders`: a code, PIN or passport number). Any other placeholder or a
    redactable shape counts either way; whether the owner asked is the calling rule's business, as before."""
    if not text:
        return None
    if placeholder_open in text and not (owner_asked and secret_like_placeholders(text)):
        return PLACEHOLDER
    if secret_spans(text, cues=False):
        return SHAPE
    if not owner_asked and find_secret_like(text):
        return DETECTED
    return None
