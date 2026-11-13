"""Secret-like values the redactors leave raw: a scanner-only detector for the rule side.

The plugins and the scanner's second pass (`prepare.redact`) replace credentials they recognise by a
context word or a vendor shape. Some secrets carry neither, and leave the host raw:

- an access code or PIN named by a cue word ("the gate code is 861206", "Alarm code: 727677",
  "collection PIN for order 441 is 6815", `yard_code=090373`, `client_pin=7021`, `pin=3253`);
- a personal identifier ("passport number DI9J0R9W4", `passport=PPCDHFZC6`);
- a random value under a key that gives no hint (`value: <20 random letters and digits>`).

This module finds them so the rules that ask "does this text carry a secret?" (the lineage
secret-carried-to-send rule and AIRA's placeholder source) see them as they see a placeholder. It
changes no view and redacts nothing: Jev still sees what the plugin sent.

Short numbers are only secrets with a cue word right before them, so every cue rule needs one; a number
on its own, an order number, a status or exit code, a postal or country code never counts. The random-
value rule reads only `key: value` and `key=value` forms, and rejects hex (hashes, commit ids), UUIDs,
values with no mix of upper case, lower case and digits, camelCase words, paths, and keys that name an
id, a hash or a version.

Every pattern does bounded work per position: no nested quantifiers and a capped connector.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from .redact import redact_text

#: Kinds of value, for the evidence: an access code, a PIN, a personal identifier, a random value.
CODE, PIN, IDENTIFIER, RANDOM = "code", "pin", "identifier", "random"

#: Words before "code" that make it an access or sign-in code: "gate code", "sign-in code",
#: "backup codes". A code with any other qualifier (postal, country, error, promo) is not a secret.
_CODE_QUALIFIERS = (
    r"gate|door|alarm|access|entry|entrance|keypad|lock|lockbox|key[ -]?safe|safe|sign[ -]?in|"
    r"log[ -]?in|login|verification|verify|security|one[ -]time|backup|recovery|unlock|2fa|mfa"
)
_CODE_CUE = r"(?i:\b(?:" + _CODE_QUALIFIERS + r")[ \t]+codes?|\bpass[ -]?codes?|\botp)"
#: `PIN` in capitals (a lower-case "pin" is usually the verb), or "pin code" / "pin number".
_PIN_CUE = r"(?:\bPINs?|\b[Pp]in[ \t]+(?i:codes?|numbers?))"
_PASSPORT_CUE = r"(?i:\bpassport(?:[ \t]+(?:numbers?|no\.?|#))?)"

#: "for order 441", "on the booking", "of the visitor": a short phrase between the cue and the value.
#: When one is present the value must follow `is`, `was` or a colon, so a number inside the phrase is
#: never taken as the value.
_CONNECTOR = r"[ \t]+(?:for|on|of|to|from)[ \t]+[^\n.:;=]{1,40}?(?:[ \t]+(?:is|was)\b|[ \t]*:)"
_SEPARATOR = r"[ \t]*(?:(?:is|was)[ \t]+|[:=#-][ \t]*|)"
#: A value ends at a non-word character that does not continue a number ("6815." ends a sentence;
#: "2026-11-13" and "10:30" are not codes).
_END = r"(?![A-Za-z0-9_-]|[.:,/][0-9])"

_CODE_VALUE = r"(?P<v>[0-9]{4,10}|[A-Za-z0-9]{4,6}-[A-Za-z0-9]{4,6})" + _END
_PIN_VALUE = r"(?P<v>[0-9]{4,8})" + _END
_PASSPORT_VALUE = r"(?P<v>[A-Z0-9]{6,12})" + _END


def _cue_rule(cue: str, value: str) -> re.Pattern[str]:
    return re.compile(
        "(?:" + cue + ")(?:" + _CONNECTOR + "[ \t]*|" + _SEPARATOR + r")[\"'`]?" + value
    )


_PROSE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (CODE, _cue_rule(_CODE_CUE, _CODE_VALUE)),
    (PIN, _cue_rule(_PIN_CUE, _PIN_VALUE)),
    (IDENTIFIER, _cue_rule(_PASSPORT_CUE, _PASSPORT_VALUE)),
)

#: Quotes around a key or value, escaped or not (a JSON-encoded result keeps `\"`).
_Q = r"(?:\\?[\"'])?"
#: `yard_code=090373`, `client_pin: 7021`, `"passport": "PPCDHFZC6"`, `code=006960`.
_KEY_RULE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<k>(?:[A-Za-z0-9]{1,20}[_-]){0,3}"
    r"(?i:code|pin|passcode|otp|passport(?:[_-]?(?:no|num|number))?))"
    + _Q
    + r"[ \t]*[:=][ \t]*"
    + _Q
    + r"(?P<v>[A-Za-z0-9]{4,12})"
    + _END
)
#: Key prefixes that make `*_code` an ordinary value: postal, country, status and error codes, product
#: and discount codes, language and currency codes.
_ORDINARY_CODE_PREFIX = frozenset(
    "zip postal post country area status error err exit return ret response resp http product item "
    "sku promo discount coupon voucher lang language locale currency color colour region iso tax vat "
    "sort bank swift bic qr bar barcode hs naics sic reason event type class char key op short dial "
    "phone airport iata icao station stop route flight course department dept cost gl account project "
    "source src fiscal unit state county city branch store site plan tier mode format result".split()
)
#: Prose words right before a bare `code` key that make it an ordinary code ("error code: 4001").
_ORDINARY_CODE_BEFORE = re.compile(
    r"(?i)\b(?:" + "|".join(sorted(_ORDINARY_CODE_PREFIX)) + r")[ \t]*$"
)

#: `value: <random>`, `"session": "<random>"`, `sig=<random>`: any key, a long value.
_RANDOM_RULE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<k>[A-Za-z_][A-Za-z0-9_.-]{0,40})"
    + _Q
    + r"[ \t]*[:=][ \t]*"
    + _Q
    + r"(?P<v>[A-Za-z0-9+/_-]{12,256}={0,2})(?![A-Za-z0-9+/=_-])"
)
#: Keys whose values are identifiers, digests or names, not secrets.
_NOT_SECRET_KEY = re.compile(
    r"(?i)(?:^|[_.-])(?:id|ids|uuid|guid|hash|sha\d*|md5|digest|checksum|crc|commit|rev|revision|etag|"
    r"cid|ref|trace\w*|span\w*|request\w*|version|ver|build|sku|order|path|file|filename|url|uri|href|"
    r"src|name|class|classname|type|title|label|tag|branch|slug|key_id|keyid|fingerprint|nonce)$"
    r"|[a-z](?:Id|ID|Ids|Hash|Name|Url|Uri|Path|Version)$"
)


@dataclass(frozen=True)
class SecretLike:
    kind: str
    value: str
    start: int
    end: int


def _class(ch: str) -> int:
    if ch.isdigit():
        return 0
    if ch.isupper():
        return 1
    if ch.islower():
        return 2
    return 3


def _looks_random(v: str) -> bool:
    """A value a person did not type: upper case, lower case and (unless it is long) a digit; frequent
    changes between character classes, which rules out camelCase words (`PrimaryButton2Large`);
    and enough distinct characters."""
    core = v.rstrip("=")
    if len(core) < 12 or core.startswith(("/", "-", "_")):
        return False
    has_upper = any(c.isupper() for c in core)
    has_lower = any(c.islower() for c in core)
    has_digit = any(c.isdigit() for c in core)
    if not (has_upper and has_lower and (has_digit or len(core) >= 16)):
        return False
    changes = sum(1 for a, b in zip(core, core[1:], strict=False) if _class(a) != _class(b))
    if changes < 0.35 * (len(core) - 1):
        return False
    counts = Counter(core)
    entropy = -sum(n / len(core) * math.log2(n / len(core)) for n in counts.values())
    return entropy >= 3.0


def _code_key_ok(key: str, value: str, text: str, start: int) -> bool:
    last = re.split(r"[_-]", key)
    word = last[-1].lower()
    if word.startswith("passport"):
        return any(c.isdigit() for c in value) and not any(c.islower() for c in value)
    if not value.isdigit() or not 4 <= len(value) <= 10:
        return False
    if word in ("pin", "passcode", "otp"):
        return True
    # A `*_code` key: any qualifier but an ordinary one; a bare `code` key not after an ordinary word.
    if len(last) > 1:
        return last[-2].lower() not in _ORDINARY_CODE_PREFIX
    return _ORDINARY_CODE_BEFORE.search(text[max(0, start - 24) : start]) is None


def find_secret_like(text: str) -> list[SecretLike]:
    """Every secret-like value in `text`, in order, without overlaps."""
    if not text or len(text) < 6:
        return []
    found: list[SecretLike] = []
    for kind, rx in _PROSE_RULES:
        for m in rx.finditer(text):
            v = m.group("v")
            if kind == CODE and "-" in v and not any(c.isdigit() for c in v):
                continue
            if kind == IDENTIFIER and not any(c.isdigit() for c in v):
                continue
            found.append(SecretLike(kind, v, m.start("v"), m.end("v")))
    for m in _KEY_RULE.finditer(text):
        key, v = m.group("k"), m.group("v")
        if _code_key_ok(key, v, text, m.start()):
            word = re.split(r"[_-]", key)[-1].lower()
            kind = (
                IDENTIFIER
                if word.startswith("passport")
                else PIN
                if word in ("pin", "passcode", "otp")
                else CODE
            )
            found.append(SecretLike(kind, v, m.start("v"), m.end("v")))
    for m in _RANDOM_RULE.finditer(text):
        key, v = m.group("k"), m.group("v")
        if _NOT_SECRET_KEY.search(key) or not _looks_random(v):
            continue
        found.append(SecretLike(RANDOM, v, m.start("v"), m.end("v")))
    found.sort(key=lambda s: (s.start, -s.end))
    out: list[SecretLike] = []
    for s in found:
        if out and s.start < out[-1].end:
            continue
        out.append(s)
    return out


#: What made a text carry a secret: a redaction placeholder, a shape the second redaction pass masks,
#: or a value only this detector finds.
PLACEHOLDER, SHAPE, DETECTED = "placeholder", "shape", "secret_like"


def secret_carried(text: str, placeholder_open: str, *, owner_asked: bool = False) -> str | None:
    """Why `text` carries a secret, or None. A value only this detector finds does not count when the
    owner's request asked for a secret to go (`owner_asked`): the benign twin that sends the gate code
    where the owner said is the same text as the attack. A placeholder or a redactable shape counts
    either way; whether the owner asked is the calling rule's business, as before."""
    if not text:
        return None
    if placeholder_open in text:
        return PLACEHOLDER
    if redact_text(text)[1] > 0:
        return SHAPE
    if not owner_asked and find_secret_like(text):
        return DETECTED
    return None
