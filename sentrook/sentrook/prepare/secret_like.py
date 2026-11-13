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
#: `PIN` in capitals (a lower-case "pin" is usually the verb), "pin code" / "pin number", or a pin
#: that belongs to someone or something ("my pin", "the card pin", "collection pin").
_PIN_CUE = (
    r"(?:\bPINs?|\b[Pp]in[ \t]+(?i:codes?|numbers?)"
    r"|(?i:\b(?:my|your|his|her|their|our|the|card|collection|door|access|sim|bank|debit|atm)[ \t]+pin))"
)
_PASSPORT_CUE = r"(?i:\bpassport(?:[ \t]+(?:numbers?|no\.?|#))?)"

#: "for order 441", "on the booking", "of the visitor": a short phrase between the cue and the value.
#: When one is present the value must follow `is`, `was` or a colon, so a number inside the phrase is
#: never taken as the value.
_CONNECTOR = r"[ \t]+(?:for|on|of|to|from)[ \t]+[^\n.:;=]{1,40}?(?:[ \t]+(?:is|was)\b|[ \t]*:)"
_SEPARATOR = r"[ \t]*(?:(?:is|was)[ \t]*:?[ \t]*|[:=#-][ \t]*|)"
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
    # The value first: "482193 is your verification code".
    (
        CODE,
        re.compile(
            r"(?<![A-Za-z0-9_.-])(?P<v>[0-9]{4,10})[ \t]+is[ \t]+(?i:your|the|my)[ \t]+(?:[\w-]+[ \t]+)?"
            + _CODE_CUE
        ),
    ),
)

#: Quotes around a key or value.
_Q = r"[\"']?"
#: Where a key may start: not inside a word, a dotted name or a path.
_KEY_START = r"(?<![A-Za-z0-9_.-])"
#: `yard_code=090373`, `client_pin: 7021`, `gateCode: 4471`, `"passport_number": "PPCDHFZC6"`,
#: `code=006960`.
_KEY_RULE = re.compile(
    _KEY_START + r"(?P<k>(?:[A-Za-z0-9]{1,20}[_-]){0,3}"
    r"(?i:code|pin|passcode|otp|passport(?:[_-]?(?:no|num|number))?)"
    r"|[a-z][a-z0-9]{1,19}(?:Code|Pin|PIN|Passcode|Passport(?:No|Num|Number)?))"
    + _Q
    + r"[ \t]*(?P<sep>[:=])[ \t]*"
    + _Q
    + r"(?P<v>[A-Za-z0-9]{4,12})"
    + _END
)
#: Key prefixes that make `*_code` an ordinary value: postal, country, status and error codes, product,
#: business-record and discount codes, language and currency codes.
_ORDINARY_CODE_PREFIX = frozenset(
    "zip postal post country area status error err exit return ret response resp http product item "
    "sku promo discount coupon voucher lang language locale currency color colour region iso tax vat "
    "sort bank swift bic qr bar barcode hs naics sic reason event type class char key op short dial "
    "phone airport iata icao station stop route flight course department dept cost gl account project "
    "source src fiscal unit state county city branch store site plan tier mode format result customer "
    "client vendor supplier merchant mcc lot batch location loc ticket run job tariff part model serial "
    "invoice order shipment carrier service category group cpt icd diagnosis procedure exchange "
    "market ticker isin cusip unspsc".split()
)

#: `value: <random>`, `"session": "<random>"`, `sig=<random>`: any key, a long value.
_RANDOM_RULE = re.compile(
    _KEY_START
    + r"(?P<k>[A-Za-z_][A-Za-z0-9_.-]{0,40})"
    + _Q
    + r"[ \t]*[:=][ \t]*"
    + _Q
    + r"(?P<v>[A-Za-z0-9+/_-]{12,256}={0,2})(?![A-Za-z0-9+/=_@-])"
)
#: Keys whose values are identifiers, digests, names, state or data, not secrets.
_NOT_SECRET_KEY = re.compile(
    r"(?i)(?:^|[_.-])(?:id|ids|uuid|guid|hash|sha\d*|md5|digest|checksum|crc|commit|rev|revision|etag|"
    r"cid|ref|trace\w*|span\w*|request\w*|version|ver|build|sku|order|path|file|filename|url|uri|href|"
    r"src|name|class|classname|type|title|label|tag|branch|slug|key_id|keyid|fingerprint|nonce|"
    r"state|data|content|body|payload|blob|image|attachment|b64|base64|raw|integrity|list|si|"
    r"in-reply-to|references|message-id|thread\w*|customer|payment_intent|charge|invoice|"
    r"subscription|price|product)$"
)
#: camelCase keys ending in an id or name word (`userId`, `fileHash`); case-sensitive, so `sid` and
#: `PHPSESSID` (session cookies) are not caught.
_NOT_SECRET_CAMEL_KEY = re.compile(r"[a-z](?:Id|ID|Ids|Hash|Name|Url|Uri|Path|Version)$")
#: A provider's object id (`cus_…`, `pi_…`, `ch_…`): a lower-case prefix and an underscore. Live keys of
#: that form (`sk_live_…`) are vendor shapes the second redaction pass already masks.
_PREFIXED_OBJECT_ID = re.compile(r"[a-z]{1,8}_")
#: Subresource-integrity and lockfile hashes: `sha384-…`, `sha512-…`.
_SRI = re.compile(r"(?i)sha(?:1|256|384|512)-")

#: JSON string escapes (`\n`, `\t`, `\"`, any depth of encoding): read as the character they stand for,
#: padded to the same length so offsets do not move, so a key on a new line of a JSON-encoded result
#: starts its own word (`\nzip_code=` is `zip_code`, not `nzip_code`).
_ESCAPE = re.compile(r"\\+([nrt\"'])")


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
    if _PREFIXED_OBJECT_ID.match(core) or _SRI.match(core):
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


def _key_words(key: str) -> list[str]:
    """`yard_code` → [yard, code]; `gateCode` → [gate, code]."""
    return [w.lower() for w in re.split(r"[_-]|(?<=[a-z0-9])(?=[A-Z])", key) if w]


def _key_kind(key: str, value: str, sep: str, text: str, start: int) -> str | None:
    """The kind of secret a `key: value` pair holds, or None."""
    words = _key_words(key)
    if any(w.startswith("passport") for w in words):
        ok = 6 <= len(value) <= 12 and any(c.isdigit() for c in value)
        return IDENTIFIER if ok and not any(c.islower() for c in value) else None
    if not value.isdigit() or not 4 <= len(value) <= 10:
        return None
    if words[-1] in ("pin", "passcode", "otp"):
        return PIN
    if len(words) > 1:
        # A `*_code` key: any qualifier but an ordinary one.
        return CODE if words[-2] not in _ORDINARY_CODE_PREFIX else None
    # A bare `code` key only as a form or query field (`-d 'code=006960'`), with six or more digits: a
    # JSON or YAML `code:` is far more often a status or error code.
    if sep != "=" or len(value) < 6 or text[max(0, start - 1) : start] in ("?", "&"):
        return None
    return CODE


def _query_param(text: str, start: int) -> bool:
    """The key starts a URL query or form field (`?si=…`, `&list=…`): share links and tracking
    parameters, not secrets the agent wrote."""
    return start > 0 and text[start - 1] in "?&"


def find_secret_like(text: str) -> list[SecretLike]:
    """Every secret-like value in `text`, in order, without overlaps."""
    if not text or len(text) < 6:
        return []
    text = _unescape(text)
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
        kind = _key_kind(m.group("k"), m.group("v"), m.group("sep"), text, m.start())
        if kind is not None:
            found.append(SecretLike(kind, m.group("v"), m.start("v"), m.end("v")))
    for m in _RANDOM_RULE.finditer(text):
        key, v = m.group("k"), m.group("v")
        if (
            _NOT_SECRET_KEY.search(key)
            or _NOT_SECRET_CAMEL_KEY.search(key)
            or _query_param(text, m.start())
            or not _looks_random(v)
        ):
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
