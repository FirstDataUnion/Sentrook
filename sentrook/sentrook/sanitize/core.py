"""Low-level sanitization primitives (no planir imports)."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sentrook.sanitize.rules import SanitizeRules, load_rules
from sentrook.sanitize.signal_excerpt import (
    is_command_like_key,
    is_content_like_key,
    pack_signal_excerpt,
)

# Credential-shaped env / shell var names: underscore-delimited segments only, so
# COMPASS / BYPASS / PASSED do not match, while LIBRARY_BOT_PASS and
# MEDIAWIKI_BOT_PASSWORD do.
_CREDENTIAL_VAR_SEGMENT = re.compile(
    r"(?i)(?:^|_)(pass(?:wd|word)?|secret|token|api[_-]?key|auth|credential|bearer)(?:_|$)"
)
# Optional export, then NAME=value (quoted or bare). Applied before keyword
# substring patterns so PASSWORD=secret is not left as [REDACTED]=secret.
_ENV_ASSIGNMENT = re.compile(
    r"""(?ix)
    ((?:export\s+)?)                  # optional export
    ([A-Za-z_][A-Za-z0-9_]*)          # var name
    \s*=\s*
    (?:
        "[^"\\]*(?:\\.[^"\\]*)*"      # double-quoted (unrolled; avoids ReDoS)
      | '[^'\\]*(?:\\.[^'\\]*)*'      # single-quoted (unrolled; avoids ReDoS)
      | [^\s;|&"']+                   # bare value (quotes terminate it — see below)
    )
    """
)
# The bare-value branch excludes quote characters on purpose. With ``[^\s;|&]+``
# an assignment *inside* a quoted string swallowed the closing quote:
#   curl -d "token=ghp_abc"  ->  curl -d "token=[REDACTED]
# which leaves the command unbalanced and therefore unparseable — so it could
# never match an allow rule. A quote terminates a shell value, so stopping there
# is also simply correct.
# ``--password secret`` / ``--token=abc`` — replacement keeps the flag.
_CLI_SECRET_FLAG = re.compile(
    r"""(?ix)
    (--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)
        (?:-\w+)?)
    (\s*=\s*|\s+)
    (?:
        "[^"\\]*(?:\\.[^"\\]*)*"
      | '[^'\\]*(?:\\.[^'\\]*)*'
      | [^\s;|&"']+
    )
    """
)

#: Hex chars of HMAC kept in a marker. 6 gives ~16.7M values — ample within one
#: session (a handful of distinct secrets) and useless to anyone without the salt.
MARKER_HEX_CHARS = 6


@dataclass(frozen=True)
class SecretMarker:
    """Mints value-stable redaction placeholders for one session.

    Without a marker every secret collapses to the same ``[REDACTED]``, so a
    value read in one step is indistinguishable from any other in the next —
    which is why Phase 4 dataflow was originally scoped to path references only.
    A marker makes the *same value* recognisable across steps without disclosing
    it: ``[REDACTED]`` becomes ``[REDACTED:a3f19c]``.

    Security properties, and why they hold:

    - **Non-invertible.** The digest is an HMAC under ``salt``, which is random
      per session and never transmitted. Even a low-entropy secret (``hunter2``)
      cannot be confirmed by anyone holding the log.
    - **No cross-session correlation.** A new salt per session means the same
      secret marks differently elsewhere.
    - **No plaintext retained.** The digest is computed at scrub time and the
      value discarded. A ``{value -> 1, 2, 3}`` counter would be simpler and leak
      even less *in the log*, but would force us to hold plaintext secrets in
      memory for the session's lifetime — a worse posture than a keyed hash of
      something already thrown away.
    - **Lexically inert.** The digest lives inside the existing brackets, so a
      marked command parses exactly as an unmarked one (no spaces, no quotes).

    It does leak *equality* within a session: the log shows two positions held
    the same value, never what it was. Documented rather than hidden.
    """

    salt: bytes
    scope: str = ""

    @classmethod
    def for_session(cls, session_id: str | None, salt: bytes | None = None) -> SecretMarker:
        """Marker for one session. ``salt`` defaults to fresh randomness."""
        return cls(salt=salt or secrets.token_bytes(32), scope=session_id or "")

    def digest(self, value: str) -> str:
        payload = f"{self.scope}\x00{normalize_secret(value)}".encode()
        return hmac.new(self.salt, payload, hashlib.sha256).hexdigest()[:MARKER_HEX_CHARS]

    def mint(self, placeholder: str, value: str) -> str:
        d = self.digest(value)
        # Keep the digest inside the brackets so the token stays lexically inert.
        return f"{placeholder[:-1]}:{d}]" if placeholder.endswith("]") else f"{placeholder}:{d}"


#: Quoting and trailing punctuation that different patterns capture inconsistently.
#: ``token=ghp_abc"`` and a bare ``ghp_abc`` must digest identically or the same
#: secret marks differently in two steps and dataflow linkage silently fails.
_SECRET_EDGE = re.compile(r"""^[\s"'`]+|[\s"'`,;:)\]}]+$""")


def normalize_secret(value: str) -> str:
    """Canonical form of a secret for marker digesting.

    Patterns capture inconsistently: ``_ENV_ASSIGNMENT`` swallows a trailing
    quote, ``keep_prefix`` patterns split off the provider prefix. Both are
    normalised away so the *same value* always yields the same marker. Not
    perfect — a secret captured with genuinely different syntax on each side can
    still diverge — but it covers the read -> egress shapes that matter.
    """
    return _SECRET_EDGE.sub("", value.strip())


def is_placeholder(value: str, placeholder: str) -> bool:
    """True when ``value`` is already a redaction placeholder, marked or not.

    Deliberately compares the *trimmed* value, not ``normalize_secret`` — that
    strips a trailing ``]``, which is part of the placeholder itself.
    """
    normalized = value.strip()
    if normalized == placeholder:
        return True
    if not placeholder.endswith("]"):
        return False
    base = placeholder[:-1] + ":"
    return (
        normalized.startswith(base)
        and normalized.endswith("]")
        and normalized[len(base) : -1].isalnum()
    )


def _mint(placeholder: str, value: str, marker: SecretMarker | None) -> str:
    """Placeholder for one redacted value — marked when a marker is supplied.

    **Already-redacted values pass through verbatim.** Only the plugin holds a
    session salt, so only the plugin mints markers; the scan server re-sanitizes
    on ingress and must not disturb them. Without this guard that re-scrub
    rewrote ``[REDACTED:48df5d]`` back to a bare ``[REDACTED]`` — markers never
    reached the scanner and Phase 4 saw nothing — and, worse, a *different*
    marker would re-mint a wrong digest and invent false linkages.
    """
    if is_placeholder(value, placeholder):
        return value.strip()
    return marker.mint(placeholder, value) if marker is not None else placeholder


_LEADING_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_TOKEN_SPAN = re.compile(r"\S+")


def _head_span(text: str) -> tuple[int, int, str] | None:
    """(start, end, token) of the command-name token, skipping env assignments.

    ``TOKEN=abc curl https://x`` has head ``curl`` — the assignment is a value
    that *should* be redacted; the head is not. Spans rather than indexes so the
    caller can splice without touching surrounding whitespace.
    """
    for match in _TOKEN_SPAN.finditer(text):
        token = match.group(0)
        if _LEADING_ASSIGNMENT.match(token):
            continue
        return match.start(), match.end(), token
    return None


def restore_head_token(
    original: str,
    scrubbed: str,
    is_secret: Callable[[str], bool] | None = None,
) -> str:
    """Undo any scrubbing that altered the command name (D14).

    A binary name is not a secret, so a pattern matching there is a false
    positive by definition — and it is the one position where the placeholder
    destroys the parse, and therefore ``exec_shape.heads``, which every rule
    downstream keys on. 58 corpus rows carry exactly this damage from an older
    sanitizer. Cheap invariant; guards every future pattern addition.

    Splices by character span so the rest of the command — including its
    original whitespace — is untouched.
    """
    src = _head_span(original)
    dst = _head_span(scrubbed)
    if src is None or dst is None or src[2] == dst[2]:
        return scrubbed
    # CRITICAL: never restore a head that is itself a secret. Without this the
    # guard silently undoes a correct redaction — `ghp_AbC…` alone as a command
    # is redacted to `ghp_[REDACTED]`, the heads differ, and restoring puts the
    # credential straight back. The head is only safe to restore when scrubbing
    # it *on its own* leaves it unchanged, which means its redaction here was
    # collateral from a longer match (e.g. gitleaks' `curl-auth-header`, whose
    # span starts at the `curl` binary).
    if is_secret is not None and is_secret(src[2]):
        return scrubbed
    return scrubbed[: dst[0]] + src[2] + scrubbed[dst[1] :]


def is_credential_field(key: str, rules: SanitizeRules) -> bool:
    return bool(rules.credential_field.search(key))


def is_credential_var_name(name: str) -> bool:
    """True when an env/shell variable name is credential-shaped."""
    return bool(_CREDENTIAL_VAR_SEGMENT.search(name))


def is_shell_style_assignment_name(name: str) -> bool:
    """True for shell/env assignment LHS we should scrub.

    Underscore or uniform case (``LIBRARY_BOT_PASS``, ``PASSWORD``, ``password``)
    are scrubbed. CamelCase prose like ``apiKey=sk-…`` is left for token-shape
    patterns so L2 rules (e.g. AIRA-068) still see ``sk-proj-`` after sanitize.
    """
    if "_" in name or name.isupper() or name.islower():
        return True
    return False


def truncate(
    text: str,
    limit: int,
    rules: SanitizeRules,
    *,
    signal_aware: bool = False,
) -> str:
    """Bound ``text`` to ``limit`` chars.

    When ``signal_aware`` is true (content-like prose keys), keep head + IOC
    spans + tail instead of a pure prefix cut so late payloads survive egress.
    """
    if len(text) <= limit:
        return text
    if limit <= 3:
        return rules.truncated
    if signal_aware:
        return pack_signal_excerpt(text, limit, ellipsis="...")
    return text[: limit - 3] + "..."


def redact_env_secret_assignments(
    text: str,
    placeholder: str,
    marker: SecretMarker | None = None,
) -> tuple[str, int]:
    """Redact values assigned to credential-shaped env vars; keep ``NAME=``.

    Returns ``(scrubbed_text, number_of_assignments_redacted)``.
    """
    count = 0

    def _repl(match: re.Match[str]) -> str:
        nonlocal count
        export, name = match.group(1), match.group(2)
        if not is_credential_var_name(name):
            return match.group(0)
        if not export and not is_shell_style_assignment_name(name):
            return match.group(0)
        count += 1
        value = match.group(0).split("=", 1)[1]
        return f"{export}{name}={_mint(placeholder, value, marker)}"

    return _ENV_ASSIGNMENT.sub(_repl, text), count


def redact_cli_secret_flags(
    text: str,
    placeholder: str,
    marker: SecretMarker | None = None,
) -> tuple[str, int]:
    """Redact values after credential-shaped CLI long-options; keep the flag."""

    def _repl(match: re.Match[str]) -> str:
        value = match.group(0)[len(match.group(1)) + len(match.group(2)) :]
        return f"{match.group(1)}{match.group(2)}{_mint(placeholder, value, marker)}"

    return _CLI_SECRET_FLAG.subn(_repl, text)


def apply_secret_patterns(
    text: str, rules: SanitizeRules, marker: SecretMarker | None = None
) -> str:
    cleaned, _hits = apply_secret_patterns_with_hits(text, rules, marker)
    return cleaned


def apply_secret_patterns_with_hits(
    text: str, rules: SanitizeRules, marker: SecretMarker | None = None
) -> tuple[str, list[str]]:
    """Apply secret scrubbers; return scrubbed text and pattern names that fired."""
    hits: list[str] = []
    cleaned = text

    cleaned, env_hits = redact_env_secret_assignments(cleaned, rules.redacted, marker)
    if env_hits:
        hits.append("env_secret_assignment")

    cleaned, cli_hits = redact_cli_secret_flags(cleaned, rules.redacted, marker)
    if cli_hits:
        hits.append("cli_secret_flag")

    for name, pattern, keep_prefix in rules.secret_value_patterns:
        if pattern.search(cleaned):
            hits.append(name)
            cleaned = pattern.sub(
                lambda match, *, keep=keep_prefix: _prefix_preserving_repl(
                    match, rules.redacted, keep, marker
                ),
                cleaned,
            )

    # The vendored gitleaks catalogue runs LAST, on purpose: Sentrook's own
    # patterns keep provider prefixes (`sk-ant-[REDACTED]`) that L2 rules match
    # on, and gitleaks would replace the whole match. Placeholders are inert, so
    # the catalogue never re-redacts what has already been handled.
    from sentrook.sanitize.gitleaks import apply_gitleaks_patterns

    cleaned, gl_hits = apply_gitleaks_patterns(
        cleaned,
        rules.redacted,
        lambda placeholder, value: _mint(placeholder, value, marker),
    )
    hits.extend(f"gitleaks:{rule_id}" for rule_id in gl_hits)
    return cleaned, hits


def _prefix_preserving_repl(
    match: re.Match[str],
    placeholder: str,
    keep_prefix: bool,
    marker: SecretMarker | None = None,
) -> str:
    """Replace a secret match, optionally keeping the first capturing group.

    The marker always digests the **whole match**, never the suffix after the
    kept prefix. Otherwise ``ghp_abc…`` caught by the provider pattern (which
    keeps ``ghp_``) and the same value caught by ``TOKEN=ghp_abc…`` (which does
    not) would mint different markers, and the dataflow link would silently
    fail. ``normalize_secret`` handles the quoting differences.
    """
    if keep_prefix:
        for index in range(1, (match.lastindex or 0) + 1):
            group = match.group(index)
            if group:
                # Idempotence: if what follows the kept prefix is already a
                # placeholder, leave the whole match alone. Digesting the *whole*
                # match (needed so the same secret marks identically however it
                # was captured) otherwise re-mints on every pass.
                remainder = match.group(0)[len(group) :]
                if is_placeholder(remainder, placeholder):
                    return match.group(0)
                return f"{group}{_mint(placeholder, match.group(0), marker)}"
    return _mint(placeholder, match.group(0), marker)


#: Structured tokens that are never PII and must survive scrubbing intact:
#: ISO-8601 timestamps and UUIDs. Both are digit-and-dash shaped, so loose PII
#: patterns match them — observed redacting every ``date`` and ``created_at``
#: field in real result excerpts, which destroys the data for research and makes
#: markers collide on timestamps. Protected as a class rather than teaching each
#: pattern about them individually.
_STRUCTURED_TOKEN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\b\d{4}-\d{2}-\d{2}"
    r"(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b",
    re.IGNORECASE,
)


def _luhn_valid(value: str) -> bool:
    """Luhn (mod-10) check — the standard card-number checksum."""
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, double = 0, False
    for digit in reversed(digits):
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double
    return total % 10 == 0


def _iban_mod97_valid(value: str) -> bool:
    """ISO 13616 mod-97 check — rearrange, letters to digits, remainder must be 1."""
    compact = "".join(value.split()).upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    digits = ""
    for char in rearranged:
        if char.isdigit():
            digits += char
        elif char.isalpha():
            digits += str(ord(char) - 55)
        else:
            return False
    return int(digits) % 97 == 1


def _phone_plausible(value: str) -> bool:
    """Reject digit runs that cannot be phone numbers.

    Two principled bounds, because a bare 13-digit run is genuinely ambiguous —
    an epoch-ms timestamp and a phone number look identical by digit count:

    - **E.164 caps a phone at 15 digits.** A longer run (a port list, a byte
      count, a concatenated id) is not a phone.
    - **Real phones in prose carry punctuation** — a leading ``+``, or spaces,
      dashes, dots or parens between groups. A bare unpunctuated run is far more
      likely an identifier or timestamp.

    Known gap, accepted deliberately: a bare unpunctuated ``07700900123`` is not
    redacted. That is the cost of not redacting every timestamp in every result
    excerpt — and over-redaction is not free here, because identical markers on
    a repeated timestamp fabricate exactly the cross-step "same value" signal
    Phase 4 reads as dataflow.
    """
    digits = sum(1 for c in value if c.isdigit())
    if not 7 <= digits <= 15:
        return False
    return value.lstrip().startswith("+") or any(c in " .-()" for c in value.strip())


def _uk_postcode_plausible(value: str) -> bool:
    r"""Reject hex runs that happen to look like a UK postcode.

    ``[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}`` under IGNORECASE matches plenty of
    6-char hex — ``e629fa``, ``c6f3ac``, ``d029fa`` — so git short SHAs, docker
    ids and hex colours were being redacted. Both git and docker output are
    ubiquitous in agent traffic, and every match mints a marker, fabricating the
    cross-step linkage Phase 4 reads as dataflow.

    The discriminator is the space. Real postcodes are written with one far more
    often than not (``SW1A 1AA``), while a hex id never has one — and a postcode
    whose letters are all in ``a-f`` (``AB12 3CD``) is only ambiguous without it.
    So: an all-hex match with no separator is not a postcode.
    """
    compact = value.strip()
    if any(ch.isspace() for ch in compact):
        return True
    return not all(ch in "0123456789abcdefABCDEF" for ch in compact)


#: Checksum validators by name, referenced from ``rules.yaml``.
#:
#: This is the one thing Presidio does that a bare regex cannot: a pattern loose
#: enough to *find* candidates will always over-match, and only a checksum can
#: separate a real card number from an epoch-ms timestamp or a list of ports.
#: We borrow the discipline rather than the dependency — Presidio needs a 382 MB
#: spaCy model and seconds to initialise, which rules it out of the hot path, and
#: it cannot run in the zero-dependency TypeScript plugin at all.
_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": _luhn_valid,
    "iban_mod97": _iban_mod97_valid,
    "phone_plausible": _phone_plausible,
    "uk_postcode_plausible": _uk_postcode_plausible,
}


#: Private-use sentinel; will not occur in argv or JSON text.
_HOLD = "\ue000"
_HOLD_RE = re.compile(_HOLD + r"(\d+)" + _HOLD)


def apply_pii_patterns(text: str, rules: SanitizeRules, marker: SecretMarker | None = None) -> str:
    """Scrub PII spans. Marked too: an email flowing read -> egress is exfiltration.

    Structured tokens are held out first and restored verbatim afterwards, so a
    timestamp or UUID can never be mistaken for a phone number.
    """
    held: list[str] = []

    def _hold(match: re.Match[str]) -> str:
        held.append(match.group(0))
        return f"{_HOLD}{len(held) - 1}{_HOLD}"

    # Hold out placeholders we already produced. A marker digest is 6 hex chars,
    # and ~2.7% of them match `uk_postcode` (`[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}`
    # under IGNORECASE matches strings like `fb89ad`). That re-redacted the
    # digest *inside* its own placeholder, producing the nested
    # `[REDACTED:[REDACTED:…]]` seen in live logs — intermittently, because it
    # depends on the digest, which is why it kept failing to reproduce.
    placeholder_re = re.compile(
        re.escape(rules.redacted[:-1]) + r"(?::[0-9a-zA-Z]+)?" + re.escape(rules.redacted[-1:])
        if rules.redacted.endswith("]")
        else re.escape(rules.redacted)
    )
    # Strip any pre-existing sentinel so the restore cannot be spoofed by input.
    redacted = placeholder_re.sub(_hold, text.replace(_HOLD, ""))
    redacted = _STRUCTURED_TOKEN.sub(_hold, redacted)
    for _, pattern, validator_name in rules.pii_patterns:
        validator = _VALIDATORS.get(validator_name) if validator_name else None

        def _sub(match: re.Match[str], *, check=validator) -> str:
            # A candidate that fails its checksum is not PII — leave it alone.
            if check is not None and not check(match.group(0)):
                return match.group(0)
            return _mint(rules.redacted, match.group(0), marker)

        redacted = pattern.sub(_sub, redacted)
    return _HOLD_RE.sub(lambda m: held[int(m.group(1))], redacted)


def scrub_string(
    text: str,
    rules: SanitizeRules,
    *,
    pii: bool,
    max_chars: int,
    key: str | None = None,
    marker: SecretMarker | None = None,
) -> str:
    cleaned = apply_secret_patterns(text, rules, marker)
    if pii:
        cleaned = apply_pii_patterns(cleaned, rules, marker)
    if is_command_like_key(key):
        # D14: a binary name is never a secret, and it is the one position where
        # the placeholder destroys the parse and therefore exec_shape.heads.
        cleaned = restore_head_token(
            text,
            cleaned,
            is_secret=lambda token: apply_secret_patterns(token, rules) != token,
        )
    return truncate(
        cleaned,
        max_chars,
        rules,
        signal_aware=is_content_like_key(key),
    )


def redact_value(
    value: Any,
    rules: SanitizeRules | None = None,
    *,
    key: str | None = None,
) -> Any:
    rules = rules or load_rules()
    if isinstance(value, str):
        limit = rules.leaf_max_chars(key)
        if len(value) > limit:
            if is_content_like_key(key):
                return pack_signal_excerpt(value, limit, ellipsis="...")
            return rules.truncated
        return value
    if isinstance(value, dict):
        return redact_args(value, rules)
    if isinstance(value, list):
        return [redact_value(item, rules) for item in value]
    return value


def redact_args(args: dict[str, Any], rules: SanitizeRules | None = None) -> dict[str, Any]:
    """Redact credential-shaped field names and truncate long strings in args."""
    rules = rules or load_rules()
    redacted: dict[str, Any] = {}
    for key, value in args.items():
        if is_credential_field(key, rules):
            redacted[key] = rules.redacted
        elif isinstance(value, str) and len(value) > rules.leaf_max_chars(key):
            if is_content_like_key(key):
                redacted[key] = pack_signal_excerpt(
                    value, rules.leaf_max_chars(key), ellipsis="..."
                )
            else:
                redacted[key] = rules.truncated
        elif isinstance(value, dict):
            redacted[key] = redact_args(value, rules)
        elif isinstance(value, list):
            redacted[key] = [redact_value(item, rules) for item in value]
        else:
            redacted[key] = value
    return redacted
