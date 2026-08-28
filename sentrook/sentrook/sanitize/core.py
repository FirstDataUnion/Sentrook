"""Low-level sanitization primitives (no planir imports)."""

from __future__ import annotations

import re
from typing import Any

from sentrook.sanitize.rules import SanitizeRules, load_rules
from sentrook.sanitize.signal_excerpt import is_content_like_key, pack_signal_excerpt

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
      | [^\s;|&]+                     # bare value
    )
    """
)
# ``--password secret`` / ``--token=abc`` — replacement keeps the flag.
_CLI_SECRET_FLAG = re.compile(
    r"""(?ix)
    (--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)
        (?:-\w+)?)
    (\s*=\s*|\s+)
    (?:
        "[^"\\]*(?:\\.[^"\\]*)*"
      | '[^'\\]*(?:\\.[^'\\]*)*'
      | [^\s;|&]+
    )
    """
)


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


def redact_env_secret_assignments(text: str, placeholder: str) -> tuple[str, int]:
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
        return f"{export}{name}={placeholder}"

    return _ENV_ASSIGNMENT.sub(_repl, text), count


def redact_cli_secret_flags(text: str, placeholder: str) -> tuple[str, int]:
    """Redact values after credential-shaped CLI long-options; keep the flag."""

    def _repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}{placeholder}"

    return _CLI_SECRET_FLAG.subn(_repl, text)


def apply_secret_patterns(text: str, rules: SanitizeRules) -> str:
    cleaned, _hits = apply_secret_patterns_with_hits(text, rules)
    return cleaned


def apply_secret_patterns_with_hits(text: str, rules: SanitizeRules) -> tuple[str, list[str]]:
    """Apply secret scrubbers; return scrubbed text and pattern names that fired."""
    hits: list[str] = []
    cleaned = text

    cleaned, env_hits = redact_env_secret_assignments(cleaned, rules.redacted)
    if env_hits:
        hits.append("env_secret_assignment")

    cleaned, cli_hits = redact_cli_secret_flags(cleaned, rules.redacted)
    if cli_hits:
        hits.append("cli_secret_flag")

    for name, pattern, keep_prefix in rules.secret_value_patterns:
        if pattern.search(cleaned):
            hits.append(name)
            cleaned = pattern.sub(
                lambda match, *, keep=keep_prefix: _prefix_preserving_repl(
                    match, rules.redacted, keep
                ),
                cleaned,
            )
    return cleaned, hits


def _prefix_preserving_repl(match: re.Match[str], placeholder: str, keep_prefix: bool) -> str:
    """Replace a secret match, optionally keeping the first capturing group."""
    if keep_prefix:
        for index in range(1, (match.lastindex or 0) + 1):
            group = match.group(index)
            if group:
                return f"{group}{placeholder}"
    return placeholder


def apply_pii_patterns(text: str, rules: SanitizeRules) -> str:
    redacted = text
    for _, pattern in rules.pii_patterns:
        redacted = pattern.sub(rules.redacted, redacted)
    return redacted


def scrub_string(
    text: str,
    rules: SanitizeRules,
    *,
    pii: bool,
    max_chars: int,
    key: str | None = None,
) -> str:
    cleaned = apply_secret_patterns(text, rules)
    if pii:
        cleaned = apply_pii_patterns(cleaned, rules)
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
        if len(value) > rules.string_leaf_max_chars:
            if is_content_like_key(key):
                return pack_signal_excerpt(value, rules.string_leaf_max_chars, ellipsis="...")
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
        elif isinstance(value, str) and len(value) > rules.string_leaf_max_chars:
            if is_content_like_key(key):
                redacted[key] = pack_signal_excerpt(
                    value, rules.string_leaf_max_chars, ellipsis="..."
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
