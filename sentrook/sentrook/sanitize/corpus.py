"""Sanitize ``CorpusExample`` payloads for Rookery ingest (redacted-only persist).

This path is intentionally stricter than plugin / pre-scan sanitization.
Prefer over-redaction: secrets must not land on Rookery disk. Patterns here
(generic credential assignments, URI userinfo, lower entropy threshold) are
**not** mirrored into OpenClaw pre-scan scrubbing, which must preserve L2
rule signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sentrook.corpus.models import CorpusExample, CorpusStep
from sentrook.sanitize.core import (
    apply_secret_patterns_with_hits,
    is_credential_field,
    truncate,
)
from sentrook.sanitize.rules import SanitizeRules, load_rules
from sentrook.sanitize.signal_excerpt import is_content_like_key

Severity = Literal["none", "low", "medium", "critical"]

# Query keys whose values are stripped from URLs (case-insensitive).
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "key",
        "api_key",
        "apikey",
        "access_token",
        "auth",
        "password",
        "secret",
        "sig",
        "signature",
        "passwd",
        "client_secret",
        "refresh_token",
        "private_key",
    }
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
# Rookery intensify: 32+ catches short bot passwords; pre-scan stays prefix-only.
_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")
_LIKELY_DIGEST_RE = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")

# Gitleaks-inspired generic assignment — corpus/Rookery only.
# Keeps the label; redacts the value (including camelCase apiKey=…).
_GENERIC_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(
        pass(?:wd|word)?
      | secret
      | token
      | api[_-]?key
      | access[_-]?key
      | auth(?:entication)?(?:[_-]?token)?
      | credential
      | private[_-]?key
      | client[_-]?secret
      | refresh[_-]?token
      | bearer
    )
    (\s*[=:]\s*)
    (?:
        "(?:\\.|[^"\\]){3,}"
      | '(?:\\.|[^'\\]){3,}'
      | [^\s"'\\;|&]{3,}
    )
    """
)

# postgres://user:password@host — keep scheme/user/host, drop password.
_CONNECTION_USERINFO = re.compile(
    r"(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?|ftp))"
    r"://([^:\s/@]+):([^@\s/]+)@"
)

# Basic auth in headers: Authorization: Basic <base64>
_BASIC_AUTH_HEADER = re.compile(r"(?i)(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]{8,})")


@dataclass
class RedactionReport:
    """Audit of sanitization — counts and paths only; never raw secret values."""

    severity: Severity = "none"
    fields_touched: list[str] = field(default_factory=list)
    pattern_counts: dict[str, int] = field(default_factory=dict)
    truncated_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "fields_touched": list(self.fields_touched),
            "pattern_counts": dict(self.pattern_counts),
            "truncated_fields": list(self.truncated_fields),
        }

    def note_pattern(self, name: str, path: str) -> None:
        self.pattern_counts[name] = self.pattern_counts.get(name, 0) + 1
        if path not in self.fields_touched:
            self.fields_touched.append(path)

    def note_truncate(self, path: str) -> None:
        if path not in self.truncated_fields:
            self.truncated_fields.append(path)
        if path not in self.fields_touched:
            self.fields_touched.append(path)

    def bump_severity(self, level: Severity) -> None:
        order = {"none": 0, "low": 1, "medium": 2, "critical": 3}
        if order[level] > order[self.severity]:
            self.severity = level


@dataclass(frozen=True)
class SanitizeCorpusResult:
    example: CorpusExample
    report: RedactionReport


def policy_reject(report: RedactionReport) -> bool:
    """True when residual risk is too high to persist even after scrubbing."""
    return report.severity == "critical"


def sanitize_corpus_example(
    example: CorpusExample,
    *,
    rules: SanitizeRules | None = None,
    intent_max_chars: int | None = None,
) -> SanitizeCorpusResult:
    """Deep-scrub a corpus example in memory; return sanitized copy + report."""
    rules = rules or load_rules()
    report = RedactionReport()
    intent_limit = (
        intent_max_chars if intent_max_chars is not None else min(rules.intent_max_chars, 400)
    )

    intent = example.intent
    if intent is not None:
        intent = _scrub_field(
            intent,
            rules,
            path="intent",
            report=report,
            pii=True,
            max_chars=intent_limit,
            intensify=True,
        )

    notes = example.notes
    if notes is not None:
        notes = _scrub_field(
            notes,
            rules,
            path="notes",
            report=report,
            pii=True,
            max_chars=rules.string_leaf_max_chars,
            intensify=True,
        )

    steps: list[CorpusStep] = []
    for index, step in enumerate(example.steps):
        args = _scrub_args(
            step.args,
            rules,
            path=f"steps[{index}].args",
            report=report,
        )
        excerpt = step.excerpt
        if excerpt is not None:
            excerpt = _scrub_field(
                excerpt,
                rules,
                path=f"steps[{index}].excerpt",
                report=report,
                pii=True,
                max_chars=200,
                intensify=True,
            )
        steps.append(
            CorpusStep(
                tool=step.tool,
                status=step.status,
                args=args,
                excerpt=excerpt,
            )
        )

    if report.pattern_counts.get("pem_private_key", 0) > 0:
        report.bump_severity("critical")
    elif report.pattern_counts:
        report.bump_severity(
            "medium"
            if any(k.startswith("sk") or "token" in k or k == "jwt" for k in report.pattern_counts)
            else "low"
        )

    cleaned = example.model_copy(update={"intent": intent, "notes": notes, "steps": steps})
    return SanitizeCorpusResult(example=cleaned, report=report)


def _scrub_field(
    text: str,
    rules: SanitizeRules,
    *,
    path: str,
    report: RedactionReport,
    pii: bool,
    max_chars: int,
    intensify: bool,
    field_key: str | None = None,
) -> str:
    original = text
    cleaned, secret_hits = apply_secret_patterns_with_hits(text, rules)
    for name in secret_hits:
        report.note_pattern(name, path)
        if name == "pem_private_key":
            report.bump_severity("critical")

    # Corpus-only extras (after shared prefixes so named hits stay accurate).
    cleaned = _apply_corpus_extra_patterns(cleaned, rules, path=path, report=report)

    if _JWT_RE.search(cleaned):
        report.note_pattern("jwt", path)
        cleaned = _JWT_RE.sub(rules.redacted, cleaned)

    cleaned = _redact_url_query(cleaned, rules, path=path, report=report)

    if pii:
        for name, pattern in rules.pii_patterns:
            if pattern.search(cleaned):
                report.note_pattern(name, path)
                cleaned = pattern.sub(rules.redacted, cleaned)

    if intensify:
        cleaned = _redact_high_entropy(cleaned, rules, path=path, report=report)

    if len(cleaned) > max_chars:
        report.note_truncate(path)
        cleaned = truncate(
            cleaned,
            max_chars,
            rules,
            signal_aware=is_content_like_key(field_key),
        )

    if cleaned != original and path not in report.fields_touched:
        report.fields_touched.append(path)
    return cleaned


def _apply_corpus_extra_patterns(
    text: str,
    rules: SanitizeRules,
    *,
    path: str,
    report: RedactionReport,
) -> str:
    cleaned = text

    def _assign_repl(match: re.Match[str]) -> str:
        report.note_pattern("generic_credential_assignment", path)
        return f"{match.group(1)}{match.group(2)}{rules.redacted}"

    cleaned = _GENERIC_CREDENTIAL_ASSIGNMENT.sub(_assign_repl, cleaned)

    def _uri_repl(match: re.Match[str]) -> str:
        report.note_pattern("connection_userinfo", path)
        return f"{match.group(1)}://{match.group(2)}:{rules.redacted}@"

    cleaned = _CONNECTION_USERINFO.sub(_uri_repl, cleaned)

    def _basic_repl(match: re.Match[str]) -> str:
        report.note_pattern("basic_auth_header", path)
        return f"{match.group(1)}{rules.redacted}"

    cleaned = _BASIC_AUTH_HEADER.sub(_basic_repl, cleaned)
    return cleaned


def _redact_high_entropy(
    text: str,
    rules: SanitizeRules,
    *,
    path: str,
    report: RedactionReport,
) -> str:
    def _entropy_sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.startswith("http") or "/" in token:
            return token
        if _LIKELY_DIGEST_RE.fullmatch(token):
            return token
        report.note_pattern("high_entropy", path)
        return rules.redacted

    return _HIGH_ENTROPY_RE.sub(_entropy_sub, text)


def _scrub_args(
    args: dict[str, Any],
    rules: SanitizeRules,
    *,
    path: str,
    report: RedactionReport,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in args.items():
        child = f"{path}.{key}"
        if is_credential_field(key, rules):
            report.note_pattern("credential_field", child)
            out[key] = rules.redacted
            continue
        if isinstance(value, str):
            use_pii = key in rules.pii_arg_keys or key.lower() in {
                "url",
                "uri",
                "href",
            }
            out[key] = _scrub_field(
                value,
                rules,
                path=child,
                report=report,
                pii=use_pii,
                max_chars=rules.string_leaf_max_chars,
                intensify=True,
                field_key=key,
            )
        elif isinstance(value, dict):
            out[key] = _scrub_args(value, rules, path=child, report=report)
        elif isinstance(value, list):
            out[key] = [
                _scrub_field(
                    item,
                    rules,
                    path=f"{child}[{i}]",
                    report=report,
                    pii=False,
                    max_chars=rules.string_leaf_max_chars,
                    intensify=True,
                )
                if isinstance(item, str)
                else (
                    _scrub_args(item, rules, path=f"{child}[{i}]", report=report)
                    if isinstance(item, dict)
                    else item
                )
                for i, item in enumerate(value)
            ]
        else:
            out[key] = value
    return out


def _redact_url_query(
    text: str,
    rules: SanitizeRules,
    *,
    path: str,
    report: RedactionReport,
) -> str:
    if "://" not in text and "?" not in text:
        return text

    def _scrub_url(url: str) -> str:
        parts = urlsplit(url)
        if not parts.query:
            return url
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        changed = False
        scrubbed: list[tuple[str, str]] = []
        for key, value in pairs:
            if key.lower() in _SENSITIVE_QUERY_KEYS:
                scrubbed.append((key, rules.redacted))
                changed = True
            else:
                scrubbed.append((key, value))
        if not changed:
            return url
        report.note_pattern("url_query", path)
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(scrubbed), parts.fragment)
        )

    # Whole-string URL
    if text.startswith("http://") or text.startswith("https://"):
        return _scrub_url(text)

    # Embedded URLs (best effort)
    url_re = re.compile(r"https?://[^\s\"']+")
    return url_re.sub(lambda m: _scrub_url(m.group(0)), text)
