"""Secret detection from the vendored gitleaks catalogue.

Sentrook does **not** maintain its own secret-pattern catalogue — that is a large
ongoing overhead and not the product. gitleaks publishes 200+ MIT-licensed rules
with entropy thresholds, is already trusted in this repo (``.gitleaks.toml``,
``useDefault = true``, run in CI), and its regexes port mechanically because Go's
RE2 has no lookaround. ``scripts/generate_gitleaks_rules.py`` compiles the pinned
TOML into ``gitleaks_rules.json`` here and a bundled ``gitleaksRules.ts`` for the
plugin, so both languages match identically from one source.

**Ordering matters.** These run *after* Sentrook's own prefix-preserving patterns
so ``sk-ant-[REDACTED]`` keeps the provider prefix L2 rules match on; gitleaks
would replace the whole match. Already-redacted placeholders are inert
(``is_placeholder``), so the catalogue never re-redacts what we already did.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

RULES_PATH = Path(__file__).with_name("gitleaks_rules.json")


@dataclass(frozen=True)
class GitleaksRule:
    id: str
    pattern: re.Pattern[str]
    entropy: float | None
    secret_group: int | None


def shannon_entropy(value: str) -> float:
    """Bits per character. gitleaks' own measure for "is this random enough".

    A provider prefix makes a pattern specific; entropy is what lets a *generic*
    pattern tell an actual credential from an ordinary identifier of the same
    shape. Without it, broad rules are unusable.
    """
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


#: Rules this interpreter could not compile. Empty on a supported Python.
unsupported_gitleaks_rule_ids: list[str] = []


@lru_cache(maxsize=1)
def load_gitleaks_rules(path: Path | None = None) -> tuple[GitleaksRule, ...]:
    rules_path = path or RULES_PATH
    if not rules_path.exists():
        return ()
    doc = json.loads(rules_path.read_text(encoding="utf-8"))
    out: list[GitleaksRule] = []
    for raw in doc.get("rules", []):
        flags = re.IGNORECASE if raw.get("ignorecase") else 0
        try:
            pattern = re.compile(raw["regex"], flags)
        except re.error:
            # Mirrors the plugin's defensive compile. One rule this interpreter
            # cannot parse must cost that rule, never the whole redaction pass —
            # the catalogue is vendored and a bump is always one PR away.
            unsupported_gitleaks_rule_ids.append(str(raw["id"]))
            continue
        out.append(
            GitleaksRule(
                id=str(raw["id"]),
                pattern=pattern,
                entropy=raw.get("entropy"),
                secret_group=raw.get("secret_group"),
            )
        )
    return tuple(out)


def _secret_span(match: re.Match[str], rule: GitleaksRule) -> tuple[str, int, int] | None:
    """The (text, start, end) of the credential itself within ``match``.

    Prefers the rule's ``secretGroup``, then group 1, then the whole match.
    **Replacing only this span matters:** several catalogue rules deliberately
    match surrounding context — ``generic-api-key`` spans the key name *and* the
    closing quote — so replacing ``group(0)`` ate the JSON structure around the
    value (``"author_id": "…"`` became ``"[REDACTED]``, unbalanced). Redacting
    the capture group removes the credential and leaves the document intact.
    """
    index = rule.secret_group or (1 if match.re.groups else 0)
    try:
        text = match.group(index)
    except (IndexError, re.error):  # pragma: no cover - defensive
        index, text = 0, match.group(0)
    if not text:
        index, text = 0, match.group(0)
    return text, match.start(index), match.end(index)


#: Never treated as credentials by the catalogue: UUIDs and ISO-8601 timestamps
#: are identifiers, not secrets. ``generic-api-key`` matches ``auth`` as a
#: *substring* (so ``author_id`` fires) and would otherwise redact every UUID in
#: a JSON result — destroying the document and, worse, minting one shared marker
#: across every event with the same id, which is precisely the cross-step "same
#: value" signal Phase 4 reads as dataflow.
_NOT_A_SECRET = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
    r"|\A\d{4}-\d{2}-\d{2}"
    r"(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\Z",
    re.IGNORECASE,
)


def apply_gitleaks_patterns(
    text: str,
    placeholder: str,
    mint,
    rules: tuple[GitleaksRule, ...] | None = None,
) -> tuple[str, list[str]]:
    """Redact catalogue matches. Returns ``(text, ids_that_fired)``.

    ``mint`` is the caller's placeholder factory (``_mint``) so markers and the
    already-redacted guard apply here exactly as they do to Sentrook's own
    patterns.
    """
    cleaned = text
    fired: list[str] = []
    for rule in rules if rules is not None else load_gitleaks_rules():
        if not rule.pattern.search(cleaned):
            continue

        def _sub(match: re.Match[str], *, r=rule) -> str:
            whole = match.group(0)
            span = _secret_span(match, r)
            if span is None:  # pragma: no cover - defensive
                return whole
            secret, start, end = span
            if _NOT_A_SECRET.match(secret.strip().strip("\"'")):
                return whole
            # Below the rule's own entropy floor this is not a credential —
            # leave it alone rather than redact an ordinary identifier.
            if r.entropy is not None and shannon_entropy(secret) < r.entropy:
                return whole
            if r.id not in fired:
                fired.append(r.id)
            # Replace only the credential, keeping the context the rule matched.
            offset = match.start()
            return whole[: start - offset] + mint(placeholder, secret) + whole[end - offset :]

        cleaned = rule.pattern.sub(_sub, cleaned)
    return cleaned, fired
