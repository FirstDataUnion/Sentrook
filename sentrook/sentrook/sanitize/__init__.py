"""Trajectory PlanIR sanitization (Options A, B, D, G)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentrook.sanitize.core import redact_args, redact_value
from sentrook.sanitize.rules import SanitizeRules, load_rules
from sentrook.sanitize.text import scrub_text

if TYPE_CHECKING:
    from sentrook.sanitize.corpus import RedactionReport, SanitizeCorpusResult
    from sentrook.sanitize.planir import SanitizePlanIRResult

__all__ = [
    "SanitizeRules",
    "SanitizePlanIRResult",
    "SanitizeCorpusResult",
    "RedactionReport",
    "hash_session_id",
    "load_rules",
    "maybe_sanitize_planir",
    "policy_reject",
    "redact_args",
    "redact_value",
    "sanitize_corpus_example",
    "sanitize_planir",
    "sanitize_planir_dict",
    "scrub_text",
]

_LAZY_EXPORTS = {
    "SanitizePlanIRResult",
    "SanitizeCorpusResult",
    "RedactionReport",
    "hash_session_id",
    "sanitize_planir",
    "sanitize_planir_dict",
    "maybe_sanitize_planir",
    "policy_reject",
    "sanitize_corpus_example",
}


_CORPUS_EXPORTS = frozenset(
    {
        "SanitizeCorpusResult",
        "RedactionReport",
        "policy_reject",
        "sanitize_corpus_example",
    }
)


def __getattr__(name: str):
    if name in _CORPUS_EXPORTS:
        from sentrook.sanitize import corpus as corpus_mod

        return getattr(corpus_mod, name)
    if name in {"SanitizePlanIRResult", "hash_session_id", "sanitize_planir", "sanitize_planir_dict"}:
        from sentrook.sanitize import planir as planir_mod

        return getattr(planir_mod, name)
    if name == "maybe_sanitize_planir":
        from sentrook.sanitize.ingress import maybe_sanitize_planir

        return maybe_sanitize_planir
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
