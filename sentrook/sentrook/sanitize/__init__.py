"""Trajectory snapshot sanitization (Options A, B, D, G)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentrook.sanitize.core import redact_args, redact_value
from sentrook.sanitize.rules import SanitizeRules, load_rules
from sentrook.sanitize.text import scrub_text

if TYPE_CHECKING:
    from sentrook.sanitize.corpus import RedactionReport, SanitizeCorpusResult
    from sentrook.sanitize.snapshot import SanitizeSnapshotResult

__all__ = [
    "SanitizeRules",
    "SanitizeSnapshotResult",
    "SanitizeCorpusResult",
    "RedactionReport",
    "hash_session_id",
    "load_rules",
    "maybe_sanitize_snapshot",
    "policy_reject",
    "redact_args",
    "redact_value",
    "sanitize_corpus_example",
    "sanitize_shadow_call",
    "sanitize_shadow_result",
    "sanitize_snapshot",
    "sanitize_snapshot_dict",
    "scrub_text",
]

_LAZY_EXPORTS = {
    "SanitizeSnapshotResult",
    "SanitizeCorpusResult",
    "RedactionReport",
    "hash_session_id",
    "sanitize_shadow_call",
    "sanitize_shadow_result",
    "sanitize_snapshot",
    "sanitize_snapshot_dict",
    "maybe_sanitize_snapshot",
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
    if name in _LAZY_EXPORTS - {"maybe_sanitize_snapshot"} - _CORPUS_EXPORTS:
        from sentrook.sanitize import snapshot as snapshot_mod

        return getattr(snapshot_mod, name)
    if name == "maybe_sanitize_snapshot":
        from sentrook.sanitize.ingress import maybe_sanitize_snapshot

        return maybe_sanitize_snapshot
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
