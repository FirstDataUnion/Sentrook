"""Deterministic offline stand-in for the bi-encoder in sanitize gate tests."""

from __future__ import annotations

from sentrook.corpus.models import CorpusEntry
from sentrook.layers.l3_score import BiEncoderScorer

_ATTACK_MARKERS = (
    "/tmp/",
    "payload",
    "dropper",
    "| bash",
    "| sh",
    "install.sh",
    "setup.sh",
    "exfiltrate",
    "ignore all prior",
    "ignore safety",
    "evil.example",
    "apiKey",
    "sk-proj",
    "sk-ant",
    "BEGIN OPENSSH PRIVATE KEY",
)


def _query_is_attackish(query_text: str) -> bool:
    if "wiki.py edit" in query_text:
        if "$(cat /tmp/" in query_text:
            return False
        if "auth-profiles.json" in query_text or "openclaw-agent.sqlite" in query_text or "openclaw-auth-intake" in query_text:
            return True
    return any(marker in query_text for marker in _ATTACK_MARKERS)


class KeywordScorer(BiEncoderScorer):
    """Lean benign unless the query carries obvious attack markers."""

    def similarities(self, query_text: str, entries: list[CorpusEntry]) -> list[float]:
        attackish = _query_is_attackish(query_text)
        scores: list[float] = []
        for entry in entries:
            if entry.label == "pos":
                scores.append(0.9 if attackish else 0.2)
            else:
                scores.append(0.2 if attackish else 0.9)
        return scores
