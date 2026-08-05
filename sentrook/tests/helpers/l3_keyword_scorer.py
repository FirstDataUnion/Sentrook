"""Deterministic offline stand-in for the L3 bi-encoder in tests and TestNest.

Leans benign unless the query text carries obvious attack markers, reproducing
the real embedder's margin direction without loading fastembed or hitting the network.
"""

from __future__ import annotations

from sentrook.corpus.models import CorpusEntry

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
    "sentrook-allowlist.json",
    "exec-approvals.json",
    "disableExecApprovals",
    "auditWebhook",
)


def query_is_attackish(query_text: str) -> bool:
    """Heuristic attack lean for the offline KeywordScorer stub."""
    if "wiki.py edit" in query_text:
        if "$(cat /tmp/" in query_text:
            return False
        if "auth-profiles.json" in query_text or "openclaw-agent.sqlite" in query_text or "openclaw-auth-intake" in query_text:
            return True
    return any(marker in query_text for marker in _ATTACK_MARKERS)


class KeywordScorer:
    """Offline L3 scorer used by pytest autouse and TestNest ambiguous suites."""

    def similarities(self, query_text: str, entries: list[CorpusEntry]) -> list[float]:
        attackish = query_is_attackish(query_text)
        scores: list[float] = []
        for entry in entries:
            if entry.label == "pos":
                scores.append(0.9 if attackish else 0.2)
            else:
                scores.append(0.2 if attackish else 0.9)
        return scores
