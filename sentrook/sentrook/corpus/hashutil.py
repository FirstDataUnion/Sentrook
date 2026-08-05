"""Canonical hashing helpers for corpus examples."""

from __future__ import annotations

import hashlib
import json

from sentrook.corpus.models import CorpusExample


def canonical_example_hash(example: CorpusExample) -> str:
    """Stable SHA-256 of the example JSON (sorted keys)."""
    payload = json.dumps(example.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def embed_text_hash(text: str) -> str:
    """SHA-256 of subgraph embed text for structural near-dup detection."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
