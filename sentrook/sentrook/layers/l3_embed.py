"""Local bi-encoder implementation of :class:`BiEncoderScorer` (Phase 1, Step 5).

Backed by fastembed (ONNX Runtime), a core dependency. Model weights and the ONNX
runtime are loaded lazily on first embed, so scans that exit at L1/L2 or use
``l3_policy=off`` never pay that cost.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

from sentrook.config import L3Policy, ScannerConfig
from sentrook.corpus.models import CorpusEntry
from sentrook.layers.l3_score import BiEncoderScorer

_DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# Map the short labels used in config/spec to fastembed's canonical model ids.
_MODEL_ALIASES = {
    "all-MiniLM-L6-v2": "sentence-transformers/all-MiniLM-L6-v2",
}


def resolve_model_name(name: str) -> str:
    return _MODEL_ALIASES.get(name, name)


def fastembed_available() -> bool:
    return importlib.util.find_spec("fastembed") is not None


def _is_missing_model_file_error(exc: BaseException) -> bool:
    msg = str(exc)
    return "NO_SUCHFILE" in msg or "File doesn't exist" in msg


def _clear_corrupt_fastembed_cache(model_name: str) -> None:
    """Remove partial fastembed model dirs after a failed ONNX load."""
    resolved = resolve_model_name(model_name)
    leaf = resolved.split("/")[-1].lower()
    roots: list[Path] = []
    for key in ("FASTEMBED_CACHE_PATH", "HF_HOME", "HUGGINGFACE_HUB_CACHE"):
        raw = os.environ.get(key)
        if raw:
            roots.append(Path(raw))
    roots.extend(
        [
            Path.home() / ".cache" / "fastembed",
            Path(os.environ.get("TMPDIR", "/tmp")) / "fastembed_cache",
        ]
    )
    seen: set[Path] = set()
    for root in roots:
        root = root.resolve()
        if root in seen or not root.is_dir():
            continue
        seen.add(root)
        for child in root.glob("models--*"):
            if leaf in child.name.lower():
                shutil.rmtree(child, ignore_errors=True)


def make_scorer(config: ScannerConfig) -> BiEncoderScorer | None:
    """Build the bi-encoder for a config, or ``None`` when L3 is off."""
    if config.l3_policy == L3Policy.OFF:
        return None
    if not fastembed_available():
        raise RuntimeError(
            "L3 is enabled but 'fastembed' is not installed. "
            "Reinstall Sentrook to restore core dependencies: pip install -e ."
        )
    return FastEmbedScorer(config.l3.bi_encoder_model)


class FastEmbedScorer:
    """Cosine-similarity scorer over a fastembed bi-encoder.

    Corpus vectors are L2-normalized and cached on each :class:`CorpusEntry` the first
    time they are seen, so repeated scans only embed the (new) query. With normalized
    vectors, cosine similarity is a plain dot product.
    """

    def __init__(self, model_name: str = _DEFAULT_MODEL) -> None:
        self.model_name = resolve_model_name(model_name)
        self._model = None

    def _ensure_model(self):
        if self._model is not None:
            return self._model
        from fastembed import TextEmbedding

        try:
            self._model = TextEmbedding(model_name=self.model_name)
        except Exception as exc:
            if not _is_missing_model_file_error(exc):
                raise
            _clear_corrupt_fastembed_cache(self.model_name)
            self._model = TextEmbedding(model_name=self.model_name)
        return self._model

    def _embed(self, texts: list[str]):
        import numpy as np

        model = self._ensure_model()
        vectors = list(model.embed(texts))
        out = []
        for vec in vectors:
            arr = np.asarray(vec, dtype="float32")
            norm = float(np.linalg.norm(arr))
            out.append(arr / norm if norm > 0.0 else arr)
        return out

    def warm_corpus(self, entries: list[CorpusEntry]) -> None:
        """Pre-embed and cache vectors for corpus entries that lack them."""
        missing = [e for e in entries if e.embedding is None]
        if not missing:
            return
        for entry, vec in zip(missing, self._embed([e.text for e in missing]), strict=True):
            entry.embedding = vec.tolist()

    def similarities(
        self, query_text: str, entries: list[CorpusEntry]
    ) -> list[float]:
        import numpy as np

        if not entries:
            return []
        self.warm_corpus(entries)
        query_vec = self._embed([query_text])[0]
        return [
            float(np.dot(query_vec, np.asarray(entry.embedding, dtype="float32")))
            for entry in entries
        ]
