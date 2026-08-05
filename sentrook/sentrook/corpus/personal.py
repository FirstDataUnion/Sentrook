"""Operator-local corpus examples from live ``allow-always`` review decisions."""

from __future__ import annotations

import threading
from pathlib import Path

import yaml

from sentrook.corpus.models import CorpusExample, RuleCorpus

DEFAULT_PERSONAL_CORPUS_DIR = Path.home() / ".sentrook" / "personal-corpus"

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _dir_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _locks[key] = lock
        return lock


def resolve_personal_corpus_dir(
    configured: str | Path | None = None,
    *,
    enabled: bool | None = None,
) -> Path | None:
    """Return the personal corpus directory when enabled, else ``None``.

  When ``configured`` is omitted, reads ``SENTROOK_PERSONAL_CORPUS_DIR`` (default
  ``~/.sentrook/personal-corpus``). Disabled when ``SENTROOK_PERSONAL_CORPUS_ENABLED``
  is ``0`` / ``false``.
    """
    import os

    if enabled is None:
        raw = (os.environ.get("SENTROOK_PERSONAL_CORPUS_ENABLED") or "").strip().lower()
        if raw in ("0", "false", "no"):
            return None
        enabled = True
    if not enabled:
        return None

    if configured is not None:
        return Path(configured).expanduser().resolve()
    raw = os.environ.get("SENTROOK_PERSONAL_CORPUS_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return DEFAULT_PERSONAL_CORPUS_DIR.resolve()


def append_personal_corpus_example(
    personal_dir: Path,
    *,
    rule_id: str,
    example: CorpusExample,
) -> tuple[str, bool]:
    """Append one example to ``personal_dir/<RULE_ID>.yaml``.

    Returns ``(example_id, created)`` where ``created`` is false when the id
    already existed (idempotent).
    """
    personal_dir = personal_dir.expanduser()
    personal_dir.mkdir(parents=True, exist_ok=True)
    path = personal_dir / f"{rule_id}.yaml"

    with _dir_lock(personal_dir):
        if path.is_file():
            with path.open(encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
            if not isinstance(doc, dict):
                raise ValueError(f"Invalid personal corpus file (expected mapping): {path}")
            spec = RuleCorpus.model_validate(doc)
        else:
            spec = RuleCorpus(rule_id=rule_id, examples=[])

        if any(existing.id == example.id for existing in spec.examples):
            return example.id, False

        spec.examples.append(example)
        payload = spec.model_dump(mode="json", exclude_none=True)
        with path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(
                payload,
                handle,
                sort_keys=False,
                default_flow_style=False,
                allow_unicode=True,
            )
    return example.id, True
