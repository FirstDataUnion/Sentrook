"""Presidio + spaCy NER pass for corpus examples (Rookery ingest).

Runs **after** regex ``sanitize_corpus_example`` and **before** disk persist.
Scoped to free-text identity leakage: ``intent``, ``args.command`` / ``args.cmd``,
and ``steps[].excerpt``. Secrets stay on the regex path + ``policy_reject``.

**On by default.** Opt out with ``ROOKERY_NER_SANITIZE=0`` (or ``SENTROOK_CORPUS_NER=0``).
Requires ``pip install 'sentrook[ner]'`` and ``python -m spacy download en_core_web_sm``
(bundled in the Rookery deploy image).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from sentrook.corpus.models import CorpusExample, CorpusStep
from sentrook.sanitize.corpus import RedactionReport, SanitizeCorpusResult
from sentrook.sanitize.rules import load_rules

# NER entities regex cannot catch reliably. Structured secrets stay on regex path.
# spaCy ``en_core_web_sm`` is strong on PERSON + city/GPE LOCATION; weak on
# street addresses and ORG (Presidio often has no ORG recognizer on this path).
_DEFAULT_ENTITIES = (
    "PERSON",
    "LOCATION",
)

_ENV_FLAGS = ("ROOKERY_NER_SANITIZE", "SENTROOK_CORPUS_NER")
_COMMAND_KEYS = frozenset({"command", "cmd"})


@dataclass
class NerPassResult:
    """Outcome of one NER scrub pass (for harness + ingest analysis)."""

    example: CorpusExample
    report: RedactionReport
    entity_counts: dict[str, int] = field(default_factory=dict)
    fields_touched: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    skipped: bool = False
    skip_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_counts": dict(self.entity_counts),
            "fields_touched": list(self.fields_touched),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


def ner_env_enabled() -> bool:
    """True unless the operator explicitly opts out (default ON).

    Either ``ROOKERY_NER_SANITIZE`` or ``SENTROOK_CORPUS_NER`` may set the value;
    the first flag present in ``_ENV_FLAGS`` order wins. Unset → enabled.
    """
    for name in _ENV_FLAGS:
        raw = os.environ.get(name)
        if raw is None:
            continue
        value = raw.strip().lower()
        if value in {"0", "false", "no", "off"}:
            return False
        if value in {"1", "true", "yes", "on"}:
            return True
        # Unrecognised value: treat as unset for this flag and keep looking.
    return True


def ner_available() -> bool:
    """True when Presidio + spaCy ``en_core_web_sm`` can be imported/loaded."""
    try:
        _engines()
    except Exception:
        return False
    return True


def scrub_corpus_ner(
    example: CorpusExample,
    *,
    report: RedactionReport | None = None,
    entities: tuple[str, ...] | None = None,
    score_threshold: float = 0.5,
) -> SanitizeCorpusResult:
    """Apply Presidio NER to intent / command / excerpt; merge into ``report``."""
    report = report or RedactionReport()
    result = apply_ner_pass(
        example,
        report=report,
        entities=entities,
        score_threshold=score_threshold,
    )
    return SanitizeCorpusResult(example=result.example, report=result.report)


def apply_ner_pass(
    example: CorpusExample,
    *,
    report: RedactionReport | None = None,
    entities: tuple[str, ...] | None = None,
    score_threshold: float = 0.5,
) -> NerPassResult:
    """Full NER pass with timing and entity counts (harness / ingest)."""
    report = report or RedactionReport()
    started = time.perf_counter()
    try:
        analyzer, anonymizer = _engines()
    except Exception as exc:  # noqa: BLE001 — spike: surface any load failure
        return NerPassResult(
            example=example,
            report=report,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            skipped=True,
            skip_reason=f"ner_unavailable: {exc}",
        )

    entity_list = list(entities or _DEFAULT_ENTITIES)
    placeholder = load_rules().redacted
    entity_counts: dict[str, int] = {}
    fields_touched: list[str] = []

    intent = example.intent
    if intent:
        intent, counts = _scrub_text(
            intent,
            analyzer=analyzer,
            anonymizer=anonymizer,
            entities=entity_list,
            score_threshold=score_threshold,
            placeholder=placeholder,
        )
        if counts:
            _merge_counts(entity_counts, counts)
            fields_touched.append("intent")
            for name, n in counts.items():
                for _ in range(n):
                    report.note_pattern(f"ner_{name.lower()}", "intent")
            report.bump_severity("medium")

    steps: list[CorpusStep] = []
    for index, step in enumerate(example.steps):
        args = dict(step.args)
        for key in _COMMAND_KEYS:
            value = args.get(key)
            if not isinstance(value, str) or not value:
                continue
            path = f"steps[{index}].args.{key}"
            cleaned, counts = _scrub_text(
                value,
                analyzer=analyzer,
                anonymizer=anonymizer,
                entities=entity_list,
                score_threshold=score_threshold,
                placeholder=placeholder,
            )
            args[key] = cleaned
            if counts:
                _merge_counts(entity_counts, counts)
                fields_touched.append(path)
                for name, n in counts.items():
                    for _ in range(n):
                        report.note_pattern(f"ner_{name.lower()}", path)
                report.bump_severity("medium")

        excerpt = step.excerpt
        if excerpt:
            path = f"steps[{index}].excerpt"
            excerpt, counts = _scrub_text(
                excerpt,
                analyzer=analyzer,
                anonymizer=anonymizer,
                entities=entity_list,
                score_threshold=score_threshold,
                placeholder=placeholder,
            )
            if counts:
                _merge_counts(entity_counts, counts)
                fields_touched.append(path)
                for name, n in counts.items():
                    for _ in range(n):
                        report.note_pattern(f"ner_{name.lower()}", path)
                report.bump_severity("medium")

        steps.append(
            CorpusStep(
                tool=step.tool,
                status=step.status,
                args=args,
                excerpt=excerpt,
            )
        )

    cleaned = example.model_copy(update={"intent": intent, "steps": steps})
    return NerPassResult(
        example=cleaned,
        report=report,
        entity_counts=entity_counts,
        fields_touched=fields_touched,
        elapsed_ms=(time.perf_counter() - started) * 1000,
    )


def _scrub_text(
    text: str,
    *,
    analyzer: Any,
    anonymizer: Any,
    entities: list[str],
    score_threshold: float,
    placeholder: str,
) -> tuple[str, dict[str, int]]:
    from presidio_anonymizer.entities import OperatorConfig

    results = analyzer.analyze(
        text=text,
        language="en",
        entities=entities,
        score_threshold=score_threshold,
    )
    if not results:
        return text, {}

    counts: dict[str, int] = {}
    for hit in results:
        counts[hit.entity_type] = counts.get(hit.entity_type, 0) + 1

    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators={
            "DEFAULT": OperatorConfig("replace", {"new_value": placeholder}),
        },
    )
    return anonymized.text, counts


def _merge_counts(dest: dict[str, int], src: dict[str, int]) -> None:
    for key, value in src.items():
        dest[key] = dest.get(key, 0) + value


@lru_cache(maxsize=1)
def _engines() -> tuple[Any, Any]:
    """Lazy singleton Presidio analyzer + anonymizer (spaCy sm)."""
    # Import check — fails clearly if model not downloaded.
    import spacy
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine

    spacy.load("en_core_web_sm")

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    )
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    anonymizer = AnonymizerEngine()
    return analyzer, anonymizer


def reset_ner_engines() -> None:
    """Drop cached engines (tests)."""
    _engines.cache_clear()
