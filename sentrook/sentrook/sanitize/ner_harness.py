"""Fixture harness for the Presidio NER corpus scrub spike.

Fixture JSON shape::

    {
      "id": "person_in_intent",
      "description": "...",
      "example": { ... CorpusExample ... },
      "expect": {
        "must_not_contain": ["Alice Johnson"],
        "must_still_contain": ["deploy"],
        "min_entity_types": ["PERSON"],
        "max_fields_touched": null
      }
    }

Run::

    pytest sentrook/tests/test_sanitize_ner.py -m ner_presidio -q
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentrook.corpus.models import CorpusExample
from sentrook.sanitize.ner import NerPassResult, apply_ner_pass, ner_available

# sentrook/sentrook/sanitize/ → sentrook/tests/fixtures/sanitize_ner/
FIXTURES_DIR = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sanitize_ner"
)


@dataclass(frozen=True)
class NerFixture:
    id: str
    description: str
    example: CorpusExample
    expect: dict[str, Any]
    path: Path


@dataclass
class FixtureCheckResult:
    fixture_id: str
    passed: bool
    failures: list[str]
    ner: NerPassResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.fixture_id,
            "passed": self.passed,
            "failures": list(self.failures),
            "ner": self.ner.to_dict(),
        }


def fixtures_dir() -> Path:
    return FIXTURES_DIR


def load_fixtures(directory: Path | None = None) -> list[NerFixture]:
    root = directory or FIXTURES_DIR
    if not root.is_dir():
        return []
    out: list[NerFixture] = []
    for path in sorted(root.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        out.append(
            NerFixture(
                id=str(raw["id"]),
                description=str(raw.get("description") or ""),
                example=CorpusExample.model_validate(raw["example"]),
                expect=dict(raw.get("expect") or {}),
                path=path,
            )
        )
    return out


def run_fixture(fixture: NerFixture) -> FixtureCheckResult:
    ner = apply_ner_pass(fixture.example)
    failures = evaluate_expect(fixture.example, ner, fixture.expect)
    return FixtureCheckResult(
        fixture_id=fixture.id,
        passed=not failures,
        failures=failures,
        ner=ner,
    )


def evaluate_expect(
    original: CorpusExample,
    ner: NerPassResult,
    expect: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if ner.skipped:
        failures.append(f"ner skipped: {ner.skip_reason}")
        return failures

    blob = _example_blob(ner.example)

    for needle in expect.get("must_not_contain") or []:
        if needle in blob:
            failures.append(f"must_not_contain still present: {needle!r}")

    for needle in expect.get("must_still_contain") or []:
        if needle not in blob:
            failures.append(f"must_still_contain missing: {needle!r}")

    required = set(expect.get("min_entity_types") or [])
    seen = set(ner.entity_counts)
    missing = required - seen
    if missing:
        failures.append(f"missing entity types: {sorted(missing)}")

    max_fields = expect.get("max_fields_touched")
    if max_fields is not None and len(ner.fields_touched) > int(max_fields):
        failures.append(
            f"fields_touched={ner.fields_touched!r} exceeds max {max_fields}"
        )

    # Sanity: original PII needles should have existed before scrub when listed.
    for needle in expect.get("must_not_contain") or []:
        if needle not in _example_blob(original):
            failures.append(
                f"fixture bug: must_not_contain {needle!r} absent from input"
            )

    return failures


def run_all_fixtures(directory: Path | None = None) -> list[FixtureCheckResult]:
    if not ner_available():
        raise RuntimeError(
            "NER deps unavailable — install sentrook[ner] and "
            "python -m spacy download en_core_web_sm"
        )
    return [run_fixture(fx) for fx in load_fixtures(directory)]


def _example_blob(example: CorpusExample) -> str:
    parts: list[str] = []
    if example.intent:
        parts.append(example.intent)
    for step in example.steps:
        for key in ("command", "cmd"):
            value = step.args.get(key)
            if isinstance(value, str):
                parts.append(value)
        if step.excerpt:
            parts.append(step.excerpt)
    return "\n".join(parts)
