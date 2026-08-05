"""Presidio NER corpus scrub spike — unit + fixture harness tests."""

from __future__ import annotations

import pytest

from sentrook.corpus.models import CorpusExample, CorpusStep
from sentrook.sanitize.corpus import sanitize_corpus_example
from sentrook.sanitize.ner import (
    apply_ner_pass,
    ner_available,
    ner_env_enabled,
    reset_ner_engines,
    scrub_corpus_ner,
)
from sentrook.sanitize.ner_harness import load_fixtures, run_fixture
from sentrook.sanitize.rules import load_rules

pytestmark = pytest.mark.ner_presidio


@pytest.fixture(autouse=True)
def _clear_ner_cache() -> None:
    reset_ner_engines()
    load_rules.cache_clear()
    yield
    reset_ner_engines()
    load_rules.cache_clear()


def test_ner_env_default_on_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ROOKERY_NER_SANITIZE", raising=False)
    monkeypatch.delenv("SENTROOK_CORPUS_NER", raising=False)
    assert ner_env_enabled()
    monkeypatch.setenv("ROOKERY_NER_SANITIZE", "0")
    assert not ner_env_enabled()
    monkeypatch.setenv("ROOKERY_NER_SANITIZE", "1")
    assert ner_env_enabled()


def test_ner_unavailable_is_soft_when_flag_off() -> None:
    # Without deps, apply_ner_pass should skip rather than raise.
    # With deps installed this still returns a non-skipped result — either is fine
    # for the flag-off path; the important contract is no exception.
    ex = CorpusExample.model_validate(
        {
            "id": "x",
            "label": "benign",
            "trust": "community",
            "intent": "hello",
            "steps": [{"tool": "exec", "status": "pending", "args": {"command": "ls"}}],
        }
    )
    result = apply_ner_pass(ex)
    assert result.example.intent == "hello"
    assert isinstance(result.skipped, bool)


@pytest.mark.skipif(not ner_available(), reason="sentrook[ner] + en_core_web_sm required")
def test_person_name_redacted_after_regex() -> None:
    ex = CorpusExample(
        id="ner-1",
        label="benign",
        trust="community",
        intent="Ask Bob Martinez to restart the sidecar",
        steps=[
            CorpusStep(
                tool="exec",
                status="pending",
                args={"command": "systemctl restart sentrook"},
            )
        ],
    )
    regexed = sanitize_corpus_example(ex)
    ner = scrub_corpus_ner(regexed.example, report=regexed.report)
    assert "Bob Martinez" not in (ner.example.intent or "")
    assert "[REDACTED]" in (ner.example.intent or "")
    assert any(k.startswith("ner_") for k in ner.report.pattern_counts)


@pytest.mark.skipif(not ner_available(), reason="sentrook[ner] + en_core_web_sm required")
def test_fixture_harness_all_pass() -> None:
    # street_address_gap is regex+NER coverage, not an NER-only expectation.
    fixtures = [f for f in load_fixtures() if f.id != "street_address_gap"]
    assert fixtures, "expected sanitize_ner fixtures"
    failed = []
    for fx in fixtures:
        result = run_fixture(fx)
        if not result.passed:
            failed.append(result)
    assert not failed, "\n".join(
        f"{r.fixture_id}: {r.failures} ner={r.ner.to_dict()}" for r in failed
    )


@pytest.mark.skipif(not ner_available(), reason="sentrook[ner] + en_core_web_sm required")
@pytest.mark.parametrize(
    "fixture",
    [f for f in load_fixtures() if f.id != "street_address_gap"],
    ids=lambda f: f.id,
)
def test_each_ner_fixture(fixture) -> None:
    result = run_fixture(fixture)
    assert result.passed, f"{result.failures} ner={result.ner.to_dict()}"


@pytest.mark.skipif(not ner_available(), reason="sentrook[ner] + en_core_web_sm required")
def test_street_address_gap_closed_by_regex_then_ner() -> None:
    """Full Rookery path: Option C regex catches streets NER alone misses."""
    fixtures = {f.id: f for f in load_fixtures()}
    fx = fixtures["street_address_gap"]
    regexed = sanitize_corpus_example(fx.example)
    excerpt = regexed.example.steps[0].excerpt or ""
    assert "221B Baker Street" not in excerpt
    assert "street_address" in regexed.report.pattern_counts
    ner = scrub_corpus_ner(regexed.example, report=regexed.report)
    assert "221B Baker Street" not in (ner.example.steps[0].excerpt or "")
