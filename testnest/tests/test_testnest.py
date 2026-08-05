from __future__ import annotations

from pathlib import Path

from testnest.loader import filter_scenarios, load_scenarios, load_suites
from testnest.profiles import load_profiles, resolve_scanner_config
from testnest.runner import run_suite
from sentrook.config import L3Policy

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTNEST_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = TESTNEST_ROOT / "fixtures" / "scenarios"
RULES = REPO_ROOT / "examples" / "rules"
CORPUS = REPO_ROOT / "examples" / "corpus"


def test_load_smoke_scenarios():
    scenarios = load_scenarios(SCENARIOS)
    names = {s.name for s in scenarios}
    assert "empty-allow" in names
    assert "demo-fetch-exec-block" in names


def test_smoke_suite_passes_v0():
    report = run_suite(
        scenarios_dir=SCENARIOS,
        rules_dir=RULES,
        profile="v0",
        suite="smoke",
        corpus_dir=CORPUS,
    )
    assert report.ok, [
        (r.scenario.name, r.outcome, r.failures) for r in report.results
    ]


def test_profiles_yaml_loads():
    profiles = load_profiles(SCENARIOS)
    assert "v0" in profiles
    assert resolve_scanner_config(SCENARIOS, "v0").l3_policy == L3Policy.OFF


def test_filter_by_tag():
    scenarios = load_scenarios(SCENARIOS)
    suites = load_suites(SCENARIOS)
    filtered = filter_scenarios(scenarios, suite=None, tags=["smoke"], suites=suites)
    assert filtered
    assert all("smoke" in s.tags for s in filtered)
