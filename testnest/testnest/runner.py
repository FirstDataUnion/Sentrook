from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from sentrook.config import L3Policy, ScannerConfig
from sentrook.corpus.loader import load_corpus, resolve_corpus_dir
from sentrook.corpus.models import LoadedRuleCorpus
from sentrook.layers.l3_embed import make_scorer
from sentrook.layers.l3_score import BiEncoderScorer
from sentrook.scan import scan_plan_file
from testnest.assertions import AssertionFailure, check_expectation
from testnest.loader import filter_scenarios, load_scenarios, load_suites
from testnest.models import Scenario
from testnest.profiles import resolve_scanner_config


class ScenarioOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    XFAILED = "xfailed"
    XPASSED = "xpassed"
    NO_PROFILE = "no_profile"


@dataclass
class ScenarioResult:
    scenario: Scenario
    profile: str
    outcome: ScenarioOutcome
    summary: str = ""
    failures: list[AssertionFailure] = field(default_factory=list)
    scan_summary: str | None = None


@dataclass
class TestNestReport:
    profile: str
    results: list[ScenarioResult] = field(default_factory=list)
    scanner_config: dict[str, Any] | None = None
    corpus_dir: str | None = None

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.PASSED)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.FAILED)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.SKIPPED)

    @property
    def xfailed(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.XFAILED)

    @property
    def xpassed(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.XPASSED)

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.xpassed == 0


def run_suite(
    *,
    scenarios_dir: Path,
    rules_dir: Path,
    profile: str = "v0",
    suite: str | None = "core",
    tags: list[str] | None = None,
    corpus_dir: Path | None = None,
    l3_scorer: BiEncoderScorer | None = None,
) -> TestNestReport:
    scenarios = load_scenarios(scenarios_dir)
    suites = load_suites(scenarios_dir)
    selected = filter_scenarios(scenarios, suite=suite, tags=tags, suites=suites)

    config = resolve_scanner_config(scenarios_dir, profile)
    corpus: dict[str, LoadedRuleCorpus] | None = None
    scorer = l3_scorer
    resolved_corpus_dir: str | None = None

    if config.l3_policy != L3Policy.OFF:
        cdir = resolve_corpus_dir(corpus_dir or config.l3.corpus_dir)
        resolved_corpus_dir = str(cdir)
        # Record the resolved path in the config we report, so sweeps are auditable.
        config = config.model_copy(
            update={"l3": config.l3.model_copy(update={"corpus_dir": resolved_corpus_dir})}
        )
        corpus = load_corpus(cdir)
        if scorer is None:
            scorer = make_scorer(config)

    report = TestNestReport(
        profile=profile,
        scanner_config=config.model_dump(mode="json"),
        corpus_dir=resolved_corpus_dir,
    )
    for scenario in selected:
        report.results.append(
            _run_scenario(scenario, scenarios_dir, rules_dir, profile, config, corpus, scorer)
        )
    return report


def _run_scenario(
    scenario: Scenario,
    scenarios_dir: Path,
    rules_dir: Path,
    profile: str,
    config: ScannerConfig,
    corpus: dict[str, LoadedRuleCorpus] | None,
    scorer: BiEncoderScorer | None,
) -> ScenarioResult:
    expectation = scenario.expectation_for(profile)
    if expectation is None:
        return ScenarioResult(
            scenario=scenario,
            profile=profile,
            outcome=ScenarioOutcome.NO_PROFILE,
            summary=f"no profile {profile!r} defined",
        )

    if expectation.skip:
        return ScenarioResult(
            scenario=scenario,
            profile=profile,
            outcome=ScenarioOutcome.SKIPPED,
            summary=expectation.skip_reason or "skipped",
        )

    plan_path = scenario.plan_path(scenarios_dir)
    try:
        scan_result = scan_plan_file(plan_path, rules_dir, config, corpus=corpus, l3_scorer=scorer)
    except Exception as exc:
        if expectation.xfail:
            return ScenarioResult(
                scenario=scenario,
                profile=profile,
                outcome=ScenarioOutcome.XFAILED,
                summary=str(exc),
            )
        return ScenarioResult(
            scenario=scenario,
            profile=profile,
            outcome=ScenarioOutcome.FAILED,
            summary=f"scan error: {exc}",
        )

    assertion = check_expectation(scan_result, expectation)

    if expectation.xfail:
        if assertion.passed:
            return ScenarioResult(
                scenario=scenario,
                profile=profile,
                outcome=ScenarioOutcome.XPASSED,
                summary=expectation.xfail_reason or "expected to fail but passed",
                scan_summary=scan_result.summary,
            )
        return ScenarioResult(
            scenario=scenario,
            profile=profile,
            outcome=ScenarioOutcome.XFAILED,
            summary=expectation.xfail_reason or "expected failure",
            failures=assertion.failures,
            scan_summary=scan_result.summary,
        )

    if assertion.passed:
        return ScenarioResult(
            scenario=scenario,
            profile=profile,
            outcome=ScenarioOutcome.PASSED,
            scan_summary=scan_result.summary,
        )

    return ScenarioResult(
        scenario=scenario,
        profile=profile,
        outcome=ScenarioOutcome.FAILED,
        failures=assertion.failures,
        scan_summary=scan_result.summary,
    )
