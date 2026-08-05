"""Shared scan helpers for sanitize ingress parity gates."""

from __future__ import annotations

from sentrook.config import ScannerConfig
from sentrook.corpus.models import LoadedRuleCorpus
from sentrook.layers.l3_score import BiEncoderScorer
from sentrook.planir import PlanIR
from sentrook.result import ScanResult
from sentrook.rules.models import Rule
from sentrook.scan import scan_plan
from sentrook.sanitize.ingress import maybe_sanitize_planir
from tests.helpers.plugin_sanitize import plugin_sanitize_planir


def scan_plan_direct(
    plan: PlanIR,
    rules: list[Rule],
    config: ScannerConfig,
    *,
    corpus: dict[str, LoadedRuleCorpus] | None = None,
    l3_scorer: BiEncoderScorer | None = None,
) -> ScanResult:
    return scan_plan(plan, rules, config, corpus=corpus, l3_scorer=l3_scorer)


def scan_plan_via_plugin_sanitize(
    plan: PlanIR,
    rules: list[Rule],
    config: ScannerConfig,
    *,
    corpus: dict[str, LoadedRuleCorpus] | None = None,
    l3_scorer: BiEncoderScorer | None = None,
) -> ScanResult:
    sanitized = plugin_sanitize_planir(plan)
    return scan_plan(
        sanitized,
        rules,
        config,
        corpus=corpus,
        l3_scorer=l3_scorer,
    )


def scan_plan_via_server_sanitize(
    plan: PlanIR,
    rules: list[Rule],
    config: ScannerConfig,
    *,
    corpus: dict[str, LoadedRuleCorpus] | None = None,
    l3_scorer: BiEncoderScorer | None = None,
) -> ScanResult:
    sanitized, _ms = maybe_sanitize_planir(plan, enabled=True)
    return scan_plan(
        sanitized,
        rules,
        config,
        corpus=corpus,
        l3_scorer=l3_scorer,
    )
