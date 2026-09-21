"""Stateful scan service: rules, corpus, and the L3 scorer kept warm.

A single :class:`ScanService` is created once (at daemon startup or first CLI
use) and reused for every PlanIR body, so the fastembed model and corpus
embeddings are loaded exactly once rather than per tool call.
"""

from __future__ import annotations

import threading

from sentrook.config import L3Policy
from sentrook.corpus.loader import load_corpus
from sentrook.corpus.models import LoadedRuleCorpus
from sentrook.layers.l3_embed import make_scorer
from sentrook.layers.l3_score import BiEncoderScorer
from sentrook.planir import PlanIR
from sentrook.result import ScanResult
from sentrook.rules.loader import load_rules
from sentrook.scan import scan_plan
from sentrook.serve.config import ServeConfig
from sentrook.serve.log import ScanLogRecord, append_scan_log, build_log_record


class ScanService:
    """Reusable scanner that keeps rules, corpus, and the L3 scorer warm."""

    def __init__(self, config: ServeConfig) -> None:
        self.config = config
        self.scanner_config = config.scanner_config()
        self.rules = load_rules(config.rules_path)
        self.corpus: dict[str, LoadedRuleCorpus] = (
            load_corpus(
                config.resolved_corpus_dir(),
                personal_corpus_dir=config.resolved_personal_corpus_dir(),
            )
            if self.scanner_config.l3_policy != L3Policy.OFF
            else {}
        )
        self.scorer: BiEncoderScorer | None = make_scorer(self.scanner_config)
        # Serialize scans: fastembed/onnx sessions are not guaranteed thread-safe,
        # and scans are fast enough that a lock is simpler than per-thread scorers.
        self._lock = threading.Lock()

    def warm(self) -> None:
        """Force the model + corpus embeddings to load before serving traffic."""
        if self.scorer is None:
            return
        for rule_corpus in self.corpus.values():
            self.scorer.warm_corpus(rule_corpus.pos)
            self.scorer.warm_corpus(rule_corpus.neg)

    def scan(self, plan: PlanIR) -> ScanResult:
        with self._lock:
            return scan_plan(
                plan,
                self.rules,
                self.scanner_config,
                plan_source=(f"serve:{plan.metadata.session_id or '?'}:{plan.run_id}"),
                rules_source=str(self.config.rules_path),
                corpus=self.corpus,
                l3_scorer=self.scorer,
            )

    def scan_and_log(self, plan: PlanIR) -> tuple[ScanResult, ScanLogRecord]:
        """Scan a PlanIR body and append a scan log line. Never raises on log I/O."""
        result = self.scan(plan)
        record = build_log_record(
            result,
            plan,
            mode=self.config.mode,
            bundle_version=self.config.bundle_version,
            sanitize_log_fields=self.config.server_sanitize_planir,
            log_content=self.config.log_content,
        )
        append_scan_log(
            self.config.log_path,
            record,
            log_content=self.config.log_content,
        )
        return result, record

    def reload(self) -> None:
        """Reload rules, corpus, and the L3 scorer from configured paths.

        **All or nothing.** Everything is built into locals first and published
        under the lock only once every step has succeeded. It used to assign
        `self.rules` before the corpus load that can raise, so a bundle whose
        rules parsed and whose corpus did not left the service running the new
        rules with the old corpus — while the caller saw an exception and the
        log said the reload failed. A rollback bundle removing a hard rule
        applied its removal that way, which is the fail-open the operator was
        being told had not happened.
        """
        from sentrook.serve.bundle import resolve_bundle_version

        rules = load_rules(self.config.rules_path)
        corpus_dir = self.config.resolved_corpus_dir()
        corpus = (
            load_corpus(
                corpus_dir,
                personal_corpus_dir=self.config.resolved_personal_corpus_dir(),
            )
            if self.scanner_config.l3_policy != L3Policy.OFF
            else {}
        )
        scorer = make_scorer(self.scanner_config)
        bundle_version = resolve_bundle_version(self.config.rules_path)
        if scorer is not None:
            # Warm before publishing: `warm_corpus` loads the encoder, so it is
            # the step most likely to fail, and it must not fail half-applied.
            for rule_corpus in corpus.values():
                scorer.warm_corpus(rule_corpus.pos)
                scorer.warm_corpus(rule_corpus.neg)

        with self._lock:
            self.rules = rules
            self.corpus = corpus
            self.scorer = scorer
            self.config.bundle_version = bundle_version
