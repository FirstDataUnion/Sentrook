"""Stateful shadow scanner: rules, corpus, and the L3 scorer kept warm.

A single :class:`ShadowScanner` is created once (at daemon startup or first CLI
use) and reused for every snapshot, so the fastembed model and corpus embeddings
are loaded exactly once rather than per tool call.
"""

from __future__ import annotations

import threading

from sentrook.config import L3Policy
from sentrook.corpus.loader import load_corpus
from sentrook.corpus.models import LoadedRuleCorpus
from sentrook.layers.l3_embed import make_scorer
from sentrook.layers.l3_score import BiEncoderScorer
from sentrook.result import ScanResult
from sentrook.rules.loader import load_rules
from sentrook.scan import scan_plan
from sentrook.shadow.config import ShadowConfig
from sentrook.shadow.log import ShadowLogRecord, append_shadow_log, build_log_record
from sentrook.shadow.snapshot import ShadowSnapshot


class ShadowScanner:
    """Reusable scanner that keeps rules, corpus, and the L3 scorer warm."""

    def __init__(self, config: ShadowConfig) -> None:
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

    def scan(self, snapshot: ShadowSnapshot) -> ScanResult:
        plan = snapshot.to_planir()
        with self._lock:
            return scan_plan(
                plan,
                self.rules,
                self.scanner_config,
                plan_source=f"shadow:{snapshot.session_id or '?'}:{snapshot.run_id}",
                rules_source=str(self.config.rules_path),
                corpus=self.corpus,
                l3_scorer=self.scorer,
            )

    def scan_and_log(self, snapshot: ShadowSnapshot) -> tuple[ScanResult, ShadowLogRecord]:
        """Scan a snapshot and append a shadow log line. Never raises on log I/O."""
        result = self.scan(snapshot)
        record = build_log_record(
            result,
            snapshot,
            mode=self.config.mode,
            bundle_version=self.config.bundle_version,
            sanitize_log_fields=self.config.server_sanitize_snapshots,
        )
        append_shadow_log(self.config.log_path, record)
        return result, record

    def reload(self) -> None:
        """Reload rules, corpus, and the L3 scorer from configured paths."""
        from sentrook.shadow.bundle import resolve_bundle_version

        with self._lock:
            self.rules = load_rules(self.config.rules_path)
            corpus_dir = self.config.resolved_corpus_dir()
            self.corpus = (
                load_corpus(
                    corpus_dir,
                    personal_corpus_dir=self.config.resolved_personal_corpus_dir(),
                )
                if self.scanner_config.l3_policy != L3Policy.OFF
                else {}
            )
            self.scorer = make_scorer(self.scanner_config)
            self.config.bundle_version = resolve_bundle_version(self.config.rules_path)
            if self.scorer is not None:
                for rule_corpus in self.corpus.values():
                    self.scorer.warm_corpus(rule_corpus.pos)
                    self.scorer.warm_corpus(rule_corpus.neg)
