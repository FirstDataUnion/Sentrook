"""Unit tests for scripts/library_push.py diff helpers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from sentrook.corpus.models import CorpusExample, CorpusStep

ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = ROOT / "scripts" / "library_push.py"
_spec = importlib.util.spec_from_file_location("library_push", _SCRIPT)
assert _spec and _spec.loader
library_push = importlib.util.module_from_spec(_spec)
sys.modules["library_push"] = library_push
_spec.loader.exec_module(library_push)


def _example(example_id: str, *, tool: str = "exec") -> CorpusExample:
    return CorpusExample(
        id=example_id,
        label="benign",
        trust="verified",
        intent="check status",
        steps=[
            CorpusStep(
                tool=tool,
                status="pending",
                args={"command": "ls"},
            )
        ],
    )


def test_diff_corpus_flags_missing_local_examples_for_push():
    local = {("AIRA-010", "neg-new"): _example("neg-new")}
    remote: dict[tuple[str, str], CorpusExample] = {}
    report = library_push.diff_corpus(
        local,
        remote,
        known_rule_ids={"AIRA-010"},
    )
    assert len(report.to_push) == 1
    assert report.to_push[0].example_id == "neg-new"


def test_diff_corpus_skips_matching_examples():
    example = _example("neg-same")
    key = ("AIRA-010", "neg-same")
    report = library_push.diff_corpus(
        {key: example},
        {key: example},
        known_rule_ids={"AIRA-010"},
    )
    assert report.to_push == []
    assert all(row.action == "skip_exists" for row in report.examples)


def test_diff_corpus_reports_content_conflicts():
    local = {("AIRA-010", "neg-x"): _example("neg-x", tool="exec")}
    remote = {("AIRA-010", "neg-x"): _example("neg-x", tool="read")}
    report = library_push.diff_corpus(
        local,
        remote,
        known_rule_ids={"AIRA-010"},
    )
    assert len(report.conflicts) == 1
    assert report.to_push == []


def test_diff_corpus_keeps_remote_only_rows():
    remote = {("AIRA-058", "neg-remote"): _example("neg-remote")}
    report = library_push.diff_corpus(
        {},
        remote,
        known_rule_ids={"AIRA-058"},
    )
    assert report.remote_only == [("AIRA-058", "neg-remote")]


def test_diff_corpus_skips_unknown_rules():
    local = {("AIRA-999", "neg-new"): _example("neg-new")}
    report = library_push.diff_corpus(
        local,
        {},
        known_rule_ids={"AIRA-010"},
    )
    assert report.to_push == []
    assert report.examples[0].action == "skip_unknown_rule"
