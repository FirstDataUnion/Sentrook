from __future__ import annotations

from pathlib import Path

import yaml

from sentrook.corpus.models import (
    LABEL_TO_INDEX,
    CorpusEntry,
    CorpusExample,
    LoadedRuleCorpus,
    RuleCorpus,
)
from sentrook.planir import PlanStep, ResultSummary
from sentrook.result import MatchedSubgraph
from sentrook.subgraph import subgraph_to_text


def resolve_corpus_dir(configured: str | Path) -> Path:
    """Resolve the corpus directory for scans.

    Tries the configured path first, then the repo checkout ``corpus/`` (for dev),
    then ``~/.sentrook/corpus/``. Returns the configured path when none exist so
    :func:`load_corpus` can treat a missing directory as an empty corpus.
    """
    path = Path(configured).expanduser()
    if path.is_dir():
        return path.resolve()

    root = Path(__file__).resolve().parents[3]
    for candidate in (root / "corpus", root / "examples" / "corpus"):
        if candidate.is_dir():
            return candidate.resolve()

    home = Path.home() / ".sentrook" / "corpus"
    if home.is_dir():
        return home.resolve()

    return path


def default_corpus_dir() -> Path:
    """Resolve the corpus directory from the default L3 configuration."""
    from sentrook.config import L3Config

    return resolve_corpus_dir(L3Config().corpus_dir)


def merge_loaded_rule_corpus(
    base: LoadedRuleCorpus,
    overlay: LoadedRuleCorpus,
) -> LoadedRuleCorpus:
    """Merge personal/overlay examples into a base rule corpus (dedupe by id)."""
    if base.rule_id != overlay.rule_id:
        raise ValueError(
            f"Cannot merge corpus for {overlay.rule_id!r} into {base.rule_id!r}"
        )

    seen_pos = {entry.example_id for entry in base.pos}
    seen_neg = {entry.example_id for entry in base.neg}
    pos = list(base.pos)
    neg = list(base.neg)
    for entry in overlay.pos:
        if entry.example_id in seen_pos:
            continue
        pos.append(entry)
        seen_pos.add(entry.example_id)
    for entry in overlay.neg:
        if entry.example_id in seen_neg:
            continue
        neg.append(entry)
        seen_neg.add(entry.example_id)

    return LoadedRuleCorpus(
        rule_id=base.rule_id,
        allow_margin=base.allow_margin,
        fail_closed_margin=base.fail_closed_margin,
        pos=pos,
        neg=neg,
    )


def load_corpus(
    corpus_dir: Path,
    *,
    personal_corpus_dir: Path | None = None,
) -> dict[str, LoadedRuleCorpus]:
    """Load every ``<RULE_ID>.yaml`` under ``corpus_dir`` keyed by rule id.

    When ``personal_corpus_dir`` is set and exists, examples from that directory
    are merged into the loaded corpus (personal examples append; thresholds stay
    on the base bundle file).

    Returns an empty mapping when the directory does not exist so callers can
    treat "no corpus" the same as "insufficient corpus" without special-casing.
    """
    corpus_dir = corpus_dir.expanduser()
    if not corpus_dir.is_dir():
        loaded: dict[str, LoadedRuleCorpus] = {}
    else:
        loaded = {}
        for file in sorted(corpus_dir.glob("*.yaml")) + sorted(corpus_dir.glob("*.yml")):
            rule_corpus = load_rule_corpus(file)
            loaded[rule_corpus.rule_id] = rule_corpus

    if personal_corpus_dir is not None:
        personal_corpus_dir = personal_corpus_dir.expanduser()
        if personal_corpus_dir.is_dir():
            for file in sorted(personal_corpus_dir.glob("*.yaml")) + sorted(
                personal_corpus_dir.glob("*.yml")
            ):
                personal_rule = load_rule_corpus(file)
                if personal_rule.rule_id in loaded:
                    loaded[personal_rule.rule_id] = merge_loaded_rule_corpus(
                        loaded[personal_rule.rule_id],
                        personal_rule,
                    )
                else:
                    loaded[personal_rule.rule_id] = personal_rule

    return loaded


def load_rule_corpus(path: Path) -> LoadedRuleCorpus:
    """Parse and validate one corpus file, pre-serializing each example's text."""
    with path.open(encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict):
        raise ValueError(f"Invalid corpus file (expected mapping): {path}")

    spec = RuleCorpus.model_validate(doc)

    pos: list[CorpusEntry] = []
    neg: list[CorpusEntry] = []
    for example in spec.examples:
        entry = _build_entry(example)
        (pos if entry.label == "pos" else neg).append(entry)

    return LoadedRuleCorpus(
        rule_id=spec.rule_id,
        allow_margin=spec.thresholds.allow_margin if spec.thresholds else None,
        fail_closed_margin=(
            spec.thresholds.fail_closed_margin if spec.thresholds else None
        ),
        pos=pos,
        neg=neg,
    )


def _build_entry(example: CorpusExample) -> CorpusEntry:
    """Turn a corpus example into a subgraph + canonical embed text.

    Step IDs are assigned ``s1``, ``s2``, … in order so the serialization aligns
    with live PlanIR fixtures, which use the same convention.
    """
    steps: list[PlanStep] = []
    for index, step in enumerate(example.steps, start=1):
        result_summary = (
            ResultSummary(ok=True, excerpt=step.excerpt)
            if step.excerpt is not None
            else None
        )
        steps.append(
            PlanStep(
                id=f"s{index}",
                tool=step.tool,
                status=step.status,
                args=step.args,
                result_summary=result_summary,
            )
        )

    subgraph = MatchedSubgraph(
        step_ids=[s.id for s in steps],
        tools=[s.tool for s in steps],
        steps=steps,
    )
    text = subgraph_to_text(
        subgraph, intent=example.intent, intent_kind=example.intent_kind
    )

    return CorpusEntry(
        example_id=example.id,
        label=LABEL_TO_INDEX[example.label],
        trust=example.trust,
        text=text,
        subgraph=subgraph,
    )
