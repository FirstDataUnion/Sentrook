from __future__ import annotations

from pathlib import Path

from sentrook.planir import PlanIR
from sentrook.subgraph import (
    SubgraphStrategy,
    extract_subgraph,
    subgraph_to_text,
)

ROOT = Path(__file__).resolve().parents[2]
PLANS = ROOT / "fixtures" / "plans"


def test_subgraph_pending_window():
    plan = PlanIR.model_validate_json(
        (PLANS / "web_fetch_exec_block.json").read_text(encoding="utf-8")
    )
    subgraph = extract_subgraph(plan, strategy=SubgraphStrategy.PENDING_WINDOW)
    assert subgraph is not None
    assert len(subgraph.steps) == 2
    text = subgraph_to_text(subgraph, intent=plan.intent)
    assert "intent:" in text
    assert "command:" in text
    assert "web_fetch(executed)" in text
