"""Shared PlanIR scanner fixture paths and loaders.

Committed smoke plans live under fixtures/plans/. A full Rookery mirror (gitignored)
may also provide eval/plans/ after `make sync-library`. Prefer the mirror when
present so optional local regression can resolve the wider fixture set.
"""

from __future__ import annotations

import json
from pathlib import Path

from sentrook.planir import PlanIR

ROOT = Path(__file__).resolve().parents[3]
RULES = ROOT / "rules" if (ROOT / "rules").is_dir() else ROOT / "examples" / "rules"
_SMOKE_PLANS = ROOT / "fixtures" / "plans"
_MIRROR_PLANS = ROOT / "eval" / "plans"
PLAN_FIXTURES = _MIRROR_PLANS if _MIRROR_PLANS.is_dir() else _SMOKE_PLANS

# Smoke-only L2 fixtures committed in this repo. Full L2_DECISION_FIXTURES live in
# Rookery tests/engine/helpers/scan_fixtures.py against eval/plans.
L2_DECISION_FIXTURES: list[tuple[str, str]] = [
    ("safe_read_only.json", "allow"),
    ("web_fetch_exec_block.json", "block"),
    ("pending_exec.json", "review"),
]


def load_plan_fixture(name: str) -> PlanIR:
    path = PLAN_FIXTURES / name
    if not path.is_file() and PLAN_FIXTURES != _SMOKE_PLANS:
        path = _SMOKE_PLANS / name
    with path.open(encoding="utf-8") as handle:
        return PlanIR.model_validate(json.load(handle))
