from __future__ import annotations

from pathlib import Path

import yaml

from sentrook.rules.compiler import compile_rule
from sentrook.rules.models import Rule

DEFAULT_RULES_DIR = Path.home() / ".sentrook" / "rules"


def resolve_rules_dir() -> Path:
    """Resolve the default rules directory.

    Prefers checkout ``rules/`` (Rookery / synced library), then ``examples/rules``
    (Sentrook demo), then ``~/.sentrook/rules/``.
    """
    root = Path(__file__).resolve().parents[3]
    for candidate in (root / "rules", root / "examples" / "rules"):
        if candidate.is_dir():
            return candidate.resolve()
    return DEFAULT_RULES_DIR


def load_rules(path: Path) -> list[Rule]:
    if path.is_file():
        return [_load_file(path)]
    if not path.is_dir():
        raise FileNotFoundError(f"Rules path not found: {path}")

    rules: list[Rule] = []
    for file in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
        rules.append(_load_file(file))
    return rules


def _load_file(path: Path) -> Rule:
    with path.open(encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict):
        raise ValueError(f"Invalid rule file (expected mapping): {path}")
    return compile_rule(doc, source_path=str(path))
