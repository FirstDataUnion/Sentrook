from __future__ import annotations

from pathlib import Path

import yaml

from testnest.models import Scenario, SuiteConfig, SuitesFile


def load_scenarios(scenarios_dir: Path) -> list[Scenario]:
    scenarios: list[Scenario] = []
    for path in sorted(scenarios_dir.rglob("*.yaml")):
        if path.name in {"suites.yaml", "profiles.yaml"}:
            continue
        with path.open(encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
        if not raw:
            continue
        scenario = Scenario.model_validate(raw)
        scenarios.append(scenario)
    return scenarios


def load_suites(scenarios_dir: Path) -> dict[str, SuiteConfig]:
    suites_path = scenarios_dir / "suites.yaml"
    if not suites_path.is_file():
        return {
            "core": SuiteConfig(description="Seed rule coverage", tags=["core"]),
            "ambiguous": SuiteConfig(
                description="Ambiguous / L3-target cases", tags=["ambiguous"]
            ),
            "all": SuiteConfig(description="Every scenario", tags=[]),
        }
    with suites_path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    return SuitesFile.model_validate(raw).suites


def filter_scenarios(
    scenarios: list[Scenario],
    *,
    suite: str | None,
    tags: list[str] | None,
    suites: dict[str, SuiteConfig],
) -> list[Scenario]:
    if tags:
        tag_set = set(tags)
        return [s for s in scenarios if tag_set.intersection(s.tags)]

    if not suite or suite == "all":
        suite_cfg = suites.get("all", SuiteConfig())
        if suite_cfg.tags:
            tag_set = set(suite_cfg.tags)
            return [s for s in scenarios if tag_set.intersection(s.tags)]
        if suite_cfg.include:
            names = set(suite_cfg.include)
            return [s for s in scenarios if s.name in names]
        return scenarios

    suite_cfg = suites.get(suite)
    if suite_cfg is None:
        msg = f"unknown suite {suite!r}; available: {', '.join(sorted(suites))}"
        raise ValueError(msg)

    if suite_cfg.include:
        names = set(suite_cfg.include)
        filtered = [s for s in scenarios if s.name in names]
    elif suite_cfg.tags:
        tag_set = set(suite_cfg.tags)
        filtered = [s for s in scenarios if tag_set.intersection(s.tags)]
    else:
        filtered = scenarios
    return filtered
