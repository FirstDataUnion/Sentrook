from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class RiskExpectation(BaseModel):
    min: float | None = None
    max: float | None = None
    exact: float | None = None

    @model_validator(mode="after")
    def _has_constraint(self) -> RiskExpectation:
        if self.exact is None and self.min is None and self.max is None:
            raise ValueError("risk expectation needs exact, min, and/or max")
        return self


class ProfileExpectation(BaseModel):
    decision: Literal["allow", "review", "block"] | None = None
    matched_rules: list[str] = Field(default_factory=list)
    matched_rules_mode: Literal["contains", "exact"] = "contains"
    layer_exits: list[str] = Field(default_factory=list)
    risk: float | RiskExpectation | None = None
    summary_contains: str | None = None
    l1_candidates: list[str] = Field(default_factory=list)
    l1_candidates_mode: Literal["contains", "exact"] = "contains"
    skip: bool = False
    skip_reason: str | None = None
    xfail: bool = False
    xfail_reason: str | None = None
    l3_required: bool | None = None

    @model_validator(mode="after")
    def _actionable_or_skipped(self) -> ProfileExpectation:
        if self.skip or self.xfail:
            return self
        if self.decision is None:
            raise ValueError("profile expectation needs decision unless skip or xfail")
        return self


class Scenario(BaseModel):
    name: str
    description: str = ""
    plan: str
    tags: list[str] = Field(default_factory=list)
    profiles: dict[str, ProfileExpectation] = Field(default_factory=dict)

    def plan_path(self, scenarios_dir: Any) -> Any:
        from pathlib import Path

        base = Path(scenarios_dir)
        path = Path(self.plan)
        if path.is_absolute():
            return path
        return (base / path).resolve()

    def expectation_for(self, profile: str) -> ProfileExpectation | None:
        return self.profiles.get(profile)


class SuiteConfig(BaseModel):
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)


class SuitesFile(BaseModel):
    suites: dict[str, SuiteConfig] = Field(default_factory=dict)
