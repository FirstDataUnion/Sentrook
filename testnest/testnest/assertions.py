from __future__ import annotations

from dataclasses import dataclass, field

from testnest.models import ProfileExpectation, RiskExpectation
from sentrook.result import ScanResult


@dataclass
class AssertionFailure:
    field: str
    expected: str
    actual: str


@dataclass
class AssertionResult:
    passed: bool
    failures: list[AssertionFailure] = field(default_factory=list)


def check_expectation(
    result: ScanResult, expectation: ProfileExpectation
) -> AssertionResult:
    failures: list[AssertionFailure] = []

    if result.decision != expectation.decision:
        failures.append(
            AssertionFailure(
                "decision",
                expectation.decision or "",
                result.decision,
            )
        )

    actual_rules = [m.id for m in result.matched_rules]
    if expectation.matched_rules:
        if expectation.matched_rules_mode == "exact":
            if actual_rules != expectation.matched_rules:
                failures.append(
                    AssertionFailure(
                        "matched_rules",
                        str(expectation.matched_rules),
                        str(actual_rules),
                    )
                )
        else:
            missing = set(expectation.matched_rules) - set(actual_rules)
            if missing:
                failures.append(
                    AssertionFailure(
                        "matched_rules",
                        f"contains {sorted(missing)}",
                        str(actual_rules),
                    )
                )

    if expectation.layer_exits and result.layers.exits != expectation.layer_exits:
        failures.append(
            AssertionFailure(
                "layer_exits",
                str(expectation.layer_exits),
                str(result.layers.exits),
            )
        )

    if expectation.l3_required is True and "L3" not in result.layers.exits:
        failures.append(
            AssertionFailure(
                "l3_required",
                "L3 in layer_exits",
                str(result.layers.exits),
            )
        )

    if expectation.risk is not None:
        if not _risk_matches(result.risk, expectation.risk):
            failures.append(
                AssertionFailure(
                    "risk",
                    str(expectation.risk),
                    str(result.risk),
                )
            )

    if expectation.summary_contains:
        if expectation.summary_contains not in result.summary:
            failures.append(
                AssertionFailure(
                    "summary",
                    f"contains {expectation.summary_contains!r}",
                    result.summary,
                )
            )

    if expectation.l1_candidates:
        actual = result.debug.l1_candidate_ids
        if expectation.l1_candidates_mode == "exact":
            if actual != expectation.l1_candidates:
                failures.append(
                    AssertionFailure(
                        "l1_candidates",
                        str(expectation.l1_candidates),
                        str(actual),
                    )
                )
        else:
            missing = set(expectation.l1_candidates) - set(actual)
            if missing:
                failures.append(
                    AssertionFailure(
                        "l1_candidates",
                        f"contains {sorted(missing)}",
                        str(actual),
                    )
                )

    return AssertionResult(passed=not failures, failures=failures)


def _risk_matches(actual: float, expected: float | RiskExpectation) -> bool:
    if isinstance(expected, RiskExpectation):
        if expected.exact is not None:
            return actual == expected.exact
        if expected.min is not None and actual < expected.min:
            return False
        if expected.max is not None and actual > expected.max:
            return False
        return True
    return actual == expected
