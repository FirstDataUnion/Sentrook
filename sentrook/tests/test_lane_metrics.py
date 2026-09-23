"""§5.2's lane and parser-coverage series, and the one definition behind them.

The lane series and the fatigue report's three-lane counterfactual are the
same question asked live and asked over a log. They were not the same answer:
the report carried its own approximation of the read-only families, written
before they existed, and it drifted. Both now call `classify_lane`.
"""

from __future__ import annotations

import pytest
from prometheus_client import generate_latest

from sentrook.config import L3Policy
from sentrook.planir import PlanIR
from sentrook.serve.lanes import SCANNER_LANES, classify_lane
from sentrook.serve.metrics import REGISTRY


def _plan(command: str) -> PlanIR:
    return PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "r-lane",
            "intent": "run a command",
            "intent_kind": "user",
            "steps": [
                {"id": "s1", "tool": "exec", "status": "pending", "args": {"command": command}}
            ],
            "metadata": {"adapter": "fixture", "hook": "before_tool_call"},
        }
    )


@pytest.mark.parametrize(
    ("matched", "expected"),
    [
        pytest.param(["AIRA-010"], "unknown", id="only the catch-all"),
        pytest.param(["AIRA-010", "AIRA-901"], "generic_safe", id="a family covered it"),
        pytest.param(["AIRA-010", "AIRA-083"], "consequence", id="a rule named the consequence"),
        # Precedence runs the other way from intuition: a family matching
        # *alongside* a consequence rule means it did not suppress it, which
        # is the family declining rather than covering.
        pytest.param(
            ["AIRA-010", "AIRA-083", "AIRA-902"], "consequence", id="family declined, not covered"
        ),
        pytest.param([], "unknown", id="nothing matched"),
    ],
)
def test_the_lane_is_read_off_what_matched(matched: list[str], expected: str) -> None:
    assert classify_lane(matched) == expected
    assert expected in SCANNER_LANES


def test_a_row_without_argv_is_unclassifiable_not_uncovered() -> None:
    """Folding it into `unknown` would inflate the "needs new coverage"
    figure and understate every lane's share."""
    assert classify_lane(["AIRA-010"], has_argv=False) == "no_argv"


def test_the_lanes_a_scan_can_see_exclude_the_plugin_side_ones() -> None:
    """`host_allowlist` and `script_bind` are decided in the plugin *after*
    the scan returns, so a scan-time metric cannot see them.

    Naming them here would produce a series that is always zero and read as
    "no review was ever waived by the host allowlist", which is the opposite
    of unknown.
    """
    assert "host_allowlist" not in SCANNER_LANES
    assert "script_bind" not in SCANNER_LANES


def test_the_lane_series_is_emitted_by_the_serve_path(tmp_path) -> None:
    """Through `ServeRuntime.scan_and_log`, not the metric function.

    F43, three times in this programme: a new counter is joined by a call
    site nothing exercises and the series reads zero forever. Reading the
    counter's declaration tells you nothing about whether anything calls it —
    that is exactly how §5.2's first series turned out to be unemittable.
    """

    from sentrook.serve.config import ServeConfig
    from sentrook.serve.runtime import ServeRuntime

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "AIRA-010.yaml").write_text(
        "rule: AIRA-010\n"
        "meta:\n  name: catch-all\n  action: review\n  authority: soft\n"
        "condition:\n  pending_tool: exec\n",
        encoding="utf-8",
    )
    runtime = ServeRuntime(
        ServeConfig(
            mode="observe",
            rules_path=rules_dir,
            corpus_dir=tmp_path / "corpus",
            log_path=tmp_path / "scan.log.jsonl",
            latency_log_path=tmp_path / "latency.log.jsonl",
            l3_policy=L3Policy.OFF,
            oidc_issuer="",
            scan_auth_mode="auto",
            scan_api_key=None,
        )
    )
    runtime.scan_and_log(_plan("pytest -q"))

    exported = generate_latest(REGISTRY).decode("utf-8")
    assert 'sentrook_scan_lane_total{lane="unknown"}' in exported
    assert 'sentrook_scan_exec_shape_total{packed="false",parse_ok="true"}' in exported
