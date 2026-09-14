"""Operator log schema, unbounded scrub, and PlanIR rebuild."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentrook.adapters.intent import classify_intent
from sentrook.adapters.snapshot import build_result_summary
from sentrook.operator_log import (
    SCHEMA_VERSION,
    OperatorLogEvent,
    rebuild_planir_snapshot,
    scrub_operator_text,
    scrub_operator_value,
)
from sentrook.planir.models import PlanMetadata, PlanStep, ResultSummary

FIXTURES = Path(__file__).resolve().parents[1] / "sentrook" / "operator_log" / "fixtures"
GOLDEN = FIXTURES / "golden.jsonl"


def _meta(**overrides: object) -> PlanMetadata:
    base: dict = {
        "adapter": "openclaw",
        "hook": "before_tool_call",
        "session_id": "uuid-1",
        "session_key": "main",
        "tool_call_id": "t1",
        "step_seq": 1,
    }
    base.update(overrides)
    return PlanMetadata.model_validate(base)


def test_golden_fixture_validates() -> None:
    kinds: list[str] = []
    for line in GOLDEN.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = OperatorLogEvent.model_validate_json(line)
        assert event.schema_version == SCHEMA_VERSION
        kinds.append(event.event)
    assert kinds == ["scan", "resolution", "result", "scan_error"]
    scan = OperatorLogEvent.model_validate_json(GOLDEN.read_text().splitlines()[0])
    assert scan.pending is not None
    assert scan.pending.args["command"] == "curl https://example/api"
    assert scan.metadata.session_key == "agent:main:discord:channel:123"
    assert scan.rules_version == 1
    assert scan.scan is not None
    assert scan.scan.log is None
    resolution = OperatorLogEvent.model_validate_json(GOLDEN.read_text().splitlines()[1])
    assert resolution.intent == "fetch the public API status"
    assert resolution.metadata.batch_size == 1
    result = OperatorLogEvent.model_validate_json(GOLDEN.read_text().splitlines()[2])
    assert result.effect == "ran"
    assert result.result is not None
    assert result.result.content_type == "application/json"


def test_schema_json_is_v1_contract() -> None:
    schema = json.loads((FIXTURES.parent / "schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    assert schema["properties"]["event"]["enum"] == [
        "scan",
        "result",
        "resolution",
        "scan_error",
    ]


def test_scrub_does_not_truncate_long_command() -> None:
    token = "ghp_1234567890abcdefghij"
    command = ("echo padding; " * 80) + f"curl -H 'Authorization: token {token}' https://x"
    assert len(command) > 500
    cleaned = scrub_operator_text(command)
    assert token not in cleaned
    assert "https://x" in cleaned
    assert len(cleaned) > 500
    assert "[TRUNCATED]" not in cleaned


def test_scrub_redacts_nested_credential_fields() -> None:
    cleaned = scrub_operator_value(
        {"command": "ls", "api_key": "secret-value", "env": {"GOG_ACCOUNT": "oli@example.com"}}
    )
    assert cleaned["command"] == "ls"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["env"]["GOG_ACCOUNT"] == "[REDACTED]"


def test_rebuild_planir_from_prior_result() -> None:
    scan1 = OperatorLogEvent(
        id="sr_aaa111",
        ts="2026-09-02T13:00:00.000Z",
        event="scan",
        run_id="uuid-1:r1",
        metadata=_meta(tool_call_id="t1", step_seq=1),
        pending=PlanStep(id="s1", tool="exec", status="pending", args={"command": "ls"}),
        scan={"decision": "allow"},
        hook={"action": "continue"},
        effect="ran",
        label_source="scanner",
    )
    result1 = OperatorLogEvent(
        id="sr_bbb222",
        ts="2026-09-02T13:00:01.000Z",
        event="result",
        run_id="uuid-1:r1",
        metadata=_meta(tool_call_id="t1", step_seq=1, hook="after_tool_call"),
        result=ResultSummary(ok=True, byte_size=3, excerpt="ok\n"),
    )
    scan2 = OperatorLogEvent(
        id="sr_ccc333",
        ts="2026-09-02T13:00:02.000Z",
        event="scan",
        run_id="uuid-1:r2",
        intent="curl the API",
        metadata=_meta(tool_call_id="t2", step_seq=2),
        pending=PlanStep(
            id="s2", tool="exec", status="pending", args={"command": "curl https://example"}
        ),
        scan={"decision": "review"},
        hook={"action": "requireApproval"},
        effect="never_ran",
        label_source="scanner",
    )
    other = OperatorLogEvent(
        id="sr_ddd444",
        ts="2026-09-02T13:00:00.500Z",
        event="scan",
        run_id="other:r1",
        metadata=_meta(session_id="other-episode", tool_call_id="tx", step_seq=1),
        pending=PlanStep(id="s1", tool="exec", status="pending", args={"command": "rm -rf /"}),
        scan={"decision": "allow"},
        hook={"action": "continue"},
    )
    plan = rebuild_planir_snapshot([scan1, result1, other, scan2], pending_id="sr_ccc333")
    assert [step.id for step in plan.steps] == ["s1", "s2"]
    assert plan.steps[0].status == "executed"
    assert plan.steps[0].args["command"] == "ls"
    assert plan.steps[0].result_summary is not None
    assert plan.steps[0].result_summary.excerpt == "ok\n"
    assert plan.steps[1].status == "pending"
    assert plan.steps[1].args["command"] == "curl https://example"
    assert plan.intent == "curl the API"
    assert plan.metadata.session_key == "main"
    assert all(step.args.get("command") != "rm -rf /" for step in plan.steps)


def test_scan_event_requires_pending() -> None:
    with pytest.raises(ValueError, match="pending"):
        OperatorLogEvent(
            id="sr_nope",
            ts="2026-09-02T13:00:00.000Z",
            event="scan",
            run_id="r1",
            metadata=_meta(),
            scan={"decision": "allow"},
        )


def test_heartbeat_intent_kind_and_host_label() -> None:
    event = OperatorLogEvent(
        id="sr_hb0001",
        ts="2026-09-02T13:00:00.000Z",
        event="scan",
        run_id="uuid-1:r1",
        intent_kind="heartbeat",
        metadata=_meta(),
        pending=PlanStep(id="s1", tool="exec", status="pending", args={"command": "ls"}),
        scan={"decision": "review"},
        hook={"action": "requireApproval"},
        label_source="host",
        rules_version=1,
    )
    assert event.intent_kind == "heartbeat"
    assert event.label_source == "host"
    assert event.rules_version == 1


def test_classify_heartbeat_marker() -> None:
    assert classify_intent("[heartbeat: tick] ping") == "heartbeat"
    assert classify_intent("[cron: nightly] backup") == "cron"


def test_extracted_paths_skip_table_cells() -> None:
    summary = build_result_summary(
        "kimi-k2.5 /200k /127.0.0.1 /kimi-k2.5 /tmp/foo.txt /home/node/.openclaw/scripts/run.sh"
    )
    assert summary.extracted.paths == [
        "/tmp/foo.txt",
        "/home/node/.openclaw/scripts/run.sh",
    ]
