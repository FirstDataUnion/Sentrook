"""Agent-agnostic PlanIR snapshot assembly.

A *snapshot* is one ``before_tool_call`` moment: an ordered list of executed tool
calls plus the single pending call the host is about to run. Both the OpenClaw
replay adapter and any live host adapter build snapshots through these helpers so
that the same trajectory yields identical PlanIR regardless of how the host
captured it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sentrook.planir import (
    PlanIR,
    PlanMetadata,
    PlanStep,
    ResultSummary,
    ResultSummaryExtracted,
    ResultSummaryFlags,
    canonicalize_tool_args,
)
from sentrook.planir.models import IntentKind
from sentrook.redact import redact_args

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_PATH_RE = re.compile(r"(?:/[\w.\-]+)+")
# Indirect-prompt-injection and poison-steering markers in ingested tool output.
# L2's cheap, high-precision net for AIRA-065: override phrasing, role-injection
# tokens, and imperative exfil steering without override tokens (AST05 transitive
# chain). Subtler payload-shaped poison (curl|bash, authorized_keys writes) stays
# with extraction rules. L3 calibrates soft review once this flag fires. Derived
# here so live (wire) and offline replay compute the same flag from the same text.
_INJECTION_MARKERS = re.compile(
    r"(?:"
    r"ignore (?:all |the |your )?(?:previous|prior|above|earlier)\b"
    r"|ignore (?:all |the |your )?safety\b"
    r"|(?:system|admin|developer)\s+override"
    r"|disregard (?:all |the |your )?(?:previous|prior|above|earlier|safety)"
    r"|system prompt|</s>|<\|im_start\|>"
    r"|exfiltrat"
    r"|upload\s+\S*(?:auth-profiles|openclaw-agent\.sqlite|database\.sqlite|credentials|secrets|\.ssh)\S*\s+to\s+https?://"
    r"|(?:important|mandatory|required)\s*:\s*before\b.{0,60}\b(?:upload|send|post|transmit)\b"
    r")",
    re.IGNORECASE,
)

_EXCERPT_LIMIT = 500
_EXTRACTED_LIMIT = 20


@dataclass
class SnapshotCall:
    """One tool call in a trajectory, host-normalized but not yet PlanIR.

    ``args`` are raw adapter args; canonicalization and redaction happen when the
    call is turned into a :class:`PlanStep`. ``result_summary`` is only meaningful
    for executed calls.
    """

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    result_summary: ResultSummary | None = None


def make_plan_step(
    step_id: str,
    tool: str,
    args: dict[str, Any],
    status: str,
    result_summary: ResultSummary | None = None,
) -> PlanStep:
    """Build a PlanStep with canonicalized + redacted args (adapter contract)."""
    return PlanStep(
        id=step_id,
        tool=tool,
        status=status,  # type: ignore[arg-type]
        args=redact_args(canonicalize_tool_args(tool, args)),
        result_summary=result_summary,
    )


def build_result_summary(
    text: str,
    *,
    ok: bool = True,
    content_type: str | None = None,
    command: str | None = None,
) -> ResultSummary:
    """Summarize a tool result body into the PlanIR ``ResultSummary`` shape.

    Extraction (URLs, paths, commands, injection markers, truncation) is identical
    for replay and live hosts so Layer 2/3 see the same signals either way.
    """
    text = text or ""
    byte_size = len(text.encode("utf-8"))
    excerpt = text[:_EXCERPT_LIMIT]
    truncated = len(text) > _EXCERPT_LIMIT

    urls = list(dict.fromkeys(_URL_RE.findall(text)))[:_EXTRACTED_LIMIT]
    paths = list(dict.fromkeys(_PATH_RE.findall(text)))[:_EXTRACTED_LIMIT]
    commands = [str(command)] if command else []

    return ResultSummary(
        ok=ok,
        content_type=content_type,
        byte_size=byte_size,
        excerpt=excerpt,
        extracted=ResultSummaryExtracted(urls=urls, paths=paths, commands=commands),
        flags=ResultSummaryFlags(
            truncated=truncated,
            injection_markers=bool(_INJECTION_MARKERS.search(text)),
        ),
    )


def primary_pending_step(plan: PlanIR) -> PlanStep | None:
    """Return the pending step under scan (last pending in trajectory order).

    When parallel tool calls are co-pending in the same batch, earlier peers are
    also ``pending`` in PlanIR; the host's active call is always the final one.
    """
    pending = [s for s in plan.steps if s.status == "pending"]
    return pending[-1] if pending else None


def build_planir_snapshot(
    *,
    executed: list[SnapshotCall],
    pending: SnapshotCall,
    co_pending: list[SnapshotCall] | None = None,
    run_id: str,
    intent: str | None = None,
    intent_kind: IntentKind | None = None,
    session_id: str | None = None,
    agent_id: str | None = "main",
    adapter: str = "fixture",
    hook: str = "before_tool_call",
    tool_call_id: str | None = None,
    step_seq: int | None = None,
    batch_size: int | None = None,
) -> PlanIR:
    """Assemble a rolling ``before_tool_call`` PlanIR from a trajectory.

    Steps are numbered ``s1``, ``s2``, … in order: executed history, optional
    co-pending batch peers, then the primary pending call (always last). Parallel
    hosts emit one snapshot per call with siblings as ``co_pending`` so replay and
    live see the same tool set without serializing intra-batch execution.
    """
    co_pending = co_pending or []
    steps: list[PlanStep] = []
    index = 1
    for call in executed:
        steps.append(
            make_plan_step(
                f"s{index}",
                call.tool,
                call.args,
                "executed",
                call.result_summary,
            )
        )
        index += 1
    for call in co_pending:
        steps.append(make_plan_step(f"s{index}", call.tool, call.args, "pending"))
        index += 1
    steps.append(make_plan_step(f"s{index}", pending.tool, pending.args, "pending"))

    return PlanIR(
        run_id=run_id,
        intent=intent,
        intent_kind=intent_kind,
        steps=steps,
        metadata=PlanMetadata(
            adapter=adapter,
            agent_id=agent_id,
            session_id=session_id,
            hook=hook,
            tool_call_id=tool_call_id,
            step_seq=step_seq,
            batch_size=batch_size,
        ),
    )
