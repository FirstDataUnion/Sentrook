"""Convert PlanIR fixtures into sentrook.shadow.snapshot/v1 for ingress-path tests."""

from __future__ import annotations

from sentrook.planir import PlanIR
from sentrook.shadow.snapshot import ShadowCall, ShadowResult, ShadowSnapshot


def planir_to_shadow_snapshot(plan: PlanIR) -> ShadowSnapshot:
    """Approximate the live wire shape from an offline PlanIR fixture.

  PlanIR fixtures may carry precomputed ``result_summary`` fields (e.g.
  ``injection_markers``) that are rebuilt from ``result.text`` on
  ``ShadowSnapshot.to_planir()``. Callers comparing matched-rule sets on
  poison/ingest scenarios should assert decision parity only.
  """
    executed: list[ShadowCall] = []
    co_pending: list[ShadowCall] = []
    pending_step = None

    for step in plan.steps:
        if step.status == "executed":
            result = None
            if step.result_summary is not None:
                result = ShadowResult(
                    ok=step.result_summary.ok,
                    text=step.result_summary.excerpt or "",
                )
            executed.append(
                ShadowCall(tool=step.tool, args=dict(step.args), result=result)
            )
        elif step.status == "pending":
            if pending_step is not None:
                co_pending.append(
                    ShadowCall(tool=pending_step.tool, args=dict(pending_step.args))
                )
            pending_step = step

    if pending_step is None:
        msg = f"plan {plan.run_id!r} has no pending step"
        raise ValueError(msg)

    meta = plan.metadata
    return ShadowSnapshot(
        adapter=meta.adapter or "openclaw",
        session_id=meta.session_id,
        agent_id=meta.agent_id,
        run_id=plan.run_id,
        intent=plan.intent,
        intent_kind=plan.intent_kind,
        executed=executed,
        co_pending=co_pending,
        pending=ShadowCall(tool=pending_step.tool, args=dict(pending_step.args)),
        tool_call_id=getattr(meta, "tool_call_id", None),
        step_seq=getattr(meta, "step_seq", None),
        batch_size=getattr(meta, "batch_size", None),
    )
