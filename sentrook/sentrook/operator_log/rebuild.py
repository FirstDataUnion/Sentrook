"""Rebuild a PlanIR snapshot from operator-log scan + result lines."""

from __future__ import annotations

from sentrook.adapters.snapshot import SnapshotCall, build_planir_snapshot
from sentrook.operator_log.models import OperatorLogEvent
from sentrook.planir.models import PlanIR, PlanStep

MAX_TRAJECTORY = 200


def _join_key(event: OperatorLogEvent) -> tuple[str, str, int | None]:
    tool_call_id = event.metadata.tool_call_id or ""
    return (event.run_id, tool_call_id, event.metadata.step_seq)


def _sort_key(event: OperatorLogEvent) -> tuple[int, str]:
    seq = event.metadata.step_seq if event.metadata.step_seq is not None else 0
    return (seq, event.ts)


def rebuild_planir_snapshot(
    events: list[OperatorLogEvent],
    *,
    pending_id: str,
    max_trajectory: int = MAX_TRAJECTORY,
) -> PlanIR:
    """Assemble PlanIR for the scan line ``pending_id`` from prior results.

    Executed history is prior ``scan.pending`` steps that have a matching
    ``result`` (join on ``tool_call_id``, else ``run_id`` + ``step_seq``).
    """
    by_id = {event.id: event for event in events}
    target = by_id.get(pending_id)
    if target is None or target.event != "scan" or target.pending is None:
        raise ValueError(f"no scan event {pending_id}")

    episode = target.metadata.session_id
    adapter = target.metadata.adapter
    same_episode = [
        event
        for event in events
        if event.metadata.adapter == adapter and event.metadata.session_id == episode
    ]
    same_episode.sort(key=_sort_key)

    results_by_join: dict[tuple[str, str, int | None], OperatorLogEvent] = {}
    for event in same_episode:
        if event.event != "result" or event.result is None:
            continue
        results_by_join[_join_key(event)] = event

    executed: list[SnapshotCall] = []
    co_pending: list[SnapshotCall] = []
    target_seq = target.metadata.step_seq
    for event in same_episode:
        if event.event != "scan" or event.pending is None:
            continue
        if event.id == pending_id:
            continue
        if target_seq is not None and event.metadata.step_seq is not None:
            if event.metadata.step_seq >= target_seq:
                continue
        result_event = results_by_join.get(_join_key(event))
        pending = event.pending
        executed.append(
            SnapshotCall(
                tool=pending.tool,
                args=dict(pending.args),
                result_summary=result_event.result if result_event else None,
            )
        )

    if target.co_pending:
        pending_by_call = {
            event.metadata.tool_call_id: event.pending
            for event in same_episode
            if event.event == "scan" and event.pending is not None and event.metadata.tool_call_id
        }
        for call_id in target.co_pending:
            peer: PlanStep | None = pending_by_call.get(call_id)
            if peer is None:
                continue
            co_pending.append(SnapshotCall(tool=peer.tool, args=dict(peer.args)))

    executed = executed[-max_trajectory:]
    return build_planir_snapshot(
        executed=executed,
        pending=SnapshotCall(tool=target.pending.tool, args=dict(target.pending.args)),
        co_pending=co_pending or None,
        run_id=target.run_id,
        intent=target.intent,
        intent_kind=target.intent_kind,
        session_id=target.metadata.session_id,
        session_key=target.metadata.session_key,
        agent_id=target.metadata.agent_id,
        adapter=target.metadata.adapter,
        hook=target.metadata.hook,
        tool_call_id=target.metadata.tool_call_id,
        step_seq=target.metadata.step_seq,
        batch_size=target.metadata.batch_size,
    )
