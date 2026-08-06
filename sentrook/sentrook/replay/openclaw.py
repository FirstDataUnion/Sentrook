from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sentrook.adapters.intent import (
    IntentKind,
    classify_intent,
    run_id_from_idempotency_key,
)
from sentrook.adapters.snapshot import (
    SnapshotCall,
    build_planir_snapshot,
    build_result_summary,
)
from sentrook.planir import PlanIR, ResultSummary

RunIntent = tuple[str | None, IntentKind | None]


def replay_session(
    session_path: Path,
    *,
    trajectory_path: Path | None = None,
    agent_id: str = "main",
    max_snapshots: int | None = None,
) -> Iterator[PlanIR]:
    """Replay an OpenClaw session JSONL into rolling before_tool_call PlanIR snapshots."""
    session_id = session_path.stem.split(".")[0]
    messages = _load_jsonl(session_path)
    trajectory_intents = _load_trajectory_intents(trajectory_path) if trajectory_path else {}
    tool_calls = _collect_tool_calls(messages, trajectory_intents)

    count = 0
    executed: list[SnapshotCall] = []
    index = 0

    while index < len(tool_calls):
        event = tool_calls[index]
        batch_id = event.get("batch_id")
        run_id = event.get("openclaw_run_id") or "run_1"
        full_run_id = f"{session_id}:{run_id}"
        intent = event.get("intent")
        intent_kind = event.get("intent_kind")

        if batch_id is None:
            pending = SnapshotCall(tool=event["tool"], args=event["args"])
            yield build_planir_snapshot(
                executed=executed,
                pending=pending,
                run_id=full_run_id,
                intent=intent,
                intent_kind=intent_kind,
                session_id=session_id,
                agent_id=agent_id,
                adapter="openclaw",
                tool_call_id=event.get("tool_call_id"),
                step_seq=count + 1,
            )
            count += 1
            if max_snapshots is not None and count >= max_snapshots:
                return
            executed.append(
                SnapshotCall(
                    tool=event["tool"],
                    args=event["args"],
                    result_summary=event.get("result_summary"),
                )
            )
            index += 1
            continue

        batch: list[dict[str, Any]] = []
        while index < len(tool_calls) and tool_calls[index].get("batch_id") == batch_id:
            batch.append(tool_calls[index])
            index += 1

        for batch_index, call in enumerate(batch):
            co_pending = [
                SnapshotCall(tool=peer["tool"], args=peer["args"])
                for peer_index, peer in enumerate(batch)
                if peer_index != batch_index
            ]
            pending = SnapshotCall(tool=call["tool"], args=call["args"])
            call_run = call.get("openclaw_run_id") or run_id
            yield build_planir_snapshot(
                executed=executed,
                co_pending=co_pending,
                pending=pending,
                run_id=f"{session_id}:{call_run}",
                intent=call.get("intent", intent),
                intent_kind=call.get("intent_kind", intent_kind),
                session_id=session_id,
                agent_id=agent_id,
                adapter="openclaw",
                tool_call_id=call.get("tool_call_id"),
                step_seq=count + 1,
                batch_size=len(batch),
            )
            count += 1
            if max_snapshots is not None and count >= max_snapshots:
                return

        for call in batch:
            executed.append(
                SnapshotCall(
                    tool=call["tool"],
                    args=call["args"],
                    result_summary=call.get("result_summary"),
                )
            )


def write_snapshots(
    snapshots: Iterator[PlanIR],
    output_dir: Path,
    *,
    prefix: str = "snapshot",
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for idx, plan in enumerate(snapshots, start=1):
        path = output_dir / f"{prefix}_{idx:03d}.json"
        path.write_text(
            json.dumps(plan.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            rows.append(_normalize_row(row))
    return rows


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Unwrap OpenClaw session envelope: {type, message: {role, content, ...}}."""
    if row.get("type") == "message" and isinstance(row.get("message"), dict):
        return row["message"]
    return row


def _load_trajectory_intents(path: Path) -> dict[str, RunIntent]:
    """Map OpenClaw run id to the compiled prompt seen at ``before_prompt_build``."""
    intents: dict[str, RunIntent] = {}
    for row in _load_jsonl(path):
        if row.get("type") == "context.compiled":
            run_id = row.get("runId") or row.get("run_id")
            data = row.get("data") or {}
            prompt = data.get("prompt") if isinstance(data, dict) else None
            if run_id and isinstance(prompt, str) and prompt.strip():
                text = prompt.strip()
                intents[str(run_id)] = (text, classify_intent(text))
            continue

        if row.get("type") != "run":
            continue
        run_id = row.get("runId") or row.get("run_id")
        prompt = row.get("prompt") or {}
        intent: str | None = None
        if isinstance(prompt, dict):
            intent = prompt.get("submitted") or prompt.get("text")
        elif isinstance(prompt, str):
            intent = prompt
        if run_id and intent and str(intent).strip():
            text = str(intent).strip()
            intents[str(run_id)] = (text, classify_intent(text))
    return intents


def _collect_tool_calls(
    messages: list[dict[str, Any]],
    trajectory_intents: dict[str, RunIntent],
) -> list[dict[str, Any]]:
    results_by_id: dict[str, ResultSummary] = {}
    for msg in messages:
        if msg.get("role") == "toolResult":
            call_id = msg.get("toolCallId")
            if call_id:
                results_by_id[str(call_id)] = _build_result_summary(msg)

    run_intents: dict[str, RunIntent] = dict(trajectory_intents)
    current_run = "run_1"
    current_intent: str | None = None
    current_kind: IntentKind | None = None

    calls: list[dict[str, Any]] = []
    batch_id = 0
    for msg in messages:
        if msg.get("role") == "user":
            run_id = run_id_from_idempotency_key(msg.get("idempotencyKey")) or current_run
            text = _user_text(msg)
            if text:
                current_run = run_id
                if run_id in run_intents:
                    current_intent, current_kind = run_intents[run_id]
                else:
                    current_intent = text
                    current_kind = classify_intent(text)
                    run_intents[run_id] = (current_intent, current_kind)
            continue

        if msg.get("role") != "assistant":
            continue

        blocks = [
            block
            for block in (msg.get("content") or [])
            if isinstance(block, dict) and block.get("type") == "toolCall"
        ]
        assign_batch = len(blocks) > 1
        if assign_batch:
            current_batch = batch_id
            batch_id += 1
        for block in blocks:
            call_id = block.get("id")
            entry: dict[str, Any] = {
                "tool": _normalize_tool_name(block.get("name", "")),
                "args": _normalize_args(block),
                "tool_call_id": str(call_id) if call_id else None,
                "result_summary": results_by_id.get(str(call_id)) if call_id else None,
                "openclaw_run_id": current_run,
                "intent": current_intent,
                "intent_kind": current_kind,
            }
            if assign_batch:
                entry["batch_id"] = current_batch
            calls.append(entry)
    return calls


def _normalize_tool_name(name: str) -> str:
    if name.startswith("functions."):
        return name.removeprefix("functions.")
    return name


def _normalize_args(block: dict[str, Any]) -> dict[str, Any]:
    args = block.get("arguments")
    if isinstance(args, dict) and args:
        return args
    partial = block.get("partialArgs")
    if isinstance(partial, str) and partial:
        try:
            parsed = json.loads(partial)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    if isinstance(args, dict):
        return args
    return {}


def _user_text(msg: dict[str, Any]) -> str | None:
    content = msg.get("content")
    if isinstance(content, str):
        return content.strip() or None
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if text:
                    parts.append(str(text))
        joined = "\n".join(parts).strip()
        return joined or None
    return None


def _build_result_summary(msg: dict[str, Any]) -> ResultSummary:
    content = msg.get("content")
    text = ""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(
            str(block.get("text", block)) if isinstance(block, dict) else str(block)
            for block in content
        )

    details = msg.get("details") or {}
    command = None
    content_type = None
    if isinstance(details, dict):
        command = details.get("command") or details.get("cmd")
        content_type = details.get("contentType")

    return build_result_summary(
        text,
        ok=not bool(msg.get("isError")),
        content_type=content_type,
        command=str(command) if command else None,
    )
