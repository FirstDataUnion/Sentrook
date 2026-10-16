"""PlanIR 2.0 validation invariants (skeleton 1.7), the checks JSON Schema cannot express.

`check` raises `InvalidPlanIR` for structural failures that make the request unscoreable (the scan
returns `status: error`). `warnings` returns the non-fatal findings that lower coverage (truncated
inputs, dropped content, provider mismatches). Token validity is not checked here: a bad token starts a
fresh session (skeleton 1.7, last bullet) and lives in `state.token`.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import ContentType, InputKind, PlanIR, ScanKind

#: Server-side caps. The plugin caps content at about 256 KB by default (skeleton 1.6); these are the
#: generous ceilings past which the request is refused rather than scanned.
MAX_INPUT_CONTENT_CHARS = 1_048_576
MAX_HISTORY_ARG_CHARS = 65_536
MAX_HISTORY_STEPS = 200
MAX_NEW_INPUTS = 200


class InvalidPlanIR(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Warning_:
    """A non-fatal finding. `code` is stable; `detail` names the offending element."""

    code: str
    detail: str


def _arg_chars(arguments: dict) -> int:
    import json

    return len(json.dumps(arguments, ensure_ascii=False))


def check(planir: PlanIR, raw_scan_kind: str | None = None) -> None:
    """Raise `InvalidPlanIR` on the first structural failure."""
    if raw_scan_kind is not None and raw_scan_kind != ScanKind.PENDING_CALL.value:
        raise InvalidPlanIR(
            "unsupported_scan_kind", f"scan_kind {raw_scan_kind!r} is not supported in this version"
        )

    history = planir.history
    if len(history) > MAX_HISTORY_STEPS:
        raise InvalidPlanIR(
            "oversize", f"history has {len(history)} steps (max {MAX_HISTORY_STEPS})"
        )
    if len(planir.new_inputs) > MAX_NEW_INPUTS:
        raise InvalidPlanIR(
            "oversize", f"{len(planir.new_inputs)} new_inputs (max {MAX_NEW_INPUTS})"
        )

    steps = [h.step for h in history]
    if any(b <= a for a, b in zip(steps, steps[1:], strict=False)):
        raise InvalidPlanIR("history_order", "history steps must be strictly increasing")
    expected_step = (steps[-1] + 1) if steps else 1
    if planir.session.step != expected_step:
        raise InvalidPlanIR(
            "step_mismatch",
            f"session.step is {planir.session.step}, expected {expected_step} (max(history.step) + 1, or 1)",
        )

    call_ids = [h.call_id for h in history]
    if len(set(call_ids)) != len(call_ids):
        raise InvalidPlanIR("duplicate_call_id", "history call_id values must be unique")
    pending_id = planir.pending_call.call_id
    if pending_id in call_ids:
        raise InvalidPlanIR(
            "duplicate_call_id", f"pending call_id {pending_id!r} already appears in history"
        )
    siblings = planir.pending_call.batch.siblings if planir.pending_call.batch else []
    sibling_ids = [s.call_id for s in siblings]
    if len(set(sibling_ids)) != len(sibling_ids) or pending_id in sibling_ids:
        raise InvalidPlanIR(
            "duplicate_call_id",
            "sibling call_id values must be unique and differ from the pending call",
        )

    by_call = {h.call_id: h for h in history}
    for inp in planir.new_inputs:
        if inp.kind is InputKind.TOOL_RESULT:
            if inp.call_id is None or inp.call_id not in by_call:
                raise InvalidPlanIR(
                    "dangling_input",
                    f"new_inputs[{inp.input_seq}] refers to unknown call_id {inp.call_id!r}",
                )
            step = by_call[inp.call_id]
            if inp.tool is not None and inp.tool != step.tool:
                raise InvalidPlanIR(
                    "input_mismatch",
                    f"new_inputs[{inp.input_seq}] tool {inp.tool!r} != history {step.tool!r}",
                )
            if inp.tool_kind is not None and inp.tool_kind != step.tool_kind:
                raise InvalidPlanIR(
                    "input_mismatch", f"new_inputs[{inp.input_seq}] tool_kind differs from history"
                )
        if inp.content is not None and len(inp.content) > MAX_INPUT_CONTENT_CHARS:
            raise InvalidPlanIR(
                "oversize",
                f"new_inputs[{inp.input_seq}] content exceeds {MAX_INPUT_CONTENT_CHARS} chars",
            )

    seqs = [i.input_seq for i in planir.new_inputs]
    if any(b <= a for a, b in zip(seqs, seqs[1:], strict=False)):
        raise InvalidPlanIR(
            "input_order", "new_inputs input_seq values must be unique and increasing"
        )

    for h in history:
        if _arg_chars(h.arguments) > MAX_HISTORY_ARG_CHARS:
            raise InvalidPlanIR(
                "oversize", f"history step {h.step} arguments exceed {MAX_HISTORY_ARG_CHARS} chars"
            )


def warnings(planir: PlanIR) -> list[Warning_]:
    """Non-fatal findings that lower coverage."""
    out: list[Warning_] = []
    by_call = {h.call_id: h for h in planir.history}
    for inp in planir.new_inputs:
        if inp.truncated:
            out.append(Warning_("input_truncated", f"input_seq {inp.input_seq}"))
        if inp.content is None and inp.content_type in (
            ContentType.IMAGE,
            ContentType.BINARY,
            ContentType.OTHER,
        ):
            out.append(
                Warning_("content_dropped", f"input_seq {inp.input_seq} ({inp.content_type.value})")
            )
        elif inp.content is None:
            out.append(Warning_("content_missing", f"input_seq {inp.input_seq}"))
        if (
            inp.kind is InputKind.TOOL_RESULT
            and inp.provider is not None
            and inp.call_id in by_call
        ):
            hist = by_call[inp.call_id].provider
            if (inp.provider.identity, inp.provider.kind) != (hist.identity, hist.kind):
                out.append(Warning_("provider_mismatch", f"input_seq {inp.input_seq}"))
    for h in planir.history:
        if h.risk is None and h.decision.value in ("allowed_on_error", "blocked_on_error"):
            out.append(Warning_("history_unscanned_step", f"step {h.step}"))
    return out
