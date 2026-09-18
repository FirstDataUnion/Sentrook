from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentrook.config import MatcherConfig
from sentrook.layers.exec_shape import SHAPE_KEY_PREFIX, step_tool_tokens
from sentrook.layers.normalize import match_text_with_normalization
from sentrook.layers.pass_kind import L2PassKind
from sentrook.layers.path_classes import ExecPath
from sentrook.layers.tool_pattern import (
    exact_index_keys,
    tool_pattern_matches,
)
from sentrook.planir import PlanIR, PlanStep, ResultSummary, stringify_arg_value
from sentrook.rules.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    IntentKindCondition,
    NoneCondition,
    PathsCondition,
    PendingToolCondition,
    Rule,
    SequenceCondition,
    SequenceSlot,
    SequenceWithGapCondition,
)


@dataclass
class MatchOutcome:
    matched: bool
    confidence: float
    reason: str
    matched_step_ids: list[str]
    pass_id: L2PassKind = L2PassKind.SEQUENCE


def evaluate_rule(rule: Rule, plan: PlanIR, config: MatcherConfig) -> MatchOutcome:
    return _eval_node(rule.condition, plan, config)


def _eval_node(node: ConditionNode, plan: PlanIR, config: MatcherConfig) -> MatchOutcome:
    if isinstance(node, PendingToolCondition):
        return _match_pending_tool(node, plan)
    if isinstance(node, PathsCondition):
        return _match_paths(node, plan)
    if isinstance(node, IntentKindCondition):
        return _match_intent_kind(node, plan)
    if isinstance(node, SequenceCondition):
        return _match_sequence(node, plan)
    if isinstance(node, SequenceWithGapCondition):
        return _match_sequence_with_gap(node, plan)
    if isinstance(node, AllCondition):
        return _match_all(node, plan, config)
    if isinstance(node, AnyCondition):
        return _match_any(node, plan, config)
    if isinstance(node, NoneCondition):
        return _match_none(node, plan, config)
    return MatchOutcome(False, 0.0, "unknown condition", [], L2PassKind.UNKNOWN)


def _match_intent_kind(node: IntentKindCondition, plan: PlanIR) -> MatchOutcome:
    if plan.intent_kind == node.kind:
        return MatchOutcome(
            True,
            1.0,
            f"intent_kind is {node.kind}",
            [],
            L2PassKind.INTENT_KIND,
        )
    return MatchOutcome(
        False,
        0.0,
        f"intent_kind is not {node.kind}",
        [],
        L2PassKind.INTENT_KIND,
    )


def _match_pending_tool(node: PendingToolCondition, plan: PlanIR) -> MatchOutcome:
    from sentrook.adapters.snapshot import primary_pending_step

    step = primary_pending_step(plan)
    if step is not None and step_matches_tool_pattern(node.tool, step):
        return MatchOutcome(
            True,
            1.0,
            f"pending tool is {step.tool} (pattern {node.tool})",
            [step.id],
            L2PassKind.PENDING_TOOL,
        )
    return MatchOutcome(False, 0.0, f"no pending {node.tool}", [], L2PassKind.PENDING_TOOL)


#: Quantifier semantics, stated as code rather than left to the reader.
#:
#: `every` is **non-vacuous on purpose**: standard "for all" over an empty set
#: is true, and that vacuous truth is exactly how F27's false negative happened
#: — a command with no recognised paths read as "every path is in scratch
#: space" and suppressed a destructive-command review. A rule asking `every`
#: means "there are paths, and they all match".
_PATHS_QUANTIFIERS = {
    "any": lambda hits, total: any(hits),
    "every": lambda hits, total: total > 0 and all(hits),
    "none": lambda hits, total: not any(hits),
}


def _segment_heads_for(shape: Any, path: ExecPath) -> list[str]:
    r"""Every head this path can honestly be said to belong to.

    Its own segment's head, plus — when that segment is a `cd` — the head of
    every **later** segment, because `cd` rebases what the later ones act on.

    `cd /srv/app && rm -rf logs` puts the only extractable path (`/srv/app`) in
    segment 0 under `cd`, while the destruction happens in segment 1. A strict
    per-segment reading would spare it, turning AIRA-084's false positive into
    the `cd`-rebase false negative §1.1 exists to prevent — and §1.1's whole
    argument for whole-command classification is that this shape is common.

    Ordering matters and is respected: a `cd` **after** the destructive head
    does not rebase it, so `rm -rf /tmp/x && cd /srv/app` does not credit
    `/srv/app` to the `rm`.
    """
    segments = list(getattr(shape, "segments", ()) or ())
    index = path.segment
    if index is None or index >= len(segments):
        return []
    own = getattr(segments[index], "head", None)
    heads = [own] if own else []
    if own == "cd":
        heads.extend(
            head for later in segments[index + 1 :] if (head := getattr(later, "head", None))
        )
    return heads


def _path_matches(node: PathsCondition, path: ExecPath, shape: Any = None) -> bool:
    r"""Whether one `ExecPath` satisfies every sub-predicate the rule gave.

    `locations` and `roles` are matched as newline-joined strings — the same
    convention as `_shape.heads` — so a rule can say "contains sensitive" with a
    plain substring, or "contains nothing but scratch" with the joined-list
    anchoring convention. The quantifier *over paths* is explicit; this inner
    matching follows the dialect used everywhere else.
    """
    if node.location is not None and not match_text_with_normalization(
        node.location, "\n".join(path.locations)
    ):
        return False
    if node.role is not None and not match_text_with_normalization(
        node.role, "\n".join(path.roles)
    ):
        return False
    if node.path is not None and not match_text_with_normalization(node.path, path.raw):
        return False
    if node.segment_head is not None:
        heads = _segment_heads_for(shape, path)
        if not any(match_text_with_normalization(node.segment_head, head) for head in heads):
            return False
    return True


def _match_paths(node: PathsCondition, plan: PlanIR) -> MatchOutcome:
    """Evaluate a `paths:` condition against the pending step's shape.

    Scoped to the pending step, like `pending_tool`. A step with no shape (a
    non-exec tool) has no paths, so `any`/`every` are false and `none` is true —
    which is the fail-closed reading for the first two and the honest one for
    the third.
    """
    from sentrook.adapters.snapshot import primary_pending_step

    step = primary_pending_step(plan)
    shape = getattr(step, "exec_shape", None) if step is not None else None
    paths = list(getattr(shape, "paths", ()) or ())
    hits = [_path_matches(node, path, shape) for path in paths]
    matched = _PATHS_QUANTIFIERS[node.quantifier](hits, len(paths))
    described = ", ".join(
        f"{name}={getattr(node, name)!r}"
        for name in ("location", "role", "path", "segment_head")
        if getattr(node, name) is not None
    )
    reason = (
        f"{node.quantifier} of {len(paths)} path(s) match {described}"
        if matched
        else f"not {node.quantifier} of {len(paths)} path(s) match {described}"
    )
    return MatchOutcome(
        matched,
        1.0 if matched else 0.0,
        reason,
        [step.id] if matched and step is not None else [],
        L2PassKind.PATHS,
    )


def _sequence_pass_kind(slots: list[SequenceSlot], *, with_gap: bool = False) -> L2PassKind:
    if any(slot.args_match or slot.result_flags for slot in slots):
        return L2PassKind.SEQUENCE_ARGS
    if with_gap:
        return L2PassKind.SEQUENCE_WITH_GAP
    return L2PassKind.SEQUENCE


def _match_sequence(node: SequenceCondition, plan: PlanIR) -> MatchOutcome:
    slots = node.steps
    pass_kind = _sequence_pass_kind(slots)
    if not slots:
        return MatchOutcome(False, 0.0, "empty sequence", [], pass_kind)

    best = MatchOutcome(False, 0.0, "no sequence match", [], pass_kind)
    n = len(plan.steps)
    k = len(slots)

    for start in range(max(0, n - k + 1)):
        window = plan.steps[start : start + k]
        outcome = _match_window(slots, window, pass_kind)
        if outcome.confidence > best.confidence:
            best = outcome
        if outcome.matched:
            return outcome

    partial = _best_partial_sequence(slots, plan.steps, pass_kind)
    if partial.confidence > best.confidence:
        best = partial
    return best


def _match_sequence_with_gap(node: SequenceWithGapCondition, plan: PlanIR) -> MatchOutcome:
    slots = node.steps
    pass_kind = _sequence_pass_kind(slots, with_gap=True)
    if not slots:
        return MatchOutcome(False, 0.0, "empty sequence", [], pass_kind)

    outcome = _match_subsequence(slots, plan.steps, pass_kind, max_gap=node.max_gap)
    if outcome.matched:
        return outcome
    return MatchOutcome(False, 0.0, "no sequence with gap match", [], pass_kind)


def _match_window(
    slots: list[SequenceSlot], window: list[PlanStep], pass_kind: L2PassKind
) -> MatchOutcome:
    if len(window) != len(slots):
        return MatchOutcome(False, 0.0, "window size mismatch", [], pass_kind)

    matched_ids: list[str] = []
    for slot, step in zip(slots, window, strict=True):
        if not _slot_matches(slot, step):
            if not step_matches_tool_pattern(slot.tool, step):
                return MatchOutcome(False, 0.0, f"tool mismatch at {step.id}", [], pass_kind)
            if slot.status != "any" and step.status != slot.status:
                return MatchOutcome(
                    False,
                    0.0,
                    f"status mismatch for {step.tool}",
                    [],
                    pass_kind,
                )
            return MatchOutcome(False, 0.0, f"args mismatch for {step.tool}", [], pass_kind)
        matched_ids.append(step.id)

    return MatchOutcome(
        True,
        1.0,
        "sequence matched",
        matched_ids,
        pass_kind,
    )


def _match_subsequence(
    slots: list[SequenceSlot],
    steps: list[PlanStep],
    pass_kind: L2PassKind,
    *,
    max_gap: int | None = None,
) -> MatchOutcome:
    k = len(slots)
    if k == 2 and max_gap is not None:
        return _match_two_slot_with_max_gap(slots, steps, max_gap, pass_kind)

    for start in range(len(steps)):
        matched = 0
        ids: list[str] = []
        step_idx = start
        for slot in slots:
            found = False
            while step_idx < len(steps):
                step = steps[step_idx]
                step_idx += 1
                if not _slot_matches(slot, step):
                    continue
                matched += 1
                ids.append(step.id)
                found = True
                break
            if not found:
                break

        if matched == k:
            return MatchOutcome(
                True,
                1.0,
                "sequence with gap matched",
                ids,
                pass_kind,
            )

    return MatchOutcome(False, 0.0, "no sequence with gap match", [], pass_kind)


def _match_two_slot_with_max_gap(
    slots: list[SequenceSlot],
    steps: list[PlanStep],
    max_gap: int,
    pass_kind: L2PassKind,
) -> MatchOutcome:
    """Match a two-step gapped sequence with a bounded window between slots."""
    slot_a, slot_b = slots[0], slots[1]
    for i, step_a in enumerate(steps):
        if not _slot_matches(slot_a, step_a):
            continue
        for j in range(i + 1, min(len(steps), i + max_gap + 2)):
            step_b = steps[j]
            if _slot_matches(slot_b, step_b):
                return MatchOutcome(
                    True,
                    1.0,
                    "sequence with gap matched",
                    [step_a.id, step_b.id],
                    pass_kind,
                )
    return MatchOutcome(False, 0.0, "no sequence with gap match", [], pass_kind)


def _best_partial_sequence(
    slots: list[SequenceSlot], steps: list[PlanStep], pass_kind: L2PassKind
) -> MatchOutcome:
    best_conf = 0.0
    best_ids: list[str] = []
    k = len(slots)

    for start in range(len(steps)):
        matched = 0
        ids: list[str] = []
        step_idx = start
        for slot in slots:
            found = False
            while step_idx < len(steps):
                step = steps[step_idx]
                step_idx += 1
                if not _slot_matches(slot, step):
                    continue
                matched += 1
                ids.append(step.id)
                found = True
                break
            if not found:
                break

        conf = matched / k if k else 0.0
        if conf > best_conf:
            best_conf = conf
            best_ids = ids

    if best_conf <= 0:
        return MatchOutcome(False, 0.0, "no partial sequence", [], pass_kind)
    return MatchOutcome(
        best_conf >= 1.0,
        best_conf,
        f"partial sequence ({best_conf:.0%})",
        best_ids,
        pass_kind,
    )


def _slot_tool_names(tool: str) -> frozenset[str]:
    """Exact alternates for L1 exact-index keys; globs are excluded.

    Prefer :func:`tool_pattern_matches` for L2 matching. Kept for callers that
    need the exact-name expansion (``write|edit`` → ``{write, edit}``).
    """
    return exact_index_keys(tool)


def step_matches_tool_pattern(pattern: str, step: PlanStep) -> bool:
    """Match a YAIRA tool pattern against a step, including ``exec:<head>``.

    Prefer this to :func:`tool_pattern_matches` anywhere a step is in hand —
    the bare function can only see the tool name, so `exec:curl` would never
    match. Shares :func:`step_tool_tokens` with L1 candidacy by construction.
    """
    return any(tool_pattern_matches(pattern, token) for token in step_tool_tokens(step))


def _slot_matches(slot: SequenceSlot, step: PlanStep) -> bool:
    if not step_matches_tool_pattern(slot.tool, step):
        return False
    if slot.status != "any" and step.status != slot.status:
        return False
    if slot.args_match and not _args_match(slot.args_match, step.args, step):
        return False
    if slot.result_flags and not _result_flags_match(slot.result_flags, step.result_summary):
        return False
    return True


def _result_flags_match(expected: dict[str, bool], result_summary: ResultSummary | None) -> bool:
    if result_summary is None:
        return False
    flags = result_summary.flags
    for key, value in expected.items():
        if getattr(flags, key, None) is not value:
            return False
    return True


def _match_none(node: NoneCondition, plan: PlanIR, config: MatcherConfig) -> MatchOutcome:
    inner = _eval_node(node.condition, plan, config)
    if inner.matched:
        return MatchOutcome(
            False,
            0.0,
            f"forbidden pattern matched ({inner.reason})",
            [],
            L2PassKind.NONE,
        )
    return MatchOutcome(
        True,
        1.0,
        "forbidden pattern absent",
        [],
        L2PassKind.NONE,
    )


def _match_all(node: AllCondition, plan: PlanIR, config: MatcherConfig) -> MatchOutcome:
    if not node.conditions:
        return MatchOutcome(False, 0.0, "empty all()", [], L2PassKind.ALL)

    confidences: list[float] = []
    reasons: list[str] = []
    ids: list[str] = []
    all_matched = True

    for child in node.conditions:
        outcome = _eval_node(child, plan, config)
        confidences.append(outcome.confidence)
        reasons.append(outcome.reason)
        ids.extend(outcome.matched_step_ids)
        if not outcome.matched:
            all_matched = False

    confidence = min(confidences) if confidences else 0.0
    return MatchOutcome(
        all_matched,
        confidence,
        "; ".join(reasons),
        list(dict.fromkeys(ids)),
        L2PassKind.ALL,
    )


def _match_any(node: AnyCondition, plan: PlanIR, config: MatcherConfig) -> MatchOutcome:
    if not node.conditions:
        return MatchOutcome(False, 0.0, "empty any()", [], L2PassKind.ANY)

    best = MatchOutcome(False, 0.0, "no any() branch matched", [], L2PassKind.ANY)
    reasons: list[str] = []

    for child in node.conditions:
        outcome = _eval_node(child, plan, config)
        reasons.append(outcome.reason)
        if outcome.matched:
            return MatchOutcome(
                True,
                outcome.confidence,
                outcome.reason,
                outcome.matched_step_ids,
                L2PassKind.ANY,
            )
        if outcome.confidence > best.confidence:
            best = MatchOutcome(
                False,
                outcome.confidence,
                outcome.reason,
                outcome.matched_step_ids,
                L2PassKind.ANY,
            )

    return MatchOutcome(
        False,
        best.confidence,
        "; ".join(reasons) if reasons else best.reason,
        best.matched_step_ids,
        L2PassKind.ANY,
    )


def _args_match(patterns: dict[str, str], args: dict, step: PlanStep | None = None) -> bool:
    """Match args against YAIRA ``args_match`` patterns.

    Multiple entries are AND. A key containing ``|`` is OR across those arg
    names with the same regex (e.g. ``command|data: "curl"``).

    ``step`` carries the derived ``exec_shape`` for ``_shape.*`` keys (§1.2).
    It is threaded through rather than merged into ``args`` on purpose: args are
    sanitized, written to the scan log and shipped to the corpus, so a synthetic
    key there would leak into all three.
    """
    for key, pattern in patterns.items():
        keys = [part.strip() for part in key.split("|") if part.strip()]
        if not keys:
            return False
        if not any(_arg_value_matches(k, pattern, args, step) for k in keys):
            return False
    return True


def _arg_value_matches(key: str, pattern: str, args: dict, step: PlanStep | None = None) -> bool:
    if key.startswith(SHAPE_KEY_PREFIX):
        return _shape_value_matches(key, pattern, step)
    if key not in args:
        return False
    value = stringify_arg_value(args[key])
    if not value:
        return False
    # Search raw + lightly deobfuscated variant (base64 echo|d, \\xNN, quote concat).
    return match_text_with_normalization(pattern, value)


def _shape_value_matches(key: str, pattern: str, step: PlanStep | None) -> bool:
    """Resolve a ``_shape.<field>`` key against the step's derived exec shape.

    **Empty values must still match** — the engine change §1.2 calls for. Every
    allow rule requires ``_shape.sinks: "^$"``, and any command touching no
    paths (``date``, ``whoami``, ``git status``) has empty lists. Under the
    ordinary short-circuit (``if not value: return False``) those stringify to
    ``""`` and the rule returns **false**, so no allow rule would ever fire.

    The failure is selective and therefore invisible: booleans still work,
    because ``str(True)`` is ``"True"`` and matches ``^true$`` case-insensitively.
    So a half-working allow rule would look merely over-narrow rather than
    broken. Presence is checked first, then the possibly-empty value is matched
    normally; an **absent** shape still fails closed.
    """
    shape = getattr(step, "exec_shape", None) if step is not None else None
    if shape is None:
        return False
    field = key[len(SHAPE_KEY_PREFIX) :]
    values = shape.to_dict()
    if field not in values:
        return False
    return match_text_with_normalization(pattern, _stringify_shape_value(values[field]))


def _stringify_shape_value(value: object) -> str:
    """List fields join newline-separated, one entry per line (§1.2).

    Rules must anchor these with ``\\A…\\z`` rather than ``^…$``:
    ``match_text_with_normalization`` applies ``DOTALL | IGNORECASE`` without
    ``MULTILINE``, so ``$`` matches before a trailing newline.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "\n".join(
            item if isinstance(item, str) else str(item)
            for item in value
            if not isinstance(item, dict)
        )
    return str(value)


def _pending_steps(plan: PlanIR) -> list[PlanStep]:
    return [s for s in plan.steps if s.status == "pending"]


def classify_match(
    outcome: MatchOutcome, rule_action: str, config: MatcherConfig
) -> tuple[bool, str]:
    """Return (counts_as_hit, effective_action).

    **`action: allow` is all-or-nothing.** For every other action a partial
    match (>= `review_threshold`, default 0.4) counts as a hit and degrades to
    `review`, which is the right conservative default: a half-matched block
    becomes a question rather than nothing.

    Applying that to an allow rule inverts it. A multi-slot sequence hitting one
    slot, or an `any:` branch scoring 0.5 through `_match_any`'s best-partial
    path, would be classified as a **review hit** — so allow rules, whose whole
    purpose is removing reviews, would manufacture them instead. Worse, the
    resulting review is attributed to the allow rule, so the fatigue report would
    show the allow family *increasing* review rate and the natural response would
    be to widen it, matching more and producing more spurious reviews.

    So for allow: only a definitive match is a hit, and anything less is not a
    hit at all.
    """
    if outcome.confidence >= config.definitive_threshold:
        return True, rule_action
    if rule_action == "allow":
        return False, "no_match"
    if outcome.confidence >= config.review_threshold:
        return True, "review"
    return False, "no_match"
