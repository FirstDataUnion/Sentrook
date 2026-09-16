from __future__ import annotations

import re
from typing import Any

from sentrook.config import L2Authority
from sentrook.layers.exec_shape import SHAPE_KEY_PREFIX, ExecShape
from sentrook.layers.tool_pattern import InvalidToolPatternError, validate_tool_pattern
from sentrook.rules.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    IntentKindCondition,
    NoneCondition,
    OwaspRefs,
    PendingToolCondition,
    Rule,
    RuleMeta,
    SequenceCondition,
    SequenceSlot,
    SequenceWithGapCondition,
)

#: Constraints an `action: allow` rule must carry. Each closes a way the rule
#: could otherwise approve something it did not actually understand.
REQUIRED_ALLOW_CONSTRAINTS: dict[str, str] = {
    # F18. `cat /etc/passwd` and `sudo cat /etc/shadow` have identical `heads`,
    # so without this an allow rule keyed on heads approves a privileged read of
    # /etc/shadow. Two shipping agent tools have exactly this bug.
    "_shape.privileged": "an allow rule must refuse privilege elevation",
    # Allowing a command we could not parse is the same class of mistake: the
    # shape is empty precisely because we do not know what the command does.
    "_shape.parse_ok": "an allow rule must require a clean parse",
}


class InvalidAllowRuleError(ValueError):
    """Raised when an `action: allow` rule is missing a required safety clause."""


class InvalidArgsMatchError(ValueError):
    """Raised when an ``args_match`` entry cannot work at scan time."""


#: Field names addressable as `_shape.<field>` — the shape's own wire keys, so
#: this cannot drift from what `_shape_value_matches` actually resolves.
_SHAPE_FIELDS = frozenset(ExecShape().to_dict())


def validate_args_match(patterns: dict[str, str] | None) -> None:
    r"""Reject at rule-compile time what would otherwise fail at scan time.

    Two failures this catches, both of which a rule author hits easily:

    **A regex Python cannot compile.** Nothing validated `args_match` before, so
    a bad pattern compiled fine and raised `re.error` on every scan that reached
    the rule — a live outage from a library publish, not a load-time refusal.
    The likeliest instance is `\z`: it is valid in Perl, PCRE and Ruby, and §1.2
    originally documented `\A…\z` as the convention for list-valued shape
    fields. Python's `re` only knows `\Z`.

    **A `_shape.` key that names no field.** It would simply never match. For an
    allow rule that fails closed and is merely a rule which never fires — a
    silent maintenance trap rather than a hole, but there is no reason to ship
    one when a typo can be caught here.
    """
    for key, pattern in (patterns or {}).items():
        for name in (part.strip() for part in key.split("|")):
            if name.startswith(SHAPE_KEY_PREFIX):
                field = name[len(SHAPE_KEY_PREFIX) :]
                if field not in _SHAPE_FIELDS:
                    raise InvalidArgsMatchError(
                        f"unknown shape field {name!r}; valid: {', '.join(sorted(_SHAPE_FIELDS))}"
                    )
        try:
            re.compile(pattern)
        except re.error as exc:
            hint = ""
            if "\\z" in pattern or r"\z" in pattern:
                hint = " (Python uses \\Z, not \\z — that is Perl/PCRE syntax)"
            raise InvalidArgsMatchError(
                f"args_match[{key!r}] is not a valid Python regex: {exc}{hint}"
            ) from exc


def validate_suppression_targets(rules: list[Rule]) -> None:
    """Every `suppresses` target must be a soft-authority review rule.

    Cross-rule, so it runs at ruleset load rather than per-document. Three ways
    an allow rule could otherwise widen its own blast radius:

    * **naming a block** — the entire point of a block is that nothing waives it;
    * **naming a hard review** — hard authority exists so an operator's lenient
      floor cannot waive a rule, and an allow rule must not do what the floor
      may not. This is the chain Phase 3a's class-1 rules are meant to close:
      AIRA-010 flagged a credential read and `skip_reason: lenient` approved it
      anyway. An allow rule suppressing a hard review would restore exactly that;
    * **naming a rule that does not exist** — silently inert today, and silently
      *active* the day someone mints that id for something else.

    Default authority is a config value rather than a rule property, so a rule
    with `authority` unset is treated as suppressible only when it is explicitly
    soft. Fail closed: a rule that does not say it is soft is not.
    """
    by_id = {rule.id: rule for rule in rules}
    for rule in rules:
        if rule.meta.action != "allow":
            continue
        for target_id in rule.meta.suppresses:
            target = by_id.get(target_id)
            if target is None:
                raise InvalidAllowRuleError(
                    f"Rule {rule.id}: suppresses unknown rule {target_id!r}"
                )
            if target.meta.action != "review":
                raise InvalidAllowRuleError(
                    f"Rule {rule.id}: may not suppress {target_id!r} "
                    f"(action is {target.meta.action!r}, only `review` may be suppressed)"
                )
            if target.meta.authority != L2Authority.SOFT:
                raise InvalidAllowRuleError(
                    f"Rule {rule.id}: may not suppress {target_id!r} "
                    f"(authority is {target.meta.authority!r}, only `soft` may be suppressed)"
                )


def _collect_args_match_keys(node: Any) -> set[str]:
    """Every `args_match` key anywhere in a condition tree."""
    keys: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "args_match" and isinstance(value, dict):
                for raw in value:
                    keys.update(part.strip() for part in str(raw).split("|"))
            else:
                keys |= _collect_args_match_keys(value)
    elif isinstance(node, list):
        for item in node:
            keys |= _collect_args_match_keys(item)
    return keys


def validate_allow_rule(meta: RuleMeta, condition_raw: dict[str, Any]) -> None:
    """Refuse an allow rule that cannot be safe, at load rather than at scan.

    Allow rules are the only fail-**open** surface in the design: a review rule
    that is wrong asks a needless question, while an allow rule that is wrong
    silently approves. So the constraints that make one safe are enforced here
    rather than left to whoever writes the rule to remember.

    `suppresses` is required and non-empty because an allow rule that suppresses
    nothing has no effect except to appear in `matched_rules` — a rule that looks
    like relief and delivers none.
    """
    if not meta.suppresses:
        raise InvalidAllowRuleError(
            "action: allow requires a non-empty `suppresses` list naming the "
            "review rules it removes"
        )
    keys = _collect_args_match_keys(condition_raw)
    for required, why in REQUIRED_ALLOW_CONSTRAINTS.items():
        if required not in keys:
            raise InvalidAllowRuleError(f"missing `{required}` constraint — {why}")


def _compile_slot(slot: Any) -> SequenceSlot:
    if isinstance(slot, str):
        validate_tool_pattern(slot)
        return SequenceSlot(tool=slot)
    tool = str(slot["tool"])
    validate_tool_pattern(tool)
    args_match = slot.get("args_match")
    validate_args_match(args_match)
    return SequenceSlot(
        tool=tool,
        status=slot.get("status", "any"),
        args_match=args_match,
        result_flags=slot.get("result_flags"),
    )


def _compile_condition(node: dict[str, Any]) -> ConditionNode:
    if "intent_kind" in node:
        return IntentKindCondition(kind=node["intent_kind"])
    if "pending_tool" in node:
        tool = str(node["pending_tool"])
        validate_tool_pattern(tool)
        return PendingToolCondition(tool=tool)
    if "sequence" in node:
        return SequenceCondition(steps=[_compile_slot(slot) for slot in node["sequence"]])
    if "sequence_with_gap" in node:
        raw = node["sequence_with_gap"]
        max_gap: int | None = None
        slots_raw: list[Any]
        if isinstance(raw, dict):
            max_gap = raw.get("max_gap")
            slots_raw = raw.get("steps") or raw.get("sequence") or []
        elif isinstance(raw, list):
            slots_raw = raw
        else:
            raise ValueError(f"sequence_with_gap must be a list or mapping, got {raw!r}")

        slots: list[SequenceSlot] = [_compile_slot(slot) for slot in slots_raw]
        return SequenceWithGapCondition(steps=slots, max_gap=max_gap)
    if "all" in node:
        return AllCondition(conditions=[_compile_condition(child) for child in node["all"]])
    if "any" in node:
        return AnyCondition(conditions=[_compile_condition(child) for child in node["any"]])
    if "none" in node:
        return NoneCondition(condition=_compile_condition(node["none"]))
    raise ValueError(f"Unsupported condition node: {node!r}")


def compile_rule(doc: dict[str, Any], source_path: str | None = None) -> Rule:
    rule_id = str(doc.get("rule") or doc.get("id") or "")
    if not rule_id:
        raise ValueError(f"Rule missing id in {source_path or 'document'}")

    meta_raw = doc.get("meta") or {}
    owasp_raw = meta_raw.get("owasp")
    owasp = None
    if isinstance(owasp_raw, dict):
        owasp = OwaspRefs(
            asi=[str(x) for x in owasp_raw.get("asi", [])],
            llm=[str(x) for x in owasp_raw.get("llm", [])],
        )

    meta = RuleMeta(
        name=str(meta_raw.get("name", rule_id)),
        severity=meta_raw.get("severity", "medium"),
        action=meta_raw.get("action", "block"),
        description=meta_raw.get("description"),
        owasp=owasp,
        authority=meta_raw.get("authority"),
        suppresses=[str(x) for x in (meta_raw.get("suppresses") or [])],
    )

    condition_raw = doc.get("condition")
    if not isinstance(condition_raw, dict):
        raise ValueError(f"Rule {rule_id}: condition must be a mapping")

    try:
        condition = _compile_condition(condition_raw)
    except InvalidToolPatternError as exc:
        raise ValueError(f"Rule {rule_id}: {exc}") from exc
    except InvalidArgsMatchError as exc:
        raise ValueError(f"Rule {rule_id}: {exc}") from exc

    if meta.action == "allow":
        try:
            validate_allow_rule(meta, condition_raw)
        except InvalidAllowRuleError as exc:
            raise ValueError(f"Rule {rule_id}: {exc}") from exc

    return Rule(
        id=rule_id,
        meta=meta,
        condition=condition,
        raw=doc,
    )
