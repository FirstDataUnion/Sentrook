from __future__ import annotations

import itertools
import re
from typing import Any

from sentrook.config import L2Authority
from sentrook.layers.exec_shape import SHAPE_KEY_PREFIX, ExecShape
from sentrook.layers.path_classes import LOCATION_CLASSES, ROLE_CLASSES
from sentrook.layers.tool_pattern import InvalidToolPatternError, validate_tool_pattern
from sentrook.rules.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    IntentKindCondition,
    NoneCondition,
    OwaspRefs,
    PathsCondition,
    PendingToolCondition,
    Rule,
    RuleMeta,
    SequenceCondition,
    SequenceSlot,
    SequenceWithGapCondition,
)
from sentrook.sanitize.sensitive_paths import (
    binary_alternation,
    load_sensitive_paths,
    unsafe_argv_fragment,
)

#: Prefix under which a *condition kind* is reported alongside `args_match`
#: keys, so `REQUIRED_ALLOW_CONSTRAINTS` can name one. Distinct from a bare
#: name so it cannot collide with an arg that happens to be called `paths`.
CONDITION_KEY_PREFIX = "condition:"


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
    # F18 a second time. `LD_PRELOAD=/tmp/evil.so ls` has the same `heads`,
    # `sinks`, `substitution` and `privileged` as a bare `ls` — the assignment
    # lives in its own tree-sitter node and was discarded, and the `env …` form
    # was eaten by wrapper stripping. Phase 3b's Listing family, written to the
    # plan's stated constraints, allowed it. Required rather than advised,
    # because "remember to think about the environment" is exactly what an
    # author forgets.
    "_shape.env_assignments": "an allow rule must constrain the environment prefix",
    # D23. AIRA-010 is `soft`, so an allow family may suppress it, and an allow
    # family that says nothing about path roles suppresses it on `cat
    # id_ed25519` — a bare basename with **zero** extractable paths, so a
    # `paths:` condition cannot see it and only the whole-command roll-up can.
    "_shape.path_roles": "an allow rule must constrain the roles of the paths it touches",
    # D23's other half, and the reason one constraint is not enough. The two
    # views fail on opposite inputs and neither substitutes for the other:
    #
    #   cat id_ed25519             path_roles=['sensitive']  paths=[]
    #   ls -la /home/node/.openclaw  path_roles=[]           paths=[(…, ['openclaw'], [])]
    #
    # The agent's own config *directory* carries a `location`, not a `role`, so
    # `_shape.path_roles` is empty for it and the clause above is satisfied
    # vacuously. Two corpus `attack` rows are exactly that listing
    # (`pos-inbox-export-obey-ls`, `pos-poisoned-fetch-steer-exec`), and §3b's
    # seed table asks for the `paths:` guard on the Read family while omitting
    # it from Listing — a safety property living in prose, which is F30.
    #
    # Only the *presence* of the condition is enforced here; which paths a
    # family refuses is its own business, gated by the `allow_rules` suite and
    # GTFOBins zero-admission.
    f"{CONDITION_KEY_PREFIX}paths": (
        "an allow rule must carry a `paths:` condition — `_shape.path_roles` is "
        "empty for the agent's own config directory, which has a location and no role"
    ),
}


#: Every condition kind `_compile_condition` understands. Declared here rather
#: than inferred so the allow-rule guard and the compiler cannot drift on what
#: counts as a condition.
_CONDITION_KINDS = frozenset(
    {"intent_kind", "pending_tool", "paths", "sequence", "sequence_with_gap", "all", "any", "none"}
)


class UnknownMacroError(ValueError):
    """Raised when an ``args_match`` pattern references a macro that does not exist."""


#: Named regex macros usable inside any ``args_match`` pattern as
#: ``${name}``. Each resolves to a **non-capturing** group so it can be
#: embedded mid-alternation without renumbering the host pattern's groups —
#: AIRA-071 does exactly that, following the macro with ``.{0,400}https?://``.
#:
#: Values are callables rather than strings so the macro binds to the canonical
#: YAML (§1.3) rather than to a snapshot of it taken at import. Adding a
#: basename to ``sensitive_paths.yaml`` reaches every rule with no rule edit,
#: which is the entire point: the seven rules this replaces carried five
#: hand-pasted copies of one list under a ``# keep in sync`` comment.
ARGS_MATCH_MACROS: dict[str, Any] = {
    "sensitive_path": lambda: load_sensitive_paths().sensitive.fragment,
    "auth_store_path": lambda: load_sensitive_paths().auth_store.fragment,
    "credential_store_path": lambda: load_sensitive_paths().credential_store.fragment,
    "reading_head": lambda: binary_alternation(load_sensitive_paths().reading_binaries),
    # Phase 3b. The allow families' head vocabulary and the flags every
    # family refuses. Both are the fail-open half of the library, so they
    # bind to the canonical YAML rather than to eight hand-pasted copies.
    "safe_exec_head": lambda: binary_alternation(
        {head for heads in load_sensitive_paths().safe_exec_binaries.values() for head in heads}
    ),
    "unsafe_argv_flag": lambda: unsafe_argv_fragment(load_sensitive_paths().unsafe_argv_flags),
    "credential_bearing_config_path": (
        lambda: load_sensitive_paths().credential_bearing_config.fragment
    ),
    "agent_config_path": lambda: load_sensitive_paths().agent_config.fragment,
    "persistence_path": lambda: load_sensitive_paths().persistence.fragment,
}


def _register_family_head_macros() -> None:
    """One `${safe_exec_head_<family>}` per family in the canonical YAML.

    Registered from the data rather than listed here, so adding a family to
    `sensitive_paths.yaml` gives it a macro and adding one here without the
    data raises `UnknownMacroError` at compile — which is the direction the
    failure should point. An allow family needs to say "every head is safe
    **and** one is mine", and without this the second half would be an inline
    head list in each of eight rules: §1.3's shape, in the fail-open half of
    the library.
    """
    for family in load_sensitive_paths().safe_exec_binaries:
        ARGS_MATCH_MACROS[f"safe_exec_head_{family}"] = lambda family=family: binary_alternation(
            load_sensitive_paths().safe_exec_binaries[family]
        )


_register_family_head_macros()


_MACRO_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_macros(pattern: str) -> str:
    """Substitute every ``${name}`` in an ``args_match`` regex.

    Unknown names raise rather than expanding to themselves. A typo would
    otherwise leave a literal ``${sensitve_path}`` in the pattern, which is a
    valid regex that matches nothing — a rule silently reduced to a no-op by a
    missing vowel, which is exactly the failure class F20 established must be
    refused at load rather than discovered in production.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        resolve = ARGS_MATCH_MACROS.get(name)
        if resolve is None:
            raise UnknownMacroError(
                f"unknown macro ${{{name}}}; known: "
                + ", ".join(f"${{{k}}}" for k in sorted(ARGS_MATCH_MACROS))
            )
        return resolve()

    return _MACRO_RE.sub(replace, pattern)


class InvalidAllowRuleError(ValueError):
    """Raised when an `action: allow` rule is missing a required safety clause."""


class InvalidArgsMatchError(ValueError):
    """Raised when an ``args_match`` entry cannot work at scan time."""


#: Leading inline-flag groups (``(?i)``, ``(?is)``) sit before the real pattern.
_INLINE_FLAGS_RE = re.compile(r"\A(?:\(\?[aiLmsux]+\))+")


def _has_unanchored_lookahead_chain(pattern: str) -> bool:
    r"""A lookahead chain that the engine will retry at every start position.

    ``(?=.*A)(?=.*B)`` reads as "contains A and contains B" and behaves that
    way — but ``re.search`` retries it at every offset, and each attempt scans
    the rest of the subject, so the cost is **quadratic in the command length**.

    Measured on AIRA-067 before this check existed: 3.96 ms at a 500-character
    subject, 259 ms at 4000. D1 raised ``limits.command_max_chars`` from 500 to
    4000 for Phase 1's parser, which made a shipped rule 64x slower with every
    test still green — nothing measures rule match latency. Prefixing ``\A``
    took it to 0.12 ms with identical results on all 541 corpus commands.

    **The negative form is worse, and for a different reason.** An unanchored
    `(?!.*X)` is a **tautology**: `re.search` retries after a failure, and the
    end-of-string position always satisfies a negative lookahead, so it matches
    every subject — verified over 307, False on none. A rule writing
    `_shape.path_roles: "(?!.*sensitive)"` therefore gets a clause that is
    *always true*, and on an allow rule that is a constraint which silently does
    nothing. Anchoring is not an optimisation there; it is the difference
    between the constraint meaning something and meaning nothing.

    An alternation *branch* opening with a lookahead has the same problem and is
    much easier to miss. AIRA-059 carried
    ``env\s*\|\s*grep|(?=.*(?:python3?|sqlite3))(?=.*openclaw-agent\.sqlite)|…``
    at 96 ms, and a check that looked only at the pattern's first construct would
    have waved it through. ``|(?=`` is the whole signature: a ``|`` cannot be
    followed by ``(?=`` inside a character class, so the substring is unambiguous.

    Anchoring is sound because a lookahead at position *k* can only succeed if it
    also succeeds at 0 — it sees a suffix of what position 0 sees. So for a
    boolean ``search`` the two are equivalent, and one is 2000x faster. The same
    argument holds branch by branch inside an alternation.
    """
    body = _INLINE_FLAGS_RE.sub("", pattern)
    return any(body.startswith(opener) or f"|{opener}" in body for opener in ("(?=", "(?!"))


#: Shape fields a rule may **not** name, with the reason and the alternative.
#:
#: `_shape.*` resolves through `_stringify_shape_value`, which drops dicts from
#: lists. So a structured field stringifies to `""` — and a rule naming it
#: compiles cleanly, passes every validation, and never matches. That is F20's
#: failure class (a rule silently reduced to a no-op) sitting in the compiler,
#: made worse by the field name being *accepted*, which reads as endorsement.
UNMATCHABLE_SHAPE_FIELDS: dict[str, str] = {
    "segments": (
        "`_shape.segments` is a list of objects and stringifies to the empty "
        "string, so any pattern but `^$` can never match. Match `_shape.heads` "
        "for binaries, or use a `paths:` condition for path arguments"
    ),
    "paths": (
        "`_shape.paths` is a list of objects and stringifies to the empty "
        "string. Use a `paths:` condition, which matches per path and requires "
        "an explicit quantifier"
    ),
    "path_classes": (
        "`_shape.path_classes` is a flat roll-up kept for metrics, and reading "
        "it from a rule forces an implicit quantifier over the paths it was "
        "built from — which is F27, a defect that produced a false positive and "
        "a false negative at the same time. Use a `paths:` condition"
    ),
}

#: Field names addressable as `_shape.<field>` — the shape's own wire keys minus
#: the ones above, so this cannot drift from what `_shape_value_matches`
#: actually resolves.
_SHAPE_FIELDS = frozenset(ExecShape().to_dict()) - frozenset(UNMATCHABLE_SHAPE_FIELDS)


def validate_args_match(patterns: dict[str, str] | None) -> dict[str, str] | None:
    r"""Reject at rule-compile time what would otherwise fail at scan time.

    Three failures this catches, all of which a rule author hits easily:

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

    **A pattern that is correct but quadratic.** See
    :func:`_has_unanchored_lookahead_chain`. Correctness is not the only thing a
    library artefact can get wrong at scale.
    """
    if patterns is None:
        return None
    expanded: dict[str, str] = {}
    for key, pattern in patterns.items():
        for name in (part.strip() for part in key.split("|")):
            if name.startswith(SHAPE_KEY_PREFIX):
                field = name[len(SHAPE_KEY_PREFIX) :]
                if field in UNMATCHABLE_SHAPE_FIELDS:
                    raise InvalidArgsMatchError(
                        f"{name} cannot be matched: {UNMATCHABLE_SHAPE_FIELDS[field]}"
                    )
                if field not in _SHAPE_FIELDS:
                    raise InvalidArgsMatchError(
                        f"unknown shape field {name!r}; valid: {', '.join(sorted(_SHAPE_FIELDS))}"
                    )
        pattern = expand_macros(pattern)
        expanded[key] = pattern
        if _has_unanchored_lookahead_chain(pattern):
            raise InvalidArgsMatchError(
                f"args_match[{key!r}] has an unanchored lookahead chain (at the "
                "start of the pattern or of an alternation branch). Prefix that "
                "chain with \\A.\n"
                "  (?=…) unanchored: `re.search` retries it at every offset and "
                "each attempt rescans the subject — quadratic in command length "
                "(3.96 ms at 500 chars, 259 ms at the 4000-char budget). \\A is "
                "equivalent for a boolean search and ~2000x faster.\n"
                "  (?!…) unanchored: a **tautology**. The end-of-string position "
                "always satisfies a negative lookahead, so the clause matches "
                "everything and constrains nothing — on an allow rule, a "
                "constraint that silently does not exist."
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
    return expanded


def validate_suppression_targets(rules: list[Rule]) -> None:
    """Every `suppresses` target must be a soft-authority review rule.

    Cross-rule, so it runs at ruleset load rather than per-document. Three ways
    an allow rule could otherwise widen its own blast radius:

    * **naming a block** — the entire point of a block is that nothing waives it;
    * **naming a hard review** — hard authority is what puts a rule out of reach
      of an operator's blanket session policy, and an allow rule must not do
      what the floor may not. This is the chain Phase 3a's class-1 rules are
      meant to close: AIRA-010 flagged a credential read and
      `skip_reason: lenient` approved it anyway. An allow rule suppressing a
      hard review would restore exactly that.

      **That floor guarantee is younger than this docstring.** Until
      `review_authority` was put on the scan response (Phase 3a), `authority`
      reached no component that could act on it: the plugin's floor is keyed on
      `review_severity`, derived from `meta.severity` alone, so hard and soft
      reviews were waived identically. Authority gated L3 downgrade and this
      suppression check and nothing else. A scan host older than that release
      still behaves the old way;
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


def _collect_args_match_keys(node: Any, *, negated: bool = False) -> set[str]:
    """Every `args_match` key, and every condition kind, in **positive** position.

    ``negated`` tracks whether we are inside a `none:`, and keys found there are
    **not** collected. Without that, an allow rule satisfies the required
    constraints by *negating* them:

        action: allow
        condition:
          none:
            sequence:
              - tool: exec
                args_match: {_shape.privileged: "^false$", …}

    which reads "allow when it is **not** the case that this is unprivileged" —
    the exact inverse of the constraint, and the guard counted it as satisfied.
    The guard is the only thing between a mistaken allow rule and a fail-open
    publish, so a shape that satisfies it while meaning the opposite has to be
    unrepresentable.

    Condition kinds are included because the allow-rule guard is the only thing
    standing between a mistaken rule and a fail-open publish, and it worked by
    walking `args_match` keys alone. A constraint expressed as a *condition*
    — `paths:` is the first — was therefore invisible to it: not exploitable
    today, since both required constraints are shape booleans that `paths:`
    cannot supply, but the guard would have silently stopped covering the
    moment a required constraint became path-shaped. Reporting the kind keeps
    the guard's view of a rule complete.
    """
    keys: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "args_match" and isinstance(value, dict):
                if not negated:
                    # An `args_match` key is never a condition kind. Reserving
                    # the prefix stops a rule satisfying a condition-shaped
                    # requirement with an arg *named* `condition:paths` — the
                    # collision the prefix was chosen to prevent, one level up
                    # from the one its comment anticipated. Harmless while
                    # every required constraint was a shape boolean; a hole the
                    # moment D23 made one of them a condition.
                    keys.update(
                        part.strip()
                        for raw in value
                        for part in str(raw).split("|")
                        if not part.strip().startswith(CONDITION_KEY_PREFIX)
                    )
                continue
            if key in _CONDITION_KINDS and not negated:
                keys.add(f"{CONDITION_KEY_PREFIX}{key}")
            # Parity, not a flag: `none: {none: …}` is a double negative and
            # lands back in positive position.
            keys |= _collect_args_match_keys(
                value, negated=(not negated) if key == "none" else negated
            )
    elif isinstance(node, list):
        for item in node:
            keys |= _collect_args_match_keys(item, negated=negated)
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
    args_match = validate_args_match(slot.get("args_match"))
    return SequenceSlot(
        tool=tool,
        status=slot.get("status", "any"),
        args_match=args_match,
        result_flags=slot.get("result_flags"),
    )


#: Sub-predicates of a `paths:` condition, each an optional regex.
#: `segment_head` is open text like `path`, not a closed vocabulary: heads come
#: from real commands, so "can this ever match?" is not decidable for it.
PATHS_PREDICATES: tuple[str, ...] = ("location", "role", "path", "segment_head")
PATHS_QUANTIFIERS: tuple[str, ...] = ("any", "every", "none")

#: `location` and `role` are matched against a **closed** vocabulary, which
#: makes "can this predicate ever match anything?" a decidable question — so it
#: is answered here rather than discovered by a rule that silently never fires.
#: `path` matches raw text and is open, so it cannot be checked this way.
_PATHS_VOCABULARY: dict[str, tuple[tuple[str, ...], bool]] = {
    # (vocabulary, may the joined value be empty)
    "location": (LOCATION_CLASSES, False),  # every path carries a location
    "role": (ROLE_CLASSES, True),  # an ordinary file has no role
}


def _can_ever_match(pattern: str, vocabulary: tuple[str, ...], allow_empty: bool) -> bool:
    """Whether ``pattern`` matches any value the field can actually hold.

    Values are newline-joined subsets of a closed vocabulary, so every possible
    value can be enumerated — 31 for locations, 8 for roles. Cheap at compile,
    and it catches the mistake that has no other symptom: a predicate written
    against the wrong vocabulary. `location: "${sensitive_path}"` and
    `location: "scratch"` both compile, and neither can match any location a
    path will ever carry.
    """
    candidates = [""] if allow_empty else []
    for size in range(1, len(vocabulary) + 1):
        candidates.extend("\n".join(c) for c in itertools.combinations(vocabulary, size))
    flags = re.IGNORECASE | re.DOTALL
    return any(re.search(pattern, candidate, flags) for candidate in candidates)


def _compile_paths(raw: Any) -> PathsCondition:
    r"""Compile and validate a `paths:` condition.

    Refuses more than it strictly must, because this is the condition that
    exists to stop a whole class of mistake and an inert one would be worse
    than none:

    * the quantifier is **required** — see :class:`PathsCondition`;
    * at least one sub-predicate is required, since a `paths:` with none asks
      only "are there any paths at all", which `every`/`none` answer
      confusingly and which a reader will misread as a path constraint;
    * every sub-predicate goes through :func:`validate_args_match`, so macros
      expand, bad regexes are refused, and the `\A` anchoring rule (D19)
      applies here too.
    """
    if not isinstance(raw, dict):
        raise InvalidArgsMatchError(f"`paths:` must be a mapping, got {raw!r}")
    quantifier = raw.get("quantifier")
    if quantifier not in PATHS_QUANTIFIERS:
        raise InvalidArgsMatchError(
            "`paths:` requires an explicit `quantifier` of "
            f"{', '.join(PATHS_QUANTIFIERS)} — got {quantifier!r}. There is no "
            "default on purpose: an unstated quantifier over a set of paths "
            "reads as both 'some' and 'every', and those give opposite answers "
            "on the same command"
        )
    unknown = set(raw) - {"quantifier", *PATHS_PREDICATES}
    if unknown:
        raise InvalidArgsMatchError(
            f"unknown `paths:` key(s) {sorted(unknown)}; "
            f"valid: quantifier, {', '.join(PATHS_PREDICATES)}"
        )
    predicates = {name: str(raw[name]) for name in PATHS_PREDICATES if raw.get(name) is not None}
    if not predicates:
        raise InvalidArgsMatchError(
            "`paths:` needs at least one of "
            f"{', '.join(PATHS_PREDICATES)} — a quantifier alone only asks "
            "whether the command references any path at all"
        )
    expanded = validate_args_match(predicates) or {}
    for name, (vocabulary, allow_empty) in _PATHS_VOCABULARY.items():
        pattern = expanded.get(name)
        if pattern is None:
            continue
        if not _can_ever_match(pattern, vocabulary, allow_empty):
            raise InvalidArgsMatchError(
                f"`paths:` {name} pattern {predicates[name]!r} cannot match any "
                f"value {name} will ever hold ({', '.join(vocabulary)}). A "
                "predicate written against the wrong vocabulary compiles "
                "cleanly and makes the rule permanently inert — usually a "
                f"${{macro}} meant for `path:`, or a misspelled {name} name"
            )
    return PathsCondition(quantifier=quantifier, **expanded)


def _compile_condition(node: dict[str, Any]) -> ConditionNode:
    if "intent_kind" in node:
        return IntentKindCondition(kind=node["intent_kind"])
    if "paths" in node:
        return _compile_paths(node["paths"])
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
    except (InvalidArgsMatchError, UnknownMacroError) as exc:
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
