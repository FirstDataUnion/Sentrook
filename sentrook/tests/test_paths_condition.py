"""Slice 2C — per-path structure and the `paths:` condition (F27).

F27 was **two** bugs wearing one coat, and the tests here are organised around
that split because fixing only the visible half is how it survived review once
already.

1. **Axis conflation.** ``path_classes`` answered "where is this path" and
   "what does it hold" with one flat vocabulary, and its residue rule let a
   role match erase the location. ``~/.ssh/id_rsa`` had *no* location.
2. **An implicit quantifier.** "path class other than tmp/workspace" reads as
   both "some path" and "every path". The two give **opposite** answers on the
   same command, and the first regression test written for this passed with the
   bug reintroduced because it silently picked the wrong one.

So: structure fixes (1), and a required quantifier keyword fixes (2).
"""

from __future__ import annotations

import re

import pytest

from sentrook.layers.exec_shape import derive_exec_shape
from sentrook.layers.l2_match import _match_paths
from sentrook.layers.pass_kind import L2PassKind
from sentrook.layers.path_classes import (
    LOCATION_CLASSES,
    PATH_CLASSES,
    ROLE_CLASSES,
    SCRATCH_LOCATIONS,
    ExecPath,
    classify_path_detail,
    derive_path_roles,
)
from sentrook.planir import PlanIR
from sentrook.rules.compiler import (
    CONDITION_KEY_PREFIX,
    UNMATCHABLE_SHAPE_FIELDS,
    InvalidArgsMatchError,
    _collect_args_match_keys,
    _compile_paths,
    compile_rule,
    validate_args_match,
)
from sentrook.rules.models import PathsCondition


def _plan(command: str, *, tool: str = "exec") -> PlanIR:
    plan = PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "fixture:paths",
            "intent": "check",
            "intent_kind": "user",
            "steps": [
                {"id": "s1", "tool": tool, "status": "pending", "args": {"command": command}}
            ],
            "metadata": {"adapter": "fixture", "hook": "before_tool_call"},
        }
    )
    from sentrook.layers.exec_shape import attach_exec_shapes

    attach_exec_shapes(plan)
    return plan


def _matches(command: str, **kwargs: str) -> bool:
    return _match_paths(PathsCondition(**kwargs), _plan(command)).matched


# --------------------------------------------------------------------------
# Bug 1 — the two axes are separate, and location is never empty
# --------------------------------------------------------------------------


def test_the_two_axes_partition_the_vocabulary() -> None:
    assert not set(LOCATION_CLASSES) & set(ROLE_CLASSES)
    assert set(LOCATION_CLASSES) | set(ROLE_CLASSES) == set(PATH_CLASSES), (
        "a class was added without deciding which axis it is on; a rule that "
        "reads a class exculpatorily needs to know"
    )
    assert SCRATCH_LOCATIONS <= set(LOCATION_CLASSES)


@pytest.mark.parametrize(
    "path,locations,roles",
    [
        # The F27 case: scratch *location*, sensitive *name*. Both, separately.
        ("/tmp/openclaw-auth-intake", ["tmp"], ["sensitive"]),
        # Previously had no location at all, because the role erased it.
        ("/home/node/.ssh/id_rsa", ["other"], ["sensitive"]),
        ("/home/node/.bashrc", ["other"], ["persistence"]),
        ("/etc/shadow", ["system"], ["sensitive"]),
        ("/home/node/.openclaw/exec-approvals.json", ["openclaw"], ["agent_config"]),
        # Nested containers are both locations; neither is wrong.
        ("/home/node/.openclaw/workspace/a.py", ["openclaw", "workspace"], []),
        ("/srv/data.csv", ["other"], []),
    ],
)
def test_locations_and_roles_are_reported_independently(
    path: str, locations: list[str], roles: list[str]
) -> None:
    assert classify_path_detail(path) == (locations, roles)


def test_every_path_carries_a_location() -> None:
    """The structural fix. `other` is the location residue, not a global one.

    Under the old flat set, `other` was added only when *nothing* matched — so
    any path with a role had no location, and a "was every path in scratch?"
    test read it as vacuously true.
    """
    for path in ("/home/node/.ssh/id_rsa", "/home/node/.bashrc", "/etc/shadow", "/x"):
        locations, _ = classify_path_detail(path)
        assert locations, path
        assert set(locations) <= set(LOCATION_CLASSES), path


@pytest.mark.parametrize(
    "command,scratch_only",
    [
        # Both F27 failure directions, as one table.
        ("rm -rf /tmp/bh_corpus", True),  # literal reading called this non-scratch
        ("rm -rf /tmp/openclaw-auth-intake", True),  # ...and this, wrongly
        ("rm -rf /home/node/.ssh", False),  # location-only reading missed this
        ("rm -rf /home/node/.bashrc", False),  # ...and this
        ("rm -rf /home/node/.openclaw /var/lib/docker", False),
    ],
)
def test_scratch_is_a_location_question_and_now_has_one_answer(
    command: str, scratch_only: bool
) -> None:
    paths = derive_exec_shape(command).paths
    assert paths, command
    assert all(p.is_scratch for p in paths) is scratch_only


# --------------------------------------------------------------------------
# Bug 2 — the quantifier is explicit, required, and non-vacuous
# --------------------------------------------------------------------------


def test_quantifier_is_required_with_no_default() -> None:
    with pytest.raises(InvalidArgsMatchError, match="requires an explicit `quantifier`"):
        _compile_paths({"role": "sensitive"})
    with pytest.raises(InvalidArgsMatchError, match="requires an explicit `quantifier`"):
        _compile_paths({"quantifier": "some", "role": "sensitive"})


def test_a_predicate_is_required() -> None:
    """A bare quantifier asks only "are there paths", which reads as more."""
    with pytest.raises(InvalidArgsMatchError, match="at least one of"):
        _compile_paths({"quantifier": "any"})


def test_unknown_keys_are_refused() -> None:
    with pytest.raises(InvalidArgsMatchError, match="unknown `paths:` key"):
        _compile_paths({"quantifier": "any", "rolls": "sensitive"})


def test_predicates_go_through_the_full_args_match_validation() -> None:
    """Macros expand, bad regexes are refused, and D19's anchoring rule applies."""
    compiled = _compile_paths({"quantifier": "any", "path": "${sensitive_path}"})
    assert "${" not in compiled.path
    with pytest.raises(InvalidArgsMatchError, match="unanchored lookahead"):
        _compile_paths({"quantifier": "any", "path": "(?=.*a)(?=.*b)"})
    with pytest.raises(InvalidArgsMatchError, match="not a valid Python regex"):
        _compile_paths({"quantifier": "any", "path": "("})


@pytest.mark.parametrize(
    "quantifier,expected",
    [("any", False), ("every", False), ("none", True)],
)
def test_empty_path_set_semantics_are_stated_not_inherited(quantifier: str, expected: bool) -> None:
    """`every` is **non-vacuous on purpose**.

    Standard "for all" over an empty set is true, and that vacuous truth is
    exactly how F27's false negative happened: a command with no recognised
    paths read as "every path is in scratch space" and suppressed a
    destructive-command review. A rule asking `every` means "there are paths,
    and they all match".
    """
    assert _matches("ls -la", quantifier=quantifier, role="sensitive") is expected


def test_quantifiers_discriminate_on_a_mixed_command() -> None:
    command = "cp ~/.ssh/id_rsa /tmp/k"
    assert _matches(command, quantifier="any", role="sensitive") is True
    assert _matches(command, quantifier="every", role="sensitive") is False
    assert _matches(command, quantifier="none", role="sensitive") is False
    # ...and the same three over a command where the role is on every path.
    both = "cp ~/.ssh/id_rsa ~/.ssh/id_ed25519"
    assert _matches(both, quantifier="every", role="sensitive") is True


def test_the_class_five_question_now_has_one_correct_expression() -> None:
    """ "Is any path located outside scratch space?" — the question F27 broke."""
    outside = {"quantifier": "any", "location": r"\A(?!.*(?:tmp|workspace))"}
    assert _matches("rm -rf /home/node/.ssh", **outside) is True
    assert _matches("rm -rf /home/node/.openclaw /var/lib/docker", **outside) is True
    assert _matches("rm -rf /home/node/.bashrc", **outside) is True
    # ...and does not fire on scratch cleanup, however secret the name looks.
    assert _matches("rm -rf /tmp/openclaw-auth-intake", **outside) is False
    assert _matches("rm -rf /tmp/bh_corpus", **outside) is False


# --------------------------------------------------------------------------
# Sub-predicates and scoping
# --------------------------------------------------------------------------


def test_sub_predicates_are_anded_per_path_not_across_paths() -> None:
    """The distinction a flat union cannot make: both properties on **one** path."""
    # One path is sensitive (in scratch), another is outside scratch — but no
    # single path is both.
    command = "cp /tmp/openclaw-auth-intake /var/lib/docker/x"
    assert (
        _matches(
            command,
            quantifier="any",
            role="sensitive",
            location=r"\A(?!.*(?:tmp|workspace))",
        )
        is False
    ), "sub-predicates must be ANDed on the same path, not satisfied by different ones"
    # ...and a command where one path really is both.
    assert (
        _matches(
            "cat /home/node/.ssh/id_rsa",
            quantifier="any",
            role="sensitive",
            location=r"\A(?!.*(?:tmp|workspace))",
        )
        is True
    )


def test_raw_path_is_matchable() -> None:
    """Carried so a question nobody has asked yet needs no engine change."""
    assert _matches("cat /home/node/.ssh/config", quantifier="any", path=r"\.ssh/") is True
    assert _matches("cat /home/node/notes.md", quantifier="any", path=r"\.ssh/") is False


def test_a_non_exec_step_has_no_paths_and_fails_closed() -> None:
    plan = _plan("irrelevant", tool="read")
    assert _match_paths(PathsCondition(quantifier="any", role="sensitive"), plan).matched is False
    assert _match_paths(PathsCondition(quantifier="every", role="sensitive"), plan).matched is False


def test_outcome_carries_the_new_pass_kind_and_the_step_id() -> None:
    outcome = _match_paths(
        PathsCondition(quantifier="any", role="sensitive"), _plan("cat ~/.ssh/id_rsa")
    )
    assert outcome.matched and outcome.pass_id is L2PassKind.PATHS
    assert outcome.matched_step_ids == ["s1"]
    assert "any of 1 path(s)" in outcome.reason


# --------------------------------------------------------------------------
# The whole-command defence the per-path view structurally cannot provide
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,roles",
    [
        ("cat id_ed25519", ["sensitive"]),  # bare basename: not path-like at all
        ("echo 'x' >> ~/.bashrc", ["persistence"]),  # redirect target: not in argv
        ("crontab -l", ["persistence"]),  # a mechanism, not a path
        ("ls -la", []),
    ],
)
def test_path_roles_sees_what_the_per_path_view_cannot(command: str, roles: list[str]) -> None:
    """§1.3's whole-command defence, in its own field.

    Each of these references sensitive or durable material and yields **zero**
    extractable paths. An allow rule must therefore establish "references no
    sensitive material" with `_shape.path_roles`, **not** with `paths:` and a
    `none` quantifier — the latter is vacuously satisfied here.
    """
    shape = derive_exec_shape(command)
    assert shape.path_roles == roles
    assert derive_path_roles(command) == roles
    if roles:
        assert shape.paths == [], "these commands have no extractable paths, by construction"
        assert _matches(command, quantifier="none", role="sensitive|persistence") is True


def test_the_roll_up_includes_both_views() -> None:
    """`path_classes` is derived, so it cannot disagree with what rules see."""
    shape = derive_exec_shape("cp ~/.ssh/id_rsa /tmp/k")
    for role in shape.path_roles:
        assert role in shape.path_classes
    for path in shape.paths:
        assert set(path.locations) <= set(shape.path_classes)
        assert set(path.roles) <= set(shape.path_classes)


# --------------------------------------------------------------------------
# Fields a rule may not name
# --------------------------------------------------------------------------


@pytest.mark.parametrize("field", sorted(UNMATCHABLE_SHAPE_FIELDS))
def test_unmatchable_shape_fields_are_refused_with_a_reason(field: str) -> None:
    """A field that stringifies to "" is a rule silently reduced to a no-op.

    `_shape.segments` shipped in this state: the compiler *validated the name*,
    which reads as endorsement, and any pattern but `^$` could never match.
    """
    with pytest.raises(InvalidArgsMatchError, match="cannot be matched"):
        validate_args_match({f"_shape.{field}": "anything"})


def test_the_unmatchable_list_is_exactly_the_structured_fields() -> None:
    """Bound to behaviour: anything that stringifies to "" must be refused."""
    from sentrook.layers.l2_match import _stringify_shape_value

    wire = derive_exec_shape("cat ~/.ssh/id_rsa | grep x").to_dict()
    for name, value in wire.items():
        empty = _stringify_shape_value(value) == "" and value not in ([], "", False)
        if empty:
            assert name in UNMATCHABLE_SHAPE_FIELDS, (
                f"_shape.{name} stringifies to '' but is still matchable — a rule "
                "naming it would compile and never fire"
            )


def test_path_classes_is_not_matchable_and_says_why() -> None:
    with pytest.raises(InvalidArgsMatchError, match="implicit quantifier"):
        validate_args_match({"_shape.path_classes": "sensitive"})


def test_path_roles_is_matchable() -> None:
    """The one path field a rule *should* read directly — no quantifier implied."""
    assert validate_args_match({"_shape.path_roles": "sensitive"})


# --------------------------------------------------------------------------
# The allow-rule guard must see condition kinds
# --------------------------------------------------------------------------


def test_the_allow_guard_sees_condition_kinds() -> None:
    """Otherwise a constraint expressed as a condition is invisible to it.

    Not exploitable today — both required constraints are shape booleans that
    `paths:` cannot supply — but the guard would have stopped covering the
    moment a required constraint became path-shaped, and it is the only thing
    between a mistaken allow rule and a fail-open publish.
    """
    condition = {
        "all": [
            {"paths": {"quantifier": "none", "role": "sensitive"}},
            {"sequence": [{"tool": "exec", "args_match": {"_shape.privileged": "^false$"}}]},
        ]
    }
    keys = _collect_args_match_keys(condition)
    assert f"{CONDITION_KEY_PREFIX}paths" in keys
    assert f"{CONDITION_KEY_PREFIX}sequence" in keys
    assert "_shape.privileged" in keys


def test_paths_cannot_be_used_to_skip_a_required_allow_constraint() -> None:
    doc = {
        "rule": "T-ALLOW",
        "meta": {"action": "allow", "suppresses": ["AIRA-010"]},
        "condition": {"all": [{"paths": {"quantifier": "none", "role": "sensitive"}}]},
    }
    with pytest.raises(ValueError, match="_shape.privileged"):
        compile_rule(doc)


def test_every_declared_condition_kind_actually_compiles() -> None:
    """`_CONDITION_KINDS` is hand-declared; this stops it drifting from reality."""
    from sentrook.rules.compiler import _CONDITION_KINDS, _compile_condition

    samples = {
        "intent_kind": {"intent_kind": "user"},
        "pending_tool": {"pending_tool": "exec"},
        "paths": {"paths": {"quantifier": "any", "role": "sensitive"}},
        "sequence": {"sequence": [{"tool": "exec"}]},
        "sequence_with_gap": {"sequence_with_gap": [{"tool": "exec"}]},
        "all": {"all": [{"pending_tool": "exec"}]},
        "any": {"any": [{"pending_tool": "exec"}]},
        "none": {"none": {"pending_tool": "exec"}},
    }
    assert set(samples) == set(_CONDITION_KINDS)
    for node in samples.values():
        _compile_condition(node)


def test_a_paths_rule_compiles_and_runs_end_to_end() -> None:
    """The worked example the dialect doc documents, pinned here."""
    from sentrook.layers.l2_match import MatcherConfig, evaluate_rule

    rule = compile_rule(
        {
            "rule": "T-CLASS5",
            "meta": {"name": "destroy outside scratch", "action": "review", "authority": "hard"},
            "condition": {
                "all": [
                    {"pending_tool": "exec"},
                    {"paths": {"quantifier": "any", "location": r"\A(?!.*(?:tmp|workspace))"}},
                ]
            },
        }
    )
    config = MatcherConfig()
    assert evaluate_rule(rule, _plan("rm -rf /home/node/.ssh"), config).matched is True
    assert evaluate_rule(rule, _plan("rm -rf /tmp/openclaw-auth-intake"), config).matched is False


def test_regex_flags_are_the_matchers_own() -> None:
    """Sub-predicates go through `match_text_with_normalization`, like everything else."""
    assert _matches("cat /home/node/.SSH/ID_RSA", quantifier="any", path=r"id_rsa") is True
    assert re.search("x", "X", re.IGNORECASE)


def test_the_documented_yaml_form_compiles_and_behaves() -> None:
    r"""Pins the escaping in docs/yaira-matcher-dialect.md and the taxonomy.

    A rule author copies YAML, not a Python raw string, and `"\\A"` in a
    double-quoted YAML scalar is what produces the regex `\A`. Getting that
    wrong yields a pattern that compiles and matches nothing — F20's class, in
    the documentation rather than the code.
    """
    import yaml

    from sentrook.layers.l2_match import MatcherConfig, evaluate_rule

    document = yaml.safe_load(
        """
rule: T-DOC
meta:
  name: destroys outside scratch
  action: review
  authority: hard
condition:
  all:
    - pending_tool: exec
    - paths:
        quantifier: any
        location: "\\\\A(?!.*(?:tmp|workspace))"
"""
    )
    # The YAML scalar really did produce the anchored regex, not a literal.
    assert document["condition"]["all"][1]["paths"]["location"] == r"\A(?!.*(?:tmp|workspace))"

    rule = compile_rule(document)
    config = MatcherConfig()
    assert evaluate_rule(rule, _plan("rm -rf /home/node/.ssh"), config).matched is True
    assert evaluate_rule(rule, _plan("rm -rf /var/lib/docker"), config).matched is True
    assert evaluate_rule(rule, _plan("rm -rf /tmp/openclaw-auth-intake"), config).matched is False
    assert evaluate_rule(rule, _plan("ls -la"), config).matched is False


# --------------------------------------------------------------------------
# L1 candidacy — the hazard §1.2 names explicitly
# --------------------------------------------------------------------------


def _scan(rule, command: str):
    from sentrook.config import L3Policy, ScannerConfig
    from sentrook.scan import scan_plan

    return scan_plan(_plan(command), [rule], ScannerConfig(l3_policy=L3Policy.OFF))


def _class5_rule(condition: dict):
    return compile_rule(
        {
            "rule": "T-CLASS5",
            "meta": {"name": "destroys outside scratch", "action": "review", "authority": "hard"},
            "condition": condition,
        }
    )


_OUTSIDE_SCRATCH = {"quantifier": "any", "location": r"\A(?!.*(?:tmp|workspace))"}


@pytest.mark.parametrize(
    "name,condition,pass_kind",
    [
        (
            "with a sibling tool condition",
            {"all": [{"pending_tool": "exec"}, {"paths": _OUTSIDE_SCRATCH}]},
            # Wrapped in a combinator the outcome reports the combinator, the
            # same as every other condition kind.
            L2PassKind.ALL,
        ),
        ("paths alone", {"paths": _OUTSIDE_SCRATCH}, L2PassKind.PATHS),
    ],
)
def test_a_paths_rule_fires_through_the_real_scan_path(
    name: str, condition: dict, pass_kind: L2PassKind
) -> None:
    """Through `scan_plan`, **not** `evaluate_rule` — the distinction is the bug.

    §1.2: "a rule could be skipped at L1 while matching at L2 — a detection
    silently lost with nothing in the trace." `_plan_satisfies_rule` ends in
    `return False`, so a condition kind L1 does not recognise makes every rule
    containing one permanently uncandidatable. `paths:` shipped that way inside
    this very slice, and the first test written for it passed because it called
    `evaluate_rule` directly and never went through L1.
    """
    rule = _class5_rule(condition)
    fired = _scan(rule, "rm -rf /home/node/.ssh")
    assert fired.decision == "review", name
    assert [m.id for m in (fired.matched_rules or [])] == ["T-CLASS5"], name
    assert [m.pass_id for m in fired.matched_rules] == [pass_kind], name

    quiet = _scan(rule, "rm -rf /tmp/openclaw-auth-intake")
    assert quiet.decision == "allow", name
    assert not (quiet.matched_rules or []), name


def test_a_paths_rule_is_indexed_under_the_exec_tools() -> None:
    """`paths:` implies an exec step, so it contributes that tool requirement."""
    from sentrook.layers.exec_shape import EXEC_TOOLS
    from sentrook.layers.l1_index import build_l1_index

    index = build_l1_index([_class5_rule({"paths": _OUTSIDE_SCRATCH})])
    assert set(index.by_tool) == set(EXEC_TOOLS), (
        "a rule whose only condition is `paths:` must still be indexed, or it "
        "is never a candidate and never fires"
    )


def test_l1_and_l2_agree_on_every_condition_kind() -> None:
    """No condition kind may be matchable at L2 and invisible to L1.

    Bound to `_CONDITION_KINDS`, so adding a kind without teaching L1 about it
    fails here rather than becoming a detection that quietly never fires.
    """
    from sentrook.layers.l1_index import _plan_satisfies_rule
    from sentrook.rules.compiler import _CONDITION_KINDS, _compile_condition

    samples = {
        "intent_kind": {"intent_kind": "user"},
        "pending_tool": {"pending_tool": "exec"},
        "paths": {"paths": {"quantifier": "any", "role": "sensitive"}},
        "sequence": {"sequence": [{"tool": "exec"}]},
        "sequence_with_gap": {"sequence_with_gap": [{"tool": "exec"}]},
        "all": {"all": [{"pending_tool": "exec"}]},
        "any": {"any": [{"pending_tool": "exec"}]},
        "none": {"none": {"pending_tool": "exec"}},
    }
    assert set(samples) == set(_CONDITION_KINDS)
    for kind, node in samples.items():
        compiled = _compile_condition(node)
        satisfied = _plan_satisfies_rule({"exec"}, compiled, intent_kind="user")
        assert satisfied is True, (
            f"condition kind {kind!r} is not satisfiable at L1 on an exec plan; "
            "every rule containing one would be skipped before L2 ever ran"
        )


def test_is_scratch_agrees_with_the_documented_rule_idiom() -> None:
    r"""One concept, two expressions — they must not drift.

    `ExecPath.is_scratch` is the Python view; `location: "\A(?!.*(?:tmp|
    workspace))"` is what a rule writes for the same question. They disagreed on
    nested locations: `~/.openclaw/workspace/a.py` is both `openclaw` and
    `workspace`, and an "every location is scratch" reading called it
    non-scratch — which would have fired a destructive-command review on
    ordinary workspace cleanup.

    Checked over every location combination the classifier can produce, not a
    hand-picked few, so a new location class cannot reopen the gap.
    """
    import itertools

    from sentrook.layers.path_classes import LOCATION_CLASSES, SCRATCH_LOCATIONS

    outside = re.compile(r"\A(?!.*(?:tmp|workspace))", re.IGNORECASE | re.DOTALL)
    for size in range(1, len(LOCATION_CLASSES) + 1):
        for combo in itertools.combinations(LOCATION_CLASSES, size):
            path = ExecPath(raw="/x", locations=list(combo))
            rule_says_outside = bool(outside.search("\n".join(combo)))
            assert path.is_scratch is not rule_says_outside, combo
    # ...and the concrete case that exposed it.
    locations, roles = classify_path_detail("/home/node/.openclaw/workspace/a.py")
    assert locations == ["openclaw", "workspace"]
    assert ExecPath(raw="/x", locations=locations, roles=roles).is_scratch is True
    assert SCRATCH_LOCATIONS == {"tmp", "workspace"}


def test_segment_is_the_segment_not_the_path_ordinal() -> None:
    """The field must mean what it is named.

    It first carried the path's *ordinal* — so both paths of `cp a b` claimed
    different segments while sharing one, and the golden fixture pinned that.
    A field whose name and contents disagree is a trap for whoever reads it
    next, which for `segment` is Phase 4's dataflow work.
    """
    same = derive_exec_shape("cp ~/.ssh/id_rsa /tmp/k").paths
    assert [p.segment for p in same] == [0, 0]
    split = derive_exec_shape("cat ~/.ssh/id_rsa && rm -rf /var/lib/docker").paths
    assert [p.segment for p in split] == [0, 1]


def test_a_path_named_twice_in_one_segment_is_one_path() -> None:
    """Deduplication is **per segment**, not per command.

    This asserted the opposite — one path for the whole command, attributed
    where it first appeared — and that was a reasonable choice while nothing
    could ask *which head* touched a path. `segment_head` made it a false
    negative: `ls -la ~/.ssh && rm -rf ~/.ssh` kept only the `ls` occurrence,
    so a rule asking for "a path outside scratch belonging to a destructive
    head" could not see the destruction at all.

    The same path in two segments is two references because they are two
    different acts. Within one segment it is still one path.
    """
    across = derive_exec_shape("cat /a && rm /a").paths
    assert [(p.raw, p.segment) for p in across] == [("/a", 0), ("/a", 1)]

    within = derive_exec_shape("cp /a /b /a").paths
    assert [(p.raw, p.segment) for p in within] == [("/a", 0), ("/b", 0)]


def test_the_duplicate_does_not_change_a_quantifier_answer() -> None:
    """Per-segment dedup grows the path list, so check it moves no quantifier.

    `any` and `none` are insensitive to a repeated identical entry, and `every`
    is too — but `every` is the one with a non-vacuous empty case, so assert it
    rather than reason about it.
    """
    from sentrook.layers.l2_match import _match_paths
    from sentrook.planir import PlanIR, PlanStep
    from sentrook.rules.models import PathsCondition

    plan = PlanIR(
        version="1.0",
        run_id="fixture:dup",
        steps=[
            PlanStep(
                id="s1",
                tool="exec",
                status="pending",
                args={"command": "ls -la /tmp/x && rm -rf /tmp/x"},
            )
        ],
    )
    from sentrook.layers.exec_shape import attach_exec_shapes

    attach_exec_shapes(plan)
    for quantifier, expected in (("any", True), ("every", True), ("none", False)):
        node = PathsCondition(quantifier=quantifier, location="tmp")
        assert _match_paths(node, plan).matched is expected, quantifier


def test_a_predicate_that_can_never_match_is_refused() -> None:
    """`location` and `role` draw from closed vocabularies, so this is decidable.

    A predicate written against the wrong vocabulary compiles cleanly and makes
    the rule **permanently inert** — no error, no match, no symptom. That is
    F20's class, and the two realistic mistakes are a `${macro}` meant for
    `path:` and a misspelled class name. Both are caught by asking whether the
    pattern matches any value the field can actually hold.
    """
    with pytest.raises(InvalidArgsMatchError, match="cannot match any value"):
        _compile_paths({"quantifier": "any", "location": "${sensitive_path}"})
    with pytest.raises(InvalidArgsMatchError, match="cannot match any value"):
        _compile_paths({"quantifier": "any", "location": "scratch"})
    with pytest.raises(InvalidArgsMatchError, match="cannot match any value"):
        _compile_paths({"quantifier": "any", "role": "tmp"})  # a location, not a role


def test_the_real_idioms_all_survive_the_vocabulary_check() -> None:
    """The check must not refuse the patterns the docs tell people to write."""
    for predicates in (
        {"quantifier": "any", "location": r"\A(?!.*(?:tmp|workspace))"},
        {"quantifier": "every", "location": "workspace"},
        {"quantifier": "any", "role": "sensitive"},
        {"quantifier": "none", "role": "sensitive|persistence"},
        {"quantifier": "none", "role": "^$"},  # roles may legitimately be empty
        {"quantifier": "any", "path": "${sensitive_path}"},  # open vocabulary, unchecked
    ):
        _compile_paths(predicates)


def test_the_vocabulary_check_enumerates_combinations_not_single_values() -> None:
    """A path carries more than one location, so the joined form must be tested.

    `~/.openclaw/workspace/a.py` is `openclaw\\nworkspace`. A check that only
    tried single values would wrongly refuse a predicate that matches only the
    joined form.
    """
    # Matches only when *both* are present — legal, and single-value testing
    # would have called it unmatchable.
    _compile_paths({"quantifier": "any", "location": r"openclaw\nworkspace"})


# --------------------------------------------------------------------------
# `segment_head` — relating a path to the head that acts on it


def _shaped(command: str):
    from sentrook.layers.exec_shape import attach_exec_shapes
    from sentrook.planir import PlanIR, PlanStep

    plan = PlanIR(
        version="1.0",
        run_id="fixture:segment-head",
        steps=[PlanStep(id="s1", tool="exec", status="pending", args={"command": command})],
    )
    attach_exec_shapes(plan)
    return plan


def _destructive_rule(segment_head: str | None = None):
    from sentrook.rules.compiler import compile_rule

    paths: dict = {"quantifier": "any", "location": r"\A(?!.*(?:tmp|workspace))"}
    if segment_head is not None:
        paths["segment_head"] = segment_head
    return compile_rule(
        {
            "rule": "T-DESTROY",
            "meta": {"action": "review"},
            "condition": {
                "all": [
                    {
                        "sequence": [
                            {
                                "tool": "exec",
                                "status": "pending",
                                "args_match": {
                                    "_shape.heads": r"(?:\A|\n)(?:rm|shred|truncate)(?:\n|\Z)"
                                },
                            }
                        ]
                    },
                    {"paths": paths},
                ]
            },
        }
    )


DESTRUCTIVE = r"(?:\A|\n)?(?:rm|shred|truncate)\Z"

SEGMENT_CASES = [
    ("rm -rf /home/node/.openclaw /var/lib/docker", True, "destroys an agent home"),
    ("rm -rf /tmp/scratch", False, "confined to scratch"),
    # The false positive `segment_head` exists for: the destructive head targets
    # scratch, and an unrelated path in another segment satisfied the location.
    ("cat /etc/hosts && rm -rf /tmp/scratch", False, "unrelated path, rm in scratch"),
    ("ls /var/log && rm -rf /tmp/x", False, "unrelated path, rm in scratch"),
    # `cd` rebase — the false *negative* a strictly per-segment reading creates.
    ("cd /srv/app && rm -rf logs", True, "cd rebase: destroys /srv/app/logs"),
    ("cd /home/node/.ssh && rm -rf id_rsa", True, "cd rebase into a key directory"),
    ("cd /tmp/x && rm -rf y", False, "cd rebase into scratch"),
    # Ordering: a `cd` after the destructive head does not rebase it.
    ("rm -rf /tmp/x && cd /srv/app", False, "cd after the rm must not rebase it"),
    ("rm -rf /tmp/build /home/node/.openclaw/agents", True, "one path outside scratch"),
]


@pytest.mark.parametrize("command,expected,why", SEGMENT_CASES)
def test_segment_head_relates_a_path_to_the_head_that_acts_on_it(
    command: str, expected: bool, why: str
) -> None:
    from sentrook.layers.l2_match import MatcherConfig, evaluate_rule

    rule = _destructive_rule(DESTRUCTIVE)
    assert evaluate_rule(rule, _shaped(command), MatcherConfig()).matched is expected, why


def test_without_segment_head_the_two_halves_are_unrelated() -> None:
    """The defect, kept as a test so the fix cannot be quietly undone.

    Without the predicate the rule reads "a destructive head is somewhere in the
    command" AND "some path somewhere is outside scratch", with nothing relating
    them — F27's implicit quantifier one level up.
    """
    from sentrook.layers.l2_match import MatcherConfig, evaluate_rule

    loose = _destructive_rule(None)
    tight = _destructive_rule(DESTRUCTIVE)
    command = "cat /etc/hosts && rm -rf /tmp/scratch"
    assert evaluate_rule(loose, _shaped(command), MatcherConfig()).matched is True
    assert evaluate_rule(tight, _shaped(command), MatcherConfig()).matched is False


def test_a_rule_that_names_cd_gets_cd_on_its_own() -> None:
    """`cd` stays addressable, and asking for it means asking for it.

    The rebase is the engine's job, so a destructive-head rule must *not* list
    `cd` — doing so also matches a bare `cd` into a non-scratch directory with
    no destruction after it at all.
    """
    from sentrook.layers.l2_match import MatcherConfig, evaluate_rule

    with_cd = _destructive_rule(r"(?:\A|\n)?(?:rm|shred|truncate|cd)\Z")
    assert evaluate_rule(with_cd, _shaped("rm -rf /tmp/x && cd /srv/app"), MatcherConfig()).matched
    without = _destructive_rule(DESTRUCTIVE)
    assert not evaluate_rule(
        without, _shaped("rm -rf /tmp/x && cd /srv/app"), MatcherConfig()
    ).matched


def test_segment_head_is_refused_when_misspelled() -> None:
    """Pydantic ignores unknown keys by default, so the compiler must not."""
    from sentrook.rules.compiler import InvalidArgsMatchError, compile_rule

    with pytest.raises((InvalidArgsMatchError, ValueError), match="segment_heads"):
        compile_rule(
            {
                "rule": "T-TYPO",
                "meta": {"action": "review"},
                "condition": {"paths": {"quantifier": "any", "segment_heads": "rm"}},
            }
        )
