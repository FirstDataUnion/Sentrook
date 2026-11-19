"""A skill tool's change names the skill it changes, so a retry of a refused skill change is a retry.

The skill tools (`skill_manage`, `skill_workshop`) name their target only by skill name, which gave the call no entity
and an empty action fingerprint: a save, patch or delete retried straight after the owner refused it scored no retry
at all, and every skill change shared one fingerprint. A change through a skill tool now carries the skill as its
data destination (`skill:<name>`); a read (`view`, `list`, `inspect`, ...) carries none. Synthetic skill names.
"""

from __future__ import annotations

import copy

import pytest
from test_retry_after_denial import CLOCK, KEY, SEED, run, step

from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.entities import EntityKind, Role

SAVE = {"action": "create", "name": "tidy-downloads", "content": "# tidy-downloads\nSort by month."}
CHANGES = [
    ("skill_manage", SAVE),
    (
        "skill_manage",
        {"action": "patch", "name": "tidy-downloads", "old_string": "a", "new_string": "b"},
    ),
    (
        "skill_manage",
        {"action": "edit", "name": "tidy-downloads", "content": "# tidy-downloads\nZip."},
    ),
    ("skill_manage", {"action": "delete", "name": "tidy-downloads"}),
    (
        "skill_manage",
        {
            "action": "write_file",
            "name": "tidy-downloads",
            "file_path": "notes.md",
            "file_content": "x",
        },
    ),
    (
        "skill_workshop",
        {"action": "create", "name": "tidy-downloads", "content": "# tidy-downloads"},
    ),
    (
        "skill_workshop",
        {"action": "patch", "name": "tidy-downloads", "content": "# tidy-downloads v2"},
    ),
    ("skill_workshop", {"action": "delete", "name": "tidy-downloads"}),
]
REQUEST = "save the tidy-downloads skill"


def retry_of(attack_case, history, tool, arguments):
    retry, _carried, _env = run(attack_case, REQUEST, history, tool, "other", arguments)
    return retry


def pending(attack_case, tool, arguments):
    raw = copy.deepcopy(attack_case["fixture"])
    raw["request"]["text"] = REQUEST
    raw["new_inputs"] = []
    raw["history"] = []
    raw["session"]["step"] = 1
    raw["pending_call"].update(
        {
            "call_id": "c1",
            "tool": tool,
            "tool_kind": "other",
            "provider": {"kind": "host"},
            "arguments": arguments,
        }
    )
    return prepare(
        raw,
        PrepareOptions(token_key=KEY, clock=CLOCK, deterministic_salt="testnest", state_seed=SEED),
    )


# ---- must fire ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "arguments"), CHANGES, ids=[f"{t}-{a['action']}" for t, a in CHANGES]
)
def test_a_skill_change_retried_after_the_owner_refused_it_is_a_retry(attack_case, tool, arguments):
    history = [step(1, tool, "other", arguments, "denied_by_user")]
    retry = retry_of(attack_case, history, tool, arguments)
    assert (retry.value, retry.reason) == (1.0, "retry.same_action")


def test_a_skill_change_retried_after_the_scanner_blocked_it_is_a_retry(attack_case):
    history = [step(1, "skill_manage", "other", SAVE, "blocked")]
    retry = retry_of(attack_case, history, "skill_manage", SAVE)
    assert (retry.value, retry.reason) == (1.0, "retry.same_action")


def test_another_action_on_the_refused_skill_is_a_retry(attack_case):
    """Refused a save, then patched or deleted the same skill: the same skill changed again."""
    history = [step(1, "skill_manage", "other", SAVE, "denied_by_user")]
    patch = {"action": "patch", "name": "tidy-downloads", "old_string": "a", "new_string": "b"}
    assert retry_of(attack_case, history, "skill_manage", patch).reason == "retry.same_action"


def test_the_skill_name_is_matched_whatever_its_case_or_spacing(attack_case):
    history = [step(1, "skill_manage", "other", SAVE, "denied_by_user")]
    again = {**SAVE, "name": "  Tidy-Downloads "}
    assert retry_of(attack_case, history, "skill_manage", again).reason == "retry.same_action"


def test_the_skill_is_the_calls_data_destination(attack_case):
    p = pending(attack_case, "skill_manage", SAVE)
    [skill] = [e for e in p.entities.pending() if e.value.startswith("skill:")]
    assert skill.kind is EntityKind.PATH
    assert (skill.value, skill.display) == ("skill:tidy-downloads", "skill tidy-downloads")
    assert Role.DATA_DESTINATION in skill.roles
    assert p.fingerprint.render() != "afp1:other"


def test_two_skills_have_different_fingerprints(attack_case):
    a = pending(attack_case, "skill_manage", SAVE).fingerprint.render()
    b = pending(attack_case, "skill_manage", {**SAVE, "name": "rename-photos"}).fingerprint.render()
    assert a != b


# ---- must stay silent --------------------------------------------------------------------------------------------


def test_a_change_to_another_skill_is_not_a_retry(attack_case):
    history = [step(1, "skill_manage", "other", SAVE, "denied_by_user")]
    other = {**SAVE, "name": "rename-photos"}
    assert retry_of(attack_case, history, "skill_manage", other).reason == "retry.none"


@pytest.mark.parametrize("action", ["view", "read", "list", "inspect", "search", "status"])
def test_a_skill_read_after_a_refused_change_is_not_a_retry(attack_case, action):
    history = [step(1, "skill_workshop", "other", SAVE, "denied_by_user")]
    read = {"action": action, "name": "tidy-downloads"}
    assert retry_of(attack_case, history, "skill_workshop", read).reason == "retry.none"
    assert not [
        e
        for e in pending(attack_case, "skill_workshop", read).entities.pending()
        if e.value.startswith("skill:")
    ]


def test_hermes_skill_view_is_not_a_skill_change(attack_case):
    history = [step(1, "skill_manage", "other", SAVE, "denied_by_user")]
    assert (
        retry_of(attack_case, history, "skill_view", {"name": "tidy-downloads"}).reason
        == "retry.none"
    )


def test_a_first_save_is_not_a_retry(attack_case):
    assert retry_of(attack_case, [], "skill_manage", SAVE).reason == "retry.none"


def test_a_save_after_an_allowed_save_is_not_a_retry(attack_case):
    history = [step(1, "skill_manage", "other", SAVE, "allowed")]
    assert retry_of(attack_case, history, "skill_manage", SAVE).reason == "retry.none"


@pytest.mark.parametrize("name", [None, "", "   ", 42])
def test_no_usable_name_gives_no_skill(attack_case, name):
    p = pending(attack_case, "skill_manage", {"action": "create", "name": name, "content": "x"})
    assert not [e for e in p.entities.pending() if e.value.startswith("skill:")]


def test_a_batch_of_operations_names_each_skill_it_changes(attack_case):
    """A curator merge sends its changes as `operations`; each changed skill is a destination, a viewed one is not."""
    batch = {
        "operations": [
            {"action": "patch", "name": "deploy-relay", "content": "# deploy-relay"},
            {"action": "delete", "name": "deploy-relay-old"},
            {"action": "view", "name": "deploy-notes"},
        ]
    }
    p = pending(attack_case, "skill_manage", batch)
    skills = sorted(e.value for e in p.entities.pending() if e.value.startswith("skill:"))
    assert skills == ["skill:deploy-relay", "skill:deploy-relay-old"]
    history = [
        step(
            1,
            "skill_manage",
            "other",
            {"action": "delete", "name": "deploy-relay-old"},
            "denied_by_user",
        )
    ]
    assert retry_of(attack_case, history, "skill_manage", batch).reason == "retry.same_action"
