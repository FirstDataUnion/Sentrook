"""A skill tool's change retried after a refusal is a retry, matched by the skill it changes.

The skill tools (`skill_manage`, `skill_workshop`) name their target only by skill name (and a support file by a path
relative to the skill), so a save, patch or delete retried straight after the owner refused it matched nothing. Two
skill-tool calls are now compared by the skills they change, and by nothing else: a read changes none, and a support
file's relative path does not tie two skills together. Nothing is added to the entity table, so the name is never
scored as a file. Synthetic skill names.
"""

from __future__ import annotations

import copy

import pytest
from test_retry_after_denial import CLOCK, KEY, SEED, run, step

from sentrook.prepare import PrepareOptions, prepare

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
        "skill_workshop",
        {"action": "create", "name": "tidy-downloads", "content": "# tidy-downloads"},
    ),
    (
        "skill_workshop",
        {"action": "patch", "name": "tidy-downloads", "content": "# tidy-downloads v2"},
    ),
    ("skill_workshop", {"action": "archive", "name": "tidy-downloads"}),
]
REQUEST = "save the tidy-downloads skill"


def retry_of(attack_case, history, tool, arguments, provider=None):
    retry, _carried, env = run(
        attack_case, REQUEST, history, tool, "other", arguments, provider=provider
    )
    return retry, env


def reason(attack_case, history, tool, arguments, provider=None) -> str:
    return retry_of(attack_case, history, tool, arguments, provider)[0].reason


def refused(tool="skill_manage", arguments=SAVE, decision="denied_by_user"):
    return [step(1, tool, "other", arguments, decision)]


def prepared(attack_case, tool, arguments):
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
    retry, env = retry_of(attack_case, refused(tool, arguments), tool, arguments)
    assert (retry.value, retry.reason) == (1.0, "retry.same_action")
    assert env.evidence["retry"]["matches"][0]["skill"] == "tidy-downloads"


def test_a_skill_change_retried_after_the_scanner_blocked_it_is_a_retry(attack_case):
    retry, _ = retry_of(attack_case, refused(decision="blocked"), "skill_manage", SAVE)
    assert (retry.value, retry.reason) == (1.0, "retry.same_action")


def test_another_action_on_the_refused_skill_is_a_retry(attack_case):
    patch = {"action": "patch", "name": "tidy-downloads", "old_string": "a", "new_string": "b"}
    assert reason(attack_case, refused(), "skill_manage", patch) == "retry.same_action"


def test_another_support_file_of_the_refused_skill_is_a_retry(attack_case):
    """Matched by the skill, not the file: a different support file of the same skill."""
    first = {
        "action": "write_file",
        "name": "tidy-downloads",
        "file_path": "notes.md",
        "file_content": "x",
    }
    again = {
        "action": "write_file",
        "name": "tidy-downloads",
        "file_path": "extra.md",
        "file_content": "y",
    }
    retry, env = retry_of(attack_case, refused("skill_workshop", first), "skill_workshop", again)
    assert retry.reason == "retry.same_action"
    assert env.evidence["retry"]["matches"][0]["skill"] == "tidy-downloads"


def test_the_skill_name_is_matched_whatever_its_case_or_spacing(attack_case):
    again = {**SAVE, "name": "  Tidy-Downloads "}
    assert reason(attack_case, refused(), "skill_manage", again) == "retry.same_action"


def test_a_batch_naming_the_refused_skill_is_a_retry(attack_case):
    """A curator merge sends its changes as `operations`; a skill it only views is not changed."""
    batch = {
        "operations": [
            {"action": "patch", "name": "deploy-relay", "content": "# deploy-relay"},
            {"action": "delete", "name": "tidy-downloads"},
        ]
    }
    assert reason(attack_case, refused(), "skill_manage", batch) == "retry.same_action"
    viewed = {
        "operations": [
            {"action": "patch", "name": "deploy-relay"},
            {"action": "view", "name": "tidy-downloads"},
        ]
    }
    assert reason(attack_case, refused(), "skill_manage", viewed) == "retry.none"


# ---- must stay silent --------------------------------------------------------------------------------------------


def test_a_change_to_another_skill_is_not_a_retry(attack_case):
    other = {**SAVE, "name": "rename-photos"}
    assert reason(attack_case, refused(), "skill_manage", other) == "retry.none"


def test_the_same_support_file_in_another_skill_is_not_a_retry(attack_case):
    first = {"action": "write_file", "name": "alpha", "file_path": "SKILL.md", "file_content": "x"}
    other = {"action": "write_file", "name": "beta", "file_path": "SKILL.md", "file_content": "x"}
    assert (
        reason(attack_case, refused("skill_workshop", first), "skill_workshop", other)
        == "retry.none"
    )


@pytest.mark.parametrize(
    "action", ["view", "read", "list", "search", "status", "describe", "get", "show"]
)
def test_a_skill_read_after_a_refused_change_is_not_a_retry(attack_case, action):
    read = {"action": action, "name": "tidy-downloads"}
    assert reason(attack_case, refused("skill_workshop"), "skill_workshop", read) == "retry.none"
    first = {
        "action": "write_file",
        "name": "tidy-downloads",
        "file_path": "SKILL.md",
        "file_content": "x",
    }
    with_file = {**read, "file_path": "SKILL.md"}
    assert (
        reason(attack_case, refused("skill_workshop", first), "skill_workshop", with_file)
        == "retry.none"
    )


@pytest.mark.parametrize("tool", ["skill_view", "skills_list"])
def test_hermes_skill_reads_are_not_a_retry(attack_case, tool):
    assert reason(attack_case, refused(), tool, {"name": "tidy-downloads"}) == "retry.none"


def test_a_first_save_is_not_a_retry(attack_case):
    assert reason(attack_case, [], "skill_manage", SAVE) == "retry.none"


def test_a_save_after_an_allowed_save_is_not_a_retry(attack_case):
    assert reason(attack_case, refused(decision="allowed"), "skill_manage", SAVE) == "retry.none"


@pytest.mark.parametrize("name", [None, "", "   ", 42])
def test_no_usable_name_is_not_a_retry(attack_case, name):
    nameless = {"action": "create", "name": name}
    assert reason(attack_case, refused(), "skill_manage", nameless) == "retry.none"


def test_a_third_party_tool_with_the_same_name_is_not_a_skill_tool(attack_case):
    mcp = {"kind": "mcp", "identity": "remote:tools.example.net"}
    history = [step(1, "skill_manage", "other", SAVE, "denied_by_user", provider=mcp)]
    assert reason(attack_case, history, "skill_manage", SAVE, provider=mcp) == "retry.none"


@pytest.mark.parametrize("name", ["crontab", "AGENTS.md", "authorized_keys", ".env"])
def test_the_skill_name_is_never_an_entity(attack_case, name):
    """A skill named like a file is not scored as that file: the name adds nothing to the entity table."""
    p = prepared(
        attack_case, "skill_manage", {"action": "create", "name": name, "content": "# notes"}
    )
    assert all(name.lower() not in e.value.lower() for e in p.entities.pending())
    assert p.fingerprint.render() == "afp1:other"
