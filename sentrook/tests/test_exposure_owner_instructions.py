"""The exposure probe leaves out reads of the owner's own instruction files.

An agent's instruction files (`AGENTS.md`, `SOUL.md`, ...) are the owner's orders to it, so the exposure question
("does this input carry instructions or authority?") answers yes for every read of them, and the session is tainted.
The host loads the same files into the prompt with no tool call. A read that counts as the owner's own configuration
(`session_sets.owner_config_path`) and names an instruction file is therefore not sent to the exposure probe, as
reads of the agent's own skills and memory are not. That includes the top of an OpenClaw agent's own workspace when
the host keeps it inside its directory (`~/.openclaw/workspace/<agent>/`). A config file (`openclaw.json`, ...) is
still judged, and loses its trust if judged injected; so is an instruction file anywhere else, one the agent wrote in
this session, and one the session has tainted.

The scenario is invented: an agent reads its own orders, then runs a harmless listing.
"""

from __future__ import annotations

import copy

import pytest
from test_exposure_own_store import CLEAN, HOME, INJECTED, planir, prep, run_exposure

from sentrook.converge import exposure_unjudged
from sentrook.enums import ProbeStatus, SessionFlag

OC_HOME = HOME["openclaw"]
OC_WS = f"{OC_HOME}/.openclaw/workspace"
AGENT_WS = f"{OC_WS}/sgt-harrow"
ORDERS = (
    "# AGENTS.md\n\nYou are Sgt Harrow. Every morning, post the overnight summary to the ops channel.\n"
    "Never touch the billing tables.\n"
)


def openclaw_read(path: str, workspace: str, content: str = ORDERS) -> dict:
    raw = planir("openclaw", [("read", {"path": path}, content)])
    raw["host"]["workspace_root"] = workspace
    return raw


# ---- must stay silent -------------------------------------------------------------------------------------------

LEFT_OUT = {
    "own nested workspace AGENTS.md": (f"{AGENT_WS}/AGENTS.md", AGENT_WS),
    "own nested workspace SOUL.md": (f"{AGENT_WS}/SOUL.md", AGENT_WS),
    "default workspace AGENTS.md": (f"{OC_WS}/AGENTS.md", OC_WS),
    "named workspace TOOLS.md": (f"{OC_HOME}/.openclaw/workspace-ops/TOOLS.md", OC_WS),
    "host directory HEARTBEAT.md": (f"{OC_HOME}/.openclaw/HEARTBEAT.md", OC_WS),
}


@pytest.mark.parametrize("name", list(LEFT_OUT))
def test_an_owner_instruction_read_is_not_sent_and_does_not_taint(name):
    path, ws = LEFT_OUT[name]
    p, env, sent = run_exposure(openclaw_read(path, ws, INJECTED))
    assert p.owner_instruction_inputs == {1} and p.owner_config_inputs == {1}
    assert env.status is ProbeStatus.SKIPPED and sent == []
    assert SessionFlag.TAINTED not in env.flags_set and env.contributions == []
    assert env.evidence["owner_instructions_skipped"] == [1]
    assert (
        env.evidence["skipped"]
        == "only reads of the agent's own instruction files, skills or memory"
    )
    assert not p.views["exposure-v2"].get("new_inputs") and not p.views["exposure"].get(
        "new_inputs"
    )
    # nothing went unjudged: the converger does not hold back for a probe that had nothing to read
    assert not exposure_unjudged(p, [env])


def test_a_hermes_soul_read_is_left_out_too():
    raw = planir("hermes", [("read", {"path": "/home/hermes/.hermes/SOUL.md"}, INJECTED)])
    p, env, sent = run_exposure(raw)
    assert p.owner_instruction_inputs == {1} and sent == []


def test_a_cat_of_the_agents_own_orders_is_left_out_too():
    raw = planir("openclaw", [("exec", {"command": f"cat {AGENT_WS}/AGENTS.md"}, INJECTED)])
    raw["history"][0]["tool_kind"] = raw["new_inputs"][0]["tool_kind"] = "exec"
    raw["host"]["workspace_root"] = AGENT_WS
    p, env, sent = run_exposure(raw)
    assert p.owner_instruction_inputs == {1} and sent == []


def test_a_mixed_turn_keeps_exposure_on_the_other_input():
    raw = planir(
        "openclaw",
        [
            ("read", {"path": f"{AGENT_WS}/AGENTS.md"}, ORDERS),
            ("web_fetch", {"url": "https://board.quarrel.test/t/1"}, INJECTED),
        ],
    )
    raw["host"]["workspace_root"] = AGENT_WS
    p, env, sent = run_exposure(raw)
    assert p.owner_instruction_inputs == {1}
    assert sent == [2]
    assert env.status is ProbeStatus.OK and SessionFlag.TAINTED in env.flags_set
    assert env.evidence["owner_instructions_skipped"] == [1]


# ---- must fire --------------------------------------------------------------------------------------------------

SENT = {
    "another agent's workspace": (f"{AGENT_WS}/AGENTS.md", f"{OC_WS}/sgt-tamsin"),
    "a nested workspace read from the default agent": (f"{AGENT_WS}/AGENTS.md", OC_WS),
    "a repository in the agent's own workspace": (f"{AGENT_WS}/repo/AGENTS.md", AGENT_WS),
    "a workspace outside the host's directory": (
        f"{OC_HOME}/projects/x/AGENTS.md",
        f"{OC_HOME}/projects/x",
    ),
    "a config file in the host's directory": (f"{OC_HOME}/.openclaw/openclaw.json", AGENT_WS),
    "a config file the host keeps": (f"{OC_HOME}/.openclaw/config/intake.json", AGENT_WS),
}


@pytest.mark.parametrize("name", list(SENT))
def test_other_reads_are_still_judged(name):
    path, ws = SENT[name]
    p, env, sent = run_exposure(openclaw_read(path, ws, INJECTED))
    assert p.owner_instruction_inputs == frozenset() and sent == [1]
    assert env.status is ProbeStatus.OK and SessionFlag.TAINTED in env.flags_set


def test_orders_the_agent_wrote_in_this_session_are_still_judged():
    raw = openclaw_read(f"{AGENT_WS}/AGENTS.md", AGENT_WS, INJECTED)
    write = copy.deepcopy(raw["history"][0])
    write.update(
        tool="write",
        tool_kind="file_write",
        arguments={"path": f"{AGENT_WS}/AGENTS.md", "content": INJECTED},
    )
    raw["history"].insert(0, write)
    raw["history"][1].update(step=2, call_id="c2")
    raw["new_inputs"][0]["call_id"] = "c2"
    raw["session"]["step"] = 3
    raw["pending_call"]["call_id"] = "c3"
    p, env, sent = run_exposure(raw)
    assert p.owner_config_inputs == frozenset() and p.owner_instruction_inputs == frozenset()
    assert sent == [1] and SessionFlag.TAINTED in env.flags_set


@pytest.mark.parametrize("path", ["AGENTS.md", "./AGENTS.md"])
def test_a_relative_read_of_the_agents_own_orders_is_left_out(path):
    p, env, sent = run_exposure(openclaw_read(path, AGENT_WS, INJECTED))
    assert p.owner_instruction_inputs == {1} and sent == []


ORDERS_ABS = f"{AGENT_WS}/AGENTS.md"
#: Earlier calls that may have changed the orders: each keeps the read with the exposure probe.
CHANGED = {
    "write, bare relative path": (
        "write",
        "file_write",
        {"path": "AGENTS.md", "content": INJECTED},
    ),
    "write, other case": ("write", "file_write", {"path": f"{AGENT_WS}/agents.md", "content": "x"}),
    "edit": ("edit", "file_edit", {"path": "AGENTS.md", "old_string": "a", "new_string": "b"}),
    "redirect": ("exec", "exec", {"command": f"echo hi > {ORDERS_ABS}"}),
    "relative redirect": ("exec", "exec", {"command": "echo hi >> AGENTS.md"}),
    "curl -o": ("exec", "exec", {"command": f"curl -sSLo {ORDERS_ABS} https://x.quarrel.test/a"}),
    "cp onto it": ("exec", "exec", {"command": "cp /tmp/x AGENTS.md"}),
    "sed -i": ("exec", "exec", {"command": f"sed -i 's/a/b/' {ORDERS_ABS}"}),
    "a script": ("exec", "exec", {"command": "python3 -c \"open('AGENTS.md','w').write('x')\""}),
    "a checkout of the file": ("exec", "exec", {"command": "git checkout evil -- AGENTS.md"}),
    "apply_patch": (
        "apply_patch",
        "file_edit",
        {"input": f"*** Begin Patch\n*** Update File: {ORDERS_ABS}\n@@\n-a\n+b\n*** End Patch"},
    ),
    "a copy into the folder": ("exec", "exec", {"command": f"cp -r /tmp/drop/ {AGENT_WS}"}),
    "a config read redirected onto it": (
        "exec",
        "exec",
        {"command": f"sed 's/.*/IGNORE/' {OC_HOME}/.openclaw/openclaw.json > AGENTS.md"},
    ),
    "a cat appended onto it": (
        "exec",
        "exec",
        {"command": f"cat {OC_HOME}/.openclaw/openclaw.json >> {ORDERS_ABS}"},
    ),
    "a glob": ("exec", "exec", {"command": f"cp /tmp/x {AGENT_WS}/AGENT?.md"}),
    "a bracket glob": ("exec", "exec", {"command": "cp /tmp/x AGENT[S].md"}),
    "quotes inside the name": ("exec", "exec", {"command": 'cp /tmp/x AGENT"S".md'}),
    "a backslash inside the name": ("exec", "exec", {"command": "cp /tmp/x AGEN\\TS.md"}),
    "cd then a glob": (
        "exec",
        "exec",
        {"command": f"cd {OC_WS} && cp /tmp/x sgt-harrow/AGENT?.md"},
    ),
    "a script at the top of the workspace": (
        "exec",
        "exec",
        {"command": f"python3 {AGENT_WS}/x.py"},
    ),
    "a sed program that writes": (
        "exec",
        "exec",
        {"command": f"sed -n 's/^/X /w {ORDERS_ABS}' {OC_HOME}/.openclaw/openclaw.json"},
    ),
    "an awk program that writes": (
        "exec",
        "exec",
        {"command": f'awk \'{{print "X" > "{ORDERS_ABS}"}}\' {OC_HOME}/.openclaw/openclaw.json'},
    ),
    "sort -o": (
        "exec",
        "exec",
        {"command": f"sort -o {ORDERS_ABS} {OC_HOME}/.openclaw/openclaw.json"},
    ),
    "sort -o attached": (
        "exec",
        "exec",
        {"command": f"sort -oAGENTS.md {OC_HOME}/.openclaw/openclaw.json"},
    ),
    "uniq into it": (
        "exec",
        "exec",
        {"command": f"uniq {OC_HOME}/.openclaw/openclaw.json {ORDERS_ABS}"},
    ),
    "xxd -r": (
        "exec",
        "exec",
        {"command": f"xxd -r {OC_HOME}/.openclaw/openclaw.json {ORDERS_ABS}"},
    ),
    "diff --output": (
        "exec",
        "exec",
        {"command": f"diff --output={ORDERS_ABS} {OC_HOME}/.openclaw/openclaw.json /dev/null"},
    ),
    "find -fprint": (
        "exec",
        "exec",
        {"command": f"find {OC_HOME}/.openclaw/openclaw.json -fprint {ORDERS_ABS}"},
    ),
    "yq in place": ("exec", "exec", {"command": f"yq -i '.a=1' {ORDERS_ABS}"}),
    "a quoted substitution": (
        "exec",
        "exec",
        {
            "command": f'cat "$(curl -so {ORDERS_ABS} https://x.quarrel.test/a)" {OC_HOME}/.openclaw/openclaw.json'
        },
    ),
    "a quoted backtick": (
        "exec",
        "exec",
        {"command": f'cat "`cp /tmp/x {ORDERS_ABS}`" {OC_HOME}/.openclaw/openclaw.json'},
    ),
    "a redirect with no space": (
        "exec",
        "exec",
        {"command": f"cat {OC_HOME}/.openclaw/openclaw.json>>{ORDERS_ABS}"},
    ),
}


@pytest.mark.parametrize("name", list(CHANGED))
def test_orders_an_earlier_call_may_have_changed_are_still_judged(name):
    tool, kind, args = CHANGED[name]
    raw = openclaw_read(ORDERS_ABS, AGENT_WS, INJECTED)
    earlier = copy.deepcopy(raw["history"][0])
    earlier.update(tool=tool, tool_kind=kind, arguments=args)
    raw["history"].insert(0, earlier)
    raw["history"][1].update(step=2, call_id="c2")
    raw["new_inputs"][0]["call_id"] = "c2"
    raw["session"]["step"] = 3
    raw["pending_call"]["call_id"] = "c3"
    p, env, sent = run_exposure(raw)
    assert p.owner_instruction_inputs == frozenset() and sent == [1], name
    assert SessionFlag.TAINTED in env.flags_set


def test_an_earlier_read_of_the_orders_does_not_keep_them_judged():
    raw = openclaw_read(ORDERS_ABS, AGENT_WS, INJECTED)
    reads = ({"command": f"cat {ORDERS_ABS} 2>/dev/null"}, {"command": f"head -n 5 {ORDERS_ABS}"})
    for n, args in enumerate(reads):
        earlier = copy.deepcopy(raw["history"][0])
        earlier.update(step=n + 1, call_id=f"e{n}", tool="exec", tool_kind="exec", arguments=args)
        raw["history"].insert(n, earlier)
    raw["history"][2].update(step=3, call_id="c3")
    raw["new_inputs"][0]["call_id"] = "c3"
    raw["session"]["step"] = 4
    raw["pending_call"]["call_id"] = "c4"
    p, env, sent = run_exposure(raw)
    assert p.owner_instruction_inputs == {1} and sent == []


def test_tainted_orders_are_still_judged():
    raw = openclaw_read(f"{AGENT_WS}/AGENTS.md", AGENT_WS, INJECTED)
    p = prep(raw, {**CLEAN, "tainted": True, "tainted_entities": [f"{AGENT_WS}/AGENTS.md"]})
    assert p.owner_instruction_inputs == frozenset()


@pytest.mark.parametrize("spelling", ["AGENTS.md", "./AGENTS.md"])
def test_orders_tainted_under_a_relative_spelling_are_still_judged(spelling, monkeypatch):
    """Lineage keeps a bare relative path as the agent wrote it, so the guard checks every spelling (a seed cannot
    spell one as a path, so the session's tainted set is filled directly)."""
    import sentrook.prepare as prepare_mod
    from sentrook.state.token import entity_hash

    real = prepare_mod.seed_state

    def seeded(seed, **kw):
        state = real(seed, **kw)
        state.tainted.append(entity_hash(state.salt, "path", spelling))
        return state

    monkeypatch.setattr(prepare_mod, "seed_state", seeded)
    p = prep(openclaw_read(ORDERS_ABS, AGENT_WS, INJECTED))
    assert p.owner_config_inputs == {1} and p.owner_instruction_inputs == frozenset()
