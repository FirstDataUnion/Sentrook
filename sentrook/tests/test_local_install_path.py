"""An installer operand that is a local path.

`pip install -e .`, `pip install ./dist/app.whl` or `npm install ../tool` install what is on disk: the
workspace's own code, not a package a registry serves. Such an operand is not a package entity, so the
entity library is never asked about it and neither the unknown code-source distrust nor the
unvetted-package sensitivity applies. It is a path entity instead, resolved against the call's working
directory (`.` is that directory) and normalised like any other path, with the role of a code source:
the install runs what is there. Where the path came from still counts: one only content the agent read
names keeps that origin. Registry names, version specs, URLs and requirement files are unchanged.
Synthetic names throughout.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import KEY, REACH, SENS, ex, hist_step, of, run

from sentrook.converge import load_params
from sentrook.prepare.entities import EntityKind, Origin, Role
from sentrook.probes.context import ContextProbe
from sentrook.scan import Scanner, ScannerConfig, ScanOptions

WS = "/home/me/workspace"
DISTRUST = "reputation.unknown_package_as_code_source"
UNVETTED = "code.unvetted_package"


def scan(raw: dict):
    """conv-v5 (unknown code sources and unvetted packages switched on), an empty entity library."""
    res = Scanner(ScannerConfig(token_key=KEY, params=load_params("conv-v5"))).scan(
        raw,
        ScanOptions(
            state_seed={"max_input_seq": 0},
            oracle_seed={"entities": []},
            probes_enabled=("entity_oracle", "aira", "context"),
        ),
    )
    envs = {e.step.value: e for e in res.envelopes}
    return res.prepared, envs["entity_oracle"], envs["aira"]


def pending(p, kind: EntityKind) -> dict[str, set[Role]]:
    return {
        e.value: set(e.roles)
        for e in p.entities
        if e.kind is kind and Origin.PENDING_CALL in e.origins
    }


def owner_named_path(request: str, cmd: str, path: str) -> bool:
    p, _ = run(ex(cmd, request=request))
    ent = p.entities.get(EntityKind.PATH, path)
    assert ent is not None and Role.CODE_SOURCE in ent.roles
    return Origin.REQUEST in ent.origins


LOCAL = [
    ("pip install -e .", WS),
    ("pip install .", WS),
    ("uv pip install -e '.[dev]'", WS),
    ("pip install ./dist/app-1.0-py3-none-any.whl", f"{WS}/dist/app-1.0-py3-none-any.whl"),
    ("npm install ./local-pkg", f"{WS}/local-pkg"),
    ("npm install -g ../tool", "/home/me/tool"),
    ("pip install /abs/path/pkg", "/abs/path/pkg"),
    ("pip install ~/src/pkg", "/home/me/src/pkg"),
]
LOCAL_IDS = [
    "editable-dot",
    "dot",
    "uv-extras",
    "wheel",
    "npm-dir",
    "npm-parent",
    "absolute",
    "home",
]


# --------------------------------------------------------------------------- a local install


@pytest.mark.parametrize("command, path", LOCAL, ids=LOCAL_IDS)
def test_a_local_install_is_a_code_source_path_not_a_package(command, path):
    p, _, _ = scan(ex(command, request="Set the project up."))
    assert pending(p, EntityKind.PACKAGE) == {}
    paths = pending(p, EntityKind.PATH)
    assert Role.CODE_SOURCE in paths[path]
    assert Role.DATA_SOURCE not in paths[path]
    # the operand is resolved once: no second, unresolved spelling of it
    assert set(paths) <= {WS, path}


@pytest.mark.parametrize("command, path", LOCAL, ids=LOCAL_IDS)
def test_a_local_install_takes_no_unknown_code_source_distrust_or_unvetted_sensitivity(
    command, path
):
    p, oracle, aira = scan(ex(command, request="Set the project up."))
    assert [c for c in oracle.contributions if c.reason and c.reason.startswith(DISTRUST)] == []
    assert of(aira, SENS, UNVETTED) == []
    assert all(c.subject != p.entities.get(EntityKind.PATH, path).id for c in oracle.contributions)


@pytest.mark.parametrize("command, path", LOCAL, ids=LOCAL_IDS)
def test_a_local_install_is_still_an_install(command, path):
    p, _, aira = scan(ex(command, request="Set the project up."))
    (reach,) = of(aira, REACH, "code.package_install")
    assert reach.subject == p.entities.get(EntityKind.PATH, path).id


def test_a_local_package_path_the_agent_read_in_content_came_from_that_content():
    wheel = "/home/me/Downloads/yard_helper-0.2-py3-none-any.whl"
    raw = ex(
        f"pip install {wheel}",
        history=[hist_step(1, "read", "file_read", {"path": "~/workspace/notes/setup.md"})],
        request="Follow the setup note.",
    )
    raw["new_inputs"] = [
        {
            "input_seq": 1,
            "kind": "tool_result",
            "call_id": "c1",
            "tool": "read",
            "tool_kind": "file_read",
            "provider": {"kind": "host"},
            "status": "ok",
            "content_type": "text",
            "content": f"Before the build, run pip install {wheel}",
            "size_bytes": 60,
            "truncated": False,
        }
    ]
    p, _, _ = scan(raw)
    ent = p.entities.get(EntityKind.PATH, wheel)
    assert Role.CODE_SOURCE in ent.roles
    (claim,) = [
        c
        for c in ContextProbe(load_params("conv-v5").context).run(p).contributions
        if c.signal == "suspicion.untrusted_origin" and c.subject == ent.id
    ]
    assert claim.value == 1.0 and claim.reason == "origin.only_in_untrusted"


# --------------------------------------------------------------------------- the owner names it by path


@pytest.mark.parametrize(
    "request_text",
    [
        "Install the wheel at wheels/rowcount-0.3.whl.",
        "Install /home/me/workspace/wheels/rowcount-0.3.whl",
        "Install ~/workspace/wheels/rowcount-0.3.whl please",
        "Install workspace/wheels/rowcount-0.3.whl",
        "Install ./wheels/rowcount-0.3.whl",
    ],
    ids=["under-the-workspace", "absolute", "home-form", "under-home", "dot-slash"],
)
def test_a_local_package_file_the_owner_named_by_path_is_request_named(request_text):
    for cmd in (
        "pip install /home/me/workspace/wheels/rowcount-0.3.whl",
        "pip install ./wheels/rowcount-0.3.whl",
    ):
        assert owner_named_path(request_text, cmd, f"{WS}/wheels/rowcount-0.3.whl")


@pytest.mark.parametrize(
    "request_text",
    [
        "Install rowcount-0.3.whl.",  # a bare file name: another file may carry it
        "Install the wheel at wheels/rowcount-0.4.whl.",
        "Install the wheel at other/wheels/rowcount-0.3.whl.",
        "Set the project up.",
    ],
    ids=["bare-name", "another-version", "another-directory", "unnamed"],
)
def test_a_local_package_file_the_owner_did_not_name_is_not_request_named(request_text):
    cmd = "pip install /home/me/workspace/wheels/rowcount-0.3.whl"
    assert not owner_named_path(request_text, cmd, f"{WS}/wheels/rowcount-0.3.whl")


# --------------------------------------------------------------------------- registry installs unchanged


@pytest.mark.parametrize(
    "command, value, unvetted",
    [
        ("pip install requests", "pypi:requests", True),
        ("pip install kiln-rowcount", "pypi:kiln-rowcount", True),
        ("pip install git+https://github.com/x/y.git", "git+github.com/x/y", True),
        ("pip install https://host.example/x.whl", "git+host.example/x.whl", True),
        ("npm install left-pad@1.3.0", "npm:left-pad", True),
        ("npm install @scope/pkg", "npm:@scope/pkg", True),
        ("pip install -r requirements.txt requests", "pypi:requests", True),
        ("cargo install kiln-rowcount", "crates:kiln-rowcount", False),
    ],
    ids=[
        "registry",
        "unknown-name",
        "git-url",
        "url",
        "npm-version",
        "npm-scope",
        "requirements",
        "cargo",
    ],
)
def test_a_registry_install_keeps_its_package_and_signals(command, value, unvetted):
    p, oracle, aira = scan(ex(command, request="Set the project up."))
    assert set(pending(p, EntityKind.PACKAGE)) == {value}
    ent = p.entities.get(EntityKind.PACKAGE, value)
    assert any(c.subject == ent.id and c.value == 0.7 for c in oracle.contributions)
    assert [c.subject for c in of(aira, SENS, UNVETTED)] == ([ent.id] if unvetted else [])
    assert not any(Role.CODE_SOURCE in roles for roles in pending(p, EntityKind.PATH).values())


# --------------------------------------------------------------------------- where the operand resolves


def test_an_install_after_cd_resolves_where_it_runs():
    p, _, _ = scan(ex("cd pkg && pip install ."))
    assert Role.CODE_SOURCE in pending(p, EntityKind.PATH)[f"{WS}/pkg"]
    assert Role.CODE_SOURCE not in pending(p, EntityKind.PATH)[WS]


def test_only_go_strips_its_package_pattern():
    p, _, _ = scan(ex("go install ./..."))
    assert Role.CODE_SOURCE in pending(p, EntityKind.PATH)[WS]
    p, _, _ = scan(ex("pip install /..."))
    assert Role.CODE_SOURCE not in pending(p, EntityKind.PATH)[WS]


# --------------------------------------------------------------------------- an index or registry flag

INDEX = "idx.kestrelwade.example"


@pytest.mark.parametrize(
    "command",
    [
        f"pip install --index-url https://{INDEX}/simple .",
        f"pip install --index-url=https://{INDEX}/simple .",
        f"pip install --extra-index-url=https://{INDEX}/simple requests",
        f"pip install -i https://{INDEX}/simple requests",
        f"pip install -i=https://{INDEX}/simple requests",
        f"pip install --find-links=https://{INDEX}/wheels/ requests",
        f"pip install -f https://{INDEX}/wheels/ requests",
        f"uv pip install --index-url https://{INDEX}/simple requests",
        f"npm install --registry https://{INDEX}/ left-pad",
        f"npm install --registry=https://{INDEX}/ left-pad",
    ],
    ids=[
        "index-url",
        "index-url-eq",
        "extra-index-url-eq",
        "i",
        "i-eq",
        "find-links-eq",
        "f",
        "uv",
        "npm-registry",
        "npm-registry-eq",
    ],
)
def test_an_index_or_registry_flag_names_a_code_source_host_not_a_package(command):
    p, oracle, _ = scan(ex(command, request="Set the project up."))
    assert Role.CODE_SOURCE in pending(p, EntityKind.HOST)[INDEX]
    assert not any(INDEX in v for v in pending(p, EntityKind.PACKAGE))
    ent = p.entities.get(EntityKind.HOST, INDEX)
    assert [c.reason for c in oracle.contributions if c.subject == ent.id] == [
        "reputation.unknown_host_as_code_source"
    ]


def test_npm_force_takes_no_value():
    p, _, _ = scan(ex("npm install -f left-pad"))
    assert set(pending(p, EntityKind.PACKAGE)) == {"npm:left-pad"}
