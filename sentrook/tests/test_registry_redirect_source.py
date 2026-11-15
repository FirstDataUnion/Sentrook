"""The host a call points a package manager at is a code source.

Writing a registry line into `.npmrc`, `pip.conf` and the like, or setting it with the package
manager's own `config set`, installs nothing yet, but every later install comes from that host. The
host is extracted with the code-source role, so the entity library's verdict, the origin of the host
and the grants on it are read as they are for any host code is taken from. Hosts the same file or
command merely names stay what they were. Invented hosts throughout.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import IRR, REACH, SENS, entity, ex, of, planir, run

from sentrook.oracle.client import SeedOracle
from sentrook.prepare.entities import EntityKind, Role
from sentrook.probes.context import ContextProbe
from sentrook.probes.oracle import EntityOracleProbe
from sentrook.scan import Scanner, ScannerConfig, ScanOptions

REGISTRY = "npm.lorrwick.example"
DISTRUST = "suspicion.distrust"
ORIGIN = "suspicion.untrusted_origin"


def npmrc_edit(line: str, **kw) -> dict:
    return planir(
        "edit",
        "file_edit",
        {
            "path": "~/workspace/.npmrc",
            "edits": [{"oldText": "registry=https://registry.npmjs.org/\n", "newText": line}],
        },
        **kw,
    )


def roles(p, host: str) -> set[Role]:
    ent = p.entities.get(EntityKind.HOST, host)
    assert ent is not None, f"no host {host}"
    return ent.roles


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize(
    "raw",
    [
        npmrc_edit(f"registry=https://{REGISTRY}/\n"),
        npmrc_edit(f"@acme:registry=https://{REGISTRY}/\n"),
        planir(
            "write",
            "file_write",
            {
                "path": "~/.config/pip/pip.conf",
                "content": f"[global]\nindex-url = https://{REGISTRY}/simple\n",
            },
        ),
        planir(
            "write",
            "file_write",
            {
                "path": "~/.cargo/config.toml",
                "content": f'[registries.mirror]\nindex = "sparse+https://{REGISTRY}/index/"\n',
            },
        ),
        planir(
            "write",
            "file_write",
            {
                "path": "~/.condarc",
                "content": f"channels:\n  - https://{REGISTRY}/conda\n  - defaults\n",
            },
        ),
        ex(f"npm config set registry https://{REGISTRY}/"),
        ex(f"pip config set global.index-url https://{REGISTRY}/simple"),
        ex(f"echo 'registry=https://{REGISTRY}/' >> ~/.npmrc"),
    ],
    ids=["npmrc", "scoped", "pip-conf", "cargo", "conda", "npm-cli", "pip-cli", "echo-append"],
)
def test_the_registry_a_call_sets_is_a_code_source(raw):
    p, env = run(raw)
    assert Role.CODE_SOURCE in roles(p, REGISTRY)
    host = entity(p, EntityKind.HOST, REGISTRY)
    # The redirect's consequence names that host.
    assert [c.subject for c in of(env, REACH, "code.registry_redirect")] == [host]
    assert [c.subject for c in of(env, IRR, "code.registry_redirect")] == [host]


def test_an_unknown_registry_takes_the_code_source_distrust_and_full_origin_weight():
    p, _ = run(npmrc_edit(f"registry=https://{REGISTRY}/\n"))
    host = entity(p, EntityKind.HOST, REGISTRY)
    oracle = EntityOracleProbe(SeedOracle({"entities": []})).run(p)
    assert [(c.reason, c.value) for c in oracle.contributions if c.subject == host] == [
        ("reputation.unknown_host_as_code_source", 0.5)
    ]
    ctx = ContextProbe().run(p)
    (origin,) = [c for c in ctx.contributions if c.signal == ORIGIN and c.subject == host]
    assert origin.value == 0.4 and origin.reason == "origin.agent_generated"


def test_a_registry_the_library_marks_known_bad_is_blocked():
    raw = npmrc_edit(f"registry=https://{REGISTRY}/\n")
    seed = {"entities": [{"kind": "host", "value": REGISTRY, "verdict": "known_bad"}]}
    sc = Scanner(ScannerConfig(token_key="unit-test-state-key-" * 2))
    r = sc.scan(raw, ScanOptions(state_seed={"max_input_seq": 0}, oracle_seed=seed)).response
    assert [f.floor for f in r.floors_applied] == ["known_bad_entity"]


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize(
    "path, content",
    [
        (
            "~/workspace/.npmrc",
            f"# docs: https://docs.keelwren.example/npm\nregistry=https://{REGISTRY}/\n",
        ),
        (
            "~/.cargo/config.toml",
            f'[registries.mirror]\nindex = "sparse+https://{REGISTRY}/index/"\n\n'
            '[http]\nproxy = "https://docs.keelwren.example:3128"\n',
        ),
        (
            "~/.condarc",
            f"channels:\n  - https://{REGISTRY}/conda\nproxy_servers:\n"
            "  https: https://docs.keelwren.example:3128\n",
        ),
    ],
    ids=["comment", "another-section", "another-key"],
)
def test_a_host_the_registry_file_only_names_is_not_a_code_source(path, content):
    p, _ = run(planir("write", "file_write", {"path": path, "content": content}))
    assert Role.CODE_SOURCE in roles(p, REGISTRY)
    assert Role.CODE_SOURCE not in roles(p, "docs.keelwren.example")


@pytest.mark.parametrize(
    "raw, host",
    [
        # Not a package-manager config file.
        (
            planir(
                "write",
                "file_write",
                {"path": "~/workspace/notes.md", "content": f"registry=https://{REGISTRY}/\n"},
            ),
            REGISTRY,
        ),
        # A config file, but no registry line.
        (
            planir(
                "write",
                "file_write",
                {
                    "path": "~/workspace/.npmrc",
                    "content": f"save-exact=true\n# see https://{REGISTRY}/help\n",
                },
            ),
            REGISTRY,
        ),
        # Reading the setting sets nothing.
        (ex(f"npm config get registry && curl -sI https://{REGISTRY}/"), REGISTRY),
        # A host named after the command that sets the registry.
        (
            ex(
                f"npm config set registry https://{REGISTRY}/ && curl -s https://docs.keelwren.example/"
            ),
            "docs.keelwren.example",
        ),
    ],
    ids=["other-file", "no-registry-line", "config-get", "later-command"],
)
def test_a_host_no_call_sets_as_registry_is_not_a_code_source(raw, host):
    p, _ = run(raw)
    assert Role.CODE_SOURCE not in roles(p, host)


# --------------------------------------------------------------------------- what the registry serves


def test_a_registry_off_the_installer_list_carries_the_unvetted_source_sensitivity():
    p, env = run(npmrc_edit(f"registry=https://{REGISTRY}/\n"))
    (sens,) = of(env, SENS, "code.unvetted_source")
    assert sens.value == 0.67 and sens.subject == entity(p, EntityKind.HOST, REGISTRY)


@pytest.mark.parametrize(
    "raw",
    [
        # A listed registry.
        npmrc_edit("registry=https://registry.npmjs.org/\n"),
        ex("pip config set global.index-url https://pypi.org/simple"),
        # A redirect that names no host.
        planir(
            "write",
            "file_write",
            {"path": "~/.cargo/config.toml", "content": '[source.crates-io]\nreplace-with = "m"\n'},
        ),
    ],
    ids=["npmjs", "pypi", "no-host"],
)
def test_a_listed_registry_or_no_host_carries_no_unvetted_source_sensitivity(raw):
    _, env = run(raw)
    assert of(env, REACH, "code.registry_redirect")
    assert of(env, SENS, "code.unvetted_source") == []
