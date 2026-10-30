"""PyPI project names compared the way PyPI compares them.

PyPI treats `Foo_Bar`, `foo.bar` and `foo-bar` as one project: runs of `-`, `_` and `.` count as
one `-`, and case does not matter. The scanner's extraction and the test-mode seed oracle fold
PyPI names that way, as the entity library does, so a seeded verdict and a live one agree. Other
ecosystems keep their own rules. Synthetic package names throughout.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import ex, run

from sentrook.enums import Enforce
from sentrook.oracle.client import EntityQuery, SeedOracle, VerdictKind
from sentrook.prepare.entities import EntityKind, Origin, extract_exec
from sentrook.probes.oracle import EntityOracleProbe
from sentrook.state.token import entity_hash, seed_state


def packages(cmd: str) -> set[str]:
    found = extract_exec(cmd, home="/home/me", workspace_root="/home/me/ws", cwd=None)
    return {f.value for f in found if f.kind is EntityKind.PACKAGE}


def seed(value: str, verdict: str = "known_bad") -> dict:
    return {"entities": [{"kind": "package", "value": value, "verdict": verdict}]}


def blocked_by_seed(cmd: str, seeded: str) -> bool:
    p, _ = run(ex(cmd))
    env = EntityOracleProbe(SeedOracle(seed(seeded))).run(p)
    return any(f.floor == "known_bad_entity" and f.enforce is Enforce.BLOCK for f in env.floors)


SPELLINGS = ["pip install Foo_Bar", "pip install foo.bar==1.0", "uv pip install FOO-bar[extra]"]


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize("cmd", SPELLINGS)
def test_pypi_spellings_extract_one_name(cmd):
    assert packages(cmd) == {"pypi:foo-bar"}


@pytest.mark.parametrize("cmd", SPELLINGS)
def test_seeded_known_bad_blocks_every_spelling(cmd):
    assert blocked_by_seed(cmd, "pypi:foo-bar")


def test_seed_written_unfolded_matches():
    assert blocked_by_seed("pip install foo-bar", "pypi:Foo_Bar")
    r = SeedOracle(seed("pypi:Foo__Bar.baz", "known_good")).lookup(
        [EntityQuery("package", "pypi:foo-bar-baz")]
    )
    assert r.get("package", "pypi:foo-bar-baz").verdict is VerdictKind.KNOWN_GOOD


def owner_named(request: str, cmd: str, value: str = "pypi:foo-bar") -> bool:
    p, _ = run(ex(cmd, request=request))
    return Origin.REQUEST in p.entities.get(EntityKind.PACKAGE, value).origins


@pytest.mark.parametrize(
    "request_text, cmd",
    [
        ("please install the foo_bar package", "pip install foo_bar"),
        ("please install Foo_Bar", "pip install Foo_Bar"),
        ("add foo.bar to the env", "pip install foo.bar==1.0"),
        ("please install foo-bar", "pip install foo_bar"),
        ("install pypi:foo_bar", "pip install foo-bar"),
    ],
)
def test_owner_named_package_keeps_request_origin_in_any_spelling(request_text, cmd):
    assert owner_named(request_text, cmd)


@pytest.mark.parametrize("request_text", ["please install foobar", "install foo_bars", "foo"])
def test_other_words_do_not_name_the_package(request_text):
    assert not owner_named(request_text, "pip install foo_bar")


def test_npm_request_match_stays_exact():
    assert not owner_named("install foo-bar", "npm install foo_bar", "npm:foo_bar")
    assert owner_named("install foo_bar", "npm install foo_bar", "npm:foo_bar")


def test_seeded_untrusted_pypi_name_is_folded():
    state = seed_state({"untrusted_entities": ["pypi:Foo_Bar", "npm:foo_bar"]}, salt="s")
    assert state.has_untrusted(entity_hash("s", "package", "pypi:foo-bar"))
    assert state.has_untrusted(entity_hash("s", "package", "npm:foo_bar"))


def test_runs_of_separators_fold_to_one():
    assert packages("pip install foo._-bar") == {"pypi:foo-bar"}


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize(
    "cmd, value",
    [
        ("npm install foo_bar", "npm:foo_bar"),
        ("npm install @scope/foo.bar", "npm:@scope/foo.bar"),
        ("cargo add foo_bar", "crates:foo_bar"),
        ("gem install foo_bar", "gem:foo_bar"),
        ("go get github.com/a/b_c", "go:github.com/a/b_c"),
    ],
)
def test_other_ecosystems_keep_their_names(cmd, value):
    assert value in packages(cmd)


def test_npm_seed_is_not_folded():
    assert not blocked_by_seed("npm install foo_bar", "npm:foo-bar")
    assert blocked_by_seed("npm install foo_bar", "npm:foo_bar")


@pytest.mark.parametrize(
    "cmd, value",
    [
        ("pip install ./dist/foo_bar-1.0.tar.gz", "pypi:./dist/foo_bar-1.0.tar.gz"),
        ("pip install .", "pypi:."),
    ],
)
def test_local_paths_are_not_folded(cmd, value):
    assert packages(cmd) == {value}


def test_already_canonical_names_unchanged():
    assert packages("pip install requests==2.0") == {"pypi:requests"}
