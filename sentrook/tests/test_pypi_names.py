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
from sentrook.prepare.entities import EntityKind, extract_exec
from sentrook.probes.oracle import EntityOracleProbe


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
