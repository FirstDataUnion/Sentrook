"""Sensitivity of installing a package nothing vouches for.

A package's install scripts run with the agent's own read access. When the entity library does not
know the package and neither the owner's request nor a grant names it, nobody has vouched for
that code, and the install carries `OracleParams.unvetted_package_sensitivity` as
`consequence.sensitivity` (0, the default, turns the rule off). A package the library knows, or one
the owner named, carries none: the owner's word is the vouching there. Synthetic names throughout.
"""

from __future__ import annotations

from typing import Any

import pytest
from test_aira_detectors import KEY, REACH, SENS, ex, hist_step, of

from sentrook.converge import load_params
from sentrook.converge.params import ConvergenceParams
from sentrook.converge.registry import REASONS
from sentrook.probes.oracle import OracleParams
from sentrook.scan import Scanner, ScannerConfig, ScanOptions

PKG = "kiln-rowcount"
WEIGHT = 0.5
REASON = "code.unvetted_package"


def scanner(weight: float = WEIGHT, as_root: bool = False) -> Scanner:
    params = ConvergenceParams(
        oracle=OracleParams(unvetted_package_sensitivity=weight, unvetted_package_as_root=as_root)
    )
    return Scanner(ScannerConfig(token_key=KEY, params=params))


def aira(raw: dict, seed: dict | None = None, weight: float = WEIGHT, as_root: bool = False):
    res = scanner(weight, as_root).scan(
        raw, ScanOptions(state_seed={"max_input_seq": 0}, oracle_seed=seed or {"entities": []})
    )
    return res.prepared, next(e for e in res.envelopes if e.step.value == "aira")


def seed(value: str, verdict: str, kind: str = "package") -> dict[str, Any]:
    return {"entities": [{"kind": kind, "value": value, "verdict": verdict}]}


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize(
    "command, value",
    [
        (f"pip install {PKG}", f"pypi:{PKG}"),
        (f"npm install {PKG}", f"npm:{PKG}"),
        (
            "pip install git+https://github.com/lorrwick-labs/rowcount.git",
            "git+github.com/lorrwick-labs/rowcount",
        ),
        ("npm install $(cat name.txt)", "npm:$(...)"),
    ],
    ids=["pypi", "npm", "git-url", "computed"],
)
def test_an_unknown_package_nobody_named_carries_the_sensitivity(command, value):
    p, env = aira(ex(command, request="Set the project up."))
    (sens,) = of(env, SENS, REASON)
    assert sens.value == WEIGHT
    assert p.entities.by_id(sens.subject).value == value


def test_an_unknown_seed_entry_is_still_unknown():
    _, env = aira(ex(f"pip install {PKG}"), seed(f"pypi:{PKG}", "unknown"))
    assert [c.value for c in of(env, SENS, REASON)] == [WEIGHT]


def test_the_value_follows_the_parameter():
    _, env = aira(ex(f"pip install {PKG}"), weight=0.67)
    assert [c.value for c in of(env, SENS, REASON)] == [0.67]


def test_the_reason_has_owner_text():
    assert "{subject}" in REASONS[REASON].subject


# --------------------------------------------------------------------------- must stay silent


def test_off_by_default():
    assert OracleParams().unvetted_package_sensitivity == 0.0
    assert load_params("conv-v4").oracle.unvetted_package_sensitivity == 0.0
    _, env = aira(ex(f"pip install {PKG}"), weight=0.0)
    assert of(env, SENS) == [] and of(env, REACH, "code.package_install")


def test_a_package_the_library_knows_carries_none():
    _, env = aira(ex(f"pip install {PKG}"), seed(f"pypi:{PKG}", "known_good"))
    assert of(env, SENS) == [] and of(env, REACH, "code.package_install")


@pytest.mark.parametrize(
    "request_text, command",
    [
        (f"Install {PKG} for the build.", f"pip install {PKG}"),
        ("Install Kiln_Rowcount.", f"pip install {PKG}"),
        (f"Add {PKG} to the project.", f"npm install --save {PKG}"),
    ],
    ids=["named", "pypi-spelling", "npm"],
)
def test_a_package_the_owner_named_carries_none(request_text, command):
    _, env = aira(ex(command, request=request_text))
    assert of(env, SENS) == [] and of(env, REACH, "code.package_install")


@pytest.mark.parametrize(
    "command",
    [
        f"sudo apt-get install -y {PKG}",
        f"brew install {PKG}",
        f"cargo install {PKG}",
        f"docker pull lorrwick/{PKG}:1.2",
    ],
    ids=["apt", "brew", "cargo", "docker"],
)
def test_an_ecosystem_the_library_does_not_cover_carries_none(command):
    _, env = aira(ex(command, request="Set the project up."))
    assert of(env, SENS, REASON) == []


def test_the_covered_ecosystems_follow_the_parameter():
    params = ConvergenceParams(
        oracle=OracleParams(
            unvetted_package_sensitivity=WEIGHT, unvetted_package_ecosystems=("npm", "apt")
        )
    )
    sc = Scanner(ScannerConfig(token_key=KEY, params=params))

    def sens(command: str) -> list:
        res = sc.scan(
            ex(command), ScanOptions(state_seed={"max_input_seq": 0}, oracle_seed={"entities": []})
        )
        return of(next(e for e in res.envelopes if e.step.value == "aira"), SENS, REASON)

    assert sens(f"sudo apt-get install -y {PKG}") and sens(f"npm install {PKG}")
    assert sens(f"pip install {PKG}") == []


def test_only_the_unnamed_package_of_two_carries_it():
    p, env = aira(ex(f"pip install {PKG} marlfen-utils", request=f"Install {PKG}."))
    (sens,) = of(env, SENS, REASON)
    assert p.entities.by_id(sens.subject).value == "pypi:marlfen-utils"


@pytest.mark.parametrize(
    "command",
    [f"pip download {PKG}", f"pip show {PKG}", f"npm view {PKG}", "npm ls", "pip install"],
)
def test_a_command_that_installs_nothing_carries_none(command):
    _, env = aira(ex(command))
    assert of(env, SENS, REASON) == []


def test_a_package_only_an_earlier_step_installed_carries_none():
    raw = ex("ls", history=[hist_step(1, "exec", "exec", {"command": f"pip install {PKG}"})])
    _, env = aira(raw)
    assert of(env, SENS) == []


# --------------------------------------------------------------------------- an owner-named package as root

NAMED = f"Install {PKG}, a calculator I found."


def test_as_root_an_owner_named_unknown_package_carries_it_when_the_option_is_on():
    p, env = aira(ex(f"sudo apt-get install -y {PKG}", request=NAMED), as_root=True)
    (sens,) = of(env, SENS, REASON)
    assert sens.value == WEIGHT and p.entities.by_id(sens.subject).value == f"apt:{PKG}"


@pytest.mark.parametrize(
    "command, seeded, as_root",
    [
        (f"sudo apt-get install -y {PKG}", None, False),  # the option is off by default
        (f"apt-get install -y {PKG}", None, True),  # not as root
        (f"sudo apt-get install -y {PKG}", seed(f"apt:{PKG}", "known_good"), True),  # known
    ],
    ids=["option-off", "not-root", "known-package"],
)
def test_an_owner_named_package_otherwise_carries_none(command, seeded, as_root):
    assert OracleParams().unvetted_package_as_root is False
    _, env = aira(ex(command, request=NAMED), seeded, as_root=as_root)
    assert of(env, SENS) == [] and of(env, REACH, "code.package_install")
