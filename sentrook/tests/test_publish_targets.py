"""Publish targets are destinations.

A command that publishes or uploads a package, image or chart sends it to the host its target names:
`npm publish --registry URL`, `twine upload --repository-url URL`, `gem push --host URL`, `cargo publish
--index URL`, `uv publish --publish-url URL`, `dotnet nuget push --source URL`, the registry of an image
given to `docker push` or `podman push`, and the host of `helm push`'s `oci://` URL. That host is a data
destination. A publish without a target (the public registry by default) names no host. Installing,
viewing and pulling with the same options keep the host a data source. Synthetic hosts throughout.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import ex, run

from sentrook.oracle.client import SeedOracle
from sentrook.prepare.entities import EntityKind, Role, extract_exec
from sentrook.probes.oracle import EntityOracleProbe

REG = "registry.example-corp.test"


def hosts(cmd: str) -> dict[str, set[str]]:
    found = extract_exec(cmd, home="/home/me", workspace_root="/home/me/ws", cwd="/home/me/ws")
    out: dict[str, set[str]] = {}
    for f in found:
        if f.kind is EntityKind.HOST:
            out.setdefault(f.value, set()).add(f.role.value)
    return out


# --------------------------------------------------------------------------- must be a destination

DESTINATIONS = [
    (f"npm publish dist/x.tgz --registry https://{REG}", REG),
    (f"npm publish --registry=https://{REG}/", REG),
    (f"npm --registry https://{REG} publish dist/x.tgz", REG),
    (f"pnpm publish --registry https://{REG} --no-git-checks", REG),
    (f"yarn publish --registry https://{REG}", REG),
    (f"cd dist && npm publish --access public --registry https://{REG}", REG),
    (
        "twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "twine upload --repository-url=https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "python3 -m twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "TWINE_REPOSITORY_URL=https://pkgs.example-corp.test/ twine upload dist/*",
        "pkgs.example-corp.test",
    ),
    ("uv publish --publish-url https://pkgs.example-corp.test/legacy/", "pkgs.example-corp.test"),
    ("gem push x-1.0.gem --host https://gems.example-corp.test", "gems.example-corp.test"),
    (
        "cargo publish --index sparse+https://crates.example-corp.test/index/",
        "crates.example-corp.test",
    ),
    (f"docker push {REG}/team/app:1.2", REG),
    (f"docker image push {REG}/app:1", REG),
    (f"sudo docker push {REG}:5000/app:1", REG),
    (f"podman push {REG}/app:1", REG),
    ("helm push chart-0.1.0.tgz oci://charts.example-corp.test/team", "charts.example-corp.test"),
    (
        "dotnet nuget push x.1.0.nupkg --source https://nuget.example-corp.test/v3/index.json",
        "nuget.example-corp.test",
    ),
]


@pytest.mark.parametrize("cmd,host", DESTINATIONS)
def test_a_publish_target_is_a_data_destination(cmd, host):
    assert hosts(cmd).get(host) == {Role.DATA_DESTINATION.value}, hosts(cmd)


def test_other_hosts_in_the_command_keep_their_role():
    got = hosts(f"npm publish --registry https://{REG} && curl https://status.example-corp.test/ok")
    assert got[REG] == {Role.DATA_DESTINATION.value}
    assert got["status.example-corp.test"] == {Role.DATA_SOURCE.value}


def test_the_published_artefact_stays_a_data_source():
    found = extract_exec(
        f"npm publish /home/me/ws/dist/x.tgz --registry https://{REG}",
        home="/home/me",
        workspace_root="/home/me/ws",
        cwd="/home/me/ws",
    )
    paths = {f.value: f.role for f in found if f.kind is EntityKind.PATH}
    assert paths.get("/home/me/ws/dist/x.tgz") is Role.DATA_SOURCE, paths


# --------------------------------------------------------------------------- must stay silent

SOURCES = [
    f"npm install --registry https://{REG} left-padx",
    f"npm view left-padx --registry https://{REG}",
    f"npm run publish --registry https://{REG}",
    f"pnpm add left-padx --registry https://{REG}",
    "pip install -i https://pkgs.example-corp.test/simple foo",
    "twine check --repository-url https://pkgs.example-corp.test/ dist/*",
    f'echo "npm publish --registry https://{REG}"',
]


@pytest.mark.parametrize("cmd", SOURCES)
def test_installing_or_reading_keeps_the_host_a_data_source(cmd):
    got = hosts(cmd)
    assert all(Role.DATA_DESTINATION.value not in roles for roles in got.values()), got


@pytest.mark.parametrize(
    "cmd",
    [
        "npm publish",
        "yarn npm publish",
        "twine upload -r internal dist/*",
        "twine upload dist/*",
        "docker push app:1",
        "docker push someuser/app:1",
        f"docker pull {REG}/app:1",
        "cargo publish --registry internal",
    ],
)
def test_a_publish_without_a_named_host_adds_none(cmd):
    assert hosts(cmd) == {}, hosts(cmd)


# --------------------------------------------------------------------------- the oracle sees it


def test_a_near_miss_registry_takes_the_destination_distrust():
    p, _ = run(ex("npm publish dist/x.tgz --registry https://registry.examp1e-corp.test"))
    seed = {"entities": [{"kind": "host", "value": REG, "verdict": "known_good"}]}
    env = EntityOracleProbe(SeedOracle(seed)).run(p)
    [c] = [c for c in env.contributions if c.signal == "suspicion.distrust"]
    assert c.reason == "reputation.near_miss_host" and c.value == 0.9


# --------------------------------------------------------------------------- shapes from review

MORE_DESTINATIONS = [
    (f"npm -w pkg publish --registry https://{REG}", REG),
    (f"npm --workspace pkg publish --registry https://{REG}", REG),
    (f"docker --context prod push {REG}/app:1", REG),
    (f"docker --config ./cfg push {REG}/app:1", REG),
    (f"docker -H ssh://builder.example-corp.test push {REG}/app:1", REG),
    (f"npx -y npm@10 publish --registry https://{REG}", REG),
    (f"corepack pnpm publish --registry https://{REG}", REG),
    (
        "uvx twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "uv run twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "pipx run twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "python3.12 -m twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "python3 -I -m twine upload --repository-url https://pkgs.example-corp.test/ dist/*",
        "pkgs.example-corp.test",
    ),
    (
        "export TWINE_REPOSITORY_URL=https://pkgs.example-corp.test/ && twine upload dist/*",
        "pkgs.example-corp.test",
    ),
    (f"npm_config_registry=https://{REG} npm publish", REG),
    ("RUBYGEMS_HOST=https://gems.example-corp.test gem push x-1.0.gem", "gems.example-corp.test"),
    (f"npm publish --@acme:registry=https://{REG}", REG),
    (f"npm publish --registry user@{REG}", REG),
    (f"podman push app:1 docker://{REG}/app:1", REG),
    (f"docker buildx build --push -t {REG}/app:1 .", REG),
    (f"docker build --push --tag {REG}/app:1 .", REG),
    ("docker push [fd00::5]:5000/app:1", "fd00::5"),
]


@pytest.mark.parametrize("cmd,host", MORE_DESTINATIONS)
def test_more_publish_forms_give_a_destination(cmd, host):
    assert Role.DATA_DESTINATION.value in hosts(cmd).get(host, set()), hosts(cmd)


def test_a_fetched_and_run_host_stays_a_code_source_when_also_published_to():
    got = hosts(
        f"curl -fsSLo i.sh https://{REG}/i.sh && sh i.sh && npm publish --registry https://{REG}"
    )
    assert got[REG] == {Role.CODE_SOURCE.value, Role.DATA_DESTINATION.value}


@pytest.mark.parametrize(
    "cmd,only",
    [
        ("podman push app:1 oci-archive:/tmp/app.tar", None),
        ("podman push app:1 dir:/tmp/app", None),
        (f"podman push --authfile auth.d/auth.json {REG}/app:1", REG),
        (
            "helm push chart-0.1.0.tgz oci://charts.example-corp.test/team --ca-file ca.d/ca.crt",
            "charts.example-corp.test",
        ),
        (
            "helm push build.out/chart-0.1.0.tgz oci://charts.example-corp.test/team",
            "charts.example-corp.test",
        ),
        ("dotnet nuget push x.1.0.nupkg -s feeds.d/local", None),
        (f"npm publish --dry-run --registry https://{REG}", None),
        (f"docker build -t {REG}/app:1 .", None),
        ("docker push localhost:5000/app:1", None),
    ],
)
def test_only_the_real_target_is_a_destination(cmd, only):
    dest = {h for h, roles in hosts(cmd).items() if Role.DATA_DESTINATION.value in roles}
    assert dest == ({only} if only else set()), hosts(cmd)


def test_a_command_that_does_not_parse_names_no_publish_target():
    # the shell parse fails on the unclosed quote: the text rules decide, as before
    got = hosts(f'npm publish --registry https://{REG}; echo "oops')
    assert got.get(REG) == {Role.DATA_SOURCE.value}
