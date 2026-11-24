"""`hermes sentrook login`: the shared golden cases (`integrations/fixtures/login`), the device id, and how
the credentials are stored."""

import json
import urllib.parse
from pathlib import Path

import pytest

from plugin import login

from .test_credentials import opened  # noqa: F401 - the fixture

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[3] / "fixtures" / "login" / "cases.json").read_text(
        encoding="utf-8"
    )
)
ISSUER = FIXTURE["issuer"]


class FakeIdentity:
    def __init__(self, case):
        self.case = case
        self.discovery = case.get("discovery", FIXTURE["discovery"])
        self.polls = list(case["polls"])
        self.requests: list[str] = []
        self.code_forms: list[dict] = []
        self.poll_forms: list[dict] = []

    def __call__(self, url, *, data=None, headers=None, timeout):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            self.requests.append("discovery")
            return 200, self.discovery, {}
        form = {k: v[0] for k, v in urllib.parse.parse_qs((data or b"").decode()).items()}
        if url == self.discovery["device_authorization_endpoint"]:
            self.requests.append("code")
            self.code_forms.append(form)
            return (
                self.case.get("code_status", 200),
                self.case.get("code_response", FIXTURE["code_response"]),
                {},
            )
        if url == FIXTURE["credentials_endpoint"]:
            self.requests.append("poll")
            self.poll_forms.append(form)
            answer = self.polls.pop(0)
            if answer.get("network_error"):
                raise OSError("connection reset")
            return answer["status"], answer["body"], {}
        raise AssertionError(f"unexpected request to {url}")


class Clock:
    def __init__(self):
        self.t = 0.0
        self.sleeps: list[float] = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def _expected_output(case):
    lines = []
    for line in case["expect"]["output"]:
        if line == "{start}":
            lines.extend(FIXTURE["start_output"])
        elif line == "{restart}":
            lines.append(login.RESTART_LINE)
        elif line == "{verify}":
            lines.append(FIXTURE["verify_report"])
        else:
            lines.append(line.replace("{cmd}", "hermes").replace("{where}", "in Hermes"))
    return lines


@pytest.fixture
def state_dir(tmp_path):
    d = tmp_path / "sentrook"
    d.mkdir()
    (d / login.DEVICE_ID_FILE).write_text(FIXTURE["device_id"] + "\n")
    return d


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["name"] for c in FIXTURE["cases"]])
def test_login_golden(case, state_dir):
    identity, clock, out, saved = FakeIdentity(case), Clock(), [], []

    def save(values):
        saved.append(dict(values))
        return "in Hermes"

    deps = login.LoginDeps(
        http=identity,
        sleep=clock.sleep,
        now=clock.now,
        out=out.append,
        hostname=lambda: "unused",
        save=save,
        verify=lambda: (FIXTURE["verify_report"], case.get("verify_ok", True)),
    )
    code = login.run_login({"state_dir": str(state_dir)}, name=case["name_arg"], env={}, deps=deps)

    expect = case["expect"]
    assert code == expect["exit"]
    assert clock.sleeps == expect["sleeps"]
    assert identity.requests == expect["requests"]
    if "code" in identity.requests:
        assert identity.code_forms == [case.get("code_request", FIXTURE["code_request"])]
    device_code = case.get("code_response", FIXTURE["code_response"]).get("device_code")
    assert identity.poll_forms == [
        {"client_id": "sentrook-plugin", "device_code": device_code}
    ] * len(identity.poll_forms)
    assert saved == ([expect["saved"]] if expect["saved"] else [])
    assert out == _expected_output(case)
    for value in (expect["saved"] or {}).values():
        if value.startswith("sentrook-scan-"):
            continue
        assert all(value not in line for line in out), "the secret is never printed"


def test_device_id_is_created_once_and_kept(tmp_path):
    state = tmp_path / "state" / "sentrook"
    first = login.device_id(state)
    assert len(first) == 32
    assert (state / login.DEVICE_ID_FILE).stat().st_mode & 0o777 == 0o600
    assert login.device_id(state) == first


def test_a_damaged_device_id_is_replaced(tmp_path):
    (tmp_path / login.DEVICE_ID_FILE).write_text("not hex\n")
    assert login.device_id(tmp_path) != "not hex"
    assert len(login.device_id(tmp_path)) == 32


def test_default_device_name_names_the_host():
    assert login.clean_device_name(None, "vps-1") == "Hermes on vps-1"
    assert login.clean_device_name("   ", "") == "Hermes"


def test_without_a_hermes_writer_nothing_starts(monkeypatch, state_dir):
    monkeypatch.setattr(login, "hermes_can_save", lambda: False)
    out = []

    def http(*a, **k):
        raise AssertionError("no request without a way to store the result")

    deps = login.LoginDeps(http=http, out=out.append)
    assert login.run_login({"state_dir": str(state_dir)}, env={}, deps=deps) == login.EXIT_FAILED
    assert "cannot store plugin credentials" in out[0]


def test_ctrl_c_changes_nothing(state_dir):
    def sleep(_):
        raise KeyboardInterrupt

    out, saved = [], []
    deps = login.LoginDeps(
        http=FakeIdentity({"polls": []}),
        sleep=sleep,
        out=out.append,
        save=lambda v: saved.append(v) or "x",
    )
    assert (
        login.run_login({"state_dir": str(state_dir)}, name="box", env={}, deps=deps)
        == login.EXIT_CANCELLED
    )
    assert out[-1] == "Cancelled. Nothing was changed."
    assert saved == []


def test_the_cli_runs_login_with_the_name(harness, monkeypatch):
    """`hermes sentrook login --name X` reaches `run_login` and exits with its code."""
    import argparse

    from plugin import cli

    seen = {}

    def fake_run_login(settings, *, name=None, env=None, deps=None):
        seen["name"] = name
        seen["verify"] = deps.verify is not None
        return 0

    monkeypatch.setattr(cli.login, "run_login", fake_run_login)
    parser = argparse.ArgumentParser()
    harness.ctx.cli["setup_fn"](parser)
    with pytest.raises(SystemExit) as done:
        harness.ctx.cli["handler_fn"](parser.parse_args(["login", "--name", "my vps"]))
    assert done.value.code == 0
    assert seen == {"name": "my vps", "verify": True}


class FakeHermesWriter:
    """`hermes_cli.gateway_setup_wizard.save_env_values` and Hermes's secret route: a save publishes the values
    to the process env, as Hermes does, unless Hermes refuses the write (managed settings) and says nothing."""

    def __init__(self, monkeypatch, refuse=False):
        import sys
        import types

        self.saved = {}

        def save_env_values(**values):
            if not refuse:
                self.saved.update(values)

        wizard = types.ModuleType("hermes_cli.gateway_setup_wizard")
        wizard.save_env_values = save_env_values
        pkg = types.ModuleType("hermes_cli")
        pkg.__path__ = []
        pkg.gateway_setup_wizard = wizard
        scope = types.ModuleType("agent.secret_scope")
        scope.get_secret = lambda name, default=None: self.saved.get(name, default)
        agent = types.ModuleType("agent")
        agent.__path__ = []
        agent.secret_scope = scope
        for name, mod in (
            ("hermes_cli", pkg),
            ("hermes_cli.gateway_setup_wizard", wizard),
            ("agent", agent),
            ("agent.secret_scope", scope),
        ):
            monkeypatch.setitem(sys.modules, name, mod)


def _approved_case():
    return FIXTURE["cases"][0]


def test_saving_goes_through_hermes_and_opens_no_env_file(state_dir, monkeypatch, opened):  # noqa: F811
    writer = FakeHermesWriter(monkeypatch)
    out = []
    deps = login.LoginDeps(
        http=FakeIdentity(_approved_case()), sleep=lambda s: None, now=lambda: 0.0, out=out.append
    )
    assert login.run_login({"state_dir": str(state_dir)}, name="test box", env={}, deps=deps) == 0
    assert writer.saved == _approved_case()["expect"]["saved"]
    assert 'Connected as "test box". Credentials saved in Hermes.' in out
    assert not [p for p in opened if p.endswith(".env")], opened


def test_a_write_hermes_refuses_is_not_reported_as_saved(state_dir, monkeypatch):
    FakeHermesWriter(monkeypatch, refuse=True)
    out = []
    deps = login.LoginDeps(
        http=FakeIdentity(_approved_case()), sleep=lambda s: None, now=lambda: 0.0, out=out.append
    )
    assert login.run_login({"state_dir": str(state_dir)}, name="test box", env={}, deps=deps) == 1
    assert not any(line.startswith("Connected") for line in out)
    assert out[-1].startswith("Signed in, but Hermes did not store the credentials")


def test_a_broken_answer_mid_poll_is_retried(state_dir):
    import http.client

    case = {
        "polls": [
            {"raise": http.client.IncompleteRead(b"")},
            *_approved_case()["polls"][-1:],
        ]
    }
    identity = FakeIdentity(case)
    real = identity.__call__

    def http_(url, **kw):
        if (
            url == FIXTURE["credentials_endpoint"]
            and identity.polls
            and "raise" in identity.polls[0]
        ):
            identity.requests.append("poll")
            raise identity.polls.pop(0)["raise"]
        return real(url, **kw)

    saved = []
    deps = login.LoginDeps(
        http=http_,
        sleep=lambda s: None,
        now=lambda: 0.0,
        out=lambda line: None,
        save=lambda v: saved.append(v) or "x",
    )
    assert login.run_login({"state_dir": str(state_dir)}, name="box", env={}, deps=deps) == 0
    assert identity.requests.count("poll") == 2
    assert saved


def test_a_damaged_device_id_file_ends_up_private(tmp_path):
    path = tmp_path / login.DEVICE_ID_FILE
    path.write_text("not hex\n")
    path.chmod(0o644)
    login.device_id(tmp_path)
    assert path.stat().st_mode & 0o777 == 0o600
