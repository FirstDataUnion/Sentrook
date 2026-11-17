"""Scan credentials come only through Hermes (`agent.secret_scope.get_secret`), never from a `.env` file
or the plugin settings, and a missing one fails closed."""

import builtins
import io
import os
import pathlib
import sys
import types
from pathlib import Path

import pytest
import yaml

import plugin
from plugin import auth

from .test_plugin import call, slash, turn

ID, SECRET = "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET"


class UnscopedSecretError(RuntimeError):
    pass


@pytest.fixture
def hermes_secrets(harness, monkeypatch):
    """Hermes's secret route under test control: the credentials live only in `.store`, never in the
    process env. `.unscoped` makes every read raise, as Hermes does for an unscoped read on a
    multiplexed gateway."""
    for k in (ID, SECRET):
        monkeypatch.delenv(k, raising=False)
    store = {ID: "client", SECRET: "secret-value"}
    state = types.SimpleNamespace(store=store, unscoped=False, reads=[])

    def get_secret(name, default=None):
        state.reads.append(name)
        if state.unscoped:
            raise UnscopedSecretError(name)
        return store.get(name, default)

    mod = types.ModuleType("agent.secret_scope")
    mod.get_secret = get_secret
    pkg = types.ModuleType("agent")
    pkg.__path__ = []
    pkg.secret_scope = mod
    monkeypatch.setitem(sys.modules, "agent", pkg)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", mod)
    harness.secrets = state
    return harness


@pytest.fixture
def opened(monkeypatch):
    """Every path the plugin opens by name."""
    seen: list[str] = []

    def spy(real, path_of):
        def wrapper(*a, **k):
            seen.append(str(path_of(a)))
            return real(*a, **k)

        return wrapper

    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", spy(real_open, lambda a: a[0]))
    monkeypatch.setattr(io, "open", spy(real_open, lambda a: a[0]))
    monkeypatch.setattr(os, "open", spy(os.open, lambda a: a[0]))
    for name in ("open", "read_text", "read_bytes"):
        monkeypatch.setattr(pathlib.Path, name, spy(getattr(pathlib.Path, name), lambda a: a[0]))
    return seen


def verify(h):
    return {name: (ok, detail) for name, ok, detail in plugin.cli.run_verify(plugin._settings())}


# Must fire


def test_credentials_set_only_in_hermes_mint_a_token_and_verify_passes(hermes_secrets, monkeypatch):
    h = hermes_secrets
    assert ID not in os.environ and SECRET not in os.environ
    turn(h)
    assert call(h, "c1", "ls") is None
    assert len(h.scans) == 1
    assert {ID, SECRET} <= set(h.secrets.reads)
    assert "credentials: present" in slash(h, "status").splitlines()

    monkeypatch.setattr(plugin.cli, "http_json", lambda *a, **k: (200, {"version": "t"}, {}))
    report = verify(h)
    assert report["credentials"] == (True, "client client, audience sentrook")
    assert report["token mint"][0] is True


# Must stay silent


def test_a_dotenv_hermes_did_not_load_is_never_read(hermes_secrets, opened, monkeypatch):
    h = hermes_secrets
    h.secrets.store.clear()
    dotenv = h.dir / ".env"
    dotenv.write_text(f"{ID}=from-dotenv\n{SECRET}=from-dotenv-secret\nSENTROOK_MODE=observe\n")
    opened.clear()
    turn(h)
    r = call(h, "c1", "ls")
    out = slash(h, "status")
    monkeypatch.setattr(plugin.cli, "http_json", lambda *a, **k: (200, {"version": "t"}, {}))
    report = verify(h)

    assert not [p for p in opened if Path(p).name == ".env"]
    assert h.scans == []
    assert r is not None and r["action"] in ("approve", "block")
    assert "mode: enforce" in out.splitlines()
    assert "from-dotenv" not in out
    assert report["credentials"][0] is False


def test_credentials_in_the_plugin_settings_are_ignored(hermes_secrets):
    h = hermes_secrets
    h.secrets.store.clear()
    h.ctx.settings.update({"client_id": "cid-7f3a91", "client_secret": "cs-b04e2d77"})
    turn(h)
    assert call(h, "c1", "ls") is not None
    assert h.scans == []
    assert "client_id" not in plugin.SETTINGS_KEYS
    assert "client_secret" not in plugin.SETTINGS_KEYS


# Must fail closed


@pytest.mark.parametrize("platform,action", [("telegram", "approve"), ("cron", "block")])
def test_a_missing_secret_fails_closed_and_status_names_it(hermes_secrets, platform, action):
    h = hermes_secrets
    del h.secrets.store[SECRET]
    turn(h, platform=platform)
    r = call(h, "c1", "ls")
    assert h.scans == []
    assert r["action"] == action
    traffic = h.traffic()[-1]
    assert traffic["decision"] != "allowed"
    assert f"credentials: missing {SECRET} (set in Hermes)" in slash(h, "status").splitlines()


def test_both_missing_are_both_named(hermes_secrets):
    h = hermes_secrets
    h.secrets.store.clear()
    line = f"credentials: missing {ID} and {SECRET} (set in Hermes)"
    assert line in slash(h, "status").splitlines()
    assert verify(h)["credentials"][1].startswith(f"{ID} and {SECRET} not set in Hermes")


@pytest.mark.parametrize("hermes", ["unscoped", "empty"])
def test_the_process_env_never_stands_in_for_hermes(hermes_secrets, monkeypatch, hermes):
    """On a multiplexed gateway the process env holds the launch profile's values: when Hermes raises
    (an unscoped read) or has nothing for this profile, the scan has no credentials."""
    h = hermes_secrets
    monkeypatch.setenv(ID, "launch-profile-client")
    monkeypatch.setenv(SECRET, "launch-profile-secret")
    if hermes == "unscoped":
        h.secrets.unscoped = True
    else:
        h.secrets.store.clear()
    turn(h)
    assert call(h, "c1", "ls")["action"] == "approve"
    assert h.scans == []
    assert auth.missing_credentials() == [ID, SECRET]


def test_verify_with_an_invalid_issuer_does_not_blame_the_credentials(hermes_secrets, monkeypatch):
    monkeypatch.delenv("SENTROOK_DEV_ENDPOINTS")
    monkeypatch.setenv("SENTROOK_OIDC_ISSUER", "http://evil.example")
    monkeypatch.setattr(plugin.cli, "http_json", lambda *a, **k: (200, {"version": "t"}, {}))
    report = verify(hermes_secrets)
    assert report["OIDC issuer"][0] is False
    assert report["credentials"] == (True, "set in Hermes; not used until the OIDC issuer is valid")


def test_outside_hermes_the_process_env_is_read(monkeypatch):
    monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
    monkeypatch.setenv(ID, " cid ")
    monkeypatch.delenv(SECRET, raising=False)
    assert auth.get_secret(ID) == "cid"
    assert auth.missing_credentials() == [SECRET]


# The manifest says the same


def manifest():
    return yaml.safe_load((Path(plugin.__file__).parent / "plugin.yaml").read_text())


def test_the_manifest_declares_the_credentials_as_hermes_secrets():
    m = manifest()
    secrets = {k: v for k, v in m["config_schema"].items() if v.get("type") == "secret"}
    assert {v["env"] for v in secrets.values()} == {ID, SECRET}
    assert not set(secrets) & set(plugin.SETTINGS_KEYS)
    assert [e["name"] for e in m["requires_env"]] == [ID, SECRET]
    assert m["requires_env"][1]["secret"] is True


def test_the_manifest_declares_a_hermes_floor():
    floor = manifest()["requires_hermes"]
    assert floor.startswith(">=") and all(p.isdigit() for p in floor[2:].split("."))


def test_no_plugin_module_names_a_dotenv_file():
    src = Path(plugin.__file__).parent
    for f in src.glob("*.py"):
        text = f.read_text()
        assert '".env"' not in text and "'.env'" not in text, f.name
        assert "dotenv" not in text.lower(), f.name
