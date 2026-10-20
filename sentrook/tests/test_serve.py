"""The HTTP daemon: routes, auth, rate limit, the test-mode contract and the CLI scan command."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from test_jev_probes import ATTACK_ANSWERS, FakeDecider

from sentrook.serve import oidc
from sentrook.serve.config import ConfigError, ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer

KEY = "unit-test-state-key-" * 2  # 40 chars, low entropy on purpose
ISSUER = "https://id.example.test"


@contextmanager
def running(config: ServeConfig):
    srv = ScanServer(
        ServeRuntime.build(config, decider=FakeDecider(ATTACK_ANSWERS)), host="127.0.0.1", port=0
    )
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def server():
    """A test-mode server in open mode, as the TestNest runner talks to it."""
    config = ServeConfig(
        state_key=KEY,
        test_mode=True,
        scan_auth_mode="open",
        rate_limit_enabled=True,
        rate_limit_scan_rate=0.001,
        rate_limit_scan_burst=3,
    )
    with running(config) as srv:
        yield srv


class _StaticJwks:
    def __init__(self, public_key):
        self._key = public_key

    def get_signing_key_from_jwt(self, token):
        return type("SigningKey", (), {"key": self._key})()


@pytest.fixture
def oidc_server(monkeypatch):
    """An OIDC-mode server whose JWKS is a locally generated RSA key; yields (server, mint)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(oidc, "_jwks_client", lambda config: _StaticJwks(private.public_key()))

    def mint(scope="sentrook.scan", sub="user-1", **overrides):
        claims = {
            "iss": ISSUER,
            "aud": "sentrook",
            "sub": sub,
            "scope": scope,
            "exp": int(time.time()) + 300,
            **overrides,
        }
        return jwt.encode(claims, private, algorithm="RS256")

    config = ServeConfig(
        state_key=KEY,
        scan_auth_mode="oidc",
        oidc_issuer=ISSUER,
        rate_limit_enabled=True,
        rate_limit_scan_rate=0.001,
        rate_limit_scan_burst=2,
    )
    with running(config) as srv:
        yield srv, mint


def test_health_and_metrics(server):
    with httpx.Client(base_url=server.url) as c:
        h = c.get("/healthz").json()
        assert h["ok"] and h["test_mode"] and "auth" not in h and h["convergence"] == "conv-v3"
        m = c.get("/metrics")
        assert m.status_code == 200 and b"http_requests_total" in m.content
        assert c.get("/nope").status_code == 404


def test_open_mode_scans_without_credentials(server, attack_case):
    with httpx.Client(base_url=server.url) as c:
        r = c.post("/scan", json=attack_case["fixture"])
        assert r.status_code == 200
        body = r.json()
        assert (
            body["response_version"] == "2.0"
            and body["status"] in ("ok", "degraded")
            and body["risk"] is not None
        )
        assert body["state"] and body["request_id"] == attack_case["fixture"]["request_id"]


def test_scan_error_shape_and_bad_json(server, attack_case):
    headers: dict[str, str] = {}
    with httpx.Client(base_url=server.url) as c:
        bad = dict(attack_case["fixture"])
        bad["session"] = {**bad["session"], "step": 7}
        r = c.post("/scan", json=bad, headers=headers)
        assert (
            r.status_code == 422
            and r.json()["status"] == "error"
            and r.json()["error"]["code"] == "step_mismatch"
        )
        r = c.post(
            "/scan", content=b"{not json", headers={**headers, "Content-Type": "application/json"}
        )
        assert r.status_code == 400 and r.json()["error"]["code"] == "bad_json"
        r = c.post("/scan", json=[1, 2], headers=headers)
        assert r.status_code == 400


def test_testnest_scan_contract(server, attack_case):
    headers: dict[str, str] = {}
    body = {
        "fixture": attack_case["fixture"],
        "state_seed": attack_case["state_seed"],
        "oracle_seed": attack_case["oracle_seed"],
        "options": {
            "deterministic": True,
            "clock": "2026-10-05T10:28:00Z",
            "salt": "testnest",
            "repeat": 2,
        },
    }
    with httpx.Client(base_url=server.url) as c:
        r = c.post("/testnest/scan", json=body, headers=headers)
        assert r.status_code == 200
        out = r.json()
        assert set(out) == {"response", "probes", "prepared"}
        assert (
            out["response"]["risk"] >= 80
            and out["response"]["metadata"]["versions"]["token_status"] == "seeded"
        )
        steps = [p["step"] for p in out["probes"]]
        assert steps == ["jev_exposure", "jev_call", "aira", "entity_oracle", "context"]
        assert set(out["prepared"]) >= {"jev_exposure_state", "jev_call_state"}
        assert out["prepared"]["jev_call_state"]["pending_call"]["tool"] == "exec"
        # deterministic: same request, same token and fingerprint
        r2 = c.post("/testnest/scan", json=body, headers=headers).json()
        assert r2["response"]["state"] == out["response"]["state"]
        assert r2["response"]["action_fingerprint"] == out["response"]["action_fingerprint"]
        # ablation through options.probes
        body["options"]["probes"] = ["jev_call", "context"]
        r3 = c.post("/testnest/scan", json=body, headers=headers).json()
        assert {p["step"]: p["status"] for p in r3["probes"]}["entity_oracle"] == "skipped"


def test_rate_limit_open_mode_per_client_address(server, attack_case):
    with httpx.Client(base_url=server.url) as c:
        codes = [c.post("/scan", json=attack_case["fixture"]).status_code for _ in range(5)]
        assert codes.count(429) >= 1 and codes[0] == 200
        r = c.post("/scan", json=attack_case["fixture"])
        assert r.status_code == 429
        assert "Retry-After" in r.headers and r.json()["error"]["code"] == "rate_limited"


def test_oidc_mode_requires_a_scoped_token(oidc_server, attack_case):
    srv, mint = oidc_server
    fixture = attack_case["fixture"]
    with httpx.Client(base_url=srv.url) as c:
        r = c.post("/scan", json=fixture)
        assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
        assert r.headers["WWW-Authenticate"].startswith("Bearer")
        for bad in ("not-a-jwt", mint(aud="someone-else"), mint(exp=int(time.time()) - 60)):
            r = c.post("/scan", json=fixture, headers={"Authorization": f"Bearer {bad}"})
            assert r.status_code == 401
        r = c.post("/scan", json=fixture, headers={"Authorization": f"Bearer {mint(scope='x')}"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "insufficient_scope"
        assert 'scope="sentrook.scan"' in r.headers["WWW-Authenticate"]
        r = c.post("/scan", json=fixture, headers={"Authorization": f"Bearer {mint()}"})
        assert r.status_code == 200 and r.json()["response_version"] == "2.0"


def test_rate_limit_oidc_mode_per_caller(oidc_server, attack_case):
    srv, mint = oidc_server
    alice = {"Authorization": f"Bearer {mint(sub='alice')}"}
    bob = {"Authorization": f"Bearer {mint(sub='bob')}"}
    with httpx.Client(base_url=srv.url) as c:
        codes = [
            c.post("/scan", json=attack_case["fixture"], headers=alice).status_code
            for _ in range(3)
        ]
        assert codes == [200, 200, 429]
        assert c.post("/scan", json=attack_case["fixture"], headers=bob).status_code == 200


def test_test_mode_route_absent_when_disabled(attack_case):
    config = ServeConfig(state_key=KEY, test_mode=False, scan_auth_mode="open")
    with running(config) as srv, httpx.Client(base_url=srv.url) as c:
        assert c.post("/testnest/scan", json={"fixture": attack_case["fixture"]}).status_code == 404
        assert c.post("/scan", json=attack_case["fixture"]).status_code == 200


def test_config_from_env_guards():
    cfg = ServeConfig.from_env(
        {
            "SENTROOK_PROBES": "jev_call,aira",
            "SENTROOK_JEV_TIMEOUT_MS": "500",
            "SENTROOK_TEST_MODE": "1",
        }
    )
    assert (
        cfg.probes == ("jev_call", "aira")
        and cfg.jev_timeout_s == 0.5
        and cfg.test_mode
        and cfg.state_key
    )
    with pytest.raises(ConfigError):
        ServeConfig.from_env({"SENTROOK_ENV": "production"})
    with pytest.raises(ConfigError):
        ServeConfig.from_env(
            {
                "SENTROOK_ENV": "production",
                "SENTROOK_STATE_KEY": "x" * 40,
                "SENTROOK_TEST_MODE": "1",
            }
        )
    cfg = ServeConfig.from_env(
        {
            "SENTROOK_ENV": "production",
            "SENTROOK_STATE_KEY": "x" * 40,
            "SENTROOK_LOG_CONTENT": "content",
        }
    )
    assert cfg.log_content == "metadata"


def test_config_auth_modes():
    prod = {"SENTROOK_ENV": "production", "SENTROOK_STATE_KEY": "x" * 40}
    # development: open without an issuer, oidc once one is set; production defaults to oidc
    assert ServeConfig.from_env({}).scan_auth_mode == "open"
    cfg = ServeConfig.from_env({"SENTROOK_OIDC_ISSUER": ISSUER})
    assert cfg.scan_auth_mode == "oidc" and cfg.oidc_issuer == ISSUER
    assert ServeConfig.from_env(prod).scan_auth_mode == "oidc"
    with pytest.raises(ConfigError, match="not allowed in production"):
        ServeConfig.from_env({**prod, "SENTROOK_SCAN_AUTH_MODE": "open"})
    for retired in ("apikey", "auto"):
        with pytest.raises(ConfigError, match="SENTROOK_SCAN_AUTH_MODE"):
            ServeConfig.from_env({"SENTROOK_SCAN_AUTH_MODE": retired})


def test_ablation_requires_test_mode():
    with pytest.raises(ConfigError, match="SENTROOK_TEST_MODE"):
        ServeConfig.from_env({"SENTROOK_PROBES": "aira,context"})
    with pytest.raises(ConfigError):
        ServeConfig(state_key=KEY, scan_auth_mode="open", probes=("aira",))


def test_cli_scan_case_file(tmp_path, attack_case, monkeypatch, capsys):
    from sentrook.cli import main

    path = tmp_path / "case.json"
    path.write_text(json.dumps(attack_case))
    monkeypatch.setenv("SENTROOK_STATE_KEY", KEY)
    monkeypatch.setenv(
        "SENTROOK_JEV_BASE_URL", "http://127.0.0.1:9"
    )  # unreachable: Jev probes degrade
    monkeypatch.setenv("SENTROOK_JEV_TIMEOUT_MS", "200")
    # keep the CLI test offline and fast; ablation needs test mode
    monkeypatch.setenv("SENTROOK_TEST_MODE", "1")
    monkeypatch.setenv("SENTROOK_PROBES", "aira,entity_oracle,context")
    assert main(["scan", str(path), "--envelopes"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["response"]["response_version"] == "2.0" and len(out["probes"]) == 5
    assert {p["step"]: p["status"] for p in out["probes"]}["jev_call"] == "skipped"


def test_cli_refuses_ablation_outside_test_mode(tmp_path, attack_case, monkeypatch, capsys):
    from sentrook.cli import main

    path = tmp_path / "case.json"
    path.write_text(json.dumps(attack_case))
    monkeypatch.setenv("SENTROOK_STATE_KEY", KEY)
    monkeypatch.delenv("SENTROOK_TEST_MODE", raising=False)
    monkeypatch.setenv("SENTROOK_PROBES", "aira,context")
    assert main(["scan", str(path)]) == 2
    assert "SENTROOK_TEST_MODE=1" in capsys.readouterr().err
    monkeypatch.delenv("SENTROOK_PROBES")
    assert main(["scan", str(path), "--probes", "aira,context"]) == 2
    assert "only available in test mode" in capsys.readouterr().err
