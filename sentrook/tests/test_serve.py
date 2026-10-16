"""The HTTP daemon: routes, auth, rate limit, the test-mode contract and the CLI scan command."""

from __future__ import annotations

import json

import httpx
import pytest
from test_jev_probes import ATTACK_ANSWERS, FakeDecider

from sentrook.serve.auth import SCAN_API_KEY_HEADER
from sentrook.serve.config import ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer

KEY = "unit-test-key-0123456789abcdef0123456789abcdef"


@pytest.fixture
def server():
    config = ServeConfig(
        state_key=KEY,
        test_mode=True,
        scan_auth_mode="apikey",
        scan_api_key="k-test",
        rate_limit_enabled=True,
        rate_limit_scan_rate=0.001,
        rate_limit_scan_burst=3,
    )
    runtime = ServeRuntime.build(config, decider=FakeDecider(ATTACK_ANSWERS))
    srv = ScanServer(runtime, host="127.0.0.1", port=0)
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


def test_health_and_metrics(server):
    with httpx.Client(base_url=server.url) as c:
        h = c.get("/healthz").json()
        assert (
            h["ok"]
            and h["test_mode"]
            and h["auth"] == "apikey:apikey"
            and h["convergence"] == "conv-v1"
        )
        m = c.get("/metrics")
        assert m.status_code == 200 and b"http_requests_total" in m.content
        assert c.get("/nope").status_code == 404


def test_scan_requires_api_key(server, attack_case):
    with httpx.Client(base_url=server.url) as c:
        r = c.post("/scan", json=attack_case["fixture"])
        assert r.status_code == 401
        r = c.post("/scan", json=attack_case["fixture"], headers={SCAN_API_KEY_HEADER: "k-test"})
        assert r.status_code == 200
        body = r.json()
        assert (
            body["response_version"] == "2.0"
            and body["status"] in ("ok", "degraded")
            and body["risk"] is not None
        )
        assert body["state"] and body["request_id"] == attack_case["fixture"]["request_id"]


def test_scan_error_shape_and_bad_json(server, attack_case):
    headers = {SCAN_API_KEY_HEADER: "k-test"}
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
    headers = {SCAN_API_KEY_HEADER: "k-test"}
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


def test_rate_limit_applies_per_key(server, attack_case):
    headers = {SCAN_API_KEY_HEADER: "k-test"}
    with httpx.Client(base_url=server.url) as c:
        codes = [
            c.post("/scan", json=attack_case["fixture"], headers=headers).status_code
            for _ in range(5)
        ]
        assert codes.count(429) >= 1 and codes[0] == 200
        r = c.post("/scan", json=attack_case["fixture"], headers=headers)
        if r.status_code == 429:
            assert "Retry-After" in r.headers and r.json()["error"]["code"] == "rate_limited"


def test_test_mode_route_absent_when_disabled(attack_case):
    config = ServeConfig(state_key=KEY, test_mode=False)
    srv = ScanServer(
        ServeRuntime.build(config, decider=FakeDecider(ATTACK_ANSWERS)), host="127.0.0.1", port=0
    )
    srv.start()
    try:
        with httpx.Client(base_url=srv.url) as c:
            assert (
                c.post("/testnest/scan", json={"fixture": attack_case["fixture"]}).status_code
                == 404
            )
            assert (
                c.post("/scan", json=attack_case["fixture"]).status_code == 200
            )  # auto mode, no key: open
    finally:
        srv.stop()


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
    with pytest.raises(RuntimeError):
        ServeConfig.from_env({"SENTROOK_ENV": "production"})
    with pytest.raises(RuntimeError):
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


def test_cli_scan_case_file(tmp_path, attack_case, monkeypatch, capsys):
    from sentrook.cli import main

    path = tmp_path / "case.json"
    path.write_text(json.dumps(attack_case))
    monkeypatch.setenv("SENTROOK_STATE_KEY", KEY)
    monkeypatch.setenv(
        "SENTROOK_JEV_BASE_URL", "http://127.0.0.1:9"
    )  # unreachable: Jev probes degrade
    monkeypatch.setenv("SENTROOK_JEV_TIMEOUT_MS", "200")
    monkeypatch.setenv(
        "SENTROOK_PROBES", "aira,entity_oracle,context"
    )  # keep the CLI test offline and fast
    assert main(["scan", str(path), "--envelopes"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["response"]["response_version"] == "2.0" and len(out["probes"]) == 5
    assert {p["step"]: p["status"] for p in out["probes"]}["jev_call"] == "skipped"
