"""Prometheus /metrics for the scan serve daemon."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import sentrook.serve.oidc as oidc
from sentrook.config import L3Policy
from sentrook.serve.config import ServeConfig
from sentrook.serve.metrics import CallerMixTracker, contains_forbidden_ids
from sentrook.serve.oidc import SCOPE_SCAN
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import _make_handler

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "examples" / "rules"
ISSUER = "https://identity.test.example"
AUDIENCE = "sentrook"
KID = "metrics-key-1"


def _benign_plan() -> dict:
    return {
        "version": "1.0",
        "run_id": "metrics-test:run_1",
        "intent": "list files",
        "steps": [
            {
                "id": "s1",
                "tool": "read",
                "status": "pending",
                "args": {"path": "/tmp/notes.md"},
            }
        ],
        "metadata": {
            "adapter": "fixture",
            "hook": "before_tool_call",
            "session_id": "metrics-test",
        },
    }


def _request(
    base_url: str,
    path: str,
    *,
    body: bytes | None = None,
    method: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(
        base_url + path,
        data=body,
        method=method or ("POST" if body is not None else "GET"),
        headers=hdrs,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _start_server(config: ServeConfig) -> tuple[ThreadingHTTPServer, str, ServeRuntime]:
    runtime = ServeRuntime(config)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(runtime))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    return httpd, base_url, runtime


def _metric_sample(text: str, name: str, **labels: str) -> float | None:
    needle_parts = [f'{key}="{value}"' for key, value in labels.items()]
    for line in text.splitlines():
        if line.startswith("#") or not line.startswith(name):
            continue
        if "{" in line:
            head, _, rest = line.partition("}")
            if not all(part in head for part in needle_parts):
                continue
            if labels and not head.startswith(f"{name}{{"):
                continue
            return float(rest.strip())
        if not labels:
            _metric, _, value = line.partition(" ")
            if _metric == name:
                return float(value)
    return None


@pytest.fixture
def serve_config(tmp_path: Path) -> ServeConfig:
    return ServeConfig(
        mode="observe",
        rules_path=RULES,
        corpus_dir=tmp_path / "corpus",
        log_path=tmp_path / "scan.log.jsonl",
        latency_log_path=tmp_path / "latency.log.jsonl",
        l3_policy=L3Policy.OFF,
        oidc_issuer="",
        scan_auth_mode="auto",
        scan_api_key=None,
    )


def test_metrics_unauthenticated_and_health_unchanged(serve_config: ServeConfig) -> None:
    httpd, base_url, _runtime = _start_server(serve_config)
    try:
        health_status, health_body = _request(base_url, "/health")
        assert health_status == 200
        health = json.loads(health_body)
        assert health["status"] == "ok"
        assert "rules_loaded" in health

        status, body = _request(base_url, "/metrics")
        assert status == 200
        text = body.decode()
        assert "http_requests_total" in text
        assert "sentrook_scan_decisions_total" in text
        assert "sentrook_active_callers" in text
        assert "sentrook_top_caller_share" in text
        assert _metric_sample(text, "http_requests_total", endpoint="/metrics") is None
        assert _metric_sample(
            text, "http_requests_total", method="GET", endpoint="/health", status="200"
        )
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_scan_records_http_and_decision_metrics(serve_config: ServeConfig) -> None:
    httpd, base_url, _runtime = _start_server(serve_config)
    try:
        status, payload = _request(base_url, "/scan", body=json.dumps(_benign_plan()).encode())
        assert status == 200
        assert json.loads(payload)["decision"] == "allow"

        _status, body = _request(base_url, "/metrics")
        text = body.decode()
        scan_count = _metric_sample(
            text, "http_requests_total", method="POST", endpoint="/scan", status="200"
        )
        assert scan_count is not None and scan_count >= 1
        decisions = _metric_sample(text, "sentrook_scan_decisions_total", decision="allow")
        assert decisions is not None and decisions >= 1
        assert "sentrook_scan_latency_seconds_bucket" in text
        assert "sentrook_scan_matched_rules_total" in text
        assert "sentrook_scan_winning_rules_total" in text
        assert "sentrook_scan_l3_outcomes_total" in text
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_review_scan_records_matched_rule_and_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A soft AIRA-010-style match should label authority=soft on match counters."""
    from sentrook.config import L2Authority
    from sentrook.layers.pass_kind import L2PassKind
    from sentrook.result import (
        DebugInfo,
        LayerInfo,
        MatchedRule,
        PlanEcho,
        ScanResult,
        TimingInfo,
    )
    from sentrook.rules.compiler import compile_rule

    config = ServeConfig(
        mode="observe",
        rules_path=RULES,
        corpus_dir=tmp_path / "corpus",
        log_path=tmp_path / "scan.log.jsonl",
        latency_log_path=tmp_path / "latency.log.jsonl",
        l3_policy=L3Policy.OFF,
        oidc_issuer="",
        scan_auth_mode="auto",
        scan_api_key=None,
    )
    httpd, base_url, runtime = _start_server(config)
    try:
        soft_rule = compile_rule(
            {
                "rule": "AIRA-010",
                "meta": {
                    "name": "pending shell exec",
                    "severity": "medium",
                    "action": "review",
                    "authority": "soft",
                },
                "condition": {"pending_tool": "exec"},
            }
        )
        assert soft_rule.meta.authority == L2Authority.SOFT
        runtime.scanner.rules = [soft_rule]

        fake = ScanResult(
            decision="review",
            risk=0.5,
            summary="matched soft exec",
            matched_rules=[
                MatchedRule(
                    id="AIRA-010",
                    name="pending shell exec",
                    severity="medium",
                    action="review",
                    reason="pending exec",
                    confidence=1.0,
                    pass_id=L2PassKind.PENDING_TOOL,
                )
            ],
            winning_rule_id="AIRA-010",
            layers=LayerInfo(),
            plan=PlanEcho(run_id="metrics-review", plan_size=1, tools=["exec"]),
            timing=TimingInfo(),
            debug=DebugInfo(scanner_version="test", rules_loaded=1),
        )
        monkeypatch.setattr(runtime.scanner, "scan", lambda _plan: fake)

        status, payload = _request(
            base_url,
            "/scan",
            body=json.dumps(
                {
                    "version": "1.0",
                    "run_id": "metrics-review:run_1",
                    "intent": "list files",
                    "steps": [
                        {
                            "id": "s1",
                            "tool": "exec",
                            "status": "pending",
                            "args": {"command": "ls -la"},
                        }
                    ],
                    "metadata": {
                        "adapter": "fixture",
                        "hook": "before_tool_call",
                        "session_id": "metrics-review",
                    },
                }
            ).encode(),
        )
        assert status == 200
        assert json.loads(payload)["decision"] == "review"

        _status, body = _request(base_url, "/metrics")
        text = body.decode()
        matched = _metric_sample(
            text,
            "sentrook_scan_matched_rules_total",
            rule_id="AIRA-010",
            authority="soft",
            action="review",
        )
        winning = _metric_sample(
            text,
            "sentrook_scan_winning_rules_total",
            rule_id="AIRA-010",
            authority="soft",
            decision="review",
        )
        assert matched is not None and matched >= 1
        assert winning is not None and winning >= 1
    finally:
        httpd.shutdown()
        httpd.server_close()

def test_fail_open_increments_counter(
    serve_config: ServeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    httpd, base_url, runtime = _start_server(serve_config)
    try:

        def _boom(_plan):
            raise RuntimeError("engine exploded")

        monkeypatch.setattr(runtime.scanner, "scan", _boom)
        status, payload = _request(base_url, "/scan", body=json.dumps(_benign_plan()).encode())
        assert status == 200
        body = json.loads(payload)
        assert body["decision"] == "allow"
        assert body.get("error")

        _status, metrics_body = _request(base_url, "/metrics")
        fail_open = _metric_sample(metrics_body.decode(), "sentrook_scan_fail_open_total")
        assert fail_open is not None and fail_open >= 1
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_unauthorized_scan_records_401(tmp_path: Path) -> None:
    config = ServeConfig(
        mode="observe",
        rules_path=RULES,
        corpus_dir=tmp_path / "corpus",
        log_path=tmp_path / "scan.log.jsonl",
        latency_log_path=tmp_path / "latency.log.jsonl",
        l3_policy=L3Policy.OFF,
        scan_auth_mode="apikey",
        scan_api_key="secret",
        oidc_issuer="",
    )
    httpd, base_url, _runtime = _start_server(config)
    try:
        status, _payload = _request(base_url, "/scan", body=json.dumps(_benign_plan()).encode())
        assert status == 401
        _status, body = _request(base_url, "/metrics")
        count = _metric_sample(
            body.decode(), "http_requests_total", method="POST", endpoint="/scan", status="401"
        )
        assert count is not None and count >= 1
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_latency_and_feedback_metrics(serve_config: ServeConfig) -> None:
    httpd, base_url, _runtime = _start_server(serve_config)
    try:
        latency_body = json.dumps(
            {
                "tool_call_id": "exec:1",
                "plugin_e2e_ms": 45,
                "engine_ms": 12,
            }
        ).encode()
        status, _payload = _request(base_url, "/latency", body=latency_body)
        assert status == 200

        feedback_body = json.dumps(
            {
                "resolution": "allow_once",
                "log": {"decision": "review", "pending_tool": "exec"},
            }
        ).encode()
        _request(base_url, "/feedback", body=feedback_body)

        _status, body = _request(base_url, "/metrics")
        text = body.decode()
        assert "sentrook_plugin_e2e_latency_seconds_bucket" in text
        assert "sentrook_feedback_total" in text
    finally:
        httpd.shutdown()
        httpd.server_close()


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKClient:
    def __init__(self, public_key):
        self._public_key = public_key

    def get_signing_key_from_jwt(self, token: str) -> _FakeSigningKey:
        return _FakeSigningKey(self._public_key)


@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def patch_jwks(monkeypatch: pytest.MonkeyPatch, rsa_keys) -> None:
    _, public_key = rsa_keys
    monkeypatch.setattr(oidc, "_jwks_client", lambda config: _FakeJWKClient(public_key))


def _mint_token(private_key, *, subject: str, fidu_user_id: str | None = None) -> str:
    now = int(time.time())
    claims: dict = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "scope": SCOPE_SCAN,
        "iat": now,
        "exp": now + 1800,
    }
    if fidu_user_id is not None:
        claims["fidu_user_id"] = fidu_user_id
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})


def test_oidc_caller_mix_is_anonymous(tmp_path: Path, rsa_keys, patch_jwks) -> None:
    private_key, _ = rsa_keys
    config = ServeConfig(
        mode="observe",
        rules_path=RULES,
        corpus_dir=tmp_path / "corpus",
        log_path=tmp_path / "scan.log.jsonl",
        latency_log_path=tmp_path / "latency.log.jsonl",
        l3_policy=L3Policy.OFF,
        scan_auth_mode="oidc",
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        scan_api_key=None,
        rate_limit_enabled=False,
    )
    httpd, base_url, runtime = _start_server(config)
    try:
        user_a = "fidu-user-alice"
        user_b = "fidu-user-bob"
        token_a = _mint_token(private_key, subject="sub-a", fidu_user_id=user_a)
        token_b = _mint_token(private_key, subject="sub-b", fidu_user_id=user_b)
        plan = json.dumps(_benign_plan()).encode()
        for token in (token_a, token_a, token_b):
            status, _payload = _request(
                base_url,
                "/scan",
                body=plan,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert status == 200

        _status, body = _request(base_url, "/metrics")
        text = body.decode()
        unique_5m = _metric_sample(text, "sentrook_active_callers", window="5m")
        share_1h = _metric_sample(text, "sentrook_top_caller_share", window="1h")
        assert unique_5m == 2
        assert share_1h is not None
        assert 0.6 <= share_1h <= 0.7
        leaked = contains_forbidden_ids(
            body,
            [user_a, user_b, "sub-a", "sub-b", *runtime.caller_mix.hashed_ids()],
        )
        assert leaked == []
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_api_key_traffic_excluded_from_caller_mix(tmp_path: Path) -> None:
    config = ServeConfig(
        mode="observe",
        rules_path=RULES,
        corpus_dir=tmp_path / "corpus",
        log_path=tmp_path / "scan.log.jsonl",
        latency_log_path=tmp_path / "latency.log.jsonl",
        l3_policy=L3Policy.OFF,
        scan_auth_mode="apikey",
        scan_api_key="shared-secret",
        oidc_issuer="",
        rate_limit_enabled=False,
    )
    httpd, base_url, runtime = _start_server(config)
    try:
        status, _payload = _request(
            base_url,
            "/scan",
            body=json.dumps(_benign_plan()).encode(),
            headers={"Authorization": "Bearer shared-secret"},
        )
        assert status == 200
        assert runtime.caller_mix.snapshot()["5m"] == (0, 0.0)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_caller_mix_tracker_unique_and_share() -> None:
    tracker = CallerMixTracker()
    tracker.observe("alice")
    tracker.observe("alice")
    tracker.observe("bob")
    unique, share = tracker.snapshot()["5m"]
    assert unique == 2
    assert share == pytest.approx(2 / 3)
    digest = hashlib.sha256(b"alice").hexdigest()
    assert digest in tracker.hashed_ids()


def test_metrics_use_private_registry() -> None:
    from prometheus_client import REGISTRY as default_registry

    from sentrook.serve import metrics as serve_metrics

    assert serve_metrics.REGISTRY is not default_registry
    serve_metrics.exposition()
