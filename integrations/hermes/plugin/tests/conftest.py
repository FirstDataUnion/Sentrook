import json
import sys
from pathlib import Path

import pytest

# The plugin is a package named after its directory; tests import it as `plugin`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import plugin  # noqa: E402
from plugin import auth, scan_client  # noqa: E402


class FakeScanner:
    """Risk from markers in the command; 500 when the command says FAIL."""

    def __init__(self):
        self.scans = []

    def __call__(self, url, *, data=None, headers=None, timeout):
        if url.endswith("/.well-known/openid-configuration"):
            return 200, {"token_endpoint": "http://idp.test/oauth/token"}, {}
        if url.endswith("/oauth/token"):
            return 200, {"access_token": "tok", "expires_in": 600}, {}
        if url == "http://scan.test/scan":
            assert headers["authorization"] == "Bearer tok"
            p = json.loads(data)
            self.scans.append(p)
            cmd = str(p["pending_call"]["arguments"].get("command", ""))
            if "FAIL" in cmd:
                return 500, {"error": {"code": "boom"}}, {}
            risk = 92 if "EXFIL" in cmd else 55 if "REVIEW" in cmd else 5
            step = p["session"]["step"]
            return (
                200,
                {
                    "response_version": "2.0",
                    "request_id": p["request_id"],
                    "status": "ok",
                    "risk": risk,
                    "enforced": None,
                    "tree": {
                        "suspicion": {"score": risk / 100},
                        "consequence": {"score": 0.5},
                        "confidence": {"score": 0.8},
                    },
                    "reasons": [{"code": "exfil.exec_egress"}] if risk > 50 else [],
                    "tool_description": {"category": "x", "template": "Runs a command on {E1}"},
                    "entities": {"E1": {"kind": "host", "display": "cl0ud-sync.io"}},
                    "action_fingerprint": f"afp1:exec|step:{step}",
                    "state": f"state-{step}",
                },
                {},
            )
        raise AssertionError(f"unexpected request {url}")


@pytest.fixture
def harness(tmp_path, monkeypatch):
    for k, v in {
        "HERMES_HOME": str(tmp_path),
        "SENTROOK_DEV_ENDPOINTS": "1",
        "SENTROOK_SCAN_URL": "http://scan.test",
        "SENTROOK_OIDC_ISSUER": "http://idp.test",
        "SENTROOK_SCAN_CLIENT_ID": "client",
        "SENTROOK_SCAN_CLIENT_SECRET": "secret-value",
    }.items():
        monkeypatch.setenv(k, v)
    for k in ("SENTROOK_MODE", "HERMES_CRON_SESSION", "HERMES_YOLO_MODE"):
        monkeypatch.delenv(k, raising=False)
    fake = FakeScanner()
    monkeypatch.setattr(auth, "http_json", fake)
    monkeypatch.setattr(scan_client, "http_json", fake)
    auth.clear_scan_token_cache()
    monkeypatch.setattr(plugin, "_store", None)
    monkeypatch.setattr(plugin, "_traffic", None)

    class Ctx:
        """Hermes's plugin context: settings are read one key at a time, like `ctx.get_config`."""

        def __init__(self):
            self.hooks = {}
            self.settings = {}

        def get_config(self, key, default=None):
            return self.settings.get(key, default)

        def register_hook(self, name, fn):
            self.hooks[name] = fn

        def register_cli_command(self, **kw):
            self.cli = kw

    ctx = Ctx()
    plugin.register(ctx)
    fake.ctx = ctx
    fake.dir = tmp_path
    fake.traffic = lambda: [
        json.loads(x) for x in (tmp_path / "sentrook" / "traffic.jsonl").read_text().splitlines()
    ]
    return fake
