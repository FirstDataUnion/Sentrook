import json
import sys
from pathlib import Path

import pytest

# The plugin is a package named after its directory; tests import it as `plugin`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import plugin  # noqa: E402
from plugin import auth, scan_client  # noqa: E402


class FakeScanner:
    """Risk from markers in the command; 500 when the command says FAIL; FLOOR enforces a review
    below the review line."""

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
            enforced = "review" if "FLOOR" in cmd else None
            step = p["session"]["step"]
            return (
                200,
                {
                    "response_version": "2.0",
                    "request_id": p["request_id"],
                    "status": "ok",
                    "risk": risk,
                    "enforced": enforced,
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
            self.commands = {}
            self.settings = {}

        def get_config(self, key, default=None):
            return self.settings.get(key, default)

        def register_hook(self, name, fn):
            self.hooks[name] = fn

        def register_cli_command(self, **kw):
            self.cli = kw

        def register_command(self, name, handler, description="", args_hint=""):
            self.commands[name] = {
                "handler": handler,
                "description": description,
                "args_hint": args_hint,
            }

    ctx = Ctx()
    plugin.register(ctx)
    fake.ctx = ctx
    fake.dir = tmp_path
    fake.traffic = lambda: [
        json.loads(x) for x in (tmp_path / "sentrook" / "traffic.jsonl").read_text().splitlines()
    ]
    return fake


@pytest.fixture
def provenance(monkeypatch):
    """Hermes's write origin (`tools.skill_provenance`) under test control; an owner's turn by default."""
    import types

    prov = {"origin": "assistant_tool", "attended": False}
    mod = types.ModuleType("tools.skill_provenance")
    mod.get_current_write_origin = lambda: prov["origin"]
    mod.is_unattended_review = lambda: (
        prov["origin"] == "background_review" and not prov["attended"]
    )
    pkg = types.ModuleType("tools")
    pkg.__path__ = []
    pkg.skill_provenance = mod
    monkeypatch.setitem(sys.modules, "tools", pkg)
    monkeypatch.setitem(sys.modules, "tools.skill_provenance", mod)
    return prov


@pytest.fixture
def loop_h(harness, provenance, monkeypatch):
    """The harness with a scanner whose reply each test sets (`.reply`), Hermes's write origin under test
    control (`.prov`, the background review by default), no terminal, and no gateway session facts
    unless a test sets `.facts`."""
    import io

    fake = harness
    reply = {"risk": 5, "enforced": None, "reasons": [{"code": "selfmod.plugin"}]}

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return fake(url, data=data, headers=headers, timeout=timeout)
        p = json.loads(data)
        fake.scans.append(p)
        return (
            200,
            {
                "response_version": "2.0",
                "request_id": p["request_id"],
                "status": "ok",
                "entities": {},
                "tool_description": {"template": "Saves a skill"},
                "action_fingerprint": f"afp1:x|step:{p['session']['step']}",
                "state": "tok",
                **reply,
            },
            {},
        )

    monkeypatch.setattr(auth, "http_json", http)
    monkeypatch.setattr(scan_client, "http_json", http)
    provenance["origin"] = "background_review"
    # Not a terminal: platforms outside the chat list are unattended unless a test says otherwise.
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM", "SENTROOK_SKILL_REVIEW"):
        monkeypatch.delenv(k, raising=False)
    fake.facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(fake.facts))

    fake.reply = reply
    fake.prov = provenance
    return fake
