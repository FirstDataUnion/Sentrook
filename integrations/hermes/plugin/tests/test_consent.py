"""Consent: the text printed after sign-in, and the one owner notice when the identity service refuses the scan
credentials because consent was withdrawn on the FIDU portal. Scans still fail closed: enforce mode asks where
someone can answer and blocks where nobody can; observe mode never asks. The texts are shared with the OpenClaw
plugin's tests (`integrations/fixtures/consent`)."""

import json
from pathlib import Path

import pytest

import plugin
from plugin import auth, card, consent, login
from plugin.scan_error_policy import SIGN_IN_FIXES, scan_auth_error_to_failure

from .test_hold import _cron, held_call_harness, send
from .test_hold import turn as hold_turn

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[3] / "fixtures" / "consent" / "cases.json").read_text(
        encoding="utf-8"
    )
)
ISSUER = FIXTURE["issuer"]
TOKEN_ERROR = FIXTURE["token_error"]
NOTICE = FIXTURE["rendered"]["hermes"]["withdrawn_notice"]
CHAT = {"session_id": "chat-1", "task_id": "chat-1"}


@pytest.fixture
def h(harness, monkeypatch):
    """The held-call harness (notices to Discord, recorded in `.sent`), with an identity service that refuses the
    credentials when `.withdrawn` is set (`.token_answer` overrides the refusal) and records every request."""
    fake = held_call_harness(harness, monkeypatch)
    fake.withdrawn = False
    fake.token_answer = (TOKEN_ERROR["status"], TOKEN_ERROR["body"])
    fake.requests = []

    def idp(url, *, data=None, headers=None, timeout):
        fake.requests.append(url)
        if url.endswith("/oauth/token") and fake.withdrawn:
            status, body = fake.token_answer
            return status, body, {}
        return fake(url, data=data, headers=headers, timeout=timeout)

    monkeypatch.setattr(auth, "http_json", idp)
    return fake


def _withdraw(h):
    h.withdrawn = True
    auth.clear_scan_token_cache()  # an issued token stays valid until it expires; this one has
    h.scans.clear()


# ---- the shared texts ------------------------------------------------------------------------------------


def test_the_texts_match_the_shared_cases():
    assert list(consent.SIGNED_IN_TEXT) == FIXTURE["signed_in"]
    assert consent.WITHDRAWN_NOTICE == FIXTURE["withdrawn_notice"]
    assert consent.TERMS_LINE == FIXTURE["terms_line"]
    assert consent.TERMS_LINE_DATED == FIXTURE["terms_line_dated"]
    assert consent.PRIVACY_URL == FIXTURE["privacy_url"]
    assert consent.TERMS_URL == FIXTURE["terms_url"]
    assert consent.COMMANDS == FIXTURE["hosts"]["hermes"]
    rendered = FIXTURE["rendered"]["hermes"]
    assert consent.signed_in_lines(None) == rendered["signed_in"]
    dated = consent.accepted_terms(FIXTURE["dated_case"])
    assert consent.signed_in_lines(dated) == rendered["signed_in_dated"]
    assert consent.withdrawn_text() == NOTICE


def test_the_stop_command_stops_every_scan():
    assert consent.COMMANDS["stop"].startswith("hermes plugins disable sentrook")
    assert consent.signed_in_lines(None)[-1].startswith(
        "To stop, run hermes plugins disable sentrook"
    )


def test_accepted_terms_are_read_only_when_plain():
    assert consent.accepted_terms({"terms_version": "v3.1"}) == ("v3.1", None)
    assert consent.accepted_terms({"terms_version": "1", "terms_accepted_at": "2026-11-26"}) == (
        "1",
        "2026-11-26",
    )
    assert consent.accepted_terms({"terms_version": "1", "terms_accepted_at": "soon\x1b[2J"}) == (
        "1",
        None,
    )
    for raw in (None, 3, "", "1\x1b[2J", "a b", "x" * 41):
        assert consent.accepted_terms({"terms_version": raw}) is None
    assert consent.accepted_terms("not a dict") is None
    assert consent.signed_in_lines(("2", None))[1] == "Terms version 2 accepted."


# ---- the identity service's answer ----------------------------------------------------------------------


def test_the_withdrawal_answer_is_told_from_other_refusals():
    assert auth.consent_withdrawn(TOKEN_ERROR["status"], TOKEN_ERROR["body"])
    assert not auth.consent_withdrawn(401, {"error": "invalid_client"})
    assert not auth.consent_withdrawn(200, TOKEN_ERROR["body"])
    assert not auth.consent_withdrawn(401, "consent_withdrawn")
    failure = scan_auth_error_to_failure(auth.ConsentWithdrawn(401))
    assert (failure.kind, failure.status, failure.setup) == ("http", 401, "consent_withdrawn")
    other = scan_auth_error_to_failure(
        RuntimeError('client_credentials token mint failed: HTTP 401: {"error": "invalid_client"}')
    )
    assert other.setup == "sign_in_rejected"


# ---- after withdrawal ------------------------------------------------------------------------------------


def test_the_notice_is_sent_once_and_not_again_after_a_restart(h, monkeypatch):
    """Must fire once: the first refused scan tells the owner; later ones, in other jobs or after a restart, do not."""
    _withdraw(h)
    out, rec = _cron(h)
    assert out["action"] == "block"
    assert rec["decision"] == "blocked_on_error"
    assert rec["notice"] == {"status": "queued", "target": "discord"}
    assert [s["args"]["message"] for s in h.sent] == [NOTICE]
    assert h.scans == [], "nothing is sent to the scan service without a token"

    out, rec = _cron(h, sid="cron-2")
    assert out["action"] == "block"
    assert rec["notice"] == {"status": "quiet"}
    _cron(h, job="7b3e1d", sid="cron-3")
    monkeypatch.setattr(plugin, "_store", None)  # a restart: only the state folder is left
    monkeypatch.setattr(plugin, "_traffic", None)
    _cron(h, sid="cron-4")
    assert len(h.sent) == 1


def test_enforce_mode_still_asks_when_attended_and_blocks_when_not(h):
    """Must stay closed: the withdrawal is an auth failure, never a reason to let a call through unscanned."""
    _withdraw(h)
    hold_turn(h, platform="telegram", sid=CHAT)
    out, rec = send(h, sid=CHAT)
    assert out["action"] == "approve"
    assert out["message"] == card.hermes_error_message("consent_withdrawn")
    assert "withdrawn on the FIDU portal" in out["message"]
    assert rec["decision"] == "blocked_on_error"
    assert rec["notice"] == {"status": "queued", "target": "discord"}

    out, rec = _cron(h)
    assert out == {"action": "block", "message": SIGN_IN_FIXES["consent_withdrawn"]["login"]}
    assert rec["notice"] == {"status": "quiet"}, (
        "no scan-failure notice on top of the consent notice"
    )
    assert len(h.sent) == 1


def test_allow_on_scan_error_still_blocks(h, monkeypatch):
    monkeypatch.setenv("SENTROOK_ON_SCAN_ERROR", "allow")
    _withdraw(h)
    hold_turn(h, platform="telegram", sid=CHAT)
    out, _rec = send(h, sid=CHAT)
    assert out["action"] == "block"


def test_observe_mode_does_not_ask_but_tells_the_owner(h, monkeypatch):
    monkeypatch.setenv("SENTROOK_MODE", "observe")
    _withdraw(h)
    hold_turn(h, platform="telegram", sid=CHAT)
    out, rec = send(h, sid=CHAT)
    assert out is None
    assert rec["decision"] == "allowed_on_error"
    out, rec = _cron(h)
    assert out is None
    assert [s["args"]["message"] for s in h.sent] == [NOTICE]


def test_signing_in_again_or_new_credentials_announce_a_later_withdrawal(h, monkeypatch):
    _withdraw(h)
    _cron(h)
    _cron(h, sid="cron-2")
    assert len(h.sent) == 1
    monkeypatch.setenv("SENTROOK_SCAN_CLIENT_ID", "client-2")  # credentials set anew by hand
    _cron(h, sid="cron-3")
    assert len(h.sent) == 2
    consent.reset(h.dir / "sentrook")  # what `hermes sentrook login` does
    _cron(h, sid="cron-4")
    assert len(h.sent) == 3


def test_a_notice_that_cannot_go_is_tried_at_the_next_refusal(h):
    _withdraw(h)
    h.ctx.settings.pop("owner_channel")
    _out, rec = _cron(h)
    assert rec["notice"]["status"] == "unsent"
    h.ctx.settings["owner_channel"] = "discord"
    _out, rec = _cron(h, sid="cron-2")
    assert rec["notice"] == {"status": "queued", "target": "discord"}


def test_other_refused_credentials_send_no_consent_notice(h):
    _withdraw(h)
    h.token_answer = (401, {"error": "invalid_client"})
    hold_turn(h, platform="telegram", sid=CHAT)
    out, rec = send(h, sid=CHAT)
    assert out["message"] == card.hermes_error_message("sign_in_rejected")
    assert "notice" not in rec
    assert not (h.dir / "sentrook" / consent.FILE).exists()


def test_under_the_plugin_host_the_notice_names_the_manual_route(h, monkeypatch):
    from plugin import skill_review

    monkeypatch.setenv(skill_review.HOST_PROCESS_ENV, "1")
    _withdraw(h)
    _cron(h)
    text = h.sent[0]["args"]["message"]
    assert "hermes sentrook login" not in text
    assert text == consent.withdrawn_text(by_hand=True)
    assert "Set new credentials in Hermes (see the install guide)" in text


def test_verify_says_consent_was_withdrawn(h, monkeypatch):
    _withdraw(h)
    monkeypatch.setattr(plugin.cli, "http_json", lambda *a, **k: (200, {"version": "t"}, {}))
    report = {name: (ok, detail) for name, ok, detail in plugin.cli.run_verify(plugin._settings())}
    assert report["token mint"] == (
        False,
        "consent for Sentrook was withdrawn on the FIDU portal; run hermes sentrook login to reconnect",
    )


# ---- no credential, no request --------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET"])
def test_no_credential_sends_nothing(h, monkeypatch, missing):
    """Must stay silent: without both credentials no token is asked for and no scan is sent, not even anonymously."""
    monkeypatch.setenv(missing, "  ")
    out, rec = _cron(h)
    assert out["action"] == "block"
    assert out["message"] == SIGN_IN_FIXES["not_signed_in"]["login"]
    assert rec["failure"]["kind"] == "config"
    assert h.requests == [] and h.scans == []


# ---- sign-in ---------------------------------------------------------------------------------------------


def test_sign_in_resets_the_notice_and_prints_what_is_sent(tmp_path):
    state = tmp_path / "sentrook"
    assert consent.claim(state, "old-client", "2026-11-26T00:00:00Z")
    disc = {"device_authorization_endpoint": f"{ISSUER}/oauth/device/code"}
    code = {
        "device_code": "dc",
        "user_code": "ABCD-1234",
        "verification_uri": f"{ISSUER}/oauth/device",
        "expires_in": 600,
        "interval": 5,
    }
    creds = {
        "client_id": "sentrook-scan-1",
        "client_secret": "not-a-real-secret-zzzzzzzzzzzzzzzz",
        "terms_version": "1",
    }

    def http(url, *, data=None, headers=None, timeout):
        if url.endswith("openid-configuration"):
            return 200, disc, {}
        return 200, code if url.endswith("/device/code") else creds, {}

    out: list[str] = []
    deps = login.LoginDeps(
        http=http, sleep=lambda s: None, now=lambda: 0.0, out=out.append, save=lambda v: "in Hermes"
    )
    code_ = login.run_login(
        {"state_dir": str(state), "oidc_issuer": ISSUER}, name="box", env={}, deps=deps
    )
    assert code_ == login.EXIT_OK
    assert not (state / consent.FILE).exists()
    assert out[-2] == FIXTURE["rendered"]["hermes"]["signed_in"][-1]
    assert "Terms version 1 accepted." in out
