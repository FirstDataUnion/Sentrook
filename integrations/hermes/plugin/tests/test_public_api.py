"""The plugin reads Hermes through its public plugin API where one exists: the owner check uses
`ctx.session_surface()` and the approval-bypass check reads the config and the process env."""

from pathlib import Path

import pytest

import plugin
from plugin import intent

from .test_grants import cli, slash


@pytest.fixture
def term(harness, monkeypatch):
    """Commands run from the local terminal unless a test changes the session surface."""
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(plugin, "session_facts", lambda: {})
    harness.file = harness.dir / "sentrook" / "grants.json"
    return harness


@pytest.fixture
def no_session(term, monkeypatch):
    """The local terminal's command line, in a process where Hermes reports no session."""
    monkeypatch.setattr(plugin, "session_surface", lambda: "")
    return term


def test_the_cli_is_the_owner_without_a_session_surface(no_session, capsys):
    reply = cli(no_session, capsys, "grant", "destination", "#ops", "--persistent")
    assert not reply.startswith("Only the owner")
    assert "#ops" in no_session.file.read_text()


def test_a_slash_command_without_a_session_surface_is_refused(no_session):
    assert slash(no_session, "grant destination #ops --persistent").startswith("Only the owner")
    assert not no_session.file.exists()


@pytest.mark.parametrize(("platform", "owner"), [("cli", True), ("tui", True), ("telegram", False)])
def test_the_platform_hermes_passes_the_handler_stands_in_for_the_surface(
    no_session, platform, owner
):
    """The interactive CLI without a gateway runs a slash command in its own process: no session
    surface, but Hermes passes the handler `platform="cli"`."""
    handler = no_session.ctx.commands["sentrook"]["handler"]
    reply = handler("grant destination #ops --persistent", session_id="S1", platform=platform)
    assert reply.startswith("Only the owner") is not owner
    assert no_session.file.exists() is owner


def test_the_interactive_terminal_is_the_owner(term, monkeypatch):
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    assert not slash(term, "grant destination #ops").startswith("Only the owner")
    assert "#ops" in term.file.read_text()


@pytest.mark.parametrize(
    ("cfg", "env", "bypass"),
    [
        ({"approvals": {"mode": False}}, {}, True),  # YAML's bare `off`
        ({"approvals": {"mode": "off"}}, {}, True),
        ({"approvals": {"mode": " OFF "}}, {}, True),
        ({"approvals": {"mode": "smart"}}, {}, False),
        ({"approvals": {"mode": "manual"}}, {}, False),
        ({"approvals": {"mode": True}}, {}, False),
        ({}, {}, False),
        ({"approvals": "off"}, {}, False),
        ({}, {"HERMES_YOLO_MODE": "1"}, True),
        ({}, {"HERMES_YOLO_MODE": "true"}, True),
        ({}, {"HERMES_YOLO_MODE": "0"}, False),
    ],
)
def test_approval_bypass_reads_the_config_and_the_process_env(monkeypatch, cfg, env, bypass):
    monkeypatch.setattr(intent, "hermes_config", lambda: cfg)
    assert intent._approval_bypass(env) is bypass
    # A bypass makes a review a block: nobody would be asked.
    assert intent.is_unattended("telegram", env) is bypass


def test_a_review_under_approvals_off_blocks(harness, monkeypatch):
    from .test_plugin import call, turn

    monkeypatch.setattr(intent, "hermes_config", lambda: {"approvals": {"mode": False}})
    turn(harness)
    assert call(harness, "c1", "rm REVIEW")["action"] == "block"


#: Hermes internals the plugin used to read and now reads through the public API.
REPLACED = ("session_context_engaged", "is_approval_bypass_active")


def test_replaced_internals_are_not_used():
    for f in Path(plugin.__file__).parent.glob("*.py"):
        text = f.read_text()
        for name in REPLACED:
            assert name not in text, f"{f.name} uses {name}"


def test_the_scan_reports_approval_gating_from_the_config(harness, monkeypatch):
    from .test_plugin import call, turn

    monkeypatch.setattr(plugin, "hermes_config", lambda: {"approvals": {"mode": False}})
    turn(harness)
    call(harness, "c1", "ls")
    assert harness.scans[-1]["host"]["policy"]["approval_gating"] is False
    monkeypatch.setattr(plugin, "hermes_config", lambda: {"approvals": {"mode": "smart"}})
    call(harness, "c2", "pwd")
    assert harness.scans[-1]["host"]["policy"]["approval_gating"] is True
