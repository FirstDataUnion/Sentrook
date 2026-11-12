"""The plugin reads Hermes through its public plugin API where one exists: the owner check uses
`ctx.session_surface()` and the approval-bypass check reads the config and the process env."""

import ast
from pathlib import Path

import pytest

import plugin
from plugin import intent, planir

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


def test_approval_gating_is_off_for_yaml_off():
    assert planir.approvals_off({"approvals": {"mode": False}})
    assert not planir.approvals_off({"approvals": {"mode": "smart"}})


#: Hermes internals the plugin used to read and now reads through the public API.
REPLACED = {
    "gateway.session_context.session_context_engaged",
    "tools.approval.is_approval_bypass_active",
}


def test_replaced_internals_are_not_imported():
    found = set()
    for f in Path(plugin.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module:
                found |= {f"{node.module}.{a.name}" for a in node.names}
    assert not found & REPLACED
