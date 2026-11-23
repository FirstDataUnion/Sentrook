"""Hermes's `plugins.isolation: host` runs the plugin in a separate plugin-host process.

Hermes keeps the write origin of a call (its background review or not) in a context variable of its own process, and
the `pre_tool_call` hook carries no marker of it, so in the plugin host every call reads as the owner's foreground
call. The plugin cannot recognise background skill and memory saves there. It says so: a warning at startup and a
line in `/sentrook status`. In-process (Hermes's default) nothing changes.
"""

import pytest

import plugin
from plugin import commands, skill_review

HOST_ENV = "HERMES_PLUGIN_HOST_PROCESS"
SID = {"session_id": "S1", "task_id": "S1"}
SAVE = ("skill_manage", {"action": "create", "name": "tidy", "content": "# Tidy\nSteps."})


@pytest.fixture
def h(loop_h):
    return loop_h


def status_lines(h):
    return commands.run_status("", dict(h.ctx.settings)).splitlines()


def startup_warnings(h, caplog):
    caplog.clear()
    with caplog.at_level("WARNING", logger=plugin.logger.name):
        plugin.register(h.ctx)
    return [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]


def isolation_warnings(h, caplog):
    return [w for w in startup_warnings(h, caplog) if "plugins.isolation" in w]


def save(h):
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="keep it tidy", platform="telegram", sender_id="u1", **SID
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=SAVE[0], args=SAVE[1], tool_call_id=f"c{len(h.scans)}", turn_id="t1", **SID
    )
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


# ---- must fire ---------------------------------------------------------------------------------------------


def test_in_the_plugin_host_startup_warns_once(h, caplog, monkeypatch):
    monkeypatch.setenv(HOST_ENV, "1")
    [warning] = isolation_warnings(h, caplog)
    assert "plugins.isolation: host" in warning
    assert "background skill and memory saves" in warning
    assert "plugins.isolation: in_process" in warning


def test_in_the_plugin_host_status_names_the_degraded_mode(h, monkeypatch):
    monkeypatch.setenv(HOST_ENV, "1")
    lines = status_lines(h)
    [line] = [x for x in lines if x.startswith("background saves:")]
    assert line == "background saves: " + skill_review.HOST_ISOLATION_TEXT
    assert "plugins.isolation: host" in line and "plugins.isolation: in_process" in line
    # It sits with the other background-save lines, after the skill review counts.
    assert (
        lines.index(line)
        == next(i for i, x in enumerate(lines) if x.startswith("skill review:")) + 1
    )


def test_the_detector_reads_hermess_plugin_host_marker():
    assert skill_review.host_isolated({HOST_ENV: "1"}) is True


# ---- must stay silent ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "0", "true"])
def test_in_process_there_is_no_warning_and_no_status_line(h, caplog, monkeypatch, value):
    """Hermes sets exactly "1" in its plugin host; anything else is the default, in-process."""
    if value is None:
        monkeypatch.delenv(HOST_ENV, raising=False)
    else:
        monkeypatch.setenv(HOST_ENV, value)
    assert isolation_warnings(h, caplog) == []
    assert not any(x.startswith("background saves:") for x in status_lines(h))
    assert skill_review.host_isolated({} if value is None else {HOST_ENV: value}) is False


def test_in_process_a_background_save_is_still_declared(h, monkeypatch):
    monkeypatch.delenv(HOST_ENV, raising=False)
    h.prov["origin"] = "background_review"
    _, rec = save(h)
    assert rec["skill_review"] is True
    assert h.scans[-1]["self_edit"]["kind"] == "background_review"


@pytest.mark.parametrize("origin", ["foreground", "assistant_tool"])
def test_in_the_plugin_host_an_owner_save_is_not_marked_as_a_background_review(
    h, monkeypatch, origin
):
    """What the plugin host reads for every call (Hermes's context-variable default, or an owner's tool call)."""
    monkeypatch.setenv(HOST_ENV, "1")
    h.prov["origin"] = origin
    _, rec = save(h)
    sent = h.scans[-1]
    assert "self_edit" not in sent
    assert sent["trigger"]["kind"] != "system"
    assert not rec.get("skill_review")
