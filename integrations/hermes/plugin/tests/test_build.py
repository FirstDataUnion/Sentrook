"""The running build: scans name the build this process imported, and a reinstall that the running processes have
not picked up yet is reported (a warning on scan, a line in status, a failed check in verify) until they restart."""

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import plugin
from plugin import build, cli, commands

SID = {"session_id": "S1", "task_id": "S1"}


@pytest.fixture
def installed(harness, tmp_path, monkeypatch):
    """A copy of the plugin installed the way Hermes installs it (`plugins/sentrook`), imported now: the running
    build is taken from it and the files can be changed after."""
    root = tmp_path / "plugins" / "sentrook"
    shutil.copytree(
        build.PLUGIN_DIR, root, ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc")
    )
    monkeypatch.setattr(build, "PLUGIN_DIR", root)
    monkeypatch.setattr(build, "RUNNING", build.current())
    build.reset_check()
    harness.root = root
    return harness


def change_files(root: Path) -> None:
    with (root / "snooze.py").open("a", encoding="utf-8") as f:
        f.write("\n# a later build\n")


def call(h, cid="c1", cmd="ls"):
    return h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": cmd}, tool_call_id=cid, turn_id="t1", **SID
    )


def status(h):
    return commands.run_status("", dict(h.ctx.settings)).splitlines()


def verify(h):
    return {n: (ok, d) for n, ok, d in cli.run_verify(dict(h.ctx.settings), timeout=0.01)}


def write_record(h, pid, files, process="hermes gateway", imported_at=None, plugin_dir=None):
    d = h.dir / "sentrook" / "processes"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{pid}.json").write_text(
        json.dumps(
            {
                "pid": pid,
                "build": files,
                "files": files,
                "process": process,
                "started": "2026-11-25T15:32:00Z",
                "imported_at": imported_at,
                "plugin_dir": str(build.PLUGIN_DIR) if plugin_dir is None else plugin_dir,
            }
        )
    )
    return d / f"{pid}.json"


def dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


# ---- the build id ----------------------------------------------------------------------------------


def test_build_is_a_hash_of_the_files_without_install_metadata(installed):
    b = build.current()
    assert b.revision is None
    assert b.id == b.files and len(b.files) == 12
    change_files(installed.root)
    assert build.current().files != b.files


def test_build_carries_the_install_revision_when_hermes_recorded_one(installed):
    (installed.root.parent / ".install-metadata.json").write_text(
        json.dumps({"sentrook": {"revision": "74a755fe" + "0" * 32, "pinned": True}})
    )
    b = build.current()
    assert b.revision == "74a755fe0000"
    assert b.id == f"74a755fe0000+{b.files}"


@pytest.mark.parametrize(
    "metadata",
    [
        "not json",
        json.dumps([1]),
        json.dumps({"other": {"revision": "a" * 40}}),
        json.dumps({"sentrook": {}}),
    ],
)
def test_unusable_install_metadata_falls_back_to_the_files_hash(installed, metadata):
    (installed.root.parent / ".install-metadata.json").write_text(metadata)
    b = build.current()
    assert b.revision is None and b.id == b.files


def test_tests_and_caches_are_not_part_of_the_build(installed):
    before = build.current().files
    (installed.root / "tests").mkdir()
    (installed.root / "tests" / "test_x.py").write_text("x = 1\n")
    (installed.root / "__pycache__").mkdir(exist_ok=True)
    (installed.root / "__pycache__" / "snooze.cpython-312.pyc").write_bytes(b"\0")
    assert build.current().files == before


# ---- must stay silent ------------------------------------------------------------------------------


def test_same_files_no_warning_anywhere(installed, caplog):
    with caplog.at_level(logging.WARNING, logger=plugin.logger.name):
        call(installed)
    assert not [r for r in caplog.records if "plugin build" in r.getMessage()]
    lines = status(installed)
    assert f"plugin build: {build.RUNNING.id}" in lines
    assert not [x for x in lines if x.startswith("restart needed")]
    ok, detail = verify(installed)["running build"]
    assert ok and build.RUNNING.id in detail


def test_scan_sends_the_build(installed):
    call(installed)
    host = installed.scans[-1]["host"]
    assert host["plugin_build"] == build.RUNNING.id
    assert host["plugin_version"] == plugin.PLUGIN_VERSION
    assert installed.traffic()[-1]["planir"]["host"]["plugin_build"] == build.RUNNING.id


def test_other_processes_on_the_installed_build_are_fine(installed):
    write_record(installed, os.getppid(), build.RUNNING.files)
    ok, detail = verify(installed)["running build"]
    assert ok
    assert not [x for x in status(installed) if x.startswith("restart needed")]


def test_records_of_processes_that_ended_are_ignored_and_removed(installed):
    path = write_record(installed, dead_pid(), "0123456789ab")
    assert verify(installed)["running build"][0]
    assert not path.exists()


# ---- must fire -------------------------------------------------------------------------------------


def test_files_changed_after_import_warn_in_status_and_verify(installed):
    running = build.RUNNING.id
    change_files(installed.root)
    lines = status(installed)
    assert f"plugin build: {running}" in lines
    [warning] = [x for x in lines if x.startswith("restart needed")]
    assert "this process" in warning
    assert "hermes-serve, hermes-gateway and hermes-dashboard" in warning
    assert build.current().id in warning
    ok, detail = verify(installed)["running build"]
    assert not ok and "hermes-serve, hermes-gateway and hermes-dashboard" in detail


def test_the_scan_keeps_the_import_time_build_and_logs_a_warning_once(installed, caplog):
    running = build.RUNNING.id
    change_files(installed.root)
    with caplog.at_level(logging.WARNING, logger=plugin.logger.name):
        call(installed, "c1")
        build.reset_check(keep_warned=True)
        call(installed, "c2")
    assert [s["host"]["plugin_build"] for s in installed.scans] == [running, running]
    warnings = [r.getMessage() for r in caplog.records if "plugin build" in r.getMessage()]
    assert len(warnings) == 1
    assert "hermes-serve, hermes-gateway and hermes-dashboard" in warnings[0]


def test_the_scan_reads_the_files_at_most_once_a_minute(installed, monkeypatch):
    reads = []
    real = build.current
    monkeypatch.setattr(build, "current", lambda: reads.append(1) or real())
    clock = [1000.0]
    monkeypatch.setattr(build.time, "monotonic", lambda: clock[0])
    call(installed, "c1")
    call(installed, "c2")
    clock[0] += 59
    call(installed, "c3")
    assert len(reads) == 1
    clock[0] += 2
    call(installed, "c4")
    assert len(reads) == 2


def test_verify_names_a_running_process_on_an_older_build(installed):
    # `verify` runs in a fresh process: what the others run comes from their records.
    write_record(installed, os.getppid(), "0123456789ab")
    ok, detail = verify(installed)["running build"]
    assert not ok
    assert (
        f"pid {os.getppid()}" in detail and "hermes gateway" in detail and "0123456789ab" in detail
    )
    assert "hermes-serve, hermes-gateway and hermes-dashboard" in detail
    [warning] = [x for x in status(installed) if x.startswith("restart needed")]
    assert f"pid {os.getppid()}" in warning and "this process" not in warning


def test_each_process_records_its_build_when_the_plugin_loads(installed):
    plugin.register(installed.ctx)
    record = json.loads(
        (installed.dir / "sentrook" / "processes" / f"{os.getpid()}.json").read_text()
    )
    assert record["pid"] == os.getpid()
    assert record["build"] == build.RUNNING.id and record["files"] == build.RUNNING.files
    # the process label is the command and at most its subcommand word, never its arguments
    assert len(record["process"].split()) <= 2
    build.forget(installed.dir / "sentrook")
    assert not (installed.dir / "sentrook" / "processes" / f"{os.getpid()}.json").exists()


def test_the_own_record_is_not_reported_as_another_process(installed):
    plugin.register(installed.ctx)
    change_files(installed.root)
    [warning] = [x for x in status(installed) if x.startswith("restart needed")]
    assert f"pid {os.getpid()}" in warning and warning.count(f"pid {os.getpid()}") == 1


@pytest.mark.parametrize(
    "argv, label",
    [
        (["/usr/local/bin/hermes", "gateway", "run"], "hermes gateway"),
        (["/opt/hermes/bin/hermes", "-z", "send the report to bob"], "hermes"),
        (["/opt/hermes/bin/hermes", "Send the report to bob"], "hermes"),
        ([], "python"),
    ],
)
def test_process_label_never_carries_arguments(monkeypatch, argv, label):
    monkeypatch.setattr(build.sys, "argv", argv)
    assert build.process_label() == label


def test_a_later_process_that_got_a_recorded_pid_is_not_reported(installed, monkeypatch):
    # The recorded process was killed (no exit to remove its record) and the system gave its pid to another process.
    path = write_record(installed, os.getppid(), "0123456789ab", imported_at=1_000_000.0)
    monkeypatch.setattr(build, "_process_start", lambda pid: 2_000_000.0)
    assert verify(installed)["running build"][0]
    assert not path.exists()


def test_the_recorded_process_itself_is_still_reported(installed, monkeypatch):
    write_record(installed, os.getppid(), "0123456789ab", imported_at=2_000_000.0)
    monkeypatch.setattr(build, "_process_start", lambda pid: 1_999_999.0)
    assert not verify(installed)["running build"][0]


def test_the_system_start_time_of_a_running_process_is_read():
    started = build._process_start(os.getpid())
    if started is None:
        pytest.skip("the system gives no start time here")
    assert started <= build._IMPORTED_EPOCH + build._START_SLACK_SECONDS


def test_records_of_another_copy_of_the_plugin_are_not_about_this_one(installed):
    write_record(installed, os.getppid(), "0123456789ab", plugin_dir="/elsewhere/plugins/sentrook")
    assert verify(installed)["running build"][0]
    assert not [x for x in status(installed) if x.startswith("restart needed")]
