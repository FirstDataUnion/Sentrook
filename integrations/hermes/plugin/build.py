"""Which build of the plugin this process runs, and whether the files installed since are another build.

A reinstall (`hermes plugins install ... --force`, `hermes plugins update`) replaces the plugin's files, but a Hermes
process that is already running (hermes-serve behind the desktop app, the gateway, the dashboard) keeps the code it
imported when it started until it restarts. The version label in `plugin.yaml` stays the same across many changes, so
it cannot tell two builds apart.

The build is a hash of the files the plugin ships (not its tests or Python's caches), taken when the plugin is
imported, with the Git revision Hermes recorded for the install (`plugins/.install-metadata.json`, next to the plugin's
own folder) in front when there is one: `<revision>+<files>`, or just `<files>`. Scans send it as `host.plugin_build`,
so the traffic log shows which build ran. Only the files decide whether two builds differ: a reinstall at another
commit that left the plugin's files alone needs no restart.

Each process that loads the plugin writes a small record of its build to `<state dir>/processes/<pid>.json` (removed
when it exits), so `hermes sentrook verify` and `status`, which run in a fresh process, can name the running
processes that still run another build. A running process also compares its build with the files on its scans (at
most once a minute) and logs a warning once per installed build it is not running.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentrook")

#: The installed plugin's own folder (`<hermes home>/plugins/<name>`).
PLUGIN_DIR = Path(__file__).resolve().parent
#: A scan reads the installed files at most this often.
CHECK_INTERVAL_SECONDS = 60.0
#: What to do about it, the same wherever it is shown.
RESTART = (
    "restart hermes-serve, hermes-gateway and hermes-dashboard "
    "(every Hermes process started before the reinstall)"
)
#: Folders that are not part of the build: the plugin's tests, Python's caches (dot-folders are skipped too).
_SKIP_DIRS = frozenset({"tests", "__pycache__"})
_REVISION = re.compile(r"[0-9a-fA-F]{7,64}")
#: A process label's second word: a subcommand (`gateway`, `serve`), never free text such as a prompt.
_SUBCOMMAND = re.compile(r"[a-z][a-z0-9_-]{0,30}")


@dataclass(frozen=True)
class Build:
    #: The hash of the plugin's files (12 hex), or "unknown" when they could not be read.
    files: str
    #: The Git revision Hermes installed (12 hex), when it recorded one.
    revision: str | None = None

    @property
    def id(self) -> str:
        return f"{self.revision}+{self.files}" if self.revision else self.files


def _shipped(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.startswith(".") and not name.endswith((".pyc", ".pyo")):
                yield Path(dirpath) / name


def files_hash(root: Path) -> str:
    """The hash of every file the plugin ships, by path and contents."""
    h = hashlib.sha256()
    for path in sorted(_shipped(root), key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        h.update(len(rel).to_bytes(4, "big") + rel + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()[:12]


def install_revision(root: Path) -> str | None:
    """The revision Hermes recorded installing this plugin at, if any."""
    try:
        data = json.loads((root.parent / ".install-metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = data.get(root.name) if isinstance(data, dict) else None
    rev = entry.get("revision") if isinstance(entry, dict) else None
    return rev[:12].lower() if isinstance(rev, str) and _REVISION.fullmatch(rev) else None


def current() -> Build:
    """The build installed now (reads every file)."""
    return Build(files_hash(PLUGIN_DIR), install_revision(PLUGIN_DIR))


try:
    #: The build this process imported. Taken once, at import.
    RUNNING = current()
except OSError as _exc:  # pragma: no cover - a file vanished mid-install
    logger.warning("sentrook could not read its own files to name its build: %s", _exc)
    RUNNING = Build("unknown")
_IMPORTED_EPOCH = time.time()
_IMPORTED_AT = datetime.fromtimestamp(_IMPORTED_EPOCH, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
#: A process whose start the system puts later than this after the record's import time is a later process with
#: the same pid (the start times read are whole seconds).
_START_SLACK_SECONDS = 2.0

# ---- the check on scans -----------------------------------------------------------------------------

_lock = threading.Lock()
_checked_at: float | None = None
_installed: Build | None = None
#: The installed builds this process has already warned about.
_warned: set[str] = set()


def reset_check(keep_warned: bool = False) -> None:
    """Forget the last read (tests)."""
    global _checked_at, _installed
    with _lock:
        _checked_at = None
        _installed = None
        if not keep_warned:
            _warned.clear()


def installed(force: bool = False) -> Build | None:
    """The build on disk: read now when forced, else at most once a `CHECK_INTERVAL_SECONDS`. None when the files
    could not be read (a reinstall under way)."""
    global _checked_at, _installed
    now = time.monotonic()
    with _lock:
        if not force and _checked_at is not None and now - _checked_at < CHECK_INTERVAL_SECONDS:
            return _installed
        _checked_at = now
    try:
        found: Build | None = current()
    except OSError:
        found = None
    with _lock:
        _installed = found
    return found


def check_on_scan() -> None:
    """Logs a warning, once per installed build, when the files on disk are not the build this process runs."""
    disk = installed()
    if disk is None or disk.files == RUNNING.files:
        return
    with _lock:
        if disk.files in _warned:
            return
        _warned.add(disk.files)
    logger.warning(
        "sentrook: the installed plugin build is %s, but this process still runs plugin build %s, imported when it "
        "started; %s",
        disk.id,
        RUNNING.id,
        RESTART,
    )


# ---- process records --------------------------------------------------------------------------------


def process_label() -> str:
    """The command this process runs, with at most its subcommand word (`hermes gateway`): never its arguments."""
    if not sys.argv or not sys.argv[0]:
        return "python"
    words = [Path(sys.argv[0]).name[:40] or "python"]
    if len(sys.argv) > 1 and _SUBCOMMAND.fullmatch(sys.argv[1]):
        words.append(sys.argv[1])
    return " ".join(words)


def _process_start(pid: int) -> float | None:
    """When a process started (seconds since the epoch), as the system says; None where it cannot be read. Tells a
    process from a later one that got its pid after it ended."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        btime = next(
            int(line.split()[1])
            for line in Path("/proc/stat").read_text().splitlines()
            if line.startswith("btime ")
        )
        ticks = int(stat.rsplit(")", 1)[-1].split()[19])
        return btime + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, StopIteration):
        pass
    if os.name == "nt":  # pragma: no cover
        return None
    try:
        out = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2,
            env={**os.environ, "LC_ALL": "C"},
        ).stdout.strip()
        return time.mktime(time.strptime(" ".join(out.split()), "%a %b %d %H:%M:%S %Y"))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":  # pragma: no cover - Windows: os.kill would end the process
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return (
                bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
            )
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _records_dir(state_dir: Path) -> Path:
    return Path(state_dir) / "processes"


_recorded: set[Path] = set()


def record_self(state_dir: Path) -> None:
    """Writes this process's record; it is removed when the process exits."""
    d = _records_dir(state_dir)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = d / f"{os.getpid()}.json"
    tmp = path.with_name(f"{path.name}.{threading.get_ident()}.tmp")
    record = {
        "pid": os.getpid(),
        "build": RUNNING.id,
        "files": RUNNING.files,
        "process": process_label(),
        "started": _IMPORTED_AT,
        "imported_at": _IMPORTED_EPOCH,
        #: Records of another copy of the plugin (another install, a checkout) are not about this one.
        "plugin_dir": str(PLUGIN_DIR),
    }
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(record, f)
    tmp.replace(path)
    if path not in _recorded:
        _recorded.add(path)
        atexit.register(_unlink, path)


def _unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def forget(state_dir: Path) -> None:
    """Removes this process's record."""
    path = _records_dir(state_dir) / f"{os.getpid()}.json"
    _recorded.discard(path)
    _unlink(path)


def _later_process(pid: int, imported_at: Any) -> bool:
    """The process now under `pid` started after the recorded one imported the plugin: the recorded one ended."""
    if not isinstance(imported_at, (int, float)) or isinstance(imported_at, bool):
        return False
    started = _process_start(pid)
    return started is not None and started > imported_at + _START_SLACK_SECONDS


def others(state_dir: Path, alive: Callable[[int], bool] = _alive) -> list[dict[str, Any]]:
    """The records of the other running processes. Those of processes that ended are removed."""
    out = []
    try:
        paths = sorted(_records_dir(state_dir).glob("*.json"))
    except OSError:
        return []
    for path in paths:
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        pid = rec.get("pid") if isinstance(rec, dict) else None
        if not isinstance(pid, int) or isinstance(pid, bool) or pid == os.getpid():
            continue
        if not alive(pid) or _later_process(pid, rec.get("imported_at")):
            _unlink(path)
            continue
        if rec.get("plugin_dir") != str(PLUGIN_DIR):
            continue
        if isinstance(rec.get("files"), str):
            out.append(rec)
    return out


def _text(v: Any, n: int) -> str:
    s = v if isinstance(v, str) else "?"
    return re.sub(r"[^\w.+:/ -]", "?", s)[:n]


def stale(state_dir: Path) -> tuple[Build | None, list[str]]:
    """The build installed now and the processes that run another one (this one first)."""
    disk = installed(force=True)
    if disk is None:
        return None, []
    names = []
    if RUNNING.files != disk.files:
        names.append(f"this process (pid {os.getpid()}, build {RUNNING.id}, since {_IMPORTED_AT})")
    for rec in others(state_dir):
        if rec["files"] != disk.files:
            names.append(
                f"pid {rec['pid']} {_text(rec.get('process'), 60)} (build {_text(rec.get('build'), 40)}, "
                f"since {_text(rec.get('started'), 20)})"
            )
    return disk, names


def restart_line(state_dir: Path) -> str | None:
    """`restart needed: ...` when a running process is not on the installed build, else None."""
    disk, names = stale(state_dir)
    if disk is None or not names:
        return None
    return (
        f"restart needed: the installed plugin is build {disk.id}, but "
        f"{'; '.join(names)} still run{'s' if len(names) == 1 else ''} another build; {RESTART}"
    )


def verify_check(state_dir: Path) -> tuple[bool, str]:
    """`verify`'s line: failed while a running process is not on the installed build."""
    line = restart_line(state_dir)
    if line is not None:
        return False, line.removeprefix("restart needed: ")
    disk = installed()
    n = len(others(state_dir))
    on = f"; {n} other Hermes process{'es' if n != 1 else ''} on it" if n else ""
    return True, f"build {disk.id if disk else RUNNING.id}{on}"
