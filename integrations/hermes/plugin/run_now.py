"""Run now: `allow` on a held call of a cron job starts the job again, so the owner's answer acts at once.

Neither Hermes nor any other host lets a plugin keep a cron call waiting for a person, so the held call is never run
by the plugin itself: the job runs again, and the one-use pass the answer set lets the same call through in that run
(`passes`, `run_bound`).

- The job is read from Hermes's own job file, `<hermes home>/cron/jobs.json`, directly: the plugin imports no private
  Hermes module to read it. A hold keeps a digest of the job's settings (`digest`, over `SETTINGS`: what the job does
  and where it delivers, not its run state), so a job changed since the hold is not run again.
- `guard` says why a run is not started: observe mode, the job cannot be read, it is gone, finished (`completed` or
  `error`, which Hermes will not run), paused, running now (a fresh fire or run claim, or a run the plugin started for
  an earlier answer that has not ended), or changed since the hold.
- The job file is the one under the current turn's Hermes home (Hermes's `get_hermes_home`, which a profile-scoped
  turn sets), else under `HERMES_HOME` (`home`).
- `start` runs `hermes cron run <job>` through Hermes's `hermes` launcher, as notices run `hermes send`
  (`hold._hermes_launcher`), in a process of its own that outlives the answer: Hermes 0.23 runs the whole job inside
  that command. It is pinned to this process's Hermes home and gets no cron delivery variables, as `hermes send` is.
  A command that exits with an error within `EARLY_EXIT` seconds (Hermes refused the run) counts as not started.
  Without the launcher, or for a turn another profile's home is serving, Hermes's own `cron.jobs.trigger_job` marks
  the job due now for the scheduler's next tick. No extra prompt is ever given: the job runs as it is.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import hold, passes
from .config import hermes_home
from .store import read_time

logger = logging.getLogger("sentrook")

#: The job's own settings: what it runs, with what, and where its output goes. Run state (next run, claims, last
#: status, pause markers, repeat counts) is left out, so the digest changes only when the job is changed.
SETTINGS = (
    "name",
    "prompt",
    "schedule",
    "skill",
    "skills",
    "script",
    "no_agent",
    "workdir",
    "model",
    "provider",
    "base_url",
    "enabled_toolsets",
    "interpreter",
    "reasoning_effort",
    "timezone",
    "context_from",
    "attach_to_session",
    "deliver",
    "failure_deliver",
    "origin",
    "monitor_script",
    "monitor_url",
)
#: Seconds to wait for `hermes cron run` to refuse the run (an error exit) before it counts as started.
EARLY_EXIT = 2.0
#: Hermes's lease on a firing job (`fire_claim`) is renewed while the run lives; older than this, the run is gone.
FIRE_CLAIM_TTL = timedelta(seconds=300)
#: A one-shot's `run_claim` lasts longer (Hermes's own default upper bound).
RUN_CLAIM_TTL = timedelta(seconds=1800)
TERMINAL = ("completed", "error")


def home(env: dict[str, str]) -> Path:
    """The Hermes home whose job file holds the current turn's jobs: Hermes's own answer for the turn, else
    `HERMES_HOME` as the plugin reads it."""
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:  # noqa: BLE001 - an older or stand-in Hermes
        return hermes_home(env)


def read_job(home: Path, job_id: str) -> dict[str, Any] | None:
    """The job from `<home>/cron/jobs.json`: the record, `{}` when the file has no such job, None when it cannot be
    read."""
    try:
        data = json.loads((home / "cron" / "jobs.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001 - unreadable
        return None
    jobs = data.get("jobs") if isinstance(data, dict) else data
    if not isinstance(jobs, list):
        return None
    found = [j for j in jobs if isinstance(j, dict) and j.get("id") == job_id]
    return found[0] if len(found) == 1 else {}


def digest(job: dict[str, Any]) -> str:
    """A digest of the job's settings (`SETTINGS`)."""
    material = json.dumps(
        {k: job.get(k) for k in SETTINGS}, sort_keys=True, ensure_ascii=False, default=str
    )
    return hashlib.sha256(material.encode()).hexdigest()[:24]


def job_digest(home: Path, job_id: str | None) -> str | None:
    """The digest a hold of job `job_id` keeps; None when the job cannot be read."""
    if not job_id:
        return None
    job = read_job(home, job_id)
    return digest(job) if job else None


def _claimed(claim: Any, now: datetime, ttl: timedelta) -> bool:
    if not isinstance(claim, dict):
        return False
    at = read_time(claim.get("at"))
    if at is None:
        try:
            at = datetime.fromisoformat(str(claim.get("at")))
        except ValueError:
            return False
        if at.tzinfo is None:
            return False
    return timedelta(0) <= now - at < ttl


def guard(
    home: Path,
    hold_entry: dict[str, Any],
    observe: bool,
    now: datetime,
    state_dir: Path | None = None,
) -> str | None:
    """Why the job of `hold_entry` is not started now (a key of the shared fixture's `run_now.reasons`); None when it
    may be. `state_dir`: the plugin's, for the runs it started (`passes.pending_run`)."""
    if observe:
        return "observe"
    job_id = hold_entry.get("job_id")
    job = read_job(home, str(job_id)) if job_id else None
    if job is None:
        return "unknown"
    if not job:
        return "missing"
    if job.get("state") in TERMINAL:
        return "terminal"
    if job.get("enabled") is False or job.get("state") == "paused" or job.get("paused_at"):
        return "paused"
    if _claimed(job.get("fire_claim"), now, FIRE_CLAIM_TTL) or _claimed(
        job.get("run_claim"), now, RUN_CLAIM_TTL
    ):
        return "running"
    if state_dir is not None and passes.pending_run(state_dir, hold_entry.get("job_ref"), now):
        return "running"
    kept = hold_entry.get("job_digest")
    if not kept:
        return "unknown"
    if kept != digest(job):
        return "changed"
    return None


#: The child processes started, so they are reaped (and a test can wait for them).
_children: list[subprocess.Popen[bytes]] = []


def _reap(proc: subprocess.Popen[bytes]) -> None:
    try:
        proc.wait()
    except Exception:  # noqa: BLE001 - nothing to reap
        pass


def _with_launcher(launcher: str, job_id: str, log: Path) -> tuple[bool, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(hold._CRON_DELIVERY_ENV)}
    env["HERMES_GATEWAY_PROFILE_PIN"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("ab") as out:
            proc = subprocess.Popen(  # noqa: S603 - Hermes's own launcher, fixed arguments
                [launcher, "cron", "run", job_id],
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
                close_fds=True,
            )
    except Exception as exc:  # noqa: BLE001 - could not start it
        return False, hold._clean(exc, 200)
    try:
        code = proc.wait(timeout=EARLY_EXIT)
    except subprocess.TimeoutExpired:
        code = None  # still running: the run is under way
    if code:
        return False, f"hermes cron run exit {code}: {hold._clean(_last_line(log), 200)}"
    _children[:] = [p for p in _children if p.poll() is None]
    _children.append(proc)
    threading.Thread(target=_reap, args=(proc,), name="sentrook-run-now", daemon=True).start()
    return True, ""


def _last_line(log: Path) -> str:
    try:
        lines = [
            ln
            for ln in log.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()
        ]
    except OSError:
        return ""
    return lines[-1] if lines else ""


def _in_process(job_id: str) -> tuple[bool, str]:
    try:
        from cron.jobs import trigger_job
    except Exception:  # noqa: BLE001 - not a Hermes with the scheduler's job store
        return False, "unavailable"
    try:
        done = trigger_job(job_id)
    except Exception as exc:  # noqa: BLE001 - Hermes refused (a finished job)
        return False, hold._clean(exc, 200)
    return (True, "") if done else (False, "Hermes has no such job")


def start(job_id: str, state_dir: Path) -> tuple[bool, str, str]:
    """Starts job `job_id` now; (started, how, why not). `how` is `hermes cron run` or `trigger_job`; the reason is
    `unavailable` when this process has no way to start a job, else what failed. The command's output goes to
    `<state dir>/run-now.log`."""
    launcher = hold._hermes_launcher()
    if launcher is not None and hold._other_home() is None:
        ok, why = _with_launcher(launcher, job_id, Path(state_dir) / "run-now.log")
        return ok, "hermes cron run", why
    ok, why = _in_process(job_id)
    return ok, "trigger_job", why


class Adapter:
    """What `hold.answer` needs to start a held call's job: `guard` and `start` for this Hermes."""

    def __init__(self, home: Path, state_dir: Path, observe: bool, now: Callable[[], datetime]):
        self.home, self.state_dir, self.observe, self.now = home, state_dir, observe, now

    def guard(self, hold_entry: dict[str, Any]) -> str | None:
        return guard(self.home, hold_entry, self.observe, self.now(), self.state_dir)

    def start(self, hold_entry: dict[str, Any]) -> tuple[bool, str | None, str]:
        """(started, the host's run id: none on Hermes, why not)."""
        ok, how, why = start(str(hold_entry.get("job_id")), self.state_dir)
        if not ok:
            logger.warning(
                "sentrook could not start cron job %s with %s: %s",
                hold_entry.get("job_id"),
                how,
                why,
            )
        return ok, None, why
