"""The owner's notice when a scan failure blocks a call on an unattended run.

Nobody is there to be asked, so the call is blocked (see `scan_error_policy`); without a notice a scanner
outage would quietly stop scheduled jobs. The notice goes where held-call notices go and has nothing to
approve: the call was not held. One notice per cron job (or, for other unattended runs, per session):
after one is sent, further failures with the same key send none for `QUIET`, so an outage gives one
message per job, not one per call. The texts are shared with the OpenClaw plugin's tests
(`integrations/fixtures/hold`).
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path

from .hold import inert
from .scan_error_policy import ScanFailure, is_auth_failure
from .store import Store, file_lock, read_time

QUIET = timedelta(hours=6)
_QUIET_HOURS = int(QUIET.total_seconds() // 3600)
MAX_KEYS = 500
FILE = "scan-failure-notices.json"
_LOCK = threading.Lock()


def reason_of(failure: ScanFailure) -> str:
    """Why the scan gave no answer, in words for the owner; never the failure's detail, which can carry
    anything."""
    if is_auth_failure(failure):
        return "Sentrook's endpoint or credentials are not configured correctly"
    return {
        "network": "Sentrook could not reach the scan service",
        "timeout": "the scan service did not answer in time",
        "rate_limited": "the scan service rate-limited the scan",
    }.get(failure.kind, "the scan service returned an error")


def quiet_key(job_id: str | None, session_ref: str) -> str:
    """What the quiet period is kept by: the cron job when there is one, else the session."""
    return f"job:{job_id}" if job_id else f"session:{session_ref}"


def notice_text(failure: ScanFailure, tool: str, where: str, is_job: bool, verify: str) -> str:
    """The notice; `where` is `where_text`'s, already made inert."""
    return "\n".join(
        [
            "Sentrook could not scan a tool call on an unattended run, so the call was blocked and did "
            "not run.",
            f"Run: {where}",
            f"Tool: {inert(tool, 80)}",
            f"Reason: {reason_of(failure)}.",
            f"To check the setup: {verify}",
            f"More scan failures in this {'job' if is_job else 'session'} are not announced for "
            f"{_QUIET_HOURS} hours.",
        ]
    )


def claim(state_dir: Path, key: str, now: datetime) -> str | None:
    """Whether a notice for `key` may go now: when it may, records `now` as its send time and returns
    that stamp (for `release`); None while the key is in its quiet period. Held under the file's lock,
    so two processes never both announce the same job. An unreadable file starts afresh: a notice too
    many beats an outage nobody hears about. Raises `LockTimeout` when the file stays locked."""
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / FILE):
        sent: dict[str, str] = {}
        for k, v in store.load_scan_failure_notices().items():
            at = read_time(v)
            if at is not None and now - at < QUIET:
                sent[k] = v
        if key in sent:
            return None
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        sent[key] = stamp
        keep = sorted(sent.items(), key=lambda kv: kv[1])[-MAX_KEYS:]
        store.save_scan_failure_notices(dict(keep))
        return stamp


def release(state_dir: Path, key: str, stamp: str) -> None:
    """Undoes `claim` after the notice could not be delivered, so the next failure for `key` is
    announced."""
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / FILE):
        sent = store.load_scan_failure_notices()
        if sent.get(key) != stamp:
            return
        del sent[key]
        store.save_scan_failure_notices(sent)
