"""Consent: what `hermes sentrook login` prints after signing in, and the one owner notice when consent is withdrawn.

The identity service issues scan credentials only after the owner accepts the terms and the sensitive-data step. The
owner can withdraw consent on the FIDU portal; the identity service then refuses this install's credentials with
`error_reason: consent_withdrawn` (`auth.ConsentWithdrawn`). Each call is then handled as for any refused
credential (`scan_error_policy`: never let through silently), and the owner gets one notice saying why, not one per call. That it was sent is kept in the
state folder, so a restart does not send it again; signing in again resets it. The texts are shared with the OpenClaw
plugin's tests (`integrations/fixtures/consent`).
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

from .store import file_lock

#: Printed after sign-in, one sentence per line. Keep it identical to `signed_in` in
#: `integrations/fixtures/consent/cases.json` and to `SIGNED_IN_TEXT` in the OpenClaw plugin's `consent.ts`. The
#: `{terms}` line is left out unless the identity service names the accepted terms version.
SIGNED_IN_TEXT: tuple[str, ...] = (
    "Sentrook is connected to your FIDU account.",
    "{terms}",
    "Each check sends the action and its context to Sentrook, which may pass it to OpenRouter and TypeSafe to judge.",
    "Secrets are replaced with placeholders before anything leaves your machine; other personal data is sent as it "
    "is.",
    "Sentrook is a beta and does not guarantee protection.",
    "Policy and terms: {links}.",
    "To stop, run {stop} or close your FIDU account.",
)
TERMS_LINE = "Terms version {version} accepted."
TERMS_LINE_DATED = "Terms version {version} accepted {date}."
PRIVACY_URL = "https://firstdataunion.org/privacy-policy/"
#: The terms page; not published yet. While empty, the terms link is left out.
TERMS_URL = ""
#: A terms version is printed only when it is short plain text, and a date only as YYYY-MM-DD.
_TERMS_VERSION = re.compile(r"[A-Za-z0-9._-]{1,40}")
_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})(?:[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)?")

WITHDRAWN_NOTICE = (
    "Sentrook consent withdrawn: scans stopped. Run {reconnect} to connect again, or switch to observe mode, or "
    "uninstall. Observe mode: {observe}"
)

COMMANDS = {
    "stop": "hermes plugins disable sentrook && hermes gateway restart",
    "reconnect": "hermes sentrook login",
    "observe": "hermes config set plugins.entries.sentrook.settings.mode observe && hermes gateway restart",
    # Under `plugins.isolation: host` Hermes has no `hermes sentrook` command line.
    "reconnect_by_hand": "Sentrook consent withdrawn: scans stopped. Set new credentials in Hermes (see the install "
    "guide) to connect again, or switch to observe mode, or uninstall. Observe mode: {observe}",
}

FILE = "consent-notice.json"
_LOCK = threading.Lock()


def accepted_terms(body: Any) -> tuple[str, str | None] | None:
    """The accepted terms version and date (YYYY-MM-DD, or None) from the identity service's credential answer, when
    it names a usable version."""
    if not isinstance(body, dict):
        return None
    version, at = body.get("terms_version"), body.get("terms_accepted_at")
    if not isinstance(version, str) or not _TERMS_VERSION.fullmatch(version):
        return None
    date = _DATE.fullmatch(at) if isinstance(at, str) else None
    return version, date.group(1) if date else None


def signed_in_lines(terms: tuple[str, str | None] | None) -> list[str]:
    links = " and ".join(url for url in (PRIVACY_URL, TERMS_URL) if url)
    out = []
    for line in SIGNED_IN_TEXT:
        if line == "{terms}":
            if terms:
                version, date = terms
                out.append(
                    TERMS_LINE_DATED.format(version=version, date=date)
                    if date
                    else TERMS_LINE.format(version=version)
                )
            continue
        out.append(line.replace("{links}", links).replace("{stop}", COMMANDS["stop"]))
    return out


def withdrawn_text(by_hand: bool = False) -> str:
    text = COMMANDS["reconnect_by_hand"] if by_hand else WITHDRAWN_NOTICE
    return text.replace("{reconnect}", COMMANDS["reconnect"]).replace(
        "{observe}", COMMANDS["observe"]
    )


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f)
    tmp.replace(path)


def claim(state_dir: Path, client_id: str, stamp: str) -> bool:
    """Whether the withdrawal notice for `client_id` may go now: records it as sent and returns True the first time,
    False once it was sent for these credentials. Credentials set anew (another client id) are announced again.
    Raises `LockTimeout` when the file stays locked."""
    path = Path(state_dir) / FILE
    with _LOCK, file_lock(path):
        if _read(path).get("client_id") == client_id:
            return False
        _write(path, {"version": 1, "client_id": client_id, "sent_at": stamp})
        return True


def release(state_dir: Path, client_id: str) -> None:
    """Undoes `claim` after the notice could not be delivered, so the next refused scan announces it."""
    path = Path(state_dir) / FILE
    with _LOCK, file_lock(path):
        if _read(path).get("client_id") == client_id:
            path.unlink(missing_ok=True)


def reset(state_dir: Path) -> None:
    """After a sign-in: a later withdrawal is announced again."""
    try:
        (Path(state_dir) / FILE).unlink(missing_ok=True)
    except OSError:
        pass
