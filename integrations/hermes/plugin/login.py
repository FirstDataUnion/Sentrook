"""`hermes sentrook login`: sign in in a browser and store the scan credentials, so nobody copies them by hand.

An OAuth device sign-in (RFC 8628) against the identity service, with the public client `sentrook-plugin`. The
user opens the printed link on any device, signs in or creates an account, and approves. The identity service
then hands this install its own scan client id and secret, once. Signing in again from the same install (same
device id, kept in the state folder) replaces that install's credential rather than adding one.

The credentials are stored through Hermes's own `.env` writer, never by opening the file here. The running
gateway loads them when Hermes restarts. Nothing the identity service writes is printed, and never the secret.
"""

from __future__ import annotations

import math
import os
import re
import secrets
import socket
import time
import unicodedata
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import consent
from .auth import CLIENT_ID_VAR, CLIENT_SECRET_VAR, get_secret, http_json
from .config import resolve_config

CLIENT_ID = "sentrook-plugin"
SCOPE = "sentrook.scan"
DEVICE_NAME_MAX = 64
DEFAULT_INTERVAL_S = 5
DEFAULT_EXPIRES_S = 600
DEVICE_ID_FILE = "device-id"
_DEVICE_ID = re.compile(r"^[0-9a-f]{32,64}$")
_CLIENT_ID_OK = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SECRET_OK = re.compile(r"^[A-Za-z0-9._~+/=-]{16,256}$")
#: A link is printed as it came, so it may hold only visible ASCII: no escape sequences, spaces or line breaks.
_PRINTABLE_URL = re.compile(r"[\x21-\x7e]{1,2048}")

EXIT_OK, EXIT_FAILED, EXIT_CANCELLED = 0, 1, 130

RESTART_LINE = "Restart Hermes so it uses them: hermes gateway restart (or restart Hermes the way you normally start it)."


class LoginError(Exception):
    """A failure with the line to print."""


@dataclass
class LoginDeps:
    """What `run_login` reaches outside itself; tests replace each one."""

    http: Callable[..., tuple[int, Any, dict[str, str]]] = http_json
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], float] = time.monotonic
    out: Callable[[str], None] = print
    hostname: Callable[[], str] = socket.gethostname
    #: Stores the two values; returns where, as the text after "Credentials saved".
    save: Callable[[dict[str, str]], str] | None = None
    #: Runs the checks after saving; returns (report, all passed).
    verify: Callable[[], tuple[str, bool]] | None = None
    timeout: float = 15.0


def clean_device_name(raw: str | None, hostname: str) -> str:
    """Plain text the identity service accepts: letters, marks, numbers, punctuation, symbols and the ASCII
    space; anything else becomes a space; runs of spaces collapse; at most 64 characters."""
    text = "".join(
        c if c == " " or unicodedata.category(c)[0] in "LMNPS" else " " for c in (raw or "")
    )
    text = " ".join(text.split())[:DEVICE_NAME_MAX].strip()
    if text:
        return text
    return clean_device_name(f"Hermes on {hostname}", "") if hostname else "Hermes"


def device_id(state_dir: Path) -> str:
    """This install's id: created once in the state folder, reused on every later sign-in."""
    path = Path(state_dir) / DEVICE_ID_FILE
    try:
        existing = path.read_text(encoding="utf-8").strip()
        if _DEVICE_ID.match(existing):
            return existing
    except OSError:
        pass
    new = secrets.token_hex(16)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(new + "\n")
    os.chmod(path, 0o600)  # a damaged file rewritten in place keeps its old mode otherwise
    return new


class SaveFailed(Exception):
    """The credentials were not stored; the message is the line to print."""


def save_with_hermes(values: dict[str, str]) -> str:
    """Hermes's public `.env` writer (`hermes_cli.gateway_setup_wizard.save_env_values`), then a read back through
    Hermes's secret route: Hermes skips a write it refuses (managed settings) without saying so."""
    from hermes_cli.gateway_setup_wizard import save_env_values

    save_env_values(**values)
    if any(get_secret(name) != value for name, value in values.items()):
        raise SaveFailed(
            "Signed in, but Hermes did not store the credentials (its settings may be managed). "
            "Set them by hand instead (see the install guide)."
        )
    return "in Hermes"


def hermes_can_save() -> bool:
    try:
        from hermes_cli.gateway_setup_wizard import save_env_values  # noqa: F401
    except ImportError:
        return False
    return True


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


def _outside(issuer: str) -> LoginError:
    return LoginError(
        f"Sign-in failed: the identity service gave a sign-in address outside {issuer}."
    )


def _form(fields: dict[str, str]) -> bytes:
    return urllib.parse.urlencode(fields).encode()


_FORM_HEADERS = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}


def _start_lines(url: str, user_code: str, expires_in: float) -> list[str]:
    minutes = max(1, math.ceil(expires_in / 60))
    unit = "minute" if minutes == 1 else "minutes"
    return [
        "Sign in to connect Sentrook on this machine:",
        "",
        f"  {url}",
        "",
        "Open the link on any device, sign in or create a free FIDU account, and check the code matches: "
        + user_code,
        f"Waiting for approval (the code expires in {minutes} {unit}; Ctrl-C to cancel)...",
    ]


def _usable(body: Any) -> dict[str, str] | None:
    if not isinstance(body, dict):
        return None
    cid, secret = body.get("client_id"), body.get("client_secret")
    if not isinstance(cid, str) or not _CLIENT_ID_OK.match(cid):
        return None
    if not isinstance(secret, str) or not _SECRET_OK.match(secret):
        return None
    return {CLIENT_ID_VAR: cid, CLIENT_SECRET_VAR: secret}


def _sign_in(
    issuer: str, name: str, dev_id: str, deps: LoginDeps
) -> tuple[dict[str, str], tuple[str, str | None] | None]:
    """The device flow up to the credentials and the accepted terms (when the identity service names them);
    raises LoginError with the line to print."""
    status, doc, _ = deps.http(f"{issuer}/.well-known/openid-configuration", timeout=deps.timeout)
    endpoint = doc.get("device_authorization_endpoint") if isinstance(doc, dict) else None
    if status != 200 or not isinstance(endpoint, str) or not endpoint:
        raise LoginError(
            "Sign-in failed: the identity service did not answer as expected. Try again later."
        )
    if _origin(endpoint) != _origin(issuer):
        raise _outside(issuer)

    status, code, _ = deps.http(
        endpoint,
        data=_form(
            {"client_id": CLIENT_ID, "scope": SCOPE, "device_name": name, "device_id": dev_id}
        ),
        headers=_FORM_HEADERS,
        timeout=deps.timeout,
    )
    if status in (400, 401) and isinstance(code, dict) and code.get("error") == "invalid_client":
        raise LoginError(
            "Sign-in failed: this identity service does not offer plugin sign-in. "
            "Set the credentials by hand instead (see the install guide)."
        )
    if status != 200 or not isinstance(code, dict):
        raise LoginError(
            f"Sign-in failed: the identity service answered HTTP {status}. Try again later."
        )
    device_code, user_code = code.get("device_code"), code.get("user_code")
    # The complete link when given, else the plain one (an empty value counts as not given).
    url = code.get("verification_uri_complete") or code.get("verification_uri")
    if not (isinstance(device_code, str) and isinstance(user_code, str) and isinstance(url, str)):
        raise LoginError(
            "Sign-in failed: the identity service did not answer as expected. Try again later."
        )
    if not _PRINTABLE_URL.fullmatch(url):
        raise LoginError(
            "Sign-in failed: the identity service gave a sign-in link that cannot be shown safely."
        )
    if _origin(url) != _origin(issuer) or not re.fullmatch(r"[0-9A-Z-]{4,16}", user_code):
        raise _outside(issuer)
    interval = code.get("interval") if isinstance(code.get("interval"), int) else DEFAULT_INTERVAL_S
    interval = max(1, interval)
    expires_in = (
        code.get("expires_in") if isinstance(code.get("expires_in"), int) else DEFAULT_EXPIRES_S
    )
    deadline = deps.now() + expires_in

    for line in _start_lines(url, user_code, expires_in):
        deps.out(line)

    expired = LoginError(
        "The code expired before it was approved. Run hermes sentrook login again."
    )
    poll_url = f"{issuer}/oauth/device/sentrook-credentials"
    while True:
        deps.sleep(interval)
        if deps.now() >= deadline:
            raise expired
        try:
            status, body, _ = deps.http(
                poll_url,
                data=_form({"client_id": CLIENT_ID, "device_code": device_code}),
                headers=_FORM_HEADERS,
                timeout=deps.timeout,
            )
        except Exception:  # noqa: BLE001 - a network blip or a broken answer: ask again on the next turn
            continue
        if status == 200:
            values = _usable(body)
            if values is None:
                raise LoginError(
                    "Sign-in failed: the identity service's answer could not be used. "
                    "Run hermes sentrook login again."
                )
            return values, consent.accepted_terms(body)
        error = body.get("error") if isinstance(body, dict) else None
        if error == "authorization_pending":
            continue
        if error == "slow_down" or status == 429:
            interval += 5
            continue
        if error == "access_denied":
            raise LoginError("Sign-in was denied in the browser. Nothing was changed.")
        if error == "expired_token":
            raise expired
        if error == "credential_limit":
            raise LoginError(
                "This account already has the most Sentrook connections allowed. Remove one you no longer use "
                f"at {issuer}/dashboard#sentrook, then run hermes sentrook login again."
            )
        if status >= 500:
            continue
        raise LoginError(
            f"Sign-in failed: the identity service refused the sign-in (HTTP {status}). "
            "Run hermes sentrook login again."
        )


def run_login(
    settings: dict[str, Any],
    *,
    name: str | None = None,
    env: dict[str, str] | None = None,
    deps: LoginDeps | None = None,
) -> int:
    """Sign in, store the credentials, run the checks. Returns the exit code."""
    deps = deps or LoginDeps()
    env = dict(os.environ) if env is None else env
    save = deps.save or save_with_hermes
    if deps.save is None and not hermes_can_save():
        deps.out(
            "This Hermes cannot store plugin credentials for Sentrook. Update Hermes, "
            "or set the credentials by hand (see the install guide)."
        )
        return EXIT_FAILED
    cfg = resolve_config(settings, env)
    issuer = cfg.endpoints.issuer
    if not issuer.ok:
        deps.out(f"Sign-in failed: the OIDC issuer setting is not usable ({issuer.reason}).")
        return EXIT_FAILED
    issuer_url = issuer.url.rstrip("/")
    device_name = clean_device_name(name, deps.hostname())
    try:
        values, terms = _sign_in(issuer_url, device_name, device_id(cfg.state_dir), deps)
    except LoginError as exc:
        deps.out(str(exc))
        return EXIT_FAILED
    except KeyboardInterrupt:
        deps.out("Cancelled. Nothing was changed.")
        return EXIT_CANCELLED
    except OSError as exc:
        deps.out(
            f"Sign-in failed: could not reach the identity service ({type(exc).__name__}). Try again later."
        )
        return EXIT_FAILED

    try:
        where = save(values)
    except SaveFailed as exc:
        deps.out(str(exc))
        return EXIT_FAILED
    # New credentials: a later withdrawal of consent is announced again.
    consent.reset(cfg.state_dir)
    deps.out(f'Connected as "{device_name}". Credentials saved {where}.')
    deps.out(RESTART_LINE)
    deps.out("")
    for line in consent.signed_in_lines(terms):
        deps.out(line)
    deps.out("")
    if deps.verify is None:
        return EXIT_OK
    report, ok = deps.verify()
    deps.out(report)
    if not ok:
        deps.out("Signed in, but a check above failed. Fix it, then run hermes sentrook verify.")
        return EXIT_FAILED
    return EXIT_OK
