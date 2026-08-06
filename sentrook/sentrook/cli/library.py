"""`sentrook library` — Rookery registry sync commands."""

from __future__ import annotations

import base64
import json
import os
import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from sentrook.cli.common import rookery_api_key
from sentrook.library.paths import DEFAULT_REGISTRY_URL

library_app = typer.Typer(help="Sync YAIRA rules and corpus from a Rookery registry.")


def _explicit_cli_flag_value(flag: str, argv: list[str] | None = None) -> str | None:
    """Return a flag value only when it was passed on the CLI (not via Typer env binding)."""
    argv = sys.argv if argv is None else argv
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return None


def _resolve_login_issuer(cli_issuer: str | None = None) -> str:
    from sentrook.library.oidc_client import identity_issuer

    explicit = _explicit_cli_flag_value("--issuer")
    if explicit is not None:
        return explicit
    if cli_issuer is not None:
        return cli_issuer
    return identity_issuer()


def _browser_open_enabled(*, no_browser: bool) -> bool:
    if no_browser:
        return False
    if os.environ.get("SENTROOK_LOGIN_NO_BROWSER", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return False
    return sys.stdout.isatty()


def _try_open_browser(url: str) -> bool:
    try:
        return webbrowser.open(url, new=2)
    except OSError:
        return False


def _format_remaining(seconds: int) -> str:
    minutes, secs = divmod(max(seconds, 0), 60)
    return f"{minutes:02d}:{secs:02d}"


def _print_device_login_prompt(
    *,
    verification_uri: str,
    verification_uri_complete: str,
    user_code: str,
    expires_in: int,
    open_browser: bool,
) -> None:
    typer.echo("")
    typer.echo("==> FIDU ID sign-in")
    typer.echo("")
    typer.echo("Open this link in your browser (code is pre-filled):")
    typer.echo(f"  {verification_uri_complete}")
    typer.echo("")
    typer.echo("Or visit:")
    typer.echo(f"  {verification_uri}")
    typer.echo("and enter code:")
    typer.echo(f"  {user_code}")
    typer.echo("")
    typer.echo(f"Approval window: {_format_remaining(expires_in)}")

    if open_browser:
        if _try_open_browser(verification_uri_complete):
            typer.echo("Opened your browser — complete sign-in there.")
        else:
            typer.echo("Could not open a browser automatically — use the link above.")
    typer.echo("")


def _make_login_wait_printer() -> tuple[Callable[[int], None], Callable[[], None]]:
    """Return (on_wait, finish) callbacks for poll_device_token progress output."""
    if not sys.stderr.isatty():
        return (lambda _remaining: None, lambda: None)

    def on_wait(remaining: int) -> None:
        line = f"Waiting for approval... {_format_remaining(remaining)} remaining"
        typer.echo(f"\r{line}", err=True, nl=False)

    def finish() -> None:
        typer.echo(err=True)

    return on_wait, finish


@library_app.command("status")
def library_status_cmd(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Rookery registry base URL (default: SENTROOK_LIBRARY_URL or localhost)",
            envvar="SENTROOK_LIBRARY_URL",
        ),
    ] = DEFAULT_REGISTRY_URL,
    library_dir: Annotated[
        Path,
        typer.Option(
            "--library-dir",
            help="Local library directory (default: SENTROOK_LIBRARY_DIR or ~/.sentrook/library/)",
            envvar="SENTROOK_LIBRARY_DIR",
        ),
    ] = Path.home() / ".sentrook" / "library",
) -> None:
    """Show local vs remote library bundle versions."""
    from sentrook.library.sync import LibraryAuthError, library_status

    try:
        status = library_status(url=url, library_dir=library_dir, api_key=rookery_api_key())
    except LibraryAuthError as exc:
        typer.echo(f"library status failed: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        typer.echo(f"library status failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    local = status.local_manifest.bundle_version if status.local_manifest else "none"
    remote = status.remote_manifest.bundle_version if status.remote_manifest else "none"
    typer.echo(f"library dir: {status.library_dir}")
    typer.echo(f"local bundle:  {local}")
    typer.echo(f"remote bundle: {remote}")
    if status.update_available:
        typer.echo("update available: yes")
        raise typer.Exit(code=2)
    typer.echo("update available: no")
    raise typer.Exit(code=0)


@library_app.command("sync")
def library_sync_cmd(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Rookery registry base URL (default: SENTROOK_LIBRARY_URL or localhost)",
            envvar="SENTROOK_LIBRARY_URL",
        ),
    ] = DEFAULT_REGISTRY_URL,
    library_dir: Annotated[
        Path,
        typer.Option(
            "--library-dir",
            help="Local library directory (default: SENTROOK_LIBRARY_DIR or ~/.sentrook/library/)",
            envvar="SENTROOK_LIBRARY_DIR",
        ),
    ] = Path.home() / ".sentrook" / "library",
    force: Annotated[
        bool,
        typer.Option("--force", help="Re-download even when versions match"),
    ] = False,
) -> None:
    """Download the latest published rules/corpus bundle from Rookery."""
    from sentrook.library.sync import LibraryAuthError, sync_library

    try:
        result = sync_library(
            url=url,
            library_dir=library_dir,
            force=force,
            api_key=rookery_api_key(),
        )
    except LibraryAuthError as exc:
        typer.echo(f"library sync failed: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        typer.echo(f"library sync failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if result.updated:
        typer.echo(f"Synced bundle {result.bundle_version} to {result.library_dir}")
    else:
        version = result.bundle_version or "unknown"
        typer.echo(f"Already up to date ({version})")
    raise typer.Exit(code=0)


@library_app.command("login")
def library_login_cmd(
    issuer: Annotated[
        str | None,
        typer.Option(
            "--issuer",
            help="FIDU identity-service issuer URL (overrides SENTROOK_IDENTITY_ISSUER)",
        ),
    ] = None,
    client_id: Annotated[
        str | None,
        typer.Option("--client-id", help="Registered public OAuth client id"),
    ] = None,
    scope: Annotated[
        str | None,
        typer.Option("--scope", help="Space-delimited scopes to request"),
    ] = None,
    no_browser: Annotated[
        bool,
        typer.Option(
            "--no-browser",
            help="Do not try to open the verification link in a browser",
        ),
    ] = False,
) -> None:
    """Authenticate this machine against FIDU ID via the OAuth device flow.

    Caches a short-lived access token + refresh token under
    ``~/.sentrook/auth/`` that ``library sync``/``status`` and scan feedback
    submit use automatically. Re-run this when the refresh token expires or
    is revoked.
    """
    from sentrook.library.oidc_client import (
        DEFAULT_CLIENT_ID,
        DEFAULT_SCOPE,
        OIDCClientError,
        describe_scopes,
        fetch_oidc_discovery,
        issuers_match,
        poll_device_token,
        save_tokens,
        start_device_login,
        token_cache_path,
    )

    resolved_issuer = _resolve_login_issuer(issuer)
    resolved_client_id = client_id or DEFAULT_CLIENT_ID
    resolved_scope = scope or DEFAULT_SCOPE

    try:
        discovery = fetch_oidc_discovery(resolved_issuer)
    except OIDCClientError as exc:
        typer.echo(f"login failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"FIDU identity issuer: {discovery.issuer}")

    try:
        authorization = start_device_login(
            issuer=resolved_issuer, client_id=resolved_client_id, scope=resolved_scope
        )
    except OIDCClientError as exc:
        typer.echo(f"login failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    _print_device_login_prompt(
        verification_uri=authorization.verification_uri,
        verification_uri_complete=authorization.verification_uri_complete,
        user_code=authorization.user_code,
        expires_in=authorization.expires_in,
        open_browser=_browser_open_enabled(no_browser=no_browser),
    )

    on_wait, finish_wait = _make_login_wait_printer()
    try:
        tokens = poll_device_token(
            issuer=resolved_issuer,
            client_id=resolved_client_id,
            device_code=authorization.device_code,
            interval=authorization.interval,
            expires_in=authorization.expires_in,
            on_wait=on_wait,
        )
    except OIDCClientError as exc:
        typer.echo(f"login failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        finish_wait()

    claims = _decode_jwt_payload_unverified(tokens.access_token)
    token_iss = claims.get("iss")
    if token_iss and not issuers_match(discovery.issuer, str(token_iss)):
        typer.echo(
            "login failed: access token issuer "
            f"({token_iss}) does not match identity service ({discovery.issuer}).",
            err=True,
        )
        raise typer.Exit(code=1)

    save_tokens(tokens)
    capabilities = describe_scopes(tokens.scope)
    typer.echo("==> Signed in to FIDU ID")
    typer.echo(f"  subject: {claims.get('sub', 'unknown')}")
    if capabilities:
        typer.echo(f"  can:     {', '.join(capabilities)}")
    typer.echo(f"  cached:  {token_cache_path()}")
    raise typer.Exit(code=0)


@library_app.command("logout")
def library_logout_cmd() -> None:
    """Remove the cached FIDU ID token."""
    from sentrook.library.oidc_client import clear_cached_tokens, token_cache_path

    path = token_cache_path()
    clear_cached_tokens()
    typer.echo(f"Cleared cached token at {path}")


@library_app.command("whoami")
def library_whoami_cmd() -> None:
    """Show the identity/scope of the cached FIDU ID token, if any."""
    from sentrook.library.oidc_client import (
        describe_scopes,
        identity_issuer,
        issuers_match,
        load_cached_tokens,
    )

    tokens = load_cached_tokens()
    if tokens is None:
        typer.echo("Not logged in. Run `sentrook library login`.")
        raise typer.Exit(code=1)

    claims = _decode_jwt_payload_unverified(tokens.access_token)
    token_iss = claims.get("iss")
    token_aud = claims.get("aud")
    typer.echo(f"subject: {claims.get('sub', 'unknown')}")
    typer.echo(f"scope:   {tokens.scope}")
    if token_iss:
        typer.echo(f"issuer:  {token_iss}")
    if token_aud:
        typer.echo(f"audience: {token_aud}")
    typer.echo(f"expires: {'expired' if tokens.is_expired() else 'valid'}")
    if capabilities := describe_scopes(tokens.scope):
        typer.echo(f"can:     {', '.join(capabilities)}")

    configured_issuer = identity_issuer()
    if token_iss and not issuers_match(configured_issuer, str(token_iss)):
        typer.echo(
            f"warning: SENTROOK_IDENTITY_ISSUER ({configured_issuer}) "
            f"differs from token issuer ({token_iss})",
            err=True,
        )
    raise typer.Exit(code=0)


def _decode_jwt_payload_unverified(token: str) -> dict:
    """Best-effort local decode for display only — Rookery does the real verification."""
    try:
        _, payload_b64, _ = token.split(".", 2)
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError, json.JSONDecodeError):
        return {}
