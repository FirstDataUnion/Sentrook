"""Persist FIDU ID OAuth tokens — OS keychain when available, file otherwise."""

from __future__ import annotations

import json
import os
from pathlib import Path

from sentrook.library.tokens import TokenSet

KEYRING_SERVICE = "sentrook-fidu"
KEYRING_ACCOUNT = "rookery-token"
DEFAULT_AUTH_DIR = Path.home() / ".sentrook" / "auth"
TOKEN_FILENAME = "rookery-token.json"


def token_cache_path() -> Path:
    auth_dir = Path(os.environ.get("SENTROOK_AUTH_DIR", str(DEFAULT_AUTH_DIR))).expanduser()
    return auth_dir / TOKEN_FILENAME


def _token_store_mode() -> str:
    return os.environ.get("SENTROOK_TOKEN_STORE", "auto").strip().lower()


def use_keyring_store() -> bool:
    """Use the OS keychain when appropriate (bare CLI on a desktop host)."""
    mode = _token_store_mode()
    if mode == "file":
        return False
    if mode == "keyring":
        return True
    # OpenClaw/sidecar always sets SENTROOK_AUTH_DIR to a bind-mounted path.
    if os.environ.get("SENTROOK_AUTH_DIR"):
        return False
    try:
        import keyring  # noqa: F401
    except ImportError:
        return False
    return True


def _keyring_load() -> TokenSet | None:
    import keyring

    raw = keyring.get_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
    if not raw:
        return None
    try:
        return TokenSet.from_dict(json.loads(raw))
    except (ValueError, KeyError, TypeError):
        return None


def _keyring_save(tokens: TokenSet) -> None:
    import keyring

    keyring.set_password(KEYRING_SERVICE, KEYRING_ACCOUNT, json.dumps(tokens.to_dict()))


def _keyring_clear() -> None:
    import keyring

    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
    except keyring.errors.PasswordDeleteError:
        pass


def _file_load(path: Path) -> TokenSet | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return TokenSet.from_dict(data)
    except (OSError, ValueError, KeyError):
        return None


def _file_save(path: Path, tokens: TokenSet) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tokens.to_dict(), indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def load_cached_tokens() -> TokenSet | None:
    if use_keyring_store():
        tokens = _keyring_load()
        if tokens is not None:
            return tokens
    return _file_load(token_cache_path())


def save_tokens(tokens: TokenSet) -> None:
    path = token_cache_path()
    if use_keyring_store():
        _keyring_save(tokens)
        path.unlink(missing_ok=True)
        return
    _file_save(path, tokens)
    try:
        if _keyring_load() is not None:
            _keyring_clear()
    except ImportError:
        pass


def clear_cached_tokens() -> None:
    path = token_cache_path()
    path.unlink(missing_ok=True)
    try:
        import keyring
    except ImportError:
        return
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
    except keyring.errors.PasswordDeleteError:
        pass
