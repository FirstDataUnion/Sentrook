from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from sentrook.library.rookery_client import rookery_auth_headers
from sentrook.library.http_client import urlopen
from sentrook.library.paths import (
    MANIFEST_FILENAME,
    resolve_library_dir,
    resolve_registry_url,
)

MANIFEST_SCHEMA = "sentrook.library.manifest/v1"


@dataclass(frozen=True)
class LibraryAuthError(RuntimeError):
    """Rookery rejected credentials for a library registry request (HTTP 401/403)."""

    status_code: int
    detail: str
    action_hint: str

    def __str__(self) -> str:
        return f"{self.detail} — {self.action_hint}"

    @property
    def error_kind(self) -> str:
        return "auth"


@dataclass(frozen=True)
class LibraryManifest:
    schema: str
    bundle_version: str
    released_at: str
    min_scanner_version: str
    rule_ids: list[str]
    stats: dict[str, int]
    bundle_url: str
    bundle_sha256: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LibraryManifest:
        return cls(
            schema=data["schema"],
            bundle_version=data["bundle_version"],
            released_at=data["released_at"],
            min_scanner_version=data["min_scanner_version"],
            rule_ids=list(data["rule_ids"]),
            stats=dict(data["stats"]),
            bundle_url=data["bundle_url"],
            bundle_sha256=data["bundle_sha256"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "bundle_version": self.bundle_version,
            "released_at": self.released_at,
            "min_scanner_version": self.min_scanner_version,
            "rule_ids": self.rule_ids,
            "stats": self.stats,
            "bundle_url": self.bundle_url,
            "bundle_sha256": self.bundle_sha256,
        }


@dataclass(frozen=True)
class LibraryStatus:
    library_dir: Path
    local_manifest: LibraryManifest | None
    remote_manifest: LibraryManifest | None
    update_available: bool


@dataclass(frozen=True)
class SyncResult:
    updated: bool
    bundle_version: str | None
    library_dir: Path


def library_status(
    *,
    url: str | None = None,
    library_dir: Path | None = None,
    api_key: str | None = None,
) -> LibraryStatus:
    url = resolve_registry_url() if url is None else url
    library_dir = resolve_library_dir() if library_dir is None else library_dir
    local_manifest = load_local_manifest(library_dir)
    remote_manifest = fetch_remote_manifest(url, api_key=api_key)
    update_available = (
        remote_manifest is not None
        and (
            local_manifest is None
            or local_manifest.bundle_version != remote_manifest.bundle_version
        )
    )
    return LibraryStatus(
        library_dir=library_dir,
        local_manifest=local_manifest,
        remote_manifest=remote_manifest,
        update_available=update_available,
    )


def sync_library(
    *,
    url: str | None = None,
    library_dir: Path | None = None,
    force: bool = False,
    api_key: str | None = None,
) -> SyncResult:
    url = resolve_registry_url() if url is None else url
    library_dir = resolve_library_dir() if library_dir is None else library_dir
    status = library_status(url=url, library_dir=library_dir, api_key=api_key)
    if status.remote_manifest is None:
        raise RuntimeError(f"registry returned no manifest: {url}")

    if not force and not status.update_available:
        return SyncResult(
            updated=False,
            bundle_version=(
                status.local_manifest.bundle_version
                if status.local_manifest
                else None
            ),
            library_dir=library_dir,
        )

    remote = status.remote_manifest
    bundle_url = _resolve_bundle_url(url, remote.bundle_url)
    bundle_bytes = _http_get(bundle_url, api_key=api_key)
    _verify_bundle_digest(bundle_bytes, remote.bundle_sha256)

    staging = library_dir / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    try:
        _extract_bundle(bundle_bytes, staging)
        (staging / MANIFEST_FILENAME).write_text(
            json.dumps(remote.to_dict(), indent=2),
            encoding="utf-8",
        )
        _promote_staging_into(library_dir, staging)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise

    return SyncResult(
        updated=True,
        bundle_version=remote.bundle_version,
        library_dir=library_dir,
    )


def _promote_staging_into(library_dir: Path, staging: Path) -> None:
    """Move a staged library tree into place without replacing library_dir itself.

    ``library_dir`` may be a mount point (e.g. a Docker volume); ``rmtree`` or
    ``rename`` on the mount path fails with EBUSY on Linux.
    """
    library_dir.mkdir(parents=True, exist_ok=True)
    for entry in list(library_dir.iterdir()):
        if entry == staging:
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    for entry in list(staging.iterdir()):
        dest = library_dir / entry.name
        if dest.exists():
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        shutil.move(str(entry), str(dest))
    staging.rmdir()


def load_local_manifest(library_dir: Path) -> LibraryManifest | None:
    path = library_dir / MANIFEST_FILENAME
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return LibraryManifest.from_dict(data)


def fetch_remote_manifest(url: str, *, api_key: str | None = None) -> LibraryManifest | None:
    manifest_url = url.rstrip("/") + "/api/v1/manifest"
    try:
        payload = json.loads(
            _http_get(manifest_url, api_key=api_key).decode("utf-8")
        )
    except HTTPError as exc:
        if exc.code == 404:
            return None
        _raise_for_http_error(exc, url=manifest_url)
    except URLError as exc:
        raise RuntimeError(f"failed to reach registry at {manifest_url}: {exc}") from exc

    if payload.get("schema") != MANIFEST_SCHEMA:
        raise RuntimeError(f"unsupported manifest schema: {payload.get('schema')}")
    return LibraryManifest.from_dict(payload)


def _resolve_bundle_url(base_url: str, bundle_url: str) -> str:
    if bundle_url.startswith("http://") or bundle_url.startswith("https://"):
        return bundle_url
    return base_url.rstrip("/") + bundle_url


def _auth_action_hint(status_code: int, detail: str) -> str:
    custom = os.environ.get("SENTROOK_AUTH_LOGIN_HINT", "").strip()
    if custom:
        return custom

    lower = detail.lower()
    if status_code == 403 or "scope" in lower:
        return (
            "Token lacks a required scope (sentrook.library.read). "
            "Sign in again with `sentrook library login`."
        )
    return "Sign in with `sentrook library login`."


def _raise_for_http_error(exc: HTTPError, *, url: str) -> None:
    detail = _format_http_error(exc)
    if exc.code in (401, 403):
        raise LibraryAuthError(
            status_code=exc.code,
            detail=detail,
            action_hint=_auth_action_hint(exc.code, detail),
        ) from exc
    raise RuntimeError(f"HTTP request failed for {url}: {detail}") from exc


def _format_http_error(exc: HTTPError) -> str:
    try:
        body = exc.read().decode("utf-8", errors="replace").strip()
        if body:
            try:
                payload = json.loads(body)
            except ValueError:
                payload = None
            if isinstance(payload, dict) and payload.get("detail"):
                return f"HTTP {exc.code}: {payload['detail']}"
            return f"HTTP {exc.code}: {body}"
    except OSError:
        pass
    return f"HTTP Error {exc.code}: {exc.reason}"


def _http_get(url: str, *, api_key: str | None = None) -> bytes:
    headers = {"Accept": "*/*", **rookery_auth_headers(api_key)}
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=60) as response:
            return response.read()
    except HTTPError as exc:
        _raise_for_http_error(exc, url=url)
    # URLError is raised to callers so they can attach registry-specific context.


def _verify_bundle_digest(bundle_bytes: bytes, expected: str) -> None:
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    normalized = expected.removeprefix("sha256:")
    if digest != normalized:
        raise RuntimeError(
            f"bundle digest mismatch: expected sha256:{normalized}, got sha256:{digest}"
        )


def _extract_bundle(bundle_bytes: bytes, target_dir: Path) -> None:
    buffer = io.BytesIO(bundle_bytes)
    with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if member.name == "manifest.json":
                continue
            if not (member.name.startswith("rules/") or member.name.startswith("corpus/")):
                continue
            destination = target_dir / member.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"failed to extract bundle member: {member.name}")
            destination.write_bytes(extracted.read())
