"""`min_scanner_version` must be enforced, not merely carried.

The manifest has declared this field since it was defined, Rookery has always
populated it, and `sync_library` parsed it into a dataclass and never looked at
it again. A field that is transported but never compared is indistinguishable
from no field at all — and it is worse than none, because it reads like a guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentrook import __version__ as SCANNER_VERSION
from sentrook.library import sync as sync_module
from sentrook.library.sync import (
    LibraryManifest,
    LibraryStatus,
    LibraryVersionError,
    _version_tuple,
    sync_library,
)


def _manifest(min_scanner_version: str) -> LibraryManifest:
    return LibraryManifest(
        schema="sentrook.library.manifest/v1",
        bundle_version="2026.09.17-0",
        released_at="2026-09-17T00:00:00+00:00",
        min_scanner_version=min_scanner_version,
        rule_ids=["AIRA-010"],
        stats={"rules": 1, "corpus_examples": 0},
        bundle_url="/api/v1/bundle/latest.tar.gz",
        bundle_sha256="sha256:" + "0" * 64,
    )


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.0.5", (1, 0, 5)),
        ("1.1.0", (1, 1, 0)),
        # Not a string comparison: "1.10.0" < "1.9.0" lexically, so a naive
        # check would start silently passing bundles at exactly the point the
        # numbers get interesting.
        ("1.10.0", (1, 10, 0)),
        ("1.1.0rc1", (1, 1, 0)),
        ("2.0", (2, 0, 0)),
        ("", (0, 0, 0)),
        ("not-a-version", (0, 0, 0)),
    ],
)
def test_version_tuple_is_numeric_and_total(version: str, expected: tuple) -> None:
    assert _version_tuple(version) == expected


def test_version_tuple_orders_double_digits_correctly() -> None:
    assert _version_tuple("1.10.0") > _version_tuple("1.9.0")
    assert _version_tuple("1.0.5") < _version_tuple("1.1.0")


def _patch_status(
    monkeypatch: pytest.MonkeyPatch, manifest: LibraryManifest, library_dir: Path
) -> None:
    monkeypatch.setattr(
        sync_module,
        "library_status",
        lambda **_: LibraryStatus(
            library_dir=library_dir,
            local_manifest=None,
            remote_manifest=manifest,
            update_available=True,
        ),
    )


def test_a_bundle_needing_a_newer_scanner_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The library on disk must survive a bundle the engine cannot run.

    A stale library keeps working. The alternative is the failure this exists to
    prevent: `${sensitive_path}` reaching an engine without the expander, where
    it compiles cleanly and matches nothing.
    """
    _patch_status(monkeypatch, _manifest("99.0.0"), tmp_path)

    def _explode(*_args, **_kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("refused bundle was downloaded anyway")

    monkeypatch.setattr(sync_module, "_http_get", _explode)

    with pytest.raises(LibraryVersionError, match="requires scanner >= 99.0.0"):
        sync_library(url="https://rookery.example", library_dir=tmp_path)

    assert list(tmp_path.iterdir()) == [], "refused sync must not touch the library"


def test_an_equal_or_older_floor_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forward compatibility: a new engine must still take old bundles."""
    for floor in ("1.0.0", "1.0.5", SCANNER_VERSION):
        assert _version_tuple(SCANNER_VERSION) >= _version_tuple(floor), floor


def test_the_shipped_version_clears_the_macro_floor() -> None:
    """The bump is the half of the guard that lives in this repo.

    Rookery sets `min_scanner_version` from the Sentrook version it is pinned
    to, so the floor only rises when this number does. Leaving it at 1.0.5 while
    publishing macro-bearing rules would have left the check correct and inert.
    """
    assert _version_tuple(SCANNER_VERSION) >= (1, 1, 0), (
        "the ${…} macro dialect needs a >= 1.1.0 floor; bump __version__ "
        "whenever the engine gains rule vocabulary an older engine cannot read"
    )


def test_an_engine_without_the_expander_fails_silently_not_loudly() -> None:
    """Why the floor has to be a *version* check and cannot be a load check.

    This is the whole argument in one assertion: the macro is a perfectly valid
    regex to an engine that does not know it is a macro. There is no exception
    to catch and nothing to notice at load — only five credential rules that
    quietly stop matching.
    """
    import re

    naive = re.compile("${sensitive_path}")  # what a 1.0.x engine compiles
    for path in ("~/.ssh/id_rsa", "/app/.env", "/x/auth-profiles.json"):
        assert naive.search(path) is None, path
