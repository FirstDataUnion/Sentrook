"""The scan log names the bundle that is actually being served.

F60 / checkpoint §8a: every live scan line carried `bundle_version: null`, so a
bundle two phases stale ran unnoticed. Two causes, one fixed here and one in
the Rookery bake: (1) `ScanService.reload` blanked a known value whenever the
rules dir had no manifest; (2) image-baked rules carried no manifest at all.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from sentrook.library.paths import MANIFEST_FILENAME
from sentrook.serve.config import ServeConfig
from sentrook.serve.runtime import ServeRuntime

RULES = Path(__file__).resolve().parents[2] / "rules"


def _runtime(tmp_path: Path) -> ServeRuntime:
    library = tmp_path / "library"
    shutil.copytree(RULES, library / "rules")
    config = ServeConfig(
        rules_path=library / "rules",
        corpus_dir=None,
        log_path=tmp_path / "scan.jsonl",
        latency_log_path=tmp_path / "latency.jsonl",
        library_dir=library,
    )
    return ServeRuntime(config)


def test_reload_names_the_bundle_a_sync_wrote_and_never_blanks_it(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    manifest = rt.config.library_dir / MANIFEST_FILENAME
    assert rt.config.bundle_version is None

    # What `sync_library` leaves behind: manifest.json beside library/rules.
    manifest.write_text(json.dumps({"bundle_version": "2026.09.24-1"}), encoding="utf-8")
    rt.reload_from_disk()
    assert rt.config.bundle_version == "2026.09.24-1"

    manifest.write_text(json.dumps({"bundle_version": "2026.09.24-2"}), encoding="utf-8")
    rt.reload_from_disk()
    assert rt.config.bundle_version == "2026.09.24-2"

    # A rules dir with no manifest must not erase what the log already knows.
    manifest.unlink()
    rt.reload_from_disk()
    assert rt.config.bundle_version == "2026.09.24-2"
