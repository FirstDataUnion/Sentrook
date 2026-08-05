"""Invoke the OpenClaw plugin's TypeScript sanitize via Node (real plugin code)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sentrook.shadow.snapshot import ShadowSnapshot

ROOT = Path(__file__).resolve().parents[3]
PLUGIN_DIR = ROOT / "integrations" / "openclaw" / "plugin"
SANITIZE_STDIN = PLUGIN_DIR / "scripts" / "sanitize-stdin.ts"


def node_available() -> bool:
    return shutil.which("node") is not None


def plugin_sanitize_snapshot_dict(payload: dict[str, Any]) -> dict[str, Any]:
    """Run ``sanitize.ts`` on a snapshot dict; return the sanitized snapshot."""
    if not node_available():
        msg = "node is required for plugin sanitize parity tests"
        raise RuntimeError(msg)
    if not SANITIZE_STDIN.is_file():
        msg = f"plugin sanitize script missing: {SANITIZE_STDIN}"
        raise FileNotFoundError(msg)

    proc = subprocess.run(
        ["node", "--experimental-strip-types", str(SANITIZE_STDIN)],
        input=json.dumps(payload).encode("utf-8"),
        cwd=PLUGIN_DIR,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        msg = f"plugin sanitize failed (exit {proc.returncode}): {stderr or stdout}"
        raise RuntimeError(msg)

    body = json.loads(proc.stdout.decode("utf-8"))
    snapshot = body.get("snapshot")
    if not isinstance(snapshot, dict):
        msg = "plugin sanitize stdout missing 'snapshot' object"
        raise RuntimeError(msg)
    return snapshot


def plugin_sanitize_snapshot(snapshot: ShadowSnapshot) -> ShadowSnapshot:
    """Sanitize using the real OpenClaw plugin implementation."""
    payload = snapshot.model_dump(mode="json", by_alias=True)
    cleaned = plugin_sanitize_snapshot_dict(payload)
    return ShadowSnapshot.model_validate(cleaned)
