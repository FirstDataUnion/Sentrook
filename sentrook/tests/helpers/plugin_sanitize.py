"""Invoke the OpenClaw plugin's TypeScript sanitize via Node (real plugin code)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sentrook.planir import PlanIR

ROOT = Path(__file__).resolve().parents[3]
PLUGIN_DIR = ROOT / "integrations" / "openclaw" / "plugin"
SANITIZE_STDIN = PLUGIN_DIR / "scripts" / "sanitize-stdin.ts"


def node_available() -> bool:
    return shutil.which("node") is not None


def plugin_sanitize_planir_dict(payload: dict[str, Any]) -> dict[str, Any]:
    """Run ``sanitize.ts`` on a PlanIR dict; return the sanitized PlanIR dict."""
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
    plan = body.get("plan")
    if not isinstance(plan, dict):
        msg = "plugin sanitize stdout missing 'plan' object"
        raise RuntimeError(msg)
    return plan


def plugin_sanitize_planir(plan: PlanIR) -> PlanIR:
    """Sanitize using the real OpenClaw plugin implementation."""
    payload = plan.model_dump(mode="json")
    cleaned = plugin_sanitize_planir_dict(payload)
    return PlanIR.model_validate(cleaned)
