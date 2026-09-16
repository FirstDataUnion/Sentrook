#!/usr/bin/env python3
"""Regenerate fixtures/secret_redaction_golden.jsonl from the Python reference.

The plugin scrubs before egress and the engine re-scrubs on ingress, so a
Python/TypeScript divergence means one of them leaks. Both suites assert against
this file. It caught 18 TS patterns missing the `i` flag that Python applies to
all of them — a real under-redaction (a `sk-ant-` key with uppercase sailed
straight through the plugin).

Run: make secret-golden   (then run BOTH suites)
"""

from __future__ import annotations

import json
from pathlib import Path

from sentrook.sanitize.planir import sanitize_planir

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "secret_redaction_golden.jsonl"


def scrub(command: str) -> str:
    plan = {
        "version": "1.0",
        "run_id": "r",
        "steps": [{"id": "s1", "tool": "exec", "status": "pending", "args": {"command": command}}],
        "metadata": {"adapter": "openclaw", "hook": "before_tool_call"},
    }
    return sanitize_planir(plan).plan.steps[0].args["command"]


def main() -> int:
    rows = [
        json.loads(line) for line in OUT.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    with OUT.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    {"name": row["name"], "input": row["input"], "scrubbed": scrub(row["input"])}
                )
                + "\n"
            )
    print(f"regenerated {len(rows)} cases -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
