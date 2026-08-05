#!/usr/bin/env bash
# Summarize sanitize_ms from Sentrook latency JSONL (Sprint 4 soak reporting).
#
# Usage:
#   ./scripts/sanitize-soak-report.sh path/to/latency.log.jsonl
#   docker exec sentrook-scan tail -n 5000 /var/log/sentrook/latency.log.jsonl | ./scripts/sanitize-soak-report.sh
#
# Reads JSONL from argv[1] or stdin. Reports p50/p95 for sanitize_ms when
# sanitize_enabled is true, plus transport_ms and engine_ms for context.
set -euo pipefail

INPUT="${1:-}"

uv run python - "${INPUT}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path


def percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = int(round((pct / 100) * (len(ordered) - 1)))
    return ordered[max(0, min(index, len(ordered) - 1))]


def load_rows(path: str | None) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


path = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else None
rows = load_rows(path)
if not rows:
    print("no latency rows")
    sys.exit(1)

enabled = [r for r in rows if r.get("sanitize_enabled") is True]
sanitize_ms = [int(r["sanitize_ms"]) for r in enabled if isinstance(r.get("sanitize_ms"), int)]
transport_ms = [int(r["transport_ms"]) for r in rows if isinstance(r.get("transport_ms"), int)]
engine_ms = [int(r["engine_ms"]) for r in rows if isinstance(r.get("engine_ms"), int)]
plugin_e2e_ms = [int(r["plugin_e2e_ms"]) for r in rows if isinstance(r.get("plugin_e2e_ms"), int)]

print(f"rows: {len(rows)}  sanitize_enabled: {len(enabled)}")
if sanitize_ms:
    print(
        "sanitize_ms: "
        f"p50={percentile(sanitize_ms, 50)} "
        f"p95={percentile(sanitize_ms, 95)} "
        f"max={max(sanitize_ms)}"
    )
else:
    print("sanitize_ms: (no rows with sanitize_enabled=true)")

if plugin_e2e_ms:
    print(
        "plugin_e2e_ms: "
        f"p50={percentile(plugin_e2e_ms, 50)} "
        f"p95={percentile(plugin_e2e_ms, 95)}"
    )
if engine_ms:
    print(
        "engine_ms: "
        f"p50={percentile(engine_ms, 50)} "
        f"p95={percentile(engine_ms, 95)}"
    )
if transport_ms:
    print(
        "transport_ms: "
        f"p50={percentile(transport_ms, 50)} "
        f"p95={percentile(transport_ms, 95)}"
    )
PY
