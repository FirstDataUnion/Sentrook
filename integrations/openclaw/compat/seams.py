"""Judges the seam probe's records (probe/index.js) for the OpenClaw compatibility check. Stdlib only: it
runs on the OpenClaw image's Python.

    python3 seams.py <probe.jsonl>

Prints `ok\t<detail>` or `FAIL\t<problems>`. Each problem names the host field that moved.
"""

from __future__ import annotations

import json
import sys

#: The shape each probed api field must have in full registration.
API_FIELDS = {
    "on": "function",
    "registerAgentToolResultMiddleware": "function",
    "registerCli": "function",
    "registerCommand": "function",
    "runtime.version": "string",
    "runtime.config.current": "function",
}

#: before_tool_call fields Sentrook reads, and their shape.
TOOL_CALL_FIELDS = {
    "toolName": "string",
    "params": "object",
    "runId": "string",
    "toolCallId": "string",
    "session": "string",
}


def judge(records: list[dict]) -> list[str]:
    problems: list[str] = []
    full = [r for r in records if r.get("at") == "register" and r.get("mode") == "full"]
    if not full:
        return ["the probe was never registered in full mode (no agent run loaded plugins)"]
    reg = full[-1]
    fields = reg.get("fields") or {}
    for path in reg.get("extra") or []:
        if fields.get(path) in (None, "undefined", "throws"):
            problems.append(f"api.{path} is missing ({fields.get(path)})")
    for path, want in API_FIELDS.items():
        if fields.get(path) != want:
            problems.append(f"api.{path} is {fields.get(path)}, expected {want}")
    if not reg.get("version"):
        problems.append("api.runtime.version is empty")
    if reg.get("current") != "object":
        problems.append(
            f"api.runtime.config.current() returned {reg.get('current')}, expected object"
        )

    calls = [r for r in records if r.get("at") == "before_tool_call"]
    if not calls:
        problems.append("before_tool_call never reached the probe")
    for field, want in TOOL_CALL_FIELDS.items():
        bad = sorted({str(c.get(field)) for c in calls if c.get(field) != want})
        if bad:
            problems.append(f"before_tool_call {field} is {'/'.join(bad)}, expected {want}")

    prompts = [r for r in records if r.get("at") == "before_prompt_build"]
    if not prompts:
        problems.append("before_prompt_build never reached the probe")
    elif not any(p.get("messages") == "array" and p.get("users") for p in prompts):
        problems.append("before_prompt_build never carried the earlier user messages")
    elif not any(p.get("ownerMarked") for p in prompts):
        shapes = sorted({str(s) for p in prompts for s in p.get("markerShapes") or []})
        problems.append(
            "no user message carried __openclaw.senderIsOwner === true "
            f"(found: {', '.join(shapes) or 'none'})"
        )
    return problems


def main() -> int:
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError) as exc:
        print(f"FAIL\tno probe records: {exc}")
        return 0
    problems = judge(records)
    if problems:
        print("FAIL\t" + "; ".join(problems))
    else:
        full = [r for r in records if r.get("mode") == "full"][-1]
        print(
            f"ok\tapi fields, before_tool_call and the owner marker as expected on {full['version']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
