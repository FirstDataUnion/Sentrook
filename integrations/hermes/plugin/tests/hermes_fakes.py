"""Stand-ins for the parts of Hermes (0.23) the plugin stages held background saves with, shaped like the real ones.

`WriteApproval` is `tools.write_approval`: `stage_write` writes `<HERMES_HOME>/pending/<store>/<8 hex>.json` with the
umask's mode (0644 here, as on Hermes) and returns the record; `list_pending`, `discard_pending`, `current_origin`.

The functions below are `tools.memory_tool` as far as the plugin reads it: its source is read to establish that
Hermes's own gate stages a destructive memory change made by an unattended background review, so they keep the
shape of Hermes's own (the gate runs before anything is written)."""

from __future__ import annotations

import json
import os
import time
import types
import uuid
from pathlib import Path
from typing import Any


def write_approval(home: Path, origin: Any) -> types.ModuleType:
    mod = types.ModuleType("tools.write_approval")
    mod.calls = []
    mod.fail = (
        None  # "raise" makes stage_write raise; "no_file" returns a record without writing it
    )

    def _pending_path(subsystem: str, pending_id: str) -> Path:
        return home / "pending" / subsystem / f"{pending_id}.json"

    def stage_write(subsystem, payload, *, summary, origin):
        mod.calls.append(
            {"subsystem": subsystem, "payload": payload, "summary": summary, "origin": origin}
        )
        if mod.fail == "raise":
            raise OSError("disk full")
        pid = uuid.uuid4().hex[:8]
        record = {
            "id": pid,
            "subsystem": subsystem,
            "action": payload.get("action", ""),
            "summary": (summary or "").strip(),
            "origin": origin or "foreground",
            "created_at": time.time(),
            "payload": payload,
        }
        if mod.fail != "no_file":
            path = getattr(mod, "_pending_path", _pending_path)(subsystem, pid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record))
            os.chmod(path, 0o644)
        return record

    def list_pending(subsystem):
        if mod.fail == "list":
            raise OSError("unreadable")
        d = _pending_path(subsystem, "").parent
        records = [json.loads(p.read_text()) for p in d.glob("*.json")] if d.exists() else []
        return sorted(records, key=lambda r: r.get("created_at", 0))

    def discard_pending(subsystem, pending_id):
        if mod.fail == "discard":
            raise OSError("cannot discard")
        path = getattr(mod, "_pending_path", _pending_path)(subsystem, pending_id)
        if path.exists():
            path.unlink()
            return True
        return False

    mod._pending_path = _pending_path
    mod.stage_write = stage_write
    mod.list_pending = list_pending
    mod.discard_pending = discard_pending
    mod.current_origin = origin
    return mod


# ---- tools.memory_tool -----------------------------------------------------------------------------------

#: `tools.memory_tool` as far as the plugin reads it, shaped like Hermes's own: the unattended-review gate runs before
#: anything is written. Loaded from a real file (`memory_tool_module`), since the plugin reads its functions' source.
MEMORY_TOOL = """
import json

_BG_DELETE_ACTIONS = ("replace", "remove", "patch")


def destructive_ops(payload):
    ops = (payload.get("operations") or []) if payload.get("action") == "batch" else [payload]
    return [op for op in ops if (op or {}).get("action") in _BG_DELETE_ACTIONS]


def _background_delete_gate(store, action, operations, target="memory", content=None, old_text=None):
    from tools.skill_provenance import is_unattended_review

    if not is_unattended_review():
        return None
    payload = (
        {"action": "batch", "target": target, "operations": operations}
        if operations is not None
        else {"action": action, "target": target, "content": content, "old_text": old_text}
    )
    if not destructive_ops(payload):
        return None
    from tools import write_approval as wa

    record = wa.stage_write("memory", payload, summary="background review consolidation", origin="background_review")
    return json.dumps({"success": True, "staged": True, "proposal_staged": True, "pending_id": record["id"]})


def _applied(result):
    return ("success" if result.get("success") else "failed"), json.dumps(result)


def _memory_tool(action, target, content, old_text, new_text, operations, store):
    if operations:
        denied = _background_delete_gate(store, action, operations, target)
        if denied is not None:
            return "rejected", denied
        return _applied({"success": True})
    invalid = _background_delete_gate(store, action, None, target, content, old_text)
    if invalid is not None:
        return "rejected", invalid
    return _applied({"success": True})


def memory_tool(action=None, target="memory", content=None, old_text=None, new_text=None, operations=None, store=None):
    outcome, result = _memory_tool(action, target, content, old_text, new_text, operations, store)
    return result
"""

GATE_HEAD = "    if not is_unattended_review():\n        return None\n"
BATCH_GATE = (
    "        denied = _background_delete_gate(store, action, operations, target)\n"
    "        if denied is not None:\n"
    '            return "rejected", denied\n'
)
#: Plausible later Hermes builds that keep every name the old checks looked for, yet make the change live.
DRIFT = {
    "off-switch-in-the-gate": MEMORY_TOOL.replace(
        GATE_HEAD, GATE_HEAD + "    if not _gate_on():\n        return None\n"
    )
    + "\n\ndef _gate_on():\n    return False\n",
    "stages-only-with-write-approval-on": MEMORY_TOOL.replace(
        GATE_HEAD,
        GATE_HEAD
        + '    from tools import write_approval as _wa\n    if not _wa.write_approval_enabled("memory"):\n'
        "        return None\n",
    ),
    "curator-exempt": MEMORY_TOOL.replace(
        "    if not is_unattended_review():", "    if not is_unattended_review() or _is_curator():"
    )
    + "\n\ndef _is_curator():\n    return True\n",
    "gate-call-only-in-a-comment": MEMORY_TOOL.replace(
        BATCH_GATE,
        "        # _background_delete_gate(store, action, operations, target) moved to the store\n",
    ),
    "gate-after-write": MEMORY_TOOL.replace(
        "    invalid = _background_delete_gate(store, action, None, target, content, old_text)\n"
        '    if invalid is not None:\n        return "rejected", invalid\n    return _applied({"success": True})',
        '    result = _applied({"success": True})\n'
        "    _background_delete_gate(store, action, None, target, content, old_text)\n    return result",
    ),
}


def memory_tool_module(directory: Path, source: str = MEMORY_TOOL) -> types.ModuleType:
    """`source` written to `directory/memory_tool.py` and loaded as `tools.memory_tool`."""
    import importlib.util

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "memory_tool.py"
    path.write_text(source)
    spec = importlib.util.spec_from_file_location("tools.memory_tool", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
