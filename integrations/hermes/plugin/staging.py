"""Held background saves kept in Hermes's own pending store, so the owner can look at them and approve or reject
them with Hermes's own commands (`/skills pending|diff|approve|reject`, `/memory pending|approve|reject`).

A background save (see `skill_review`) that Sentrook reviews and does not let through is held: the agent is told it
was not saved. Held that way, its content is lost. Instead, when the save is one Hermes can replay, the plugin stages
it with Hermes's `tools.write_approval.stage_write`, the same store Hermes's own `write_approval` settings use. Those
settings stay as the owner left them: Hermes's commands list, show, approve and reject staged records with the gate
off, and approving replays the save through Hermes's own skill and memory paths.

What is staged (`plan`): `skill_manage` create, edit, patch, write_file and remove_file, and a batch of only those;
`memory` add, and a batch of only adds. The payload is the call's own arguments, so approving makes exactly the save
the scan judged.

What is never staged, and stays held as before (`refusal`, `plan`):
- a block, and a score at the block line that a retry rule capped at review;
- a save the plugin did not declare with its `self_edit` block (`skill_review: review`);
- a save whose scan says it adds a secret (`self_edit.adds` has `secret`), or that the plugin's own redaction changed:
  staging would write the secret in plain text to a file;
- a save larger than the copy the scanner was sent (`input_cap_bytes`): the scan did not see all of it;
- a skill `delete` (Hermes deletes an approved staged skill for good, not to its archive);
- a memory `patch` or `remove` (alone or in a batch). Hermes pins each to the whole entry it matches when it stages
  one, which the plugin must not work out itself. Hermes's own gate stages these when its unattended background
  review makes them (`host_stages`): then the plugin lets the call through to that gate and reads what it did in
  `post_tool_call` (`host_outcome`). Where that gate cannot be established, they stay held.

The plugin writes each record's summary itself (`summary`): its own words and the kind of change, at most 200
characters, never the saved text. The staged file is made readable by the owner only (0600, as Hermes keeps its
memory files). At most `MAX_PENDING` records the plugin staged wait in each store; past that, saves are held as
before. Anything that fails while staging holds the save as before: nothing here ever raises or lets a save through.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import stat
import threading
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .redact import Redactor
from .store import file_lock

SKILLS = "skills"
MEMORY = "memory"
#: `skill_manage` actions a staged record replays.
SKILL_ACTIONS = frozenset({"create", "edit", "patch", "write_file", "remove_file"})
#: The call arguments Hermes itself stages for a `skill_manage` call (its flat-shape keys).
SKILL_KEYS = (
    "content",
    "category",
    "file_path",
    "file_content",
    "old_string",
    "new_string",
    "replace_all",
    "absorbed_into",
)
MEMORY_TARGETS = frozenset({"memory", "user"})
#: Memory actions Hermes's unattended-review gate stages itself (`replace` is no longer offered by Hermes).
DESTRUCTIVE_MEMORY = frozenset({"patch", "remove"})
#: At most this many records the plugin staged wait in each store.
MAX_PENDING = 20
#: A batch longer than this is not staged (Hermes caps batches lower still).
MAX_BATCH_OPS = 50
#: Every summary the plugin writes starts with this: it is how its own records are counted.
SUMMARY_PREFIX = "Held by Sentrook"
SUMMARY_MAX = 200
_PENDING_ID = re.compile(r"[0-9a-f]{8}")
#: A skill name shown in a summary: no dots, colons or at signs, so no chat client renders it as a link or mention.
_SHOWN_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
_LOCK = threading.Lock()
#: Serialises counting and staging across processes (`store.file_lock` locks `<this>.lock`).
LOCK_FILE = "staging"

#: What the agent is told about a save the plugin staged.
STAGED_TEXT = (
    "Sentrook held this save for the owner's review, so it was not saved. It is staged for the owner to approve "
    "or reject. Do not retry this save in this run."
)


@dataclass(frozen=True)
class Plan:
    """How a held save is kept: staged by the plugin (`by` "sentrook", with the `payload` Hermes replays on
    approval) or left to Hermes's own gate (`by` "hermes")."""

    store: str
    what: str
    by: str = "sentrook"
    payload: dict[str, Any] = field(default_factory=dict)


# ---- what may be staged ------------------------------------------------------------------------------


def refusal(
    resp: dict[str, Any], *, declared: bool, redacted: bool, whole: bool, block_at: float
) -> str | None:
    """Why a reviewed background save must stay held whatever it saves, or None. `declared`: the plugin sent the
    save with its `self_edit` block; `redacted`: the plugin's own redaction changed the call's arguments (a secret
    the scanner may not have seen, if it was cut from the scanned copy); `whole`: the scanner was sent the whole
    call, not a copy cut to the input cap, so what it reports covers everything that would be staged."""
    if not declared:
        return "not_declared"
    if redacted:
        return "redacted"
    if not whole:
        return "too_large"
    risk = resp.get("risk")
    if isinstance(risk, bool) or not isinstance(risk, (int, float)) or risk >= block_at:
        return "block_level"
    if resp.get("enforced") == "block":
        return "block_level"
    block = resp.get("self_edit")
    if block is None:
        # an older scanner: it does not say whether the save carries a secret; the plugin's redaction found none
        return None
    adds = block.get("adds") if isinstance(block, dict) else None
    if not isinstance(adds, list):
        return "self_edit_unreadable"
    return "secret" if "secret" in adds else None


def plan(tool: str, args: Any, redactor: Redactor) -> Plan | str:
    """How this held save can be kept, or why it cannot (a short reason)."""
    if not isinstance(args, dict):
        return "arguments"
    if tool == "skill_manage":
        return _skill_plan(args, redactor)
    if tool == "memory":
        return _memory_plan(args)
    return "tool"


def _skill_name(name: Any, redactor: Redactor) -> str | None:
    """`name` as a summary may show it, or None."""
    if not isinstance(name, str) or not _SHOWN_NAME.fullmatch(name):
        return None
    return name if redactor.string(name) == name else None


def _skill_what(action: str, name: str | None) -> str:
    skill = f"skill '{name}'" if name else "a skill"
    return {
        "create": f"create {skill}",
        "edit": f"rewrite {skill}",
        "patch": f"edit {skill}",
        "write_file": f"write a file in {skill}",
        "remove_file": f"remove a file from {skill}",
    }[action]


def _skill_plan(args: dict[str, Any], redactor: Redactor) -> Plan | str:
    default = args.get("name")
    ops = args.get("operations")
    if ops is not None:
        if not isinstance(ops, list) or not ops or len(ops) > MAX_BATCH_OPS:
            return "batch"
        names: list[str | None] = []
        for op in ops:
            if not isinstance(op, dict):
                return "batch"
            action = op.get("action")
            if action == "delete":
                return "delete"
            if action not in SKILL_ACTIONS:
                return "action"
            name = op.get("name") or default
            if not isinstance(name, str) or not name.strip():
                return "name"
            names.append(_skill_name(name, redactor))
        shown = sorted({n for n in names if n})
        on = (
            " on "
            + ", ".join(f"'{n}'" for n in shown[:3])
            + (" and more" if len(shown) > 3 else "")
            if shown
            else ""
        )
        payload: dict[str, Any] = {"action": "batch", "operations": ops}
        if isinstance(default, str) and default:
            payload["name"] = (
                default  # Hermes replays a batch with the top-level name as each op's default
            )
        return Plan(SKILLS, f"{len(ops)} skill changes{on}", payload=payload)
    action = args.get("action")
    if action == "delete":
        return "delete"
    if action not in SKILL_ACTIONS:
        return "action"
    if not isinstance(default, str) or not default.strip():
        return "name"
    payload = {
        "action": action,
        "name": default,
        **{k: args[k] for k in SKILL_KEYS if args.get(k) is not None},
    }
    return Plan(SKILLS, _skill_what(action, _skill_name(default, redactor)), payload=payload)


def _memory_text(op: dict[str, Any]) -> str | None:
    """What a memory add writes (Hermes reads `new_text` as `content`)."""
    for key in ("content", "new_text"):
        v = op.get(key)
        if isinstance(v, str) and v.strip():
            return v
    return None


def _memory_where(target: str) -> str:
    return "the user profile" if target == "user" else "memory"


def _memory_plan(args: dict[str, Any]) -> Plan | str:
    target = args.get("target")
    if target not in MEMORY_TARGETS:
        return "target"
    ops = args.get("operations")
    if ops:  # Hermes takes the batch shape whenever `operations` is non-empty
        if not isinstance(ops, list) or len(ops) > MAX_BATCH_OPS:
            return "batch"
        actions = [op.get("action") if isinstance(op, dict) else None for op in ops]
        if all(a == "add" for a in actions):
            if any(_memory_text(op) is None for op in ops):
                return "content"
            n = len(ops)
            return Plan(
                MEMORY,
                f"add {n} {'entry' if n == 1 else 'entries'} to {_memory_where(target)}",
                payload={"action": "batch", "target": target, "operations": ops},
            )
        if any(a in DESTRUCTIVE_MEMORY for a in actions) and all(
            a == "add" or a in DESTRUCTIVE_MEMORY for a in actions
        ):
            return _host_plan({"action": "batch", "target": target, "operations": ops}, target)
        return "action"
    action = args.get("action")
    if action == "add":
        content = _memory_text(args)
        if content is None:
            return "content"
        return Plan(
            MEMORY,
            f"add 1 entry to {_memory_where(target)}",
            payload={"action": "add", "target": target, "content": content, "old_text": None},
        )
    if action in DESTRUCTIVE_MEMORY:
        return _host_plan(
            {
                "action": action,
                "target": target,
                "content": _memory_text(args),
                "old_text": args.get("old_text"),
            },
            target,
        )
    return "action"


def _host_plan(payload: dict[str, Any], target: str) -> Plan | str:
    if not host_stages(payload):
        return "destructive_memory"
    return Plan(MEMORY, f"change or remove entries in {_memory_where(target)}", by="hermes")


def host_stages(payload: dict[str, Any]) -> bool:
    """Hermes's own gate will stage this destructive memory change instead of making it.

    Established from the running Hermes itself, never from a version string: the call is in an unattended
    background review (the gate's own condition); `tools.memory_tool` has the gate (`_background_delete_gate`,
    whose source reads that condition, stages with `stage_write` and reports `proposal_staged`); the memory tool
    calls it before it writes anything (`_memory_tool`, reached from `memory_tool`); and the gate's own
    `destructive_ops` counts this change. Anything missing, unreadable or raising means no: the save stays held."""
    try:
        from tools import memory_tool as mt
        from tools import write_approval as wa
        from tools.skill_provenance import is_unattended_review

        if is_unattended_review() is not True:
            return False
        if not callable(getattr(wa, "stage_write", None)):
            return False
        gate, tool, entry = mt._background_delete_gate, mt._memory_tool, mt.memory_tool
        gate_src, tool_src = inspect.getsource(gate), inspect.getsource(tool)
        if not all(
            s in gate_src for s in ("is_unattended_review", "stage_write", "proposal_staged")
        ):
            return False
        if not _gated_before_every_write(tool_src):
            return False
        if "_memory_tool(" not in inspect.getsource(entry):
            return False
        return bool(mt.destructive_ops(payload))
    except Exception:  # noqa: BLE001 - an older, newer or different host: held
        return False


def _gated_before_every_write(source: str) -> bool:
    """In the memory tool's source, every write (`_applied(`) has a call of the gate after the write before it:
    each path through the tool consults the gate before it writes."""
    writes = [i for i in range(len(source)) if source.startswith("_applied(", i)]
    if not writes:
        return False
    start = 0
    for at in writes:
        if source.find("_background_delete_gate(", start, at) < 0:
            return False
        start = at
    return True


# ---- the summary --------------------------------------------------------------------------------------


def inert(text: str, cap: int = SUMMARY_MAX) -> str:
    """`text` without control, formatting (bidi, zero-width), private-use or unassigned characters, at most
    `cap` long."""
    kept = "".join(
        c for c in text if unicodedata.category(c) not in ("Cc", "Cf", "Co", "Cn", "Zl", "Zp")
    )
    return kept[:cap]


def summary(p: Plan, *, rule: bool) -> str:
    """The pending record's summary: the plugin's own words and the kind of change, never what it saves."""
    why = "a Sentrook rule asks for a review" if rule else "Sentrook asks for a review"
    return inert(f"{SUMMARY_PREFIX} ({why}): {p.what}. Not saved until you approve it.")


# ---- staging ----------------------------------------------------------------------------------------------


def _pending_file(store: str, pending_id: str) -> Path:
    """Where Hermes keeps a pending record (its `write_approval._pending_path`)."""
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "pending" / store / f"{pending_id}.json"


def make_private(path: Path) -> bool:
    """Makes the staged file readable by its owner only; never follows a link. True when it is."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        if os.name == "nt":  # no POSIX modes: the Hermes home's own access rules apply
            return True
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchmod(fd, 0o600)
            return stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        finally:
            os.close(fd)
    except OSError:
        return False


def _discard(wa: Any, store: str, pending_id: str) -> None:
    try:
        if callable(getattr(wa, "discard_pending", None)):
            wa.discard_pending(store, pending_id)
        else:
            _pending_file(store, pending_id).unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - nothing more to do; the record stays for the owner to reject
        pass


def ours(records: Any) -> int:
    """How many of Hermes's pending records the plugin staged (by their summary)."""
    if not isinstance(records, list):
        raise ValueError("pending records are not a list")
    return sum(
        1
        for r in records
        if isinstance(r, dict) and str(r.get("summary") or "").startswith(SUMMARY_PREFIX)
    )


def stage(p: Plan, text: str, state_dir: Path) -> tuple[str | None, str]:
    """Stages `p` in Hermes's pending store with the summary `text`: (the pending id, "staged"), or (None, why not).
    Never raises."""
    try:
        from tools import write_approval as wa

        stage_write, list_pending = wa.stage_write, wa.list_pending
    except Exception:  # noqa: BLE001 - an older or different host, or the plugin runs out of process
        return None, "unavailable"
    try:
        current = getattr(wa, "current_origin", None)
        origin = current() if callable(current) else "background_review"
        with _LOCK, file_lock(state_dir / LOCK_FILE):
            if ours(list_pending(p.store)) >= MAX_PENDING:
                return None, "over_cap"
            record = stage_write(p.store, p.payload, summary=text, origin=origin)
    except Exception:  # noqa: BLE001 - not staged: held as before
        return None, "failed"
    pending_id = record.get("id") if isinstance(record, dict) else None
    if not isinstance(pending_id, str) or not _PENDING_ID.fullmatch(pending_id):
        return None, "failed"
    try:
        path = _pending_file(p.store, pending_id)
    except Exception:  # noqa: BLE001
        _discard(wa, p.store, pending_id)
        return None, "failed"
    if not make_private(path):
        # not written (Hermes logs a failed write and still returns the record), or it cannot be kept private
        _discard(wa, p.store, pending_id)
        return None, "not_written"
    return pending_id, "staged"


# ---- what Hermes's own gate did ------------------------------------------------------------------------


def host_outcome(status: str, result: Any) -> dict[str, Any]:
    """What happened to a destructive memory change the plugin left to Hermes's gate, from the tool's result:
    {"result": "staged", "id"}, "saved" (Hermes made the change), "not_saved" (refused or failed, nothing written)
    or "unknown" (the result does not say)."""
    data = result
    if isinstance(result, str):
        try:
            data = json.loads(result)
        except ValueError:
            data = None
    if not isinstance(data, dict):
        # a blocked call never ran; a cancelled one may still finish in Hermes, so it is unknown
        return {"result": "not_saved" if status == "blocked" else "unknown"}
    pending_id = data.get("pending_id")
    staged = data.get("staged") is True or data.get("proposal_staged") is True
    if (
        status == "ok"
        and data.get("success") is True
        and staged
        and isinstance(pending_id, str)
        and _PENDING_ID.fullmatch(pending_id)
    ):
        return {"result": "staged", "id": pending_id}
    if status == "ok" and data.get("success") is True and not staged:
        return {"result": "saved"}
    if data.get("success") is False or status == "blocked":
        return {"result": "not_saved"}
    return {"result": "unknown"}


def keep_private(store: str, pending_id: str) -> None:
    """Makes a record Hermes staged itself readable by its owner only, as the plugin's own are. Best effort."""
    try:
        make_private(_pending_file(store, pending_id))
    except Exception:  # noqa: BLE001
        pass
