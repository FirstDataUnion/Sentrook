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
  review makes them. Only on a Hermes build whose gate the plugin has verified (`VERIFIED_GATES`, `host_stages`)
  does the plugin let the call through to that gate, and it reads what Hermes did in `post_tool_call`
  (`host_outcome`). On any other build they stay held, and after one such change was saved without the owner, for
  the rest of the process.

The plugin writes each record's summary itself (`summary`): its own words and the kind of change, at most 200
characters, never the saved text. The staged file is made readable by the owner only (0600, as Hermes keeps its
memory files). At most `MAX_PENDING` records the plugin staged wait in each store; past that, saves are held as
before. Anything that fails while staging holds the save as before: nothing here ever raises or lets a save through.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
import threading
import types
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
    """What a memory add writes, as Hermes reads it: `content`, or `new_text` when `content` is empty."""
    v = op.get("content") or op.get("new_text")
    return v if isinstance(v, str) and v else None


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


#: The functions of Hermes's `tools.memory_tool` that decide whether an unattended background review's destructive
#: memory change is staged instead of made, in the order `gate_build` hashes them.
GATE_FUNCTIONS = ("_background_delete_gate", "_memory_tool", "memory_tool", "destructive_ops")
#: Hermes builds whose gate the plugin has verified stages those changes (`gate_build`'s digest -> what it covers).
#: Any other build holds them. A Hermes bump that changes these functions must add its digest here on purpose, after
#: checking the gate still stages every destructive change of an unattended review; the host compatibility check
#: fails until it does.
VERIFIED_GATES = {
    # Hermes 0.23.0 and 0.23.2 (the tested floor and latest), and main as of 2026-11-05: the four functions are the
    # same text in all three. 0.22.4 differs.
    "821d3b9ff07b7bbf021d9310b7b23c8f1165b14992a7f83b46225b3cb2b70b34": "Hermes 0.23.0 to 0.23.2",
}
#: Set once a change left to Hermes's gate was saved, or may have been, without the owner: from then on this process
#: holds such changes, whatever the build.
_gate_distrusted = False


def distrust_gate() -> None:
    """Stops leaving destructive memory changes to Hermes's gate for the rest of this process."""
    global _gate_distrusted
    _gate_distrusted = True


def _future_flags(module: Any) -> int:
    import __future__

    flags = 0
    for name in __future__.all_feature_names:
        feature = getattr(__future__, name)
        if getattr(module, name, None) is feature:
            flags |= feature.compiler_flag
    return flags


def _same_code(a: types.CodeType, b: types.CodeType) -> bool:
    """Two code objects use the same names, variables and constants (nested code compared the same way). Not the
    bytecode itself: the compiler emits slightly different bytecode for the same function depending on the module
    around it, so only what the source names and states is compared."""
    if (a.co_name, a.co_names, a.co_varnames, a.co_freevars, a.co_cellvars) != (
        b.co_name,
        b.co_names,
        b.co_varnames,
        b.co_freevars,
        b.co_cellvars,
    ) or len(a.co_consts) != len(b.co_consts):
        return False
    for x, y in zip(a.co_consts, b.co_consts, strict=True):
        if isinstance(x, types.CodeType) or isinstance(y, types.CodeType):
            if not (
                isinstance(x, types.CodeType) and isinstance(y, types.CodeType) and _same_code(x, y)
            ):
                return False
        elif type(x) is not type(y) or x != y:
            return False
    return True


def _source_of(module: Any, name: str) -> str:
    """The source of `module.name`, a plain function, checked against the code that is running: the source file can
    change on disk under a running Hermes (an upgrade in place), and then it no longer describes what runs."""
    fn = getattr(module, name)
    if not isinstance(fn, types.FunctionType) or fn.__module__ != module.__name__:
        raise ValueError(f"{name} is not a plain function of {module.__name__}")
    text = inspect.getsource(fn).replace("\r\n", "\n")
    compiled = compile(text, "<gate>", "exec", flags=_future_flags(module), dont_inherit=True)
    code = next(
        c for c in compiled.co_consts if isinstance(c, types.CodeType) and c.co_name == fn.__name__
    )
    if not _same_code(code, fn.__code__):
        raise ValueError(f"{name}'s source on disk is not the code that runs")
    return text


def gate_build(module: Any) -> str:
    """The digest of Hermes's gate in `module` (`tools.memory_tool`): sha256 over each of `GATE_FUNCTIONS`' name and
    the sha256 of its source text as `inspect.getsource` reads it (line endings made `\\n`). Raw source text, not an
    AST dump: an AST dump's format changes between Python versions, so the same Hermes would hash differently on
    another interpreter, while the text is the same wherever it runs; a change to a comment or docstring changes the
    digest too, so it must be checked again, which is the safe direction. Raises when any function is missing, not
    a plain function, or its source cannot be read or does not match the running code."""
    return gate_digest({name: _source_of(module, name) for name in GATE_FUNCTIONS})


def gate_digest(sources: dict[str, str]) -> str:
    """`gate_build`'s digest from each of `GATE_FUNCTIONS`' source text."""
    parts = [
        f"{name} {hashlib.sha256(sources[name].encode('utf-8')).hexdigest()}"
        for name in GATE_FUNCTIONS
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def host_stages(payload: dict[str, Any]) -> bool:
    """Hermes's own gate will stage this destructive memory change instead of making it.

    Only on a Hermes build the plugin has verified (`VERIFIED_GATES`, by `gate_build`'s digest of the running gate's
    source), never from a version string or from what the source seems to say: the call is in an unattended
    background review (the gate's own condition), `tools.write_approval.stage_write` exists, and the gate's own
    `destructive_ops` counts this change. Not once this process saw such a change saved without the owner
    (`distrust_gate`). Anything missing, unreadable, unknown or raising means no: the save stays held."""
    if _gate_distrusted:
        return False
    try:
        from tools import memory_tool as mt
        from tools import write_approval as wa
        from tools.skill_provenance import is_unattended_review

        if is_unattended_review() is not True:
            return False
        if not callable(getattr(wa, "stage_write", None)):
            return False
        if gate_build(mt) not in VERIFIED_GATES:
            return False
        return bool(mt.destructive_ops(payload))
    except Exception:  # noqa: BLE001 - an older, newer or different host: held
        return False


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
    """Where Hermes keeps a pending record: its own `write_approval._pending_path` where it has one, else the same
    path built from the Hermes home."""
    try:
        from tools import write_approval as wa

        own = getattr(wa, "_pending_path", None)
    except Exception:  # noqa: BLE001
        own = None
    if callable(own):
        return Path(own(store, pending_id))
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
