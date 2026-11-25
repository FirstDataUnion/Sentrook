"""The agent's setup proposals: the `sentrook_propose_setup` tool.

The agent learns from the owner what is routine (a folder they work in, a service they are about to use, the name of a
key) that the plugin cannot find in config or traffic. This tool lets it add those to the owner's setup screen
(`/sentrook setup`, `setup.py`) instead of handing the owner commands described in its own words. It sets nothing:
the owner reads each item there, in the plugin's words, and sets it with the screen's code.

**What it takes.** Up to `MAX_ITEMS` items, each one of:
- a grant, `{kind, pattern, allows?, expires?, reason}` (kind destination, file, provider, repo or credential);
- a channel binding, `{binding, reason}`.
Each `reason` is one sentence of at most `MAX_REASON` characters, shown to the owner only as a quoted note. Each item
is checked by the code the owner's own commands use: a grant must be one `grant <kind> <pattern> --persistent
[--allows ...] [--expires ...]` would accept (`grants.parse_grant`), a binding one `bind add` would add that could
ever apply (`planir.binding_problem`), and either must be one the setup screen can show (`setup.proposal_item`,
`setup.valid_item`). An item that fails comes back to the agent with that code's error; the others are stored.
Session grants are refused (setup is for lasting grants, or ones with an expiry), and so are settings: the setup
screen shows grants and bindings only, the owner changes settings with their own commands, and attended platforms are
never proposed. A credential grant names the key, never its value.

**Where it goes.** `<state>/proposals.json`, locked like the grants file: an id `p-` and six hex digits, the session
ref, when it was made and when it expires (`setup.PROPOSAL_TTL`, a day). At most `MAX_OPEN` proposals are open; a new
one replaces the oldest. The agent hears only how many items were added and to ask the owner to open the setup screen
(and which items were not added, with why): never the screen, its evidence, its warnings or its code.

**Who may call it** is decided as for the setup report (`setup_report.allowed`, `setup_report.Markers`): only the
owner, in a turn from their own message in a direct chat or the local terminal, with someone there. Everywhere else
the answer is `setup_report.REFUSAL` and nothing is stored. The OpenClaw plugin takes the same items, text for text.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import grants, setup
from .config import destination_ok
from .planir import binding_problem
from .redact import Redactor
from .store import LockTimeout, Store, file_lock, read_time

TOOL = "sentrook_propose_setup"
#: Items in one call.
MAX_ITEMS = 20
#: Characters in one item's reason.
MAX_REASON = 200
#: Proposals open at once; a new one replaces the oldest.
MAX_OPEN = 3

GRANT_FIELDS = frozenset({"kind", "pattern", "allows", "expires", "reason", "scope"})
BINDING_FIELDS = frozenset({"binding", "reason"})

NO_ITEMS = "Give items: a list of 1 to 20 grants or channel bindings, each with a reason. Nothing was added."
TOO_MANY = f"At most {MAX_ITEMS} items in one proposal. Nothing was added."
NOT_SAVED = "Sentrook could not save the proposal. Nothing was added."

NOT_AN_ITEM = (
    "Not an item: give a grant (kind, pattern, reason) or a channel binding (binding, reason)."
)
SETTING = "Settings are not proposed: the owner changes them with their own commands; explain the setting to them instead."
ATTENDED = "Attended platforms are never proposed: only the owner adds one, by changing the setting themselves."
SESSION = "Session grants are not proposed: setup is for lasting grants; give expires (such as 7d) to end one sooner."
NO_REASON = "Each item needs a reason: one sentence on why the owner would want it."
LONG_REASON = f"The reason must be at most {MAX_REASON} characters."
NO_KIND = "A grant needs a kind: destination, file, provider, repo or credential."
NO_PATTERN = "A grant needs a pattern, such as api.example.com."
ONE_WORD = "The pattern must be one word, with no spaces or backticks."
BAD_ALLOWS = "allows must be a list of read, write, edit, delete or exec."
BAD_EXPIRES = "expires must be a lifetime such as 7d: a number with m, h or d, from 1m to 365d."
NOT_A_GRANT = "Not a grant the grant command would accept."
NO_CHANNEL = 'binding must be the channel as Sentrook saw it, such as "discord:#daily-brief".'
CHANNEL_WORD = "The channel must be one word, with no spaces or backticks."
NOT_SHOWN = "The setup screen could not show this item."
BROAD = (
    "A destination may use a wildcard only as *. and one registrable domain, such as *.example.com: ask the owner to "
    "grant anything broader themselves."
)
VALUE_NAME = (
    "The credential name looks like a key's value, not its name: give the variable name, such as "
    "MY_SERVICE_TOKEN, never the key itself."
)
#: Characters that make a pattern match more than one name.
_WILDCARD = re.compile(r"[*?\[\]]")

#: (subcommand) -> the command as the owner types it.
Cmd = Callable[[str], str]


def description(cmd: Cmd) -> str:
    return (
        "Adds items to the owner's Sentrook setup list, for the owner to review and set themselves with "
        f"{cmd('setup')}: grants (destination, file, provider, repo or credential) and channel bindings the owner "
        f"told you they need, each with a short reason. At most {MAX_ITEMS} items. Sets nothing itself; never "
        "settings or attended platforms, never session grants. Works only when the owner asks in a direct chat."
    )


def schema(cmd: Cmd) -> dict[str, Any]:
    return {
        "name": TOOL,
        "description": description(cmd),
        "parameters": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "description": f"1 to {MAX_ITEMS} items: each a grant or a channel binding, with a reason.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "description": "A grant's kind: destination, file, provider, repo or credential.",
                            },
                            "pattern": {
                                "type": "string",
                                "description": (
                                    "What the grant covers, as the grant command takes it: api.example.com, "
                                    "~/notes/*, npm:@example/, github.com/owner/repo, or NAME@host for a key "
                                    "(its name only, never its value)."
                                ),
                            },
                            "allows": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "File grants only: read, write, edit, delete, exec.",
                            },
                            "expires": {
                                "type": "string",
                                "description": "How long the grant lasts, such as 4h or 7d (at most 365d).",
                            },
                            "binding": {
                                "type": "string",
                                "description": (
                                    "Instead of a grant: a chat channel a scheduled job posts to, as Sentrook "
                                    "saw it, such as discord:#daily-brief."
                                ),
                            },
                            "reason": {
                                "type": "string",
                                "description": (
                                    f"Why the owner would want it, in one sentence of at most {MAX_REASON} "
                                    "characters."
                                ),
                            },
                        },
                        "required": ["reason"],
                    },
                }
            },
            "required": ["items"],
            "additionalProperties": False,
        },
    }


# ---- checking the items ------------------------------------------------------------------------------------------


def _word(s: Any) -> bool:
    return isinstance(s, str) and bool(s) and not any(c.isspace() for c in s) and "`" not in s


def check_item(raw: Any) -> dict[str, Any] | str:
    """One item as it is stored, or why it is refused."""
    if not isinstance(raw, dict):
        return NOT_AN_ITEM
    if "setting" in raw:
        setting = raw["setting"]
        return ATTENDED if isinstance(setting, str) and "attended" in setting.lower() else SETTING
    kind = raw.get("kind")
    if "attended" in raw or (isinstance(kind, str) and kind.strip().lower() == "attended"):
        return ATTENDED
    if (
        ("scope" in raw and raw["scope"] != "persistent")
        or "session" in raw
        or "session_ref" in raw
    ):
        return SESSION
    binding = "binding" in raw
    fields = BINDING_FIELDS if binding else GRANT_FIELDS
    unknown = sorted(str(k) for k in raw if k not in fields)
    if unknown:
        takes = (
            "a channel binding takes binding and reason"
            if binding
            else "a grant takes kind, pattern, allows, expires and reason"
        )
        return f'Unknown field "{grants._clean(unknown[0], 40)}": {takes}.'
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return NO_REASON
    if len(reason) > MAX_REASON:
        return LONG_REASON
    stored = _binding(raw["binding"]) if binding else _grant(raw)
    if isinstance(stored, str):
        return stored
    stored["reason"] = reason
    shown = setup.proposal_item(stored)
    if shown is None or setup.valid_item(shown) is None:
        return NOT_SHOWN
    return stored


def _binding(channel: Any) -> dict[str, Any] | str:
    """A channel binding as `bind add` takes it, that could ever relieve a send."""
    if not isinstance(channel, str) or not channel:
        return NO_CHANNEL
    if len(channel) > grants.MAX_PATTERN or not channel.isprintable():
        return f"The channel must be at most {grants.MAX_PATTERN} printable characters."
    if not _word(channel):
        return CHANNEL_WORD
    problem = binding_problem(channel)
    if problem:
        return f"This channel binding would never apply: {problem}."
    return {"binding": True, "pattern": channel}


def _grant(raw: dict[str, Any]) -> dict[str, Any] | str:
    """A grant as `grant <kind> <pattern> --persistent [--allows ...] [--expires ...]` takes it."""
    kind, pattern, allows, expires = (
        raw.get("kind"),
        raw.get("pattern"),
        raw.get("allows"),
        raw.get("expires"),
    )
    if not isinstance(kind, str) or not kind or any(c.isspace() for c in kind):
        return NO_KIND
    if not isinstance(pattern, str) or not pattern:
        return NO_PATTERN
    if not _word(pattern):
        return ONE_WORD
    words = [kind, pattern, "--persistent"]
    if allows is not None:
        if not isinstance(allows, list) or not all(
            isinstance(a, str) and a and not any(c.isspace() or c == "," for c in a) for a in allows
        ):
            return BAD_ALLOWS
        words.append("--allows=" + ",".join(allows))
    if expires is not None:
        if not isinstance(expires, str) or any(c.isspace() for c in expires):
            return BAD_EXPIRES
        words.append("--expires=" + expires)
    # The agent's own, stricter rule first: the grant command's refusal would offer it forms it may not propose.
    if kind.lower() == "destination" and _too_broad(pattern):
        return BROAD
    parsed = grants.parse_grant(" ".join(words), lambda sub: sub)
    if isinstance(parsed, str):
        return parsed or NOT_A_GRANT
    if parsed["kind"] == "credential" and _value_shaped(parsed["pattern"].partition("@")[0]):
        return VALUE_NAME
    out: dict[str, Any] = {"kind": parsed["kind"], "pattern": parsed["pattern"]}
    if parsed.get("allows"):
        out["allows"] = parsed["allows"]
    if expires is not None:
        out["expires"] = expires
    return out


def _too_broad(pattern: str) -> bool:
    """A destination the agent may not propose: a wildcard anywhere but as `*.` and a domain the grant command takes
    (`config.destination_ok`: one registrable domain, or a name that never resolves on the public internet). Only the
    owner may put a wildcard in a channel's name or before an `@`."""
    return bool(_WILDCARD.search(pattern)) and (
        not pattern.startswith("*.")
        or _WILDCARD.search(pattern[2:]) is not None
        or not destination_ok(pattern)
    )


def _value_shaped(name: str) -> bool:
    """A credential name that the plugin's redactor would take for a secret value (a token's own shape)."""
    return Redactor("standard", "").string(name) != name


def check(args: Any) -> tuple[list[dict[str, Any]], list[tuple[int, str]]] | str:
    """(stored items, [(item number, why)] for those refused), or why the whole call is refused. Items sent as JSON
    text read as the list it holds, as Hermes's own coercion to the schema's types would read them."""
    items = args.get("items") if isinstance(args, dict) else None
    if isinstance(items, str):
        try:
            items = json.loads(items)
        except ValueError:
            items = None
    if not isinstance(items, list) or not items:
        return NO_ITEMS
    if len(items) > MAX_ITEMS:
        return TOO_MANY
    ok: list[dict[str, Any]] = []
    refused: list[tuple[int, str]] = []
    for i, raw in enumerate(items, 1):
        got = check_item(raw)
        if isinstance(got, str):
            refused.append((i, got))
        else:
            ok.append(got)
    return ok, refused


def reply(added: int, refused: list[tuple[int, str]], cmd: Cmd) -> str:
    """What the agent hears: how many were added and where the owner reviews them, and the items not added."""
    if added:
        lines = [
            f"Added {added} item{'' if added == 1 else 's'} to Sentrook's setup list. Ask the owner to send "
            f"{cmd('setup')} to review {'it' if added == 1 else 'them'}."
        ]
    else:
        lines = ["Nothing was added to Sentrook's setup list."]
    if refused:
        n = len(refused)
        lines.append(f"{n} item{'' if n == 1 else 's'} not added:")
        lines += [f"- Item {i}: {why}" for i, why in refused]
    return "\n".join(lines)


# ---- storing them ------------------------------------------------------------------------------------------------


def new_id() -> str:
    return f"p-{secrets.token_hex(3)}"


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def save(
    state_dir: Path,
    items: list[dict[str, Any]],
    ref: str,
    now: datetime,
    make_id: Callable[[], str] = new_id,
    unchecked: bool = False,
) -> tuple[str, list[str]] | None:
    """Stores a proposal of `items` from the session `ref`: (its id, the ids of the open proposals it replaced). Expired
    proposals are dropped. `unchecked`: the chat had read content no scan had seen yet when the agent proposed it.
    None when the proposals file cannot be read, so nothing in it is overwritten."""
    store = Store(state_dir)
    try:
        with file_lock(state_dir / "proposals.json"):
            return _save_locked(store, items, ref, now, make_id, unchecked)
    except LockTimeout:
        return None


def _save_locked(
    store: Store,
    items: list[dict[str, Any]],
    ref: str,
    now: datetime,
    make_id: Callable[[], str],
    unchecked: bool,
) -> tuple[str, list[str]] | None:
    raw = store.load_proposals()
    if raw is None:
        return None
    taken = {p.get("id") for p in raw["proposals"] if isinstance(p, dict)}
    pid = make_id()
    while pid in taken:
        pid = make_id()
    # Oldest first; proposals made in the same second stay in the order they were stored.
    live = sorted(setup._live_proposals(raw, now), key=lambda p: read_time(p["created_at"]))
    replaced = []
    while len(live) >= MAX_OPEN:
        replaced.append(live.pop(0)["id"])
    live.append(
        {
            "id": pid,
            "session_ref": ref,
            "created_at": _iso(now),
            "expires_at": _iso(now + setup.PROPOSAL_TTL),
            "items": items,
            **({"unchecked": True} if unchecked else {}),
        }
    )
    raw["proposals"] = live
    store.save_proposals(raw)
    return pid, replaced


def propose(
    state_dir: Path,
    checked: tuple[list[dict[str, Any]], list[tuple[int, str]]] | str,
    ref: str,
    now: datetime,
    cmd: Cmd,
    make_id: Callable[[], str] = new_id,
    unchecked: bool = False,
) -> tuple[str, dict[str, Any]]:
    """The tool's answer to a call whose arguments `check` gave `checked`, from the session `ref`, and what the
    traffic log records of it."""
    if isinstance(checked, str):
        return checked, {"outcome": "refused", "reason": "invalid", "items": 0}
    ok, refused = checked
    log: dict[str, Any] = {"items": len(ok), "rejected": len(refused)}
    if not ok:
        return reply(0, refused, cmd), {"outcome": "none", **log}
    saved = save(state_dir, ok, ref, now, make_id, unchecked)
    if saved is None:
        return NOT_SAVED, {"outcome": "error", "reason": "proposals file unreadable", **log}
    pid, replaced = saved
    return reply(len(ok), refused, cmd), {
        "outcome": "stored",
        "proposal": pid,
        **({"unchecked": True} if unchecked else {}),
        **({"replaced": replaced} if replaced else {}),
        **log,
    }
