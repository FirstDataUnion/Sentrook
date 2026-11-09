"""PlanIR 2.0 assembly from Hermes hook data.

The plugin reports facts; Sentrook classifies trust. The turn's request, platform and sender come from
`pre_llm_call`, the assistant message (narration and the batch's sibling calls) from `post_api_request`,
both joined by `turn_id`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform as _platform
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .config import PluginConfig
from .intent import channel_of, resolve_platform, sender_of, trigger_kind
from .redact import Redactor, cap_args
from .skill_review import REQUEST_TEXT as LOOP_REQUEST_TEXT
from .skill_review import TRIGGER as LOOP_TRIGGER

PLUGIN_VERSION = "2.0.0-beta.6"

TOOL_KIND = {
    "terminal": "exec",
    "execute_code": "exec",
    "read_file": "file_read",
    "search_files": "file_read",
    "write_file": "file_write",
    "patch": "file_edit",
    "web_extract": "web_fetch",
    "web_search": "web_fetch",
    "memory": "memory_write",
    "delegate_task": "subagent_spawn",
}


def _h(s: Any) -> str:
    return hashlib.sha256(str(s).encode()).hexdigest()[:12]


def session_ref(sid: str) -> str:
    """A session's `session_ref`: what a scan of it sends, and what snoozes and session grants are
    bound to."""
    return f"s_{_h(sid)}"


# Hermes's process-control tool (`process_manage`; older versions name it `process`). Writing to, closing or
# killing a running process is code execution; listing, polling, reading its log, waiting and handing it off
# are not. An unknown or missing action keeps `exec`.
PROCESS_TOOLS = ("process_manage", "process")
PROCESS_READ_ACTIONS = frozenset({"list", "poll", "log", "wait", "handoff"})


def tool_kind(name: str, args: Any = None) -> str:
    if name in PROCESS_TOOLS:
        action = args.get("action") if isinstance(args, dict) else None
        return "other" if isinstance(action, str) and action in PROCESS_READ_ACTIONS else "exec"
    if name in TOOL_KIND:
        return TOOL_KIND[name]
    if name.startswith("browser_"):
        return "browser"
    if name.startswith("mcp__") or name.startswith("mcp_"):
        return "mcp"
    return "other"


def hermes_config() -> dict[str, Any]:
    """Effective config via Hermes's own loader (the plugin interpreter has no PyYAML)."""
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly()
        return cfg if isinstance(cfg, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def hermes_version() -> str:
    try:
        import hermes_cli

        return str(getattr(hermes_cli, "__version__", None) or "unknown")
    except Exception:  # noqa: BLE001
        return "unknown"


def remote_identity(url: str) -> str | None:
    """A remote MCP server's identity: `remote:<hostname>`, the lowercase hostname without the port, the
    scheme or the brackets around an IPv6 literal (http and https on one host are one server). Same rule
    on every host."""
    from urllib.parse import urlsplit

    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    host = (host or "").rstrip(".")
    return f"remote:{host}" if host else None


_REMOTE_PORT = re.compile(r"[^:]*:(?:\d+|\*)")


def provider_pattern(pattern: str) -> str:
    """A provider grant's pattern read as identities are: a `remote:` one loses its port and IPv6
    brackets."""
    if pattern[:7].lower() != "remote:":
        return pattern
    host = pattern[7:].strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif _REMOTE_PORT.fullmatch(host):
        host = host.rsplit(":", 1)[0]
    return "remote:" + host.rstrip(".")


def provider_for(name: str, host_cfg: dict[str, Any]) -> dict[str, Any]:
    host = {"kind": "host", "name": None, "identity": None, "transport": None}
    toolset = None
    try:
        from tools.registry import registry

        toolset = registry.get_toolset_for_tool(name)
    except Exception:  # noqa: BLE001
        toolset = None
    toolset = toolset or ""
    if not toolset.startswith("mcp-") and not name.startswith("mcp_"):
        return host
    server = toolset[4:] if toolset.startswith("mcp-") else None
    if not server and name.startswith("mcp__") and name.count("__") >= 2:
        server = name.split("__")[1]
    cfg = (host_cfg.get("mcp_servers") or {}).get(server or "")
    if not server or not isinstance(cfg, dict):
        return {"kind": "mcp", "name": server, "identity": None, "transport": None}
    identity, transport = None, None
    if cfg.get("url"):
        identity, transport = remote_identity(str(cfg["url"])), "http"
    elif cfg.get("command"):
        cmd = str(cfg["command"])
        args = [str(a) for a in cfg.get("args") or []]
        pkg = next((a for a in args if not a.startswith("-")), None)
        transport = "stdio"
        if cmd in ("npx", "pnpm", "bunx") and pkg:
            identity = f"npm:{pkg}"
        elif cmd in ("uvx", "pipx") and pkg:
            identity = f"pypi:{pkg}"
        else:
            identity = f"local:{_h(' '.join([cmd, *args]))}"
    return {"kind": "mcp", "name": server, "identity": identity, "transport": transport}


def _pieces_in(pattern: str, text: str) -> bool:
    """The pattern's pieces between `*`s appear in `text`, in order (a leading `*.` also matches the apex,
    a trailing `/` the folder or scope itself)."""
    pattern = pattern.rstrip("/")
    pieces = [p for p in (pattern[2:] if pattern.startswith("*.") else pattern).split("*") if p]
    if sum(map(len, pieces)) < 3:
        return False
    at = 0
    for p in pieces:
        at = text.find(p, at)
        if at < 0:
            return False
        at += len(p)
    return True


#: The arguments the scanner reads a command's working directory from, in its order.
_CWD_KEYS = ("cwd", "dir", "working_directory", "workdir")
#: A path that starts with `./`, where the scanner finds one (also after a JSON-escaped newline or tab).
_DOT_PATH = re.compile(r"(?:(?<![\w.:-])|(?<=\\[ntr]))\./")


def call_cwd(args: Any) -> str | None:
    """The working directory a command names for itself, if any. The scanner reads it for exec calls only."""
    if isinstance(args, dict):
        for k in _CWD_KEYS:
            if isinstance(args.get(k), str) and args[k]:
                return args[k]
    return None


def relevant_grants(
    grants: list[dict[str, Any]],
    args_text: str,
    *,
    identity: str | None = None,
    home: str | None = None,
    workspace: str | None = None,
    cwd: str | None = None,
) -> list[dict[str, Any]]:
    """Only grants that could cover this call. The scanner decides what a grant covers; this only keeps
    the owner's other grants out of the request, so it errs towards sending. A provider grant is also
    matched against the call's provider identity (a `remote:` pattern without its port, as the identity
    is). Paths are read the way the scanner resolves them: under
    home in any form (`~/…`, `$HOME/…` or full), and `./…` against the command's `cwd`, else the workspace."""
    text = args_text.lower()
    texts = [text]
    if base := cwd or workspace:
        texts.append(_DOT_PATH.sub(lambda _: base.rstrip("/").lower() + "/", text))
    pats = [
        (provider_pattern(g["pattern"]) if g["kind"] == "provider" else g["pattern"]).lower()
        for g in grants
    ]
    if home:
        root = home.rstrip("/").lower()
        texts = [t.replace("~/", root + "/").replace("$home/", root + "/") for t in texts]
        pats = [root + p[1:] if p.startswith("~/") else p for p in pats]
    out = []
    for i, (g, pat) in enumerate(zip(grants, pats, strict=True)):
        hay = list(texts)
        if g["kind"] == "provider" and identity:
            hay.append(identity.lower())
        if any(_pieces_in(pat, h) for h in hay):
            out.append({"grant_ref": f"g_{i + 1}", **g})
    return out


def _text(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(p if isinstance(p, str) else str((p or {}).get("text", "")) for p in v)
    return "" if v is None else json.dumps(v, default=str)


def build_planir(
    *,
    kw: dict[str, Any],
    cfg: PluginConfig,
    redactor: Redactor,
    sid: str,
    sess: dict[str, Any],
    turn: dict[str, Any],
    facts: dict[str, str],
    env: dict[str, str],
    host_cfg: dict[str, Any],
    grants: list[dict[str, Any]] | None = None,
    self_edit: dict[str, Any] | None = None,
    request_turn: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Returns the PlanIR plus bookkeeping; mutates `sess` (step, turns, seen call ids).

    `grants`: every grant in force (`grants.effective`); the persistent config grants alone when not
    given (a config grant has no session, so a session one is never sent).
    `self_edit`: the call is a save by Hermes's own self-improvement loop, declared as a self-edit: sent
    with trigger `system` (instead of the chat the loop's fork inherited) and this top-level block, the
    conversation the review read (`conversation.block`).
    `request_turn`: the call is made by Hermes's background review, after the owner's turn: the request
    text comes from this turn (the session's last owner turn, `{}` when none is stored; an empty request
    sends `skill_review.REQUEST_TEXT`) and the call's own turn is not counted as a new one. Narration and
    batch siblings still come from `turn`, the fork's own."""
    turn_id = kw.get("turn_id") or sess.get("last_turn_id")
    tool = str(kw.get("tool_name") or "unknown")
    host_id = kw.get("tool_call_id")
    step = sess["next_step"]
    sess["next_step"] += 1
    call_id = str(host_id) if host_id else f"{turn_id}:{step}"
    # Host ids are not reliable across a session; re-mint a repeat.
    if host_id and host_id in sess["seen_call_ids"]:
        call_id = f"{turn_id}:{host_id}"
    if host_id:
        sess["seen_call_ids"].append(host_id)
    if turn_id and turn_id not in sess["turns"] and request_turn is None:
        sess["turns"].append(turn_id)
    request_text = _text((turn if request_turn is None else request_turn).get("user_message"))
    if request_turn is not None and not request_text.strip():
        request_text = LOOP_REQUEST_TEXT
    # A background call's turn is the number of the owner turn its request came from.
    last = sess.get("last_turn_id")
    request_turn_no = (
        sess["turns"].index(last) + 1
        if request_turn is not None and last in sess["turns"]
        else None
    )

    platform = resolve_platform(turn.get("platform"), facts, env)
    parent = turn.get("parent_session_id") or None
    is_sub = platform == "subagent" or bool(parent)
    raw_args = kw.get("args") if isinstance(kw.get("args"), dict) else {"value": kw.get("args")}
    tk = tool_kind(tool, raw_args)
    prv = provider_for(tool, host_cfg)
    args = redactor.value(raw_args)

    siblings = []
    for c in turn.get("tool_calls") or []:
        if c.get("id") and c.get("id") != host_id:
            name = str(c.get("name") or "unknown")
            sargs = (
                c.get("arguments")
                if isinstance(c.get("arguments"), dict)
                else {"value": c.get("arguments")}
            )
            siblings.append(
                {
                    "call_id": str(c["id"]),
                    "tool": name,
                    "tool_kind": tool_kind(name, sargs),
                    "provider": provider_for(name, host_cfg),
                    "arguments": cap_args(redactor.value(sargs), cfg.history_args_cap_bytes),
                }
            )

    window = sess["history"][-cfg.history_limit :]
    window_ids = {h["call_id"] for h in window}
    # Every tool result must refer to a call in the history window (a scanner invariant).
    sent_inputs = [i for i in sess["buffer"] if i["call_id"] in window_ids]
    history = [{k: v for k, v in h.items() if not k.startswith("_")} for h in window]

    approvals = host_cfg.get("approvals") or {}
    security = host_cfg.get("security") or {}
    narration = (turn.get("assistant_text") or "").strip()
    routing = facts.get("key") or None

    planir = {
        "planir_version": "2.0",
        "request_id": str(uuid.uuid4()),
        "run_ref": f"r_{_h(turn_id or sid)}",
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_kind": "pending_call",
        "origin": "live",
        "host": {
            "platform": "hermes",
            "platform_version": hermes_version(),
            "plugin_version": PLUGIN_VERSION,
            "workspace_root": os.getcwd(),
            "home": str(Path.home()),
            "os": {"Darwin": "macos", "Windows": "windows"}.get(_platform.system(), "linux"),
            "policy": {
                "exec_mode": "unknown",
                "approval_gating": approvals.get("mode") not in ("off", None),
                "result_masking": bool(security.get("redact_secrets", True)),
            },
        },
        "session": {
            "session_ref": session_ref(sid),
            "routing_key": f"h_{_h(routing)}" if routing else None,
            "agent_ref": "a_main",
            "agent_role": "subagent" if is_sub else "main",
            "parent_session_ref": f"s_{_h(parent)}" if parent else None,
            "turn": request_turn_no if request_turn_no is not None else max(1, len(sess["turns"])),
            "step": step,
            "state": sess["token"],
        },
        "trigger": copy.deepcopy(LOOP_TRIGGER)
        if self_edit is not None
        else {
            "kind": trigger_kind(platform),
            "channel": channel_of(platform),
            "sender": sender_of(platform, facts, turn.get("sender_id"), env),
        },
        "request": {
            "text": redactor.string(request_text),
            "carried_from_turn": None,
        },
        "new_inputs": sent_inputs,
        "history": history,
        "pending_call": {
            "call_id": call_id,
            **({"host_call_id": str(host_id)} if host_id else {}),
            "tool": tool,
            "tool_kind": tk,
            "provider": prv,
            "host_approval": "unknown",
            **({"agent_narration": redactor.string(narration)[:4000]} if narration else {}),
            "arguments": cap_args(args, cfg.input_cap_bytes),
            "batch": {"siblings": siblings},
        },
        "grants": relevant_grants(
            [g for g in cfg.grants if g["scope"] == "persistent"] if grants is None else grants,
            json.dumps(raw_args, default=str, ensure_ascii=False),
            identity=prv["identity"],
            home=str(Path.home()),
            workspace=os.getcwd(),
            cwd=call_cwd(raw_args) if tk == "exec" else None,
        ),
        **({"self_edit": self_edit} if self_edit is not None else {}),
        "options": {"packs": cfg.packs, "redaction": redactor.level},
    }
    return {
        "planir": planir,
        "call_id": call_id,
        "host_call_id": str(host_id) if host_id else None,
        "step": step,
        "tool": tool,
        "tool_kind": tk,
        "provider": prv,
        "history_args": cap_args(args, cfg.history_args_cap_bytes),
        "subagent": is_sub,
        "platform": platform,
    }
