"""PlanIR 2.0 assembly from Hermes hook data.

The plugin reports facts; Sentrook classifies trust. The turn's request, platform and sender come from
`pre_llm_call`, the assistant message (narration and the batch's sibling calls) from `post_api_request`,
both joined by `turn_id`.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as _platform
import time
import uuid
from pathlib import Path
from typing import Any

from .config import PluginConfig
from .intent import channel_of, resolve_platform, sender_of, trigger_kind
from .redact import Redactor, cap_args

PLUGIN_VERSION = "2.0.0-beta.5"

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


# Hermes's process-control tool (`process_manage`; older versions name it `process`). Writing to, closing or
# killing a running process is code execution; listing, polling, reading its log, waiting and handing it off
# are not. An unknown or missing action keeps `exec`.
PROCESS_TOOLS = ("process_manage", "process")
PROCESS_READ_ACTIONS = frozenset({"list", "poll", "log", "wait", "handoff"})


def tool_kind(name: str, args: Any = None) -> str:
    if name in PROCESS_TOOLS:
        action = args.get("action") if isinstance(args, dict) else None
        return "other" if action in PROCESS_READ_ACTIONS else "exec"
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
        from urllib.parse import urlsplit

        identity, transport = f"remote:{urlsplit(str(cfg['url'])).hostname}", "http"
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


def relevant_grants(grants: list[dict[str, Any]], args_text: str) -> list[dict[str, Any]]:
    """Only grants plausibly relevant to this call: the pattern (minus globs) appears in its arguments."""
    text = args_text.lower()
    out = []
    for i, g in enumerate(grants):
        needle = g["pattern"].lower()
        needle = needle[2:] if needle.startswith("*.") else needle.lstrip("*")
        needle = needle.replace("*", "")
        if len(needle) >= 3 and needle in text:
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
) -> dict[str, Any]:
    """Returns the PlanIR plus bookkeeping; mutates `sess` (step, turns, seen call ids).

    `grants`: every grant in force (`grants.effective`); the config grants alone when not given."""
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
    if turn_id and turn_id not in sess["turns"]:
        sess["turns"].append(turn_id)

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
            "session_ref": f"s_{_h(sid)}",
            "routing_key": f"h_{_h(routing)}" if routing else None,
            "agent_ref": "a_main",
            "agent_role": "subagent" if is_sub else "main",
            "parent_session_ref": f"s_{_h(parent)}" if parent else None,
            "turn": max(1, len(sess["turns"])),
            "step": step,
            "state": sess["token"],
        },
        "trigger": {
            "kind": trigger_kind(platform),
            "channel": channel_of(platform),
            "sender": sender_of(platform, facts, turn.get("sender_id"), env),
        },
        "request": {
            "text": redactor.string(_text(turn.get("user_message"))),
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
            cfg.grants if grants is None else grants, json.dumps(raw_args, default=str)
        ),
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
