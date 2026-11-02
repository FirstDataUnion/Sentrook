"""Sentrook for Hermes.

Scans every tool call before it runs: builds a PlanIR 2.0 request from the hook and the turn context
gathered on other hooks, sends it to Sentrook's /scan over OIDC, and allows, asks for Hermes's native
approval, or blocks. Every request and response is redacted on the host and appended to a local
traffic log.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from . import cli, commands, grants, owner, snooze
from .auth import env_with_hermes_dotenv, resolve_oidc_credentials
from .config import PluginConfig, resolve_config
from .decision import block_reason, decide, review_message, tiers_of
from .intent import is_unattended, session_facts
from .planir import PLUGIN_VERSION, build_planir, hermes_config, session_ref, tool_kind
from .redact import Redactor, cap_head_tail
from .scan_client import ScanOk, post_scan
from .scan_error_policy import ScanFailure, scan_error_to_directive
from .store import Store
from .traffic import TrafficLog

logger = logging.getLogger("sentrook")

#: History decisions after which the tool did not run.
NOT_RUN = frozenset({"blocked", "denied_by_user", "review_timed_out", "blocked_on_error"})

#: Every key the plugin reads from `plugins.entries.sentrook.settings` in config.yaml.
SETTINGS_KEYS = (
    "scan_url",
    "rookery_url",
    "oidc_issuer",
    "client_id",
    "client_secret",
    "oidc_audience",
    "oidc_scope",
    "mode",
    "review_at",
    "block_at",
    "on_scan_error",
    "attended_platforms",
    "timeout_ms",
    "channel_bindings",
    "grants",
    "state_dir",
    "traffic_log",
    "history_limit",
    "input_cap_bytes",
    "history_args_cap_bytes",
    "packs",
)

_ctx: Any = None
_store: Store | None = None
_traffic: TrafficLog | None = None


def _settings() -> dict[str, Any]:
    return settings_from_ctx(_ctx)


def _load() -> tuple[PluginConfig, dict[str, str]]:
    env = env_with_hermes_dotenv()
    return resolve_config(_settings(), env), env


def _state(cfg: PluginConfig) -> tuple[Store, TrafficLog]:
    global _store, _traffic
    if _store is None or _store.dir != cfg.state_dir:
        _store = Store(cfg.state_dir)
    if _traffic is None or _traffic.path != cfg.traffic_log_path:
        _traffic = TrafficLog(
            cfg.traffic_log_path, cfg.traffic_log_max_bytes, cfg.traffic_log_enabled
        )
    return _store, _traffic


def _sid(kw: dict[str, Any]) -> str:
    return str(kw.get("session_id") or kw.get("task_id") or "default")


def _rule_key(fingerprint: str | None, request_id: str) -> str:
    """Hermes persists Session/Always approvals per rule key. Keyed on the action fingerprint, an approval
    covers the same action (same source and destination) again, not other calls of the same tool."""
    return "sentrook:" + hashlib.sha256((fingerprint or request_id).encode()).hexdigest()[:16]


# ---- owner-only commands ----------------------------------------------------------------------------


def owner_command(verb: str, fn: Callable[[str, dict[str, Any]], str]) -> Callable[..., str]:
    """A slash-command handler that runs `fn` only for the owner and audits every attempt.

    Commands that change how Sentrook behaves (grants, snooze) and those that show past traffic go
    through this. Any failure while checking the sender refuses the command. `fn` gets the raw
    arguments and who ran it: `{"basis", "platform", "sender_ref"}`.
    """

    def handler(raw_args: str = "", *_a: Any, **_kw: Any) -> str:
        try:
            cfg, env = _load()
            store, traffic = _state(cfg)
        except Exception as exc:  # noqa: BLE001 - nowhere to audit; refuse
            logger.warning("owner check for %s failed: %s", verb, exc)
            return owner.refusal(verb)
        try:
            check = owner.gate(verb, traffic, store.salt(), facts=session_facts(), env=env)
        except Exception as exc:  # noqa: BLE001
            logger.warning("owner check for %s failed: %s", verb, exc)
            owner.audit(
                traffic,
                verb,
                {"owner": False, "basis": ["none"], "platform": ""},
                ref=None,
                reason="error",
            )
            return owner.refusal(verb)
        if not check["owner"]:
            return owner.refusal(verb)
        return fn(raw_args, {k: check[k] for k in ("basis", "platform", "sender_ref")})

    return handler


# ---- context joins ---------------------------------------------------------------------------------


def on_pre_llm_call(**kw: Any) -> None:
    try:
        cfg, _ = _load()
        store, _t = _state(cfg)
        turn_id = kw.get("turn_id")
        store.merge_turn(
            turn_id,
            {
                "platform": kw.get("platform"),
                "sender_id": kw.get("sender_id"),
                "parent_session_id": kw.get("parent_session_id"),
                "user_message": kw.get("user_message"),
            },
        )
        sid = _sid(kw)
        if turn_id:
            with store.session_lock(sid):
                s = store.load_session(sid)
                s["last_turn_id"] = turn_id
                store.save_session(sid, s, cfg.history_limit * 2)
    except Exception as exc:  # noqa: BLE001
        logger.warning("pre_llm_call failed: %s", exc)


def on_post_api_request(**kw: Any) -> None:
    """The assistant message: narration and every tool call of the batch, before the first tool hook."""
    try:
        resp = kw.get("response") if isinstance(kw.get("response"), dict) else {}
        am = (
            resp.get("assistant_message")
            if isinstance(resp.get("assistant_message"), dict)
            else None
        )
        if am is None:
            return
        calls = []
        for c in am.get("tool_calls") or []:
            fn = c.get("function") or {}
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {"value": args}
            calls.append(
                {"id": c.get("id"), "name": fn.get("name") or c.get("name"), "arguments": args}
            )
        content = am.get("content")
        text = content if isinstance(content, str) else ""
        cfg, _ = _load()
        _state(cfg)[0].merge_turn(kw.get("turn_id"), {"assistant_text": text, "tool_calls": calls})
    except Exception as exc:  # noqa: BLE001
        logger.warning("post_api_request failed: %s", exc)


# ---- the scan ----------------------------------------------------------------------------------------


def on_pre_tool_call(tool_name: str = "", args: Any = None, **kw: Any) -> dict[str, Any] | None:
    try:
        cfg, env = _load()
        store, traffic = _state(cfg)
        sid = _sid(kw)
        with store.session_lock(sid):
            return _scan_one(
                cfg, env, store, traffic, sid, {**kw, "tool_name": tool_name, "args": args}
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pre_tool_call failed: %s", exc)
        detail = str(exc).replace("\n", " ").strip()[:160]
        return {
            "action": "block",
            "message": f"Sentrook plugin error; this tool was not scanned or run. Detail: {detail}",
        }


def _scan_one(
    cfg: PluginConfig,
    env: dict[str, str],
    store: Store,
    traffic: TrafficLog,
    sid: str,
    kw: dict[str, Any],
) -> dict[str, Any] | None:
    sess = store.load_session(sid)
    turn = store.load_turn(kw.get("turn_id") or sess.get("last_turn_id"))
    facts = session_facts()
    host_cfg = hermes_config()
    redactor = Redactor("standard", store.salt())
    built = build_planir(
        kw=kw,
        cfg=cfg,
        redactor=redactor,
        sid=sid,
        sess=sess,
        turn=turn,
        facts=facts,
        env=env,
        host_cfg=host_cfg,
        grants=grants.effective(cfg, store.load_grants(), datetime.now(UTC), session_ref(sid)),
    )
    planir = built["planir"]
    unattended = is_unattended(
        built["platform"],
        env,
        subagent=built["subagent"],
        attended_platforms=cfg.attended_platforms,
    )

    ep = cfg.endpoints
    result: ScanOk | ScanFailure
    if not ep.scan.ok:
        result = ScanFailure(ok=False, kind="config", detail=f"scan URL: {ep.scan.reason}")
    elif not ep.issuer.ok:
        result = ScanFailure(ok=False, kind="config", detail=f"OIDC issuer: {ep.issuer.reason}")
    else:
        result = post_scan(
            scan_url=ep.scan.url,
            oidc=resolve_oidc_credentials(_settings(), env, ep.issuer.url),
            body=json.dumps(planir, ensure_ascii=False, default=str).encode(),
            timeout_ms=cfg.timeout_ms,
        )

    entry: dict[str, Any] = {
        "step": built["step"],
        "turn": planir["session"]["turn"],
        "call_id": built["call_id"],
        "tool": built["tool"],
        "tool_kind": built["tool_kind"],
        "provider": built["provider"],
        "arguments": built["history_args"],
        "result": None,
        "action_fingerprint": None,
        "risk": None,
        "tiers": None,
        "request_id": planir["request_id"],
        "decision": "allowed",
        "_host_call_id": built["host_call_id"],
    }

    directive: dict[str, Any] | None = None
    verdict: str | None = None
    snoozed = False
    if isinstance(result, ScanOk):
        resp = result.response
        verdict = decide(resp, cfg.review_at, cfg.block_at)
        sess["token"] = resp.get("state")
        sess["buffer"] = []
        entry["action_fingerprint"] = resp.get("action_fingerprint")
        entry["risk"] = resp.get("risk")
        entry["tiers"] = tiers_of(resp)
        if cfg.mode == "observe" or verdict == "allow":
            entry["decision"] = "allowed"
        elif verdict == "block" or unattended:
            # A review nobody can answer (or Hermes would auto-approve) is a block.
            entry["decision"] = "blocked"
            directive = {"action": "block", "message": block_reason(resp, built["tool"])}
        elif snooze.applies(resp) and snooze.active(
            store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
        ):
            # The owner snoozed reviews for this session: scanned and logged, not asked.
            entry["decision"] = "allowed"
            snoozed = True
        else:
            entry["decision"] = "review_timed_out"  # provisional until the user answers
            key = _rule_key(resp.get("action_fingerprint"), planir["request_id"])
            directive = {
                "action": "approve",
                "message": review_message(resp, built["tool"]),
                "rule_key": key,
            }
            store.put_review(
                key, {"sid": sid, "request_id": planir["request_id"], "on_error": False}
            )
    else:
        logger.warning("scan failed (%s): %s", result.kind, result.detail)
        if cfg.mode != "observe":
            key = "sentrook:error:" + hashlib.sha256(planir["request_id"].encode()).hexdigest()[:16]
            d = scan_error_to_directive(
                result, on_scan_error=cfg.on_scan_error, unattended=unattended, rule_key=key
            )
            if d is not None:
                directive = {
                    "action": d.action,
                    "message": d.message,
                    **({"rule_key": d.rule_key} if d.rule_key else {}),
                }
                if d.action == "approve":
                    store.put_review(
                        key, {"sid": sid, "request_id": planir["request_id"], "on_error": True}
                    )
        entry["decision"] = "blocked_on_error" if directive else "allowed_on_error"

    sess["history"].append(entry)
    store.save_session(sid, sess, cfg.history_limit * 2)

    traffic.write(
        {
            "kind": "scan",
            "request_id": planir["request_id"],
            "session_ref": planir["session"]["session_ref"],
            "step": built["step"],
            "tool": built["tool"],
            "mode": cfg.mode,
            "verdict": verdict,
            "decision": entry["decision"],
            **({"snoozed": True} if snoozed else {}),
            "latency_ms": result.latency_ms if isinstance(result, ScanOk) else None,
            "planir": planir,
            "response": result.response if isinstance(result, ScanOk) else None,
            "failure": None
            if isinstance(result, ScanOk)
            else {"kind": result.kind, "status": result.status, "detail": result.detail},
        }
    )
    if isinstance(result, ScanOk):
        logger.info(
            "scan step=%s tool=%s risk=%s enforced=%s status=%s verdict=%s decision=%s%s ms=%s",
            built["step"],
            built["tool"],
            result.response.get("risk"),
            result.response.get("enforced"),
            result.response.get("status"),
            verdict,
            entry["decision"],
            " (snoozed)" if snoozed else "",
            result.latency_ms,
        )
    return directive


# ---- outcomes -----------------------------------------------------------------------------------------


_APPROVED = {
    "once",
    "session",
    "always",
    "allow-once",
    "allow_once",
    "allow-always",
    "allow_always",
}


def on_post_approval_response(**kw: Any) -> None:
    """Write the user's answer into history, joined by the rule key we issued."""
    try:
        pattern = str(kw.get("pattern_key") or kw.get("rule_key") or "")
        key = pattern.removeprefix("plugin_rule:")
        if not key.startswith("sentrook:"):
            return
        cfg, _ = _load()
        store, traffic = _state(cfg)
        review = store.pop_review(key)
        if not review:
            return
        choice = str(kw.get("choice") or kw.get("decision") or "").strip().lower()
        approved = choice in _APPROVED
        if review.get("on_error"):
            final = "allowed_on_error" if approved else "blocked_on_error"
        else:
            final = (
                "approved_by_user"
                if approved
                else "denied_by_user"
                if choice == "deny"
                else "review_timed_out"
                if choice == "timeout"
                else "blocked"
            )
        sid = review["sid"]
        with store.session_lock(sid):
            s = store.load_session(sid)
            for h in s["history"]:
                if h.get("request_id") == review["request_id"]:
                    h["decision"] = final
            store.save_session(sid, s, cfg.history_limit * 2)
        traffic.write(
            {
                "kind": "resolution",
                "request_id": review["request_id"],
                "resolution": choice,
                "decision": final,
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("post_approval_response failed: %s", exc)


def on_post_tool_call(tool_name: str = "", args: Any = None, result: Any = "", **kw: Any) -> None:
    """Buffer the result (exactly what the model saw) for the next scan; blocked calls add nothing."""
    try:
        host_id = kw.get("tool_call_id")
        if not host_id:
            return
        cfg, _ = _load()
        store, _t = _state(cfg)
        sid = _sid(kw)
        with store.session_lock(sid):
            s = store.load_session(sid)
            entry = next(
                (
                    h
                    for h in reversed(s["history"])
                    if host_id in (h.get("_host_call_id"), h.get("call_id"))
                ),
                None,
            )
            if entry is None:
                return
            status = str(kw.get("status") or "ok")
            text = (
                result
                if isinstance(result, str)
                else json.dumps(result, ensure_ascii=False, default=str)
            )
            size = len(text.encode("utf-8"))
            ran = status not in ("blocked", "cancelled") and not (
                entry["decision"] in NOT_RUN and status != "ok"
            )
            entry["result"] = {
                "status": "ok" if status == "ok" and ran else "error",
                "size_bytes": size if ran else 0,
            }
            if ran:
                capped, truncated, _ = cap_head_tail(
                    Redactor("standard", store.salt()).string(text), cfg.input_cap_bytes
                )
                s["input_seq"] += 1
                s["buffer"].append(
                    {
                        "input_seq": s["input_seq"],
                        "kind": "tool_result",
                        "call_id": entry["call_id"],
                        "tool": entry["tool"],
                        "tool_kind": entry.get("tool_kind") or tool_kind(tool_name, args),
                        "provider": entry["provider"],
                        "status": "ok" if status == "ok" else "error",
                        "content_type": "text",
                        "content": capped,
                        "size_bytes": size,
                        "truncated": truncated,
                    }
                )
            store.save_session(sid, s, cfg.history_limit * 2)
    except Exception as exc:  # noqa: BLE001
        logger.warning("post_tool_call failed: %s", exc)


def register(ctx: Any) -> None:
    global _ctx
    _ctx = ctx
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("post_api_request", on_post_api_request)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("post_approval_response", on_post_approval_response)
    try:
        cli.register_cli(ctx, _settings, owner_command)
    except Exception as exc:  # noqa: BLE001 - older hosts without plugin CLI commands
        logger.info("sentrook CLI not registered: %s", exc)
    try:
        commands.register_slash(ctx, _settings, owner_command)
    except Exception as exc:  # noqa: BLE001 - older hosts without plugin slash commands
        logger.info("/sentrook not registered: %s", exc)
    cfg, _ = _load()
    ep = cfg.endpoints

    def show(e: Any) -> str:
        return e.url if e.ok else f"INVALID ({e.reason})"

    logger.info(
        "sentrook %s registered: scan=%s issuer=%s%s mode=%s review>=%s block>=%s on_scan_error=%s traffic=%s",
        PLUGIN_VERSION,
        show(ep.scan),
        show(ep.issuer),
        " (dev endpoints)" if ep.dev else "",
        cfg.mode,
        cfg.review_at,
        cfg.block_at,
        cfg.on_scan_error,
        cfg.traffic_log_path if cfg.traffic_log_enabled else "off",
    )
    if not ep.scan.ok or not ep.issuer.ok:
        logger.error(
            "sentrook endpoint configuration is invalid; every tool call will fail closed until fixed"
        )


def settings_from_ctx(ctx: Any) -> dict[str, Any]:
    """The plugin's settings, read on every call so `hermes config set` applies without a restart.

    Hermes exposes them one key at a time (`ctx.get_config(key)`, cached by Hermes); a host without
    it gives no settings, and everything resolves from env and defaults.
    """
    get = getattr(ctx, "get_config", None)
    if not callable(get):
        return {}
    out: dict[str, Any] = {}
    for key in SETTINGS_KEYS:
        try:
            value = get(key, None)
        except Exception:  # noqa: BLE001 - a rejected or unreadable key is treated as unset
            value = None
        if value is not None:
            out[key] = value
    return out
