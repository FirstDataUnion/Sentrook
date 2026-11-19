"""Sentrook for Hermes.

Scans every tool call before it runs: builds a PlanIR 2.0 request from the hook and the turn context
gathered on other hooks, sends it to Sentrook's /scan over OIDC, and allows, asks for Hermes's native
approval, or blocks. Every request and response is redacted on the host and appended to a local
traffic log.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from . import (
    card,
    cli,
    commands,
    conversation,
    grants,
    history,
    hold,
    host_turns,
    owner,
    scan_failure_notice,
    skill_review,
    snooze,
)
from .auth import resolve_oidc_credentials
from .config import PluginConfig, resolve_config
from .decision import block_reason, decide, tiers_of, unattended_view
from .intent import (
    conversation_sender_of,
    hermes_config,
    is_unattended,
    resolve_platform,
    session_facts,
)
from .planir import PLUGIN_VERSION, build_planir, request_turn_id, session_ref, tool_kind
from .redact import Redactor, cap_head_tail
from .scan_client import ScanOk, post_scan
from .scan_error_policy import ScanFailure, is_auth_failure, scan_error_to_directive
from .store import LockTimeout, Store
from .traffic import TrafficLog

logger = logging.getLogger("sentrook")

#: History decisions after which the tool did not run.
NOT_RUN = frozenset({"blocked", "denied_by_user", "review_timed_out", "blocked_on_error", "held"})

#: Every key the plugin reads from `plugins.entries.sentrook.settings` in config.yaml.
SETTINGS_KEYS = (
    "scan_url",
    "rookery_url",
    "oidc_issuer",
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
    "skill_review",
    "owner_channel",
)

_ctx: Any = None
_store: Store | None = None
_traffic: TrafficLog | None = None


def _settings() -> dict[str, Any]:
    return settings_from_ctx(_ctx)


def _load() -> tuple[PluginConfig, dict[str, str]]:
    env = dict(os.environ)
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


def _turn_no(sess: dict[str, Any], turn_id: Any) -> int:
    """The session turn number of `turn_id` (the PlanIR's `session.turn`); the latest when unknown."""
    turns = sess.get("turns") or []
    return turns.index(turn_id) + 1 if turn_id in turns else max(1, len(turns))


def _capturing(cfg: PluginConfig, store: Store) -> bool:
    """The conversation log is kept only while background saves are declared as self-edits; once the
    setting reads as review, the logs are deleted (by the first hook that sees it) and nothing is kept."""
    if cfg.skill_review == "allow":
        return True
    try:
        if store.delete_conversations():
            logger.info("sentrook skill_review is review: conversation logs deleted")
    except Exception as exc:  # noqa: BLE001
        logger.warning("deleting conversation logs failed: %s", exc)
    return False


def _record(store: Store, sid: str, entry: dict[str, Any] | None) -> None:
    """Adds `entry` to the session's conversation log; a failure is logged, never raised."""
    if entry is None:
        return
    try:
        store.update_conversation(sid, conversation.append(entry))
    except Exception as exc:  # noqa: BLE001
        logger.warning("conversation log failed: %s", exc)


def _self_edit(store: Store, sid: str, tool: str, args: Any, redactor: Redactor) -> dict[str, Any]:
    """A loop save's `self_edit` block; an empty conversation when the log cannot be read."""
    kind, where = skill_review.BACKGROUND_REVIEW, skill_review.store_of(tool)
    try:
        return conversation.block(kind, where, store.load_conversation(sid), redactor.value(args))
    except Exception as exc:  # noqa: BLE001
        logger.warning("self_edit conversation failed: %s", exc)
        return {"kind": kind, "store": where, "conversation": []}


def _rule_key(
    fingerprint: str | None,
    request_id: str,
    snoozes: str | None = None,
    *,
    tool: str = "",
    args: Any = None,
    secret: str = "",
) -> str:
    """Hermes persists Session/Always approvals per rule key, and approves a later review with the same key without
    asking. The key is the tool and the scan's approval fingerprint (`approval_fingerprint`: the action's sources,
    destinations and code, the same in every session; `action_fingerprint` when a scanner sends none), so an
    approval covers the same action through the same tool again, in this session (Session) or any later one
    (Always), never another tool's call. A fingerprint that names nothing (`afp1:<kind>` alone, or with only the
    tool's provider) would cover every such call of that kind, or of that tool, so its key also holds the call's
    arguments: the approval covers that exact call. No fingerprint: a key of the request alone.

    The key is an HMAC under `secret` (derived from this install's salt), so two installs never share keys and the
    stored key reveals nothing about the action.

    A block a snooze turned into a review is keyed the same way plus the snoozes covering it (`snoozes`, from
    `snooze.covering`) under its own prefix: Session or Always covers the same action while those snoozes last, as
    the card says, and never a review or a later snooze."""
    if fingerprint:
        material = f"{tool}|{fingerprint}"
        # parts after `afp1:<kind>`; a tool provider (`prov:`) alone is the server, not what the call acts on
        targets = [part for part in fingerprint.split("|")[1:] if not part.startswith("prov:")]
        if not targets:
            arguments = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
            material += "|args:" + hashlib.sha256(arguments.encode()).hexdigest()
    else:
        material = request_id
    prefix = "sentrook:"
    if snoozes is not None:
        material = f"{material}|{snoozes}"
        prefix = "sentrook:relaxed:"
    digest = hmac.new(
        ("sentrook rule key v1|" + secret).encode(), material.encode(), hashlib.sha256
    ).hexdigest()
    return prefix + digest[:16]


def _error_rule_key(session_ref: str, outage: str, cause: str) -> str:
    """A scan error's rule key: the session, the outage (`error_epoch`: the first failed scan since the session's
    last good one) and the cause (`card.error_cause`). Session or Always answers the scan errors of that kind in that
    chat until Sentrook scans again, as the card says; a later outage, another kind of failure (credentials that
    expire during an outage) or another chat asks again, and an Always Hermes stores never matches them."""
    material = f"{session_ref}|{outage}|{cause}"
    return "sentrook:error:" + hashlib.sha256(material.encode()).hexdigest()[:16]


# ---- owner-only commands ----------------------------------------------------------------------------


def session_surface() -> str:
    """The calling session's client or platform as Hermes reports it (`ctx.session_surface()`):
    `cli` for the interactive terminal, "" outside a session or when it cannot be read."""
    read = getattr(_ctx, "session_surface", None)
    try:
        value = read() if callable(read) else ""
    except Exception:  # noqa: BLE001 - unreadable reads as no session
        value = ""
    return value if isinstance(value, str) else ""


def owner_command(
    verb: str,
    fn: Callable[[str, dict[str, Any]], str],
    *,
    local_cli: bool = False,
    platform: str = "",
) -> Callable[..., str]:
    """A command handler that runs `fn` only for the owner and audits every attempt. `local_cli` is
    for the `hermes sentrook` command line, which only someone at the machine's shell can run.
    `platform` is the one Hermes passes a slash-command handler, used when Hermes reports no session
    surface (the interactive CLI runs a slash command in its own process when it has no gateway).

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
            check = owner.gate(
                verb,
                traffic,
                store.salt(),
                facts=session_facts(),
                env=env,
                surface=session_surface() or platform,
                local_cli=local_cli,
            )
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
        cfg, env = _load()
        store, _t = _state(cfg)
        turn_id = kw.get("turn_id")
        # The curator's prompt (a fresh agent under the background-review origin) is neither a message, a
        # request nor a turn of the owner's session: its calls carry the owner's last request (`_scan_one`).
        background = skill_review.in_background_review()
        # A turn Hermes starts itself with its own text (`host_turns`) is a turn, never an owner message; an
        # event notice is not a request either, and its text goes as an untrusted input.
        host = None if background else host_turns.classify(kw.get("user_message"))
        own, content = host_turns.parts(host, kw.get("user_message")) if host else (None, None)
        if host is None:
            # An ordinary message behind host notes: the request is the message without them.
            rest = host_turns.strip_notes(kw.get("user_message"))
            if rest != host_turns.message_text(kw.get("user_message")):
                own = rest
        # The turn is a request (an owner's message, or a standing instruction's own words) unless the host's
        # text is only content.
        is_request = host is None or own is not None
        merged = False
        try:
            store.merge_turn(
                turn_id,
                {
                    "pre_llm_call": True,
                    "platform": kw.get("platform"),
                    "sender_id": kw.get("sender_id"),
                    "parent_session_id": kw.get("parent_session_id"),
                    "user_message": kw.get("user_message"),
                    "host_turn": host.form if host else None,
                    "request_text": own,
                },
            )
            merged = bool(turn_id)
        except Exception as exc:  # noqa: BLE001 - the turn's calls then read as a turn never seen
            logger.warning("pre_llm_call could not store the turn: %s", exc)
        sid = _sid(kw)
        with store.session_lock(sid):
            s = store.load_session(sid)
            if not background:
                # Without a turn id, calls that name none must not fall back to the previous turn.
                s["last_turn_id"] = turn_id or None
                # Only a turn whose request was stored can be carried later.
                if merged and is_request:
                    s["last_request_turn_id"] = turn_id
                if turn_id and turn_id not in s["turns"]:
                    s["turns"].append(turn_id)
                if host is not None and content is not None:
                    _buffer_host_text(cfg, store, s, content, host.input_kind or "other")
                store.save_session(sid, s, cfg.history_limit * 2)
            if _capturing(cfg, store) and not background:
                facts = session_facts()
                platform = resolve_platform(kw.get("platform"), facts, env)
                sender = conversation_sender_of(platform, facts, kw.get("sender_id"), env)
                if host is not None and sender["relation"] == "owner":
                    sender = dict(host_turns.SENDER, basis=list(host_turns.SENDER["basis"]))
                _record(
                    store,
                    sid,
                    conversation.user_entry(
                        _turn_no(s, turn_id),
                        sender,
                        kw.get("user_message"),
                        Redactor("standard", store.salt()),
                        turn_id,
                    ),
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pre_llm_call failed: %s", exc)


def _buffer_host_text(
    cfg: PluginConfig, store: Store, s: dict[str, Any], message: Any, kind: str
) -> None:
    """A host turn's text as the next scan's new input (`subagent_reply` or `other`), redacted and capped
    like a tool result. Untrusted, like any input."""
    text = host_turns.message_text(message)
    redacted = Redactor("standard", store.salt()).string(text)
    capped, truncated, _ = cap_head_tail(redacted, cfg.input_cap_bytes)
    s["input_seq"] += 1
    s["buffer"].append(
        {
            "input_seq": s["input_seq"],
            "kind": kind,
            "call_id": None,
            "content_type": "text",
            "content": capped,
            "size_bytes": len(text.encode("utf-8")),
            "truncated": truncated,
            "subagent_session_ref": None,
        }
    )


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
        store = _state(cfg)[0]
        store.merge_turn(kw.get("turn_id"), {"assistant_text": text, "tool_calls": calls})
        # The review fork's own words are not the conversation it reviews.
        if _capturing(cfg, store) and text.strip() and not skill_review.in_background_review():
            sid = _sid(kw)
            _record(
                store,
                sid,
                conversation.assistant_entry(
                    _turn_no(store.load_session(sid), kw.get("turn_id")),
                    text,
                    Redactor("standard", store.salt()),
                ),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("post_api_request failed: %s", exc)


# ---- the scan ----------------------------------------------------------------------------------------


def on_pre_tool_call(tool_name: str = "", args: Any = None, **kw: Any) -> dict[str, Any] | None:
    try:
        cfg, env = _load()
        store, traffic = _state(cfg)
        _capturing(cfg, store)
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
    last_request = store.load_turn(request_turn_id(sess))
    facts = session_facts()
    host_cfg = hermes_config()
    tool_name = str(kw.get("tool_name") or "")
    loop_save = skill_review.is_loop_save(tool_name)
    redactor = Redactor("standard", store.salt())
    # With `skill_review: allow` a loop save is declared as a self-edit and carries the conversation the
    # review read; with `review` it is sent like any other call.
    self_edit = (
        _self_edit(store, sid, tool_name, kw.get("args"), redactor)
        if loop_save and cfg.skill_review == "allow"
        else None
    )
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
        self_edit=self_edit,
        # The background review's calls serve the owner's last request, not a turn of their own.
        request_turn=last_request if skill_review.in_background_review() else None,
        last_request=last_request,
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
    relaxed = False
    held: dict[str, Any] | None = None
    failure_notice: dict[str, Any] | None = None
    if isinstance(result, ScanOk):
        resp = result.response
        # A run nobody can answer lowers a block to a review only for a retry of a review nobody answered: that
        # retry is held for the owner. The attended-owner ceiling is dropped there (`decision.unattended_view`).
        verdict = decide(unattended_view(resp) if unattended else resp, cfg.review_at, cfg.block_at)
        if (
            cfg.mode != "observe"
            and not unattended
            and snooze.relaxes(resp, verdict)
            and snooze.active(
                store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
            )
        ):
            # The owner snoozed this attended session and nothing independent points to an attack: the block
            # asks instead. It is allowed silently only where the owner answered Session or Always for the same
            # action under the same snoozes (`_rule_key`).
            verdict = "review"
            relaxed = True
        sess.pop("error_epoch", None)  # Sentrook scans again: the next failure is a new outage
        sess["token"] = resp.get("state")
        sess["buffer"] = []
        entry["action_fingerprint"] = resp.get("action_fingerprint")
        entry["risk"] = resp.get("risk")
        entry["tiers"] = tiers_of(resp)
        if cfg.mode == "observe" or verdict == "allow":
            entry["decision"] = "allowed"
        elif verdict == "block":
            entry["decision"] = "blocked"
            directive = {"action": "block", "message": block_reason(resp)}
        elif unattended:
            # A review nobody can answer (or Hermes would auto-approve) waits for the owner (`hold`).
            entry["decision"] = "held"
            directive = {"action": "block", "message": hold.HELD_TEXT}
            held = _hold(cfg, traffic, built, resp)
        elif (
            not relaxed
            and snooze.applies(resp, cfg.block_at)
            and snooze.active(
                store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
            )
        ):
            # The owner snoozed reviews for this session: scanned and logged, not asked.
            entry["decision"] = "allowed"
            snoozed = True
        else:
            entry["decision"] = "review_timed_out"  # provisional until the user answers
            snoozes = (
                snooze.covering(
                    store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
                )
                if relaxed
                else None
            )
            key = _rule_key(
                resp.get("approval_fingerprint") or resp.get("action_fingerprint"),
                planir["request_id"],
                snoozes,
                tool=tool_name,
                args=kw.get("args"),
                secret=store.salt(),
            )
            # The grant the scan suggests: the prompt shows its command, and approving always sets it where
            # the owner is the one answering (never for a block a snooze turned into a review).
            hint = hold.grant_hint(resp, cfg.review_at) if grants.owner_sender(planir) else None
            remember = hint is not None and not relaxed and grants.may_remember(planir)
            directive = {
                "action": "approve",
                "message": card.hermes_message(
                    resp,
                    built["tool"],
                    relaxed=relaxed,
                    hint=hint,
                    remember=remember,
                    why_id=planir["request_id"] if cfg.traffic_log_enabled else None,
                ),
                "rule_key": key,
            }
            store.put_review(
                key,
                {
                    "sid": sid,
                    "request_id": planir["request_id"],
                    "on_error": False,
                    # The same action can wait in several chats under one key (`Store.put_review` keeps one entry
                    # per session): the answer sets the grant only from the chat it was asked in.
                    **(
                        {
                            "hint": hint,
                            "platform": built["platform"],
                            "session_key": _approval_session_key(),
                        }
                        if remember
                        else {}
                    ),
                },
            )
    else:
        logger.warning("scan failed (%s): %s", result.kind, result.detail)
        if cfg.mode != "observe":
            outage = sess.setdefault("error_epoch", planir["request_id"])
            cause = card.error_cause(result.kind, is_auth_failure(result))
            key = _error_rule_key(planir["session"]["session_ref"], outage, cause)
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
                elif unattended:
                    failure_notice = _scan_failure_notice(cfg, built, result)
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
            **({"relaxed": True} if relaxed else {}),
            **({"hold": held} if held is not None else {}),
            **({"notice": failure_notice} if failure_notice is not None else {}),
            **({"skill_review": True} if loop_save else {}),
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
            "scan step=%s tool=%s risk=%s enforced=%s status=%s verdict=%s decision=%s%s%s ms=%s",
            built["step"],
            built["tool"],
            result.response.get("risk"),
            result.response.get("enforced"),
            result.response.get("status"),
            verdict,
            entry["decision"],
            " (snoozed)" if snoozed else " (block relaxed to review by snooze)" if relaxed else "",
            " (self-edit)" if self_edit is not None else " (loop save)" if loop_save else "",
            result.latency_ms,
        )
    return directive


def _where(built: dict[str, Any]) -> str:
    """The job or session a held call belongs to, for the owner's notice."""
    return _run_of(built)[0]


def _run_of(built: dict[str, Any]) -> tuple[str, str | None]:
    """(the job or session a call belongs to, for the owner's notices; the cron job id when Hermes says
    which)."""
    sref = built["planir"]["session"]["session_ref"]
    run = None
    try:
        read = getattr(_ctx, "current_cron_execution", None)
        run = read() if callable(read) else None
    except Exception:  # noqa: BLE001 - no cron identity: name the session
        run = None
    job_id, job_name = getattr(run, "job_id", None), getattr(run, "job_name", None)
    if isinstance(job_id, str) and job_id.strip():
        name = (
            job_name.strip()
            if isinstance(job_name, str) and job_name.strip() != job_id.strip()
            else None
        )
        return hold.where_text("cron job", sref, job_id.strip(), name), job_id.strip()
    if built["subagent"] or built["platform"] == "subagent":
        return hold.where_text("subagent run", sref), None
    if built["platform"] == "cron":
        return hold.where_text("cron job", sref), None
    return hold.where_text("unattended run", sref), None


def _scan_failure_notice(
    cfg: PluginConfig, built: dict[str, Any], failure: ScanFailure
) -> dict[str, Any]:
    """Tells the owner a scan failure blocked a call on an unattended run: once per cron job (or session)
    per quiet period. Returns what the scan record says about the notice. Never raises: the call is
    blocked whatever happens here."""
    target, why = hold.notice_target(cfg.owner_channel, hold.home_platforms())
    if target and not callable(getattr(_ctx, "dispatch_tool", None)):
        target, why = None, "this Hermes cannot dispatch send_message from a plugin"
    if not target:
        return {"status": "unsent", "target": None, "reason": why}
    where, job_id = _run_of(built)
    sref = built["planir"]["session"]["session_ref"]
    key = scan_failure_notice.quiet_key(job_id, sref)
    try:
        stamp = scan_failure_notice.claim(cfg.state_dir, key, datetime.now(UTC))
        if stamp is None:
            return {"status": "quiet"}
    except LockTimeout:
        return {"status": "unsent", "target": None, "reason": "notice file locked"}
    except Exception as exc:  # noqa: BLE001 - still blocked, just not announced
        logger.warning("sentrook could not read or write scan-failure notices: %s", exc)
        return {"status": "unsent", "target": None, "reason": "notice file not written"}
    text = scan_failure_notice.notice_text(
        failure, built["tool"], where, job_id is not None, "hermes sentrook verify"
    )
    # Not delivered: the next failure in this job is announced instead.
    hold.deliver(
        _ctx,
        target,
        text,
        on_fail=lambda: scan_failure_notice.release(cfg.state_dir, key, stamp),
    )
    return {"status": "queued", "target": target}


def _hold(
    cfg: PluginConfig, traffic: TrafficLog, built: dict[str, Any], resp: dict[str, Any]
) -> dict[str, Any]:
    """Stores the hold and sends the owner's notice; returns what the scan record says about it. The
    call is held whatever happens here: a hold that cannot be stored only cannot be approved."""
    now = datetime.now(UTC)
    planir = built["planir"]
    target, why = hold.notice_target(cfg.owner_channel, hold.home_platforms())
    if target and not callable(getattr(_ctx, "dispatch_tool", None)):
        target, why = None, "this Hermes cannot dispatch send_message from a plugin"
    notice: dict[str, Any] = (
        {"status": "queued", "target": target}
        if target
        else {"status": "unsent", "target": None, "reason": why}
    )
    hint = hold.grant_hint(resp, cfg.review_at) if grants.owner_sender(planir) else None
    where = _where(built)
    try:
        hid = hold.create(
            cfg.state_dir,
            request_id=planir["request_id"],
            session_ref=planir["session"]["session_ref"],
            tool=built["tool"],
            where=where,
            hint=hint,
            notice=notice,
            now=now,
            record=traffic.write,
        )
        if hid is None:
            notice = {"status": "unsent", "target": None, "reason": "holds file unreadable"}
    except LockTimeout:
        hid, notice = None, {"status": "unsent", "target": None, "reason": "holds file locked"}
    except Exception as exc:  # noqa: BLE001 - still held, just not approvable
        logger.warning("sentrook could not store a hold: %s", exc)
        hid, notice = None, {"status": "unsent", "target": None, "reason": "holds file not written"}
    if hid is not None and target:
        try:
            text = hold.notice_text(
                resp, built["tool"], where, hid, commands.CMD("approve"), commands.CMD("why")
            )
            hold.deliver(_ctx, target, text)
        except Exception as exc:  # noqa: BLE001 - a malformed response: still held, not announced
            logger.warning("sentrook held a call but could not build its notice: %s", exc)
            notice = {"status": "unsent", "target": None, "reason": "notice could not be built"}
    else:
        logger.warning("sentrook held a call but sent no notice: %s", notice.get("reason"))
    return {
        "id": hid,
        "expires_at": (now + hold.HOLD_TTL).strftime("%Y-%m-%dT%H:%M:%SZ") if hid else None,
        "hint": hint is not None,
        "notice": notice,
    }


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
#: Answers that approve for good: they also set a review's suggested grant.
_ALWAYS = {"always", "allow-always", "allow_always"}


def _approval_session_key() -> str:
    """The session key Hermes gives the approval hook for the current chat (`HERMES_SESSION_KEY`, else `default`)."""
    return session_facts().get("key") or "default"


def _remember(
    cfg: PluginConfig, traffic: TrafficLog, review: dict[str, Any], session_key: str
) -> dict[str, Any] | None:
    """Sets the suggested grant of a review approved always, as a persistent grant ending in 30 days, once per
    review, when the answer came from the chat the review was asked in (`session_key`, as the approval hook
    reports it). Returns the grants change, or None when there was nothing to set or it could not be written
    (logged: the answer itself stands)."""
    grant = grants.hint_grant(review.get("hint"))
    if grant is None or review.get("session_key") != session_key:
        return None
    by = {"basis": ["review_always"], "platform": str(review.get("platform") or "")}
    try:
        _reply, change = grants.add_suggested(
            cfg.state_dir,
            grant,
            by,
            datetime.now(UTC),
            hold.GRANT_TTL,
            str(review["request_id"]),
            source="from_review",
        )
    except Exception as exc:  # noqa: BLE001 - the approval stands without the grant
        logger.warning("sentrook could not set the suggested grant: %s", exc)
        return None
    if change is None:
        logger.warning("sentrook could not set the suggested grant: %s", _reply)
        return None
    if not change.get("existing"):
        traffic.write({"kind": "grants", **change, "by": by})
    return change


def on_post_approval_response(**kw: Any) -> None:
    """Write the user's answer into history, joined by the rule key we issued. A deny the review loop
    gave itself (`skill_review.auto_denied`) is recorded as a block, not as the user's."""
    try:
        pattern = str(kw.get("pattern_key") or kw.get("rule_key") or "")
        key = pattern.removeprefix("plugin_rule:")
        if not key.startswith("sentrook:"):
            return
        cfg, _ = _load()
        store, traffic = _state(cfg)
        # the same action can wait in several chats under one key: take the answering session's review
        review = store.pop_review(key, str(kw.get("session_id") or kw.get("task_id") or "") or None)
        if not review:
            return
        choice = str(kw.get("choice") or kw.get("decision") or "").strip().lower()
        approved = choice in _APPROVED
        # The review loop's own deny on the terminal: nobody was asked, so it is not the owner's denial.
        auto = skill_review.auto_denied(kw, choice)
        if review.get("on_error"):
            final = "allowed_on_error" if approved else "blocked_on_error"
        else:
            final = (
                "approved_by_user"
                if approved
                else "denied_by_user"
                if choice == "deny" and not auto
                else "review_timed_out"
                if choice == "timeout"
                else "blocked"
            )
        remembered = (
            _remember(cfg, traffic, review, str(kw.get("session_key") or "default"))
            if approved and choice in _ALWAYS and not review.get("on_error")
            else None
        )
        sid = review["sid"]
        with store.session_lock(sid):
            s = store.load_session(sid)
            for h in s["history"]:
                if h.get("request_id") == review["request_id"]:
                    h["decision"] = final
                    # the scanner tells this unseen deny from a real block: a retry of it may ask, not block
                    if auto:
                        h["decided_by"] = history.REVIEW_LOOP
                    else:
                        h.pop("decided_by", None)
            store.save_session(sid, s, cfg.history_limit * 2)
        traffic.write(
            {
                "kind": "resolution",
                "request_id": review["request_id"],
                "resolution": choice,
                "decision": final,
                **({"decided_by": history.REVIEW_LOOP} if auto else {}),
                **({"grant_id": remembered["entry"]["id"]} if remembered else {}),
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("post_approval_response failed: %s", exc)


def on_post_tool_call(tool_name: str = "", args: Any = None, result: Any = "", **kw: Any) -> None:
    """Buffer the result (exactly what the model saw) for the next scan, and add it to the conversation
    log; blocked calls add nothing."""
    try:
        cfg, _ = _load()
        store, _t = _state(cfg)
        capturing = _capturing(cfg, store)
        host_id = kw.get("tool_call_id")
        if not host_id:
            return
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
                redactor = Redactor("standard", store.salt())
                redacted = redactor.string(text)
                capped, truncated, _ = cap_head_tail(redacted, cfg.input_cap_bytes)
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
                if capturing:
                    # The review fork's reads count too: they are what its save draws on.
                    _record(
                        store,
                        sid,
                        conversation.tool_entry(
                            _turn_no(s, kw.get("turn_id")),
                            entry["tool"],
                            args if args else entry.get("arguments"),
                            redacted,
                            redactor,
                        ),
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
        cli.register_cli(ctx, _settings, functools.partial(owner_command, local_cli=True))
    except Exception as exc:  # noqa: BLE001 - older hosts without plugin CLI commands
        logger.info("sentrook CLI not registered: %s", exc)
    try:
        commands.register_slash(ctx, _settings, owner_command)
    except Exception as exc:  # noqa: BLE001 - older hosts without plugin slash commands
        logger.info("/sentrook not registered: %s", exc)
    cfg, _ = _load()
    ep = cfg.endpoints
    try:
        _capturing(cfg, _state(cfg)[0])
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook state not readable at startup: %s", exc)

    def show(e: Any) -> str:
        return e.url if e.ok else f"INVALID ({e.reason})"

    logger.info(
        "sentrook %s registered: scan=%s issuer=%s%s mode=%s review>=%s block>=%s on_scan_error=%s "
        "skill_review=%s traffic=%s",
        PLUGIN_VERSION,
        show(ep.scan),
        show(ep.issuer),
        " (dev endpoints)" if ep.dev else "",
        cfg.mode,
        cfg.review_at,
        cfg.block_at,
        cfg.on_scan_error,
        cfg.skill_review,
        cfg.traffic_log_path if cfg.traffic_log_enabled else "off",
    )
    if not ep.scan.ok or not ep.issuer.ok:
        logger.error(
            "sentrook endpoint configuration is invalid; every tool call will fail closed until fixed"
        )
    if cfg.skill_review_unknown is not None:
        logger.warning(
            "sentrook skill_review %r is not allow or review; reading it as allow",
            cfg.skill_review_unknown,
        )
    if unsent := grants.unsent_summary(cfg):
        logger.warning(
            "sentrook config grants never sent: %s. A config grant has no session: drop its scope to "
            "apply it in every session, or use /sentrook grant for one session; see /sentrook grants",
            unsent,
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
