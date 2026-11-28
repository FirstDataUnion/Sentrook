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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import (
    agent_skills,
    always_allow,
    build,
    card,
    channel_context,
    cli,
    commands,
    consent,
    conversation,
    folders,
    grants,
    history,
    hold,
    host_turns,
    notice_retry,
    owner,
    owner_settings,
    passes,
    proposals,
    run_now,
    scan_failure_notice,
    session_allow,
    setup,
    setup_report,
    skill_review,
    skill_turn,
    snooze,
    staging,
)
from .auth import CREDENTIAL_VARS, resolve_oidc_credentials
from .auth import missing_credentials as auth_missing_credentials
from .commands import OWNER_CHAT
from .config import PluginConfig, hermes_home, resolve_config
from .decision import (
    BLOCK_CATEGORIES,
    block_category,
    block_reason,
    decide,
    describe,
    tiers_of,
    unattended_view,
)
from .intent import (
    asks_for_children,
    children_auto_approved,
    conversation_sender_of,
    hermes_config,
    host_yolo,
    is_unattended,
    owner_attends,
    resolve_platform,
    session_facts,
)
from .planir import (
    PLUGIN_VERSION,
    build_planir,
    previous_turn_id,
    request_turn_id,
    session_ref,
    tool_kind,
)
from .redact import Redactor, cap_head_tail
from .scan_client import ScanOk, post_scan
from .scan_error_policy import (
    ScanFailure,
    failure_cause,
    invalid_endpoint_effect,
    scan_error_to_directive,
)
from .store import LockTimeout, Store
from .traffic import TrafficLog

logger = logging.getLogger("sentrook")

#: History decisions after which the tool did not run.
NOT_RUN = frozenset(
    {"blocked", "denied_by_user", "review_timed_out", "blocked_on_error", "held", "staged"}
)

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
    "hide_tool_calls",
    # replaced by hide_tool_calls; still accepted, does nothing
    "dashboard_show_calls",
)

_ctx: Any = None
_store: Store | None = None
_traffic: TrafficLog | None = None
#: The plugin's own agent tools that `ctx.register_tool` took (the setup report and the setup proposal), by name,
#: with the handler each was registered with.
_own_tools: dict[str, Callable[..., str]] = {}
#: The calls of each own tool that `pre_tool_call` allowed, for its handler to take, by session and the inputs the
#: handler reads (the report's days, the proposal's checked items).
_tool_markers = {
    setup_report.TOOL: setup_report.Markers(setup_report.days_of),
    proposals.TOOL: setup_report.Markers(proposals.check),
}
#: Proposals `pre_tool_call` allowed while the session held content no scan had seen yet, by session and checked
#: items (`_unchecked_key`), for the handler to store with the proposal.
_proposal_unchecked: dict[str, bool] = {}
#: The traffic log record each own tool's calls are logged as.
_TOOL_RECORD = {setup_report.TOOL: "setup_report", proposals.TOOL: "setup_proposal"}
#: Review prompts a sub-agent asked in its parent's chat, by request id, until the answer comes: what a hold needs if
#: the prompt times out or cannot be shown (`_child_prompt_fallback`). Oldest dropped past `_CHILD_PROMPTS_KEPT`.
_child_prompts: dict[str, dict[str, Any]] = {}
_CHILD_PROMPTS_KEPT = 64
#: The prompt outcomes after which a sub-agent's review falls back to a hold: nobody answered in time, Hermes could not
#: show the prompt, or it withdrew it (the sub-agent or the chat's turn ended first).
_CHILD_FALLBACK = {"timeout", "notify_failed", "cancelled"}


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


def _call_rule_key(request_id: str, secret: str) -> str:
    """The rule key of a block a snooze turned into a review although it carries a strong signal: the call's own
    request, so a Session or Always answer Hermes stores for it never matches another call, and the next one asks
    again. An HMAC under `secret`, as `_rule_key`."""
    digest = hmac.new(
        ("sentrook rule key v1|" + secret).encode(),
        f"call|{request_id}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return "sentrook:call:" + digest[:16]


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
    arguments and who ran it: `{"basis", "platform", "sender_ref"}`, plus the chat the check judged under
    `OWNER_CHAT` (its chat id and type, never recorded).
    """

    def handler(raw_args: str = "", *_a: Any, **_kw: Any) -> str:
        try:
            cfg, env = _load()
            store, traffic = _state(cfg)
        except Exception as exc:  # noqa: BLE001 - nowhere to audit; refuse
            logger.warning("owner check for %s failed: %s", verb, exc)
            return owner.refusal(verb)
        try:
            facts = session_facts()
            check = owner.gate(
                verb,
                traffic,
                store.salt(),
                facts=facts,
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
            return owner.refusal(verb, check["basis"])
        who = {k: check[k] for k in ("basis", "platform", "sender_ref")}
        # The chat the check judged, for a command that stores it (`notify here`); taken off `who` before `who`
        # is recorded anywhere (`commands.dispatch`).
        who[OWNER_CHAT] = {k: str(facts.get(k) or "") for k in ("chat_id", "chat_type")}
        return fn(raw_args, who)

    return handler


# ---- context joins ---------------------------------------------------------------------------------


def on_pre_llm_call(**kw: Any) -> None:
    try:
        cfg, env = _load()
        store, _t = _state(cfg)
        # Notices another process kept to send again are sent by a process that keeps running (`notice_retry`).
        notice_retry.resume(cfg.state_dir)
        turn_id = kw.get("turn_id")
        # The curator's prompt (a fresh agent under the background-review origin) is neither a message, a
        # request nor a turn of the owner's session: its calls carry the owner's last request (`_scan_one`).
        background = skill_review.in_background_review()
        # A turn Hermes starts itself with its own text (`host_turns`) is a turn, never an owner message; an
        # event notice is not a request either, and its text goes as an untrusted input.
        host = None if background else host_turns.classify(kw.get("user_message"))
        own, content = host_turns.parts(host, kw.get("user_message")) if host else (None, None)
        # In a group or channel, the history Hermes puts in front of the message is other people's words: never
        # the request, and sent as an untrusted input (`channel_context`).
        rest = host_turns.strip_notes(kw.get("user_message"))
        channel = (
            None
            if background or host is not None
            else channel_context.split(
                rest, group=(session_facts().get("chat_type") or "dm").lower() != "dm"
            )
        )
        if channel is not None:
            rest = channel[1] or channel_context.NO_REQUEST
        # A message Hermes built around skills (a skill's slash command, a cron job with skills): the request
        # is the owner's words; what is neither theirs nor an installed skill's own text is untrusted content.
        skill = None if background or host is not None else _skill_turn(rest, kw, env)
        if skill is not None:
            own, content = skill.request, skill.content
        elif host is None:
            # An ordinary message behind host notes or channel history: the request is the message without them.
            if channel is not None or rest != host_turns.message_text(kw.get("user_message")):
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
                # The cron run this session serves, or (a delegated child) the one its parent serves, for holds and
                # passes of the job (`_inherited_run`).
                parent_id = kw.get("parent_session_id")
                own_rec = _cron_record()
                if own_rec is not None:
                    s["cron"] = {**own_rec, "session": sid}
                elif isinstance(parent_id, str) and parent_id.strip():
                    run_rec = _inherited_run(store, s, parent_id)
                    if run_rec is not None:
                        s["cron"] = run_rec
                else:
                    # a turn that is neither a cron run nor a delegated child: no run to pass on
                    s.pop("cron", None)
                # Without a turn id, calls that name none must not fall back to the previous turn.
                s["last_turn_id"] = turn_id or None
                # Only a turn whose request was stored can be carried later.
                if merged and is_request:
                    s["last_request_turn_id"] = turn_id
                if turn_id and turn_id not in s["turns"]:
                    s["turns"].append(turn_id)
                if channel is not None:
                    _buffer_host_text(cfg, store, s, channel[0], "other")
                if host is not None and content is not None:
                    _buffer_host_text(cfg, store, s, content, host.input_kind or "other")
                elif skill is not None and content is not None:
                    _buffer_host_text(cfg, store, s, content, "other")
                store.save_session(sid, s, cfg.history_limit * 2)
            if _capturing(cfg, store) and not background:
                facts = session_facts()
                platform = resolve_platform(kw.get("platform"), facts, env)
                sender = conversation_sender_of(platform, facts, kw.get("sender_id"), env)
                if host is not None and sender["relation"] == "owner":
                    sender = dict(host_turns.SENDER, basis=list(host_turns.SENDER["basis"]))
                entries: list[tuple[dict[str, Any], Any]] = [(sender, kw.get("user_message"))]
                if channel is not None:
                    # The channel history is other people's; the sender wrote only the new message.
                    entries = [
                        ({"relation": "other", "basis": ["group_chat"]}, channel[0]),
                        (sender, channel[1]),
                    ]
                for who, text in entries:
                    _record(
                        store,
                        sid,
                        conversation.user_entry(
                            _turn_no(s, turn_id),
                            who,
                            text,
                            Redactor("standard", store.salt()),
                            turn_id,
                        ),
                    )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pre_llm_call failed: %s", exc)


def _cron_job_prompt(home: Path) -> str | None:
    """The running cron job's own prompt, from Hermes's job file (`<home>/cron/jobs.json`, read directly: the
    plugin uses no private Hermes module); None outside a cron run, or when the job or the file cannot be read.
    "" for a job with no prompt (it only runs its skills), told apart from no record at all."""
    try:
        read = getattr(_ctx, "current_cron_execution", None)
        run = read() if callable(read) else None
        job_id = getattr(run, "job_id", None)
        if not isinstance(job_id, str) or not job_id.strip():
            return None
        data = json.loads((home / "cron" / "jobs.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - no job record: the split falls back to the whole instruction
        return None
    jobs = data.get("jobs") if isinstance(data, dict) else data
    job = next(
        (j for j in jobs or [] if isinstance(j, dict) and j.get("id") == job_id.strip()), None
    )
    if job is None:
        return None
    prompt = job.get("prompt")
    return prompt if isinstance(prompt, str) else ""


def _skill_turn(text: str, kw: dict[str, Any], env: dict[str, str]) -> skill_turn.SkillTurn | None:
    """`skill_turn.split` of a user message, with the running cron job's prompt; None for any other message,
    and when the split itself fails (the message is then the request, as before)."""
    try:
        if not text.startswith(
            ("[IMPORTANT: The user has invoked", "[IMPORTANT: The following skill")
        ):
            return None
        # The values Hermes may have given a skill's `${HERMES_SESSION_ID}`: the turn's own ids.
        ids = tuple(
            str(kw[k]) for k in ("task_id", "session_id") if isinstance(kw.get(k), str) and kw[k]
        )
        home = hermes_home(env)
        return skill_turn.split(
            text,
            job_prompt=_cron_job_prompt(home),
            installed=functools.partial(skill_turn.installed_skills, home),
            session_ids=ids,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("skill turn not split: %s", exc)
        return None


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
    if _own_tool(tool_name):
        return _own_tool_gate({**kw, "tool_name": tool_name, "args": args})
    try:
        cfg, env = _load()
        store, traffic = _state(cfg)
        _capturing(cfg, store)
        try:
            build.check_on_scan()
        except Exception as exc:  # noqa: BLE001 - never in the way of a scan
            logger.info("sentrook build check failed: %s", exc)
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
    turn_id = kw.get("turn_id") or sess.get("last_turn_id")
    turn = store.load_turn(turn_id)
    last_request = store.load_turn(request_turn_id(sess))
    # The turn before this one: its final message is what a short reply from the owner answers.
    prior_tid = previous_turn_id(sess, turn_id)
    prior_turn = store.load_turn(prior_tid) if prior_tid else None
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
        prior_turn=prior_turn,
    )
    planir = built["planir"]
    built["loop_save"] = loop_save
    # The cron run this call belongs to: kept on the run's own session, so its sub-agents find it (`_inherited_run`).
    own_run = _cron_record()
    if own_run is not None:
        sess["cron"] = {**own_run, "session": sid}
    elif not built["subagent"]:
        # not a cron run now (a resumed cron session, say): its sub-agents must not take an old run
        sess.pop("cron", None)
    built["job_run"] = (
        _inherited_run(store, sess, turn.get("parent_session_id"))
        if own_run is None and built["subagent"]
        else None
    )
    if built["job_run"] is not None:
        sess["cron"] = built["job_run"]
    # Any other call of the unattended review or curator: nobody can answer it either (see `skill_review`).
    background_run = not loop_save and skill_review.in_unattended_review()
    built["background_run"] = background_run
    # The config's attended platforms and those the owner added with `/sentrook attended add`.
    attendance = {
        "subagent": built["subagent"],
        "attended_platforms": owner_settings.attended_of(cfg),
    }
    # A sub-agent of the owner's attended chat asks in that chat: Hermes shows its prompt there (`asks_for_children`).
    # Approvals off or YOLO still count, as they would in the parent chat, and so does Hermes approving a sub-agent's
    # prompts by itself (`children_auto_approved`).
    parent_chat = (
        _parent_chat(store, turn)
        if built["subagent"]
        and not loop_save
        and not background_run
        and not children_auto_approved(host_cfg, env)
        else None
    )
    in_parent_chat = parent_chat is not None and not is_unattended(
        parent_chat, env, attended_platforms=attendance["attended_platforms"]
    )
    # A loop save never asks: the owner's turn is over, so nobody can answer it on any surface (see `skill_review`).
    unattended = (
        loop_save
        or background_run
        or (not in_parent_chat and is_unattended(built["platform"], env, **attendance))
    )
    # Whether a sub-agent of this session asks in this chat, for its own scans (`_parent_chat`).
    sender = (planir.get("trigger") or {}).get("sender") or {}
    sess["children"] = {
        "ask": not unattended
        and (
            in_parent_chat
            or asks_for_children(
                built["platform"],
                env,
                sender_relation=sender.get("relation"),
                sender_basis=sender.get("basis"),
                attended_platforms=attendance["attended_platforms"],
            )
        ),
        "platform": parent_chat if in_parent_chat else built["platform"],
    }

    ep = cfg.endpoints
    result: ScanOk | ScanFailure
    oidc = None
    if not ep.scan.ok:
        result = ScanFailure(ok=False, kind="config", detail=f"scan URL: {ep.scan.reason}")
    elif not ep.issuer.ok:
        result = ScanFailure(ok=False, kind="config", detail=f"OIDC issuer: {ep.issuer.reason}")
    else:
        oidc = resolve_oidc_credentials(_settings(), env, ep.issuer.url)
        result = post_scan(
            scan_url=ep.scan.url,
            oidc=oidc,
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
    strong = False  # a relaxed block with a strong signal: a warning, and nothing answers it but this prompt
    let_through = False
    session_allowed: dict[str, Any] | None = None
    always_allowed: dict[str, Any] | None = None
    allow_key: str | None = None
    always_key: str | None = None
    held: dict[str, Any] | None = None
    by_pass: dict[str, Any] | None = (
        None  # the owner's pass or denial that settled an unattended review
    )
    stage: dict[str, Any] | None = (
        None  # what became of a held background save (`_stage_background`)
    )
    notice: dict[str, Any] | None = (
        None  # the owner's notice of a background save or a scan failure
    )
    if isinstance(result, ScanOk):
        resp = result.response
        # A run nobody can answer lowers a block to a review only for a retry of a review nobody answered or code
        # that reaches no network sink: that call is held for the owner. The attended-owner ceiling is dropped there
        # (`decision.unattended_view`).
        verdict = decide(unattended_view(resp) if unattended else resp, cfg.review_at, cfg.block_at)
        asked = (
            None
            if cfg.mode == "observe" or unattended
            else snooze.asks(resp, verdict, planir, built["platform"])
            # a review of an action the owner was asked about during a snooze asks with the warning, never snoozed
            or ("strong" if verdict == "review" and snooze.asked_before(sess, resp) else None)
        )
        if asked == "strong" and verdict == "block" and host_yolo():
            # Hermes would approve the prompt by itself (session YOLO): a block with a strong signal stays a block.
            asked = None
        if asked is not None and snooze.active(
            store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
        ):
            # The owner snoozed this attended session: the block asks instead (`snooze.asks`). One the scanner marks
            # relaxable is allowed silently only where the owner answered Session or Always for the same action under
            # the same snoozes (`_rule_key`); any other asks every time, with a warning (`_call_rule_key`).
            verdict = "review"
            relaxed = True
            strong = asked == "strong"
        sess.pop("error_epoch", None)  # Sentrook scans again: the next failure is a new outage
        sess["token"] = resp.get("state")
        sess["buffer"] = []
        entry["action_fingerprint"] = resp.get("action_fingerprint")
        entry["risk"] = resp.get("risk")
        entry["tiers"] = tiers_of(resp)
        # Whether the call sends or writes something, for a hold later in the run (`run_now`); not sent to the scanner.
        if passes.acts(entry["tool_kind"], resp):
            entry["_acts"] = True
        if cfg.mode == "observe" or verdict == "allow":
            entry["decision"] = "allowed"
        elif verdict == "block":
            entry["decision"] = "blocked"
            directive = {"action": "block", "message": block_reason(resp)}
            if loop_save:
                notice = _background_notice(cfg, built, resp, "blocked")
        elif (
            loop_save
            and snooze.applies(resp, cfg.block_at)
            and (
                skill_review.lenient(resp, declared=self_edit is not None)
                or (
                    # unattended runs are never snoozed: only a save after a session the owner attends
                    _background_save_attended(store, sess, kw, built, env, attendance)
                    and snooze.active(
                        store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
                    )
                )
            )
        ):
            # A reviewed background save the scanner marks lenient, or one a snooze covers, runs and the owner is
            # told; never one the scanner enforces or that scores at the block line.
            entry["decision"] = "allowed"
            let_through = skill_review.lenient(resp, declared=self_edit is not None)
            snoozed = not let_through
            notice = _background_notice(
                cfg, built, resp, "allowed-snoozed" if snoozed else "allowed-lenient"
            )
        elif loop_save:
            # Held, but not as an approvable hold: approving could not make the save (the hold keeps no arguments and
            # suggests no grant for a background save), and a curator pass must not crowd out other runs' holds.
            # Where Hermes can replay it, the save is staged in Hermes's own pending store for the owner instead
            # (`staging`). History and status record it; the owner gets a notice.
            stage = _stage_background(
                cfg, built, resp, tool_name, kw.get("args"), redactor, self_edit is not None
            )
            if stage["status"] == "staged":
                entry["decision"] = "staged"
                directive = {"action": "block", "message": staging.STAGED_TEXT}
                notice = _background_notice(cfg, built, resp, "staged", stage)
            elif stage["status"] == "host":
                # Hermes's own gate stages this change instead of making it: the call goes to it, and
                # `post_tool_call` reads what it did and tells the owner.
                entry["decision"] = "host_staging"
                entry["_background"] = _background_info(built, resp)
            else:
                entry["decision"] = "held"
                directive = {"action": "block", "message": hold.HELD_TEXT}
                notice = _background_notice(cfg, built, resp, "held")
        elif background_run:
            # Another call of the unattended review: nobody can answer it, and approving it later could not bring the
            # review back. Not run, the agent told so, the owner told once per session (`skill_review`).
            entry["decision"] = "held"
            directive = {"action": "block", "message": skill_review.HELD_CALL_TEXT}
            notice = _background_notice(cfg, built, resp, "held-call")
        elif unattended:
            # A review nobody can answer (or Hermes would auto-approve): the owner's denial or pass for this job and
            # action settles it (`passes`); otherwise it waits for the owner (`hold`).
            _where_text, job_id, source = _run_of(built)
            match = passes.match_of(
                str(built.get("tool") or ""),
                resp,
                kw.get("args"),
                store.salt(),
                job_id is None and source is None,
            )
            # A run the plugin started for an owner's `allow` (`run_now`): its pass serves this run only.
            rerun = _rerun(cfg, job_id, built) if job_id else None
            try:
                settled = passes.check(
                    cfg.state_dir,
                    passes.job_ref(job_id) or (source or {}).get("ref"),
                    match,
                    resp,
                    datetime.now(UTC),
                    in_run=rerun["id"] if rerun else None,
                )
            except Exception as exc:  # noqa: BLE001 - nothing settled: held as before
                logger.warning("sentrook could not read the passes: %s", exc)
                settled = None
            if settled is not None and settled["kind"] == "deny":
                entry["decision"] = "denied_by_owner"
                directive = {"action": "block", "message": passes.DECLINED_TEXT}
                by_pass = {"id": settled["id"], "kind": "deny"}
            elif settled is not None:
                entry["decision"] = "allowed_by_pass"
                by_pass = {
                    "id": settled["id"],
                    "kind": "allow",
                    "uses": settled.get("uses"),
                    "use_count": settled.get("use_count"),
                }
                if rerun is not None and settled["id"] == rerun["id"]:
                    _note_rerun(cfg, rerun["id"], passed=True)
            else:
                entry["decision"] = "held"
                directive = {"action": "block", "message": hold.HELD_TEXT}
                held = _hold(
                    cfg,
                    traffic,
                    built,
                    resp,
                    sid=sid,
                    job_id=job_id,
                    source=source,
                    match=match,
                    acted=_acted(sess) or _run_acted(store, built),
                )
                if rerun is not None and held.get("id"):
                    _note_rerun(cfg, rerun["id"], held=str(held["id"]))
        elif (
            in_parent_chat and (child_pass := _parent_pass(cfg, store, built, resp, kw)) is not None
        ):
            # A sub-agent asks in its parent's chat, but the owner already answered a held call from a sub-agent of
            # the same parent (`passes`): that answer settles it.
            if child_pass["kind"] == "deny":
                entry["decision"] = "denied_by_owner"
                directive = {"action": "block", "message": passes.DECLINED_TEXT}
                by_pass = {"id": child_pass["id"], "kind": "deny"}
            else:
                entry["decision"] = "allowed_by_pass"
                by_pass = {
                    "id": child_pass["id"],
                    "kind": "allow",
                    "uses": child_pass.get("uses"),
                    "use_count": child_pass.get("use_count"),
                }
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
        elif (
            covered := session_allow.covering(
                sess,
                allow_key := _allow_key(cfg, resp, planir, built, relaxed, store),
                resp,
                datetime.now(UTC),
                cfg.block_at,
            )
        ) is not None:
            # The owner answered Session for a call of this tool about the same parties, at most 10 points below this
            # risk, with every attack-type warning this one carries, in this chat (`session_allow`). History says
            # allowed: the owner was not shown this call.
            entry["decision"] = "allowed"
            session_allowed = {"by": covered.get("request_id")}
        elif (
            standing := always_allow.covering(
                always_allow.load(cfg.state_dir),
                always_key := _always_key(cfg, resp, planir, built, relaxed, store),
                resp,
                datetime.now(UTC),
                cfg.block_at,
            )
        ) is not None:
            # The owner answered Always for a call of this MCP tool on this server, at most 10 points below this
            # risk, with every attack-type warning this one carries (`always_allow`). History says allowed: the
            # owner was not shown this call.
            entry["decision"] = "allowed"
            always_allowed = {"by": standing[1].get("request_id"), "id": standing[0].get("id")}
        else:
            entry["decision"] = "review_timed_out"  # provisional until the user answers
            snoozes = (
                snooze.covering(
                    store.load_snooze(), planir["session"]["session_ref"], datetime.now(UTC)
                )
                if relaxed
                else None
            )
            key = (
                _call_rule_key(planir["request_id"], store.salt())
                if strong
                else _rule_key(
                    resp.get("approval_fingerprint") or resp.get("action_fingerprint"),
                    planir["request_id"],
                    snoozes,
                    tool=tool_name,
                    args=kw.get("args"),
                    secret=store.salt(),
                )
            )
            # The grant the scan suggests: the prompt shows its command, and approving always sets it where
            # the owner is the one answering (never for a block a snooze turned into a review).
            hint = hold.grant_hint(resp, cfg.review_at) if grants.owner_sender(planir) else None
            remember = hint is not None and not relaxed and grants.may_remember(planir)
            # A Session answer that sets the suggested grant leaves later calls to the scanner, which scores them
            # with it: no allowance besides (`session_allow`).
            if remember:
                allow_key = None
                always_key = None
            if relaxed:
                snooze.note_asked(sess, resp)
            directive = {
                "action": "approve",
                "message": card.hermes_message(
                    resp,
                    built["tool"],
                    relaxed=relaxed,
                    strong=strong,
                    hint=hint,
                    remember=remember,
                    why_id=planir["request_id"] if cfg.traffic_log_enabled else None,
                    session=None if relaxed else "parties" if allow_key is not None else "exact",
                    always=always_key is not None,
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
                    # per session): the answer sets the grant, or the allowance, only from the chat it was asked in.
                    **(
                        {"session_key": _approval_session_key()}
                        if remember or allow_key is not None or always_key is not None
                        else {}
                    ),
                    **({"hint": hint, "platform": built["platform"]} if remember else {}),
                    **(
                        {
                            "allow": {
                                "key": allow_key,
                                "risk": float(resp["risk"]),
                                "warnings": session_allow.warnings(resp),
                            }
                        }
                        if allow_key is not None and session_allow.risk_of(resp) is not None
                        else {}
                    ),
                    **(
                        {
                            "always": {
                                "key": always_key,
                                "tool": str(built.get("tool") or ""),
                                "server": server[0],
                                "identity": server[1],
                                "risk": float(resp["risk"]),
                                "warnings": session_allow.warnings(resp),
                            }
                        }
                        if always_key is not None
                        and (server := always_allow.server_of(built.get("provider"))) is not None
                        and session_allow.risk_of(resp) is not None
                        else {}
                    ),
                    **({"child": True} if in_parent_chat else {}),
                },
            )
            if in_parent_chat:
                _keep_child_prompt(
                    planir["request_id"],
                    {"built": built, "resp": resp, "sid": sid, "args": kw.get("args")},
                )
    else:
        logger.warning("scan failed (%s): %s", result.kind, result.detail)
        withdrawn = result.setup == "consent_withdrawn" and oidc is not None
        if withdrawn:
            # One notice for the withdrawal, in either mode, instead of one per job or session.
            notice = _consent_notice(cfg, oidc.client_id)
        if cfg.mode != "observe":
            outage = sess.setdefault("error_epoch", planir["request_id"])
            cause = failure_cause(result)
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
                elif unattended and not withdrawn:
                    notice = _scan_failure_notice(cfg, built, result)
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
            **({"lenient": True} if let_through else {}),
            **({"relaxed": True} if relaxed else {}),
            **({"relaxed_strong": True} if strong else {}),
            **({"session_allowed": session_allowed} if session_allowed is not None else {}),
            **({"always_allowed": always_allowed} if always_allowed is not None else {}),
            **({"hold": held} if held is not None else {}),
            **({"pass": by_pass} if by_pass is not None else {}),
            **({"notice": notice} if notice is not None else {}),
            **({"staging": stage} if stage is not None else {}),
            **({"skill_review": True} if loop_save else {}),
            **({"background_run": True} if background_run else {}),
            **({"parent_chat": True} if in_parent_chat else {}),
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
            " (snoozed)"
            if snoozed
            else " (covered by an earlier Session answer)"
            if session_allowed is not None
            else f" (covered by an earlier Always answer, {always_allowed['id']})"
            if always_allowed is not None
            else f" ({'refused by' if by_pass['kind'] == 'deny' else 'let through by'} {by_pass['id']})"
            if by_pass is not None
            else " (block with a strong signal asked by snooze)"
            if strong
            else " (block relaxed to review by snooze)"
            if relaxed
            else " (let through)"
            if let_through
            else "",
            " (self-edit)" if self_edit is not None else " (loop save)" if loop_save else "",
            result.latency_ms,
        )
    return directive


# ---- the plugin's own agent tools: the setup report and the setup proposal --------------------------------


def _own_tool(tool_name: str) -> bool:
    """`tool_name` is one of the agent tools this plugin registered: the name, a registration Hermes took, and the
    handler Hermes's tool registry would run is this plugin's. Any other tool of that name, and any call where the
    registry cannot be read, is scanned like every call."""
    handler = _own_tools.get(tool_name)
    if handler is None:
        return False
    try:
        from tools.registry import registry
    except Exception:  # noqa: BLE001 - the plugin host, where Hermes's registry is in the parent process: scanned,
        return False  # and the handler refuses it without a marker
    try:
        entry = registry.get_entry(tool_name)
    except Exception:  # noqa: BLE001 - unreadable: not known to be ours
        return False
    return getattr(entry, "handler", None) is handler


def _unchecked_key(sid: str, args: Any) -> str:
    return sid + "\n" + json.dumps(proposals.check(args), sort_keys=True, default=str)


def _items_asked(args: Any) -> int:
    items = args.get("items") if isinstance(args, dict) else None
    return len(items) if isinstance(items, list) else 0


def _tool_refused(
    traffic: TrafficLog | None, tool: str, sid: str, reason: str, args: Any = None
) -> dict[str, Any]:
    if traffic is not None:
        traffic.write(
            {
                "kind": _TOOL_RECORD[tool],
                "session_ref": session_ref(sid),
                "outcome": "refused",
                "reason": reason,
                **({"items": _items_asked(args)} if tool == proposals.TOOL else {}),
            }
        )
    return {"action": "block", "message": setup_report.REFUSAL}


def _own_tool_gate(kw: dict[str, Any]) -> dict[str, Any] | None:
    """`pre_tool_call` for the plugin's own agent tools: not scanned, and allowed only on the owner's own turn
    (`setup_report.allowed`), judged from the trigger a scan of this call would send. An allowed call gets its
    marker and a step in the session's history, so its result goes to the next scan like any tool result. Anything
    else, a failure included, gets `setup_report.REFUSAL` and nothing more."""
    sid = _sid(kw)
    tool = kw["tool_name"]
    traffic: TrafficLog | None = None
    try:
        cfg, env = _load()
        store, traffic = _state(cfg)
        _capturing(cfg, store)
        with store.session_lock(sid):
            sess = store.load_session(sid)
            turn = store.load_turn(kw.get("turn_id") or sess.get("last_turn_id"))
            last_request = store.load_turn(request_turn_id(sess))
            background = skill_review.in_background_review()
            built = build_planir(
                kw=kw,
                cfg=cfg,
                redactor=Redactor("standard", store.salt()),
                sid=sid,
                sess=sess,
                turn=turn,
                facts=session_facts(),
                env=env,
                host_cfg={},
                grants=[],
                request_turn=last_request if background else None,
                last_request=last_request,
            )
            ok = setup_report.allowed(
                built["planir"],
                platform=built["platform"],
                subagent=built["subagent"],
                env=env,
                attended_platforms=owner_settings.attended_of(cfg),
                background=background or skill_review.in_unattended_review(),
                isolated=skill_review.host_isolated(env),
            )
            if not ok:
                return _tool_refused(traffic, tool, sid, "not_owner_turn", kw.get("args"))
            sess["history"].append(
                {
                    "step": built["step"],
                    "turn": built["planir"]["session"]["turn"],
                    "call_id": built["call_id"],
                    "tool": built["tool"],
                    "tool_kind": built["tool_kind"],
                    "provider": built["provider"],
                    "arguments": built["history_args"],
                    "result": None,
                    "action_fingerprint": None,
                    "risk": None,
                    "tiers": None,
                    "request_id": built["planir"]["request_id"],
                    "decision": "allowed",
                    "_host_call_id": built["host_call_id"],
                }
            )
            store.save_session(sid, sess, cfg.history_limit * 2)
            _tool_markers[tool].put(sid, kw.get("args"))
            if tool == proposals.TOOL:
                # Content the chat read since the last scan reaches the scanner only with the next scanned call: what
                # it was cannot be checked now, so the owner is told.
                pending = any(
                    i.get("tool") not in _own_tools for i in built["planir"]["new_inputs"]
                )
                key = _unchecked_key(sid, kw.get("args"))
                _proposal_unchecked[key] = _proposal_unchecked.get(key, False) or pending
                while len(_proposal_unchecked) > 500:
                    _proposal_unchecked.pop(next(iter(_proposal_unchecked)))
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook %s check failed: %s", tool, exc)
        return _tool_refused(traffic, tool, sid, "error", kw.get("args"))


def report_handler(
    args: Any = None, task_id: Any = None, session_id: Any = None, **_kw: Any
) -> str:
    """The setup report tool's handler. Hermes passes it only the task and session ids, so it answers only for a
    call `pre_tool_call` allowed (`_own_tool_gate`'s marker, the same session and days) and refuses anything
    else."""
    sid = str(session_id or task_id or "default")
    traffic: TrafficLog | None = None
    try:
        cfg, env = _load()
        traffic = _state(cfg)[1]
        if not _tool_markers[setup_report.TOOL].take(sid, args):
            _tool_refused(traffic, setup_report.TOOL, sid, "no_marker")
            return setup_report.REFUSAL
        days = setup_report.days_of(args)
        text = _report_text(cfg, env, days, datetime.now(UTC))
        traffic.write(
            {
                "kind": "setup_report",
                "session_ref": session_ref(sid),
                "outcome": "answered",
                "days": days,
            }
        )
        return text
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook setup report failed: %s", exc)
        _tool_refused(traffic, setup_report.TOOL, sid, "error")
        return setup_report.REFUSAL


def propose_handler(
    args: Any = None, task_id: Any = None, session_id: Any = None, **_kw: Any
) -> str:
    """The setup proposal tool's handler: stores the items the owner's setup screen will list (`proposals.propose`)
    for a call `pre_tool_call` allowed (`_own_tool_gate`'s marker, the same session and checked items), and refuses
    anything else. It writes the proposals file and nothing else: no grant, binding or setting."""
    sid = str(session_id or task_id or "default")
    traffic: TrafficLog | None = None
    try:
        cfg, _env = _load()
        traffic = _state(cfg)[1]
        if not _tool_markers[proposals.TOOL].take(sid, args):
            _tool_refused(traffic, proposals.TOOL, sid, "no_marker", args)
            return setup_report.REFUSAL
        checked = proposals.check(args)
        unchecked = _proposal_unchecked.pop(_unchecked_key(sid, args), True)
        ref = session_ref(sid)
        text, logged = proposals.propose(
            cfg.state_dir, checked, ref, datetime.now(UTC), commands.CMD, unchecked=unchecked
        )
        traffic.write({"kind": "setup_proposal", "session_ref": ref, **logged})
        return text
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook setup proposal failed: %s", exc)
        _tool_refused(traffic, proposals.TOOL, sid, "error", args)
        return setup_report.REFUSAL


def _report_text(cfg: PluginConfig, env: dict[str, str], days: int, now: datetime) -> str:
    notify = owner_settings.notify_of(cfg)
    target, why = _notice_target(cfg)
    if not target:
        where = None
    elif notify.chat_id:
        where = f"a {notify.platform} chat"
    else:
        where = f"the {target} home channel"
    state = {
        "plugin_version": PLUGIN_VERSION,
        "mode": cfg.mode,
        "review_at": cfg.review_at,
        "block_at": cfg.block_at,
        "scan_ok": cfg.endpoints.scan.ok and cfg.endpoints.issuer.ok,
        "credentials_missing": auth_missing_credentials(),
        "notice": {
            "target": where,
            "source": "the notify command"
            if notify.source == "command"
            else "the owner_channel setting",
            "why": why,
        },
        "attended_platforms": sorted(owner_settings.attended_of(cfg)),
        "unsent_grants": len(cfg.unsent_grants),
        "shadowed_skills": None,
        "traffic_log": cfg.traffic_log_enabled,
    }
    data = grants.load(cfg.state_dir)
    force = setup.in_force(cfg, data, now)
    log = cfg.traffic_log_path if cfg.traffic_log_enabled else None
    ev = setup.read_evidence(log, cfg.review_at, now, timedelta(days=days))
    return setup_report.render(
        state, force, ev, now, days, capped=log is not None and setup_report.log_capped(log)
    )


def _allow_key(
    cfg: PluginConfig,
    resp: dict[str, Any],
    planir: dict[str, Any],
    built: dict[str, Any],
    relaxed: bool,
    store: Store,
) -> str | None:
    """The allowance key a Session answer to this review would keep, and a later review is matched by
    (`session_allow`): only on the owner's own turn (whoever answers elsewhere is not known to be the owner), never
    for a block a snooze turned into a review or a score at the block line (a block the scanner capped to a review),
    and None when the review names no party."""
    risk = session_allow.risk_of(resp)
    if relaxed or not grants.may_remember(planir) or risk is None or risk >= cfg.block_at:
        return None
    return session_allow.key(
        str(built.get("tool") or ""), session_allow.parties(resp), store.salt()
    )


def _always_key(
    cfg: PluginConfig,
    resp: dict[str, Any],
    planir: dict[str, Any],
    built: dict[str, Any],
    relaxed: bool,
    store: Store,
) -> str | None:
    """The standing allowance key an Always answer to this review would keep, and a later review is matched by
    (`always_allow`): an MCP tool call with a server identity, on the owner's own turn, as `_allow_key`; never for a
    block a snooze turned into a review or a score at the block line."""
    risk = session_allow.risk_of(resp)
    if relaxed or not grants.may_remember(planir) or risk is None or risk >= cfg.block_at:
        return None
    return always_allow.key(str(built.get("tool") or ""), built.get("provider"), resp, store.salt())


def _cron_run() -> tuple[str | None, str | None, datetime | None]:
    """(the cron job Hermes says the current code runs for, the run as a key, when it started); Nones outside a cron
    run. The key is a hash of Hermes's execution id."""
    try:
        read = getattr(_ctx, "current_cron_execution", None)
        run = read() if callable(read) else None
    except Exception:  # noqa: BLE001 - no cron identity
        return None, None, None
    job_id = getattr(run, "job_id", None)
    if not isinstance(job_id, str) or not job_id.strip():
        return None, None, None
    execution = getattr(run, "execution_id", None)
    key = (
        "r_" + hashlib.sha256(execution.encode()).hexdigest()[:12]
        if isinstance(execution, str) and execution
        else None
    )
    started = getattr(run, "started_at", None)
    at: datetime | None = None
    if isinstance(started, str) and started:
        try:
            at = datetime.fromisoformat(started.replace("Z", "+00:00"))
            at = at if at.tzinfo is not None else None
        except ValueError:
            at = None
    return job_id.strip(), key, at


def _cron_record() -> dict[str, Any] | None:
    """The current cron run as the plugin keeps it on the run's session (`sess["cron"]`): the job, its name, the run
    as a key and when it started, from Hermes's run metadata only. None outside a cron run."""
    job_id, key, started = _cron_run()
    if job_id is None:
        return None
    try:
        read = getattr(_ctx, "current_cron_execution", None)
        name = getattr(read() if callable(read) else None, "job_name", None)
    except Exception:  # noqa: BLE001 - no name: the notice shows the id only
        name = None
    return {
        "job_id": job_id,
        "job_name": name.strip() if isinstance(name, str) and name.strip() else None,
        "run_key": key,
        "started_at": started.isoformat() if started else None,
    }


def _inherited_run(store: Store, sess: dict[str, Any], parent_id: Any) -> dict[str, Any] | None:
    """The cron run a sub-agent belongs to: the one its own session already took from its parent, else its parent
    session's (`sess["cron"]`, kept by the parent's own turns and scans, or taken in turn from its own parent). The
    parent is the one Hermes names for the child's turn (`parent_session_id`), never text. Hermes gives a delegated
    child no cron execution of its own, so this is how its holds and passes reach the job. None when the parent is
    not a cron run, or is not known to the plugin."""
    own = sess.get("cron")
    if isinstance(own, dict) and own.get("job_id"):
        return own
    if not isinstance(parent_id, str) or not parent_id.strip():
        return None
    rec = store.load_session(parent_id).get("cron")
    if not isinstance(rec, dict) or not isinstance(rec.get("job_id"), str) or not rec["job_id"]:
        return None
    return {k: rec.get(k) for k in ("job_id", "job_name", "run_key", "started_at", "session")}


def _run_identity(built: dict[str, Any]) -> tuple[str | None, str | None, datetime | None]:
    """(the cron job, the run as a key, when it started) for the current call: Hermes's own cron execution, else the
    cron run a sub-agent belongs to (`built["job_run"]`)."""
    job_id, key, started = _cron_run()
    if job_id is not None:
        return job_id, key, started
    rec = built.get("job_run")
    if not isinstance(rec, dict) or not rec.get("job_id"):
        return None, None, None
    at = None
    if isinstance(rec.get("started_at"), str):
        try:
            at = datetime.fromisoformat(rec["started_at"])
            at = at if at.tzinfo is not None else None
        except ValueError:
            at = None
    return str(rec["job_id"]), rec.get("run_key"), at


def _run_acted(store: Store, built: dict[str, Any]) -> bool:
    """For a sub-agent of a cron run: whether the run's own session had already sent or written something (`_acted`),
    so `allow` does not start the job again and repeat it."""
    rec = built.get("job_run")
    sid = rec.get("session") if isinstance(rec, dict) else None
    if not isinstance(sid, str) or not sid:
        return False
    try:
        return _acted(store.load_session(sid))
    except Exception:  # noqa: BLE001 - not known: treated as not acted, as for the run's own calls
        return False


def _acted(sess: dict[str, Any]) -> bool:
    """Whether this run had already sent or written something (`passes.acts`) that ran, before the call being held.
    A cron run is a session of its own on Hermes."""
    for e in sess.get("history") or []:
        if not isinstance(e, dict) or not e.get("_acts") or e.get("decision") in NOT_RUN:
            continue
        result = e.get("result")
        if result is None or (isinstance(result, dict) and result.get("status") == "ok"):
            return True
    return False


def _rerun(cfg: PluginConfig, job_id: str, built: dict[str, Any]) -> dict[str, Any] | None:
    """The record of a run the plugin started for an answer, when the current run is it (`passes.run_of`), a
    sub-agent of it included; earlier such runs of the job that ended unseen get their outcome line now."""
    _job, key, started = _run_identity(built)
    try:
        mine, gone = passes.run_of(
            cfg.state_dir, passes.job_ref(job_id), key, started, datetime.now(UTC)
        )
    except Exception as exc:  # noqa: BLE001 - not known as a started run
        logger.warning("sentrook could not read the started runs: %s", exc)
        return None
    for rec in gone:
        _outcome_notice(cfg, rec)
    return mine


def _note_rerun(cfg: PluginConfig, pid: str, **what: Any) -> None:
    try:
        passes.note(cfg.state_dir, pid, **what)
    except Exception as exc:  # noqa: BLE001 - the outcome line may say less
        logger.warning("sentrook could not note the started run: %s", exc)


def _outcome_notice(cfg: PluginConfig, rec: dict[str, Any]) -> None:
    """Tells the owner how a run started for their answer went (`passes.outcome_text`), and logs it."""
    text = passes.outcome_text(rec, hold.OUTCOMES)
    target, why = _notice_target(cfg)
    if target:
        _deliver(cfg, target, text)
    else:
        logger.warning("sentrook started run ended but sent no notice: %s", why)
    _state(cfg)[1].write(
        {
            "kind": "run_now",
            "op": "ended",
            "pass_id": rec.get("id"),
            "hold_id": rec.get("hold_id"),
            "job_ref": rec.get("job_ref"),
            "passed": bool(rec.get("passed")),
            "held": list(rec.get("held") or []),
            "notice": {"status": "queued", "target": hold.target_label(target)}
            if target
            else {"status": "unsent", "target": None, "reason": why},
        }
    )


def on_session_end(**kw: Any) -> None:
    """The end of a turn: when it is the end of a cron run, the owner gets one line listing the run's other held calls
    (`hold.end_of_run`), and, for a run the plugin started for an owner's answer, one line on how it went."""
    try:
        job_id, key, started = _cron_run()
        if job_id is None:
            return
        cfg, _ = _load()
        now = datetime.now(UTC)
        rec = passes.run_end(cfg.state_dir, passes.job_ref(job_id), key, started, now)
        if rec is not None:
            _outcome_notice(cfg, rec)
        _end_lines(cfg, passes.job_ref(job_id), key, now)
    except Exception as exc:  # noqa: BLE001
        logger.warning("on_session_end failed: %s", exc)


def _end_lines(cfg: PluginConfig, ref: str | None, key: str | None, now: datetime) -> None:
    """Sends the run's end line (`hold.end_line_text`) for each group the run leads, and logs it."""
    groups = hold.end_of_run(cfg.state_dir, ref, key, now)
    if not groups:
        return
    target, why = _notice_target(cfg)
    for lead, members, can_all in groups:
        if target:
            _deliver(cfg, target, hold.end_line_text(lead, members, commands.CMD, can_all))
        else:
            logger.warning("sentrook run ended with held calls but sent no end line: %s", why)
        _state(cfg)[1].write(
            {
                "kind": "run_group",
                "op": "end_line",
                "lead": lead.get("id"),
                "listed": [m.get("id") for m in members],
                "job_ref": ref,
                "notice": {"status": "queued", "target": hold.target_label(target)}
                if target
                else {"status": "unsent", "target": None, "reason": why},
            }
        )


def _where(built: dict[str, Any]) -> str:
    """The job or session a held call belongs to, for the owner's notice."""
    return _run_of(built)[0]


def _source_of(built: dict[str, Any]) -> dict[str, str] | None:
    """Where an unattended run that is not a cron job came from, as Hermes's run metadata names it, for binding a
    held call's answers (`passes.source_of`); None when Hermes names nothing usable. Never from the prompt or the
    call:
    - a subagent: its parent session (`parent_session_ref`, from the `parent_session_id` Hermes gives each turn of
      a delegated child);
    - a webhook run: its route, from the user id Hermes's webhook platform binds for an authenticated route
      (`webhook:<route>`); the delivery id in the chat id changes with every delivery, so it is not used.
    An API-server run has no source: Hermes 0.23 checks one shared key and gives the run no key name, and its
    session ids come from the client."""
    planir = built.get("planir") or {}
    if built.get("subagent") or built.get("platform") == "subagent":
        parent = (planir.get("session") or {}).get("parent_session_ref")
        return passes.source_of("subagent", parent) if isinstance(parent, str) else None
    if built.get("platform") == "webhook":
        user = session_facts().get("user_id") or ""
        route = user[len("webhook:") :] if user.startswith("webhook:") else ""
        return passes.source_of("hook", route)
    return None


def _parent_chat(store: Store, turn: dict[str, Any]) -> str | None:
    """The platform of the chat a sub-agent asks its reviews in: its parent session's, when the parent's own scans
    recorded that a sub-agent of it asks there (`sess["children"]`, from `asks_for_children`, or inherited by a
    sub-agent that asks in its own parent's chat). None when the parent session is not known to the plugin or its
    sub-agents hold: the parent is a cron job, a webhook or other unattended run, a chat that is not the owner's, or
    a surface where Hermes answers a child's prompt itself (the classic terminal)."""
    parent = turn.get("parent_session_id")
    if not isinstance(parent, str) or not parent.strip():
        return None
    rec = store.load_session(parent).get("children")
    if not isinstance(rec, dict) or rec.get("ask") is not True:
        return None
    platform = rec.get("platform")
    return platform if isinstance(platform, str) and platform else None


def _parent_pass(
    cfg: PluginConfig, store: Store, built: dict[str, Any], resp: dict[str, Any], kw: dict[str, Any]
) -> dict[str, Any] | None:
    """The owner's pass or denial for sub-agents of this sub-agent's parent session that settles this call
    (`passes.check`), or None: then it is asked."""
    source = _source_of(built)
    if source is None:
        return None
    match = passes.match_of(str(built.get("tool") or ""), resp, kw.get("args"), store.salt(), False)
    try:
        return passes.check(cfg.state_dir, source.get("ref"), match, resp, datetime.now(UTC))
    except Exception as exc:  # noqa: BLE001 - nothing settled: asked
        logger.warning("sentrook could not read the passes: %s", exc)
        return None


def _keep_child_prompt(request_id: str, pending: dict[str, Any]) -> None:
    _child_prompts[request_id] = pending
    while len(_child_prompts) > _CHILD_PROMPTS_KEPT:
        _child_prompts.pop(next(iter(_child_prompts)))


def _child_prompt_fallback(
    cfg: PluginConfig, traffic: TrafficLog, store: Store, request_id: str
) -> dict[str, Any] | None:
    """A sub-agent's review prompt in its parent's chat timed out or could not be shown: the call (not run) becomes a
    hold for the owner, bound to the parent session (`_source_of`), with the usual notice. None when the prompt is
    not known here (asked before a restart)."""
    pending = _child_prompts.pop(request_id, None)
    if pending is None:
        return None
    built, resp, sid = pending["built"], pending["resp"], pending["sid"]
    source = _source_of(built)
    match = passes.match_of(
        str(built.get("tool") or ""), resp, pending.get("args"), store.salt(), source is None
    )
    return _hold(
        cfg,
        traffic,
        built,
        resp,
        sid=sid,
        source=source,
        match=match,
        acted=_acted(store.load_session(sid)),
    )


#: How the owner's notices name a webhook run.
_WEBHOOK_RUN = "webhook run"


def _run_of(built: dict[str, Any]) -> tuple[str, str | None, dict[str, str] | None]:
    """(the job or session a call belongs to, for the owner's notices; the cron job id when Hermes says
    which; else the run's source, when Hermes names one: `_source_of`)."""
    sref = built["planir"]["session"]["session_ref"]
    if built.get("loop_save"):
        return hold.where_text(skill_review.RUN, sref), None, None
    if built.get("background_run"):
        return hold.where_text(skill_review.RUN_CALLS, sref), None, None
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
        return hold.where_text("cron job", sref, job_id.strip(), name), job_id.strip(), None
    source = _source_of(built)
    rec = built.get("job_run")
    if isinstance(rec, dict) and rec.get("job_id"):
        # A sub-agent of a cron run: the job's own holds and passes apply (`_inherited_run`).
        job_id = str(rec["job_id"])
        name = rec.get("job_name") if rec.get("job_name") != job_id else None
        return hold.where_text("cron job", sref, job_id, name, subagent=True), job_id, None
    if built["subagent"] or built["platform"] == "subagent":
        return hold.where_text("subagent run", sref, source=source), None, source
    if built["platform"] == "cron":
        return hold.where_text("cron job", sref), None, None
    if built["platform"] == "webhook":
        return hold.where_text(_WEBHOOK_RUN, sref, source=source), None, source
    return hold.where_text("unattended run", sref), None, None


def _background_save_attended(
    store: Store,
    sess: dict[str, Any],
    kw: dict[str, Any],
    built: dict[str, Any],
    env: dict[str, str],
    attendance: dict[str, Any],
) -> bool:
    """A background save follows a session the owner attends (`owner_attends`), so a snooze may cover it.

    Hermes's review fork fires no `pre_llm_call` (its persistence is off) and calls under a turn id of its own, so its
    own turn names no platform; on a gateway its thread still holds the chat's platform, but the terminal binds none
    (the CLI) or an empty one (the TUI). A save whose own turn, thread and environment name no platform takes it from
    the turn it follows: the latest turn of the same session that fired `pre_llm_call` (`last_turn_id`; the
    background review never moves it). Only when the call names its session, and never from another session's turn
    or an earlier one: a later run in the session (a webhook, the API server), or a turn without an id, ends it. A
    platform found that way is judged like any other, sub-agent included; an empty one is not attended."""
    platform, subagent = built["platform"], attendance["subagent"]
    if not platform and kw.get("session_id"):
        last = store.load_turn(sess.get("last_turn_id"))
        found = last.get("platform") if last.get("pre_llm_call") else None
        if isinstance(found, str) and found.strip():
            platform = found.strip().lower()
            subagent = subagent or platform == "subagent" or bool(last.get("parent_session_id"))
    return owner_attends(platform, env, **{**attendance, "subagent": subagent})


def _deliver(
    cfg: PluginConfig, target: str, text: str, on_fail: Callable[[], None] | None = None
) -> None:
    """Sends one of the owner's notices (`hold.deliver`); one that gets through clears a failed test notice to the
    same target (`owner_settings.notice_delivered`). A notice to a chat Hermes cannot address yet is tried again
    (`notice_retry`)."""
    state_dir = cfg.state_dir
    hold.deliver(
        _ctx,
        target,
        text,
        on_fail=on_fail,
        on_ok=lambda: owner_settings.notice_delivered(state_dir, target),
        state_dir=state_dir,
    )


def _notice_target(cfg: PluginConfig) -> tuple[str | None, str]:
    """(where the owner's notices go, as `hermes send --to` takes it, or None; why there is none): the chat or
    platform set by `/sentrook notify`, else `owner_channel` (see `owner_settings`)."""
    return hold.owner_target(
        owner_settings.notify_of(cfg), callable(getattr(_ctx, "dispatch_tool", None))
    )


def _stage_background(
    cfg: PluginConfig,
    built: dict[str, Any],
    resp: dict[str, Any],
    tool: str,
    args: Any,
    redactor: Redactor,
    declared: bool,
) -> dict[str, Any]:
    """Keeps a held background save in Hermes's pending store where it may be (`staging`). Returns what the scan
    record says: status `staged` (with the store and the pending id), `host` (Hermes's own gate will stage it) or
    `held` (with why not). Never raises: anything that fails holds the save as before."""
    try:
        size = len(json.dumps(args, ensure_ascii=False, default=str).encode("utf-8"))
        why = staging.refusal(
            resp,
            declared=declared,
            redacted=redactor.value(args) != args,
            whole=size <= cfg.input_cap_bytes,
            block_at=cfg.block_at,
        )
        if why is not None:
            return {"status": "held", "reason": why}
        p = staging.plan(tool, args, redactor)
        if isinstance(p, str):
            return {"status": "held", "reason": p}
        if p.by == "hermes":
            return {"status": "host", "store": p.store, "by": "hermes"}
        text = staging.summary(p, rule=resp.get("enforced") == "review")
        pending_id, reason = staging.stage(p, text, cfg.state_dir)
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook could not stage a held background save: %s", exc)
        return {"status": "held", "reason": "failed"}
    if pending_id is None:
        if reason != "over_cap":
            logger.warning("sentrook could not stage a held background save: %s", reason)
        return {"status": "held", "reason": reason}
    return {"status": "staged", "store": p.store, "id": pending_id, "by": "sentrook"}


def _background_info(built: dict[str, Any], resp: dict[str, Any]) -> dict[str, Any] | None:
    """What a background-save notice says about the save, from the plugin's own words and the response's display
    fields only; None when the response is malformed."""
    try:
        planir = built["planir"]
        return {
            "tool": built["tool"],
            "shown": describe(resp, built["tool"]),
            "where": _where(built),
            "category": BLOCK_CATEGORIES[block_category(resp)],
            "rule": resp.get("enforced") == "review",
            "request_id": planir["request_id"],
            "session_ref": planir["session"]["session_ref"],
            "call": planir.get("pending_call"),
        }
    except Exception as exc:  # noqa: BLE001 - a malformed response: not announced
        logger.warning("sentrook could not build a background-save notice: %s", exc)
        return None


def _background_notice(
    cfg: PluginConfig,
    built: dict[str, Any],
    resp: dict[str, Any],
    outcome: str,
    stage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Tells the owner a background save was blocked, held, staged, or let through without asking (`outcome`:
    blocked, held, staged, allowed-lenient or allowed-snoozed; `stage` as `_stage_background` returns it), or that
    another call of the background review was held (`held-call`): once per
    kind and session per quiet period. Returns what the scan record says about the notice. Never raises: the save's
    outcome stands whatever happens here."""
    return _send_background_notice(cfg, _background_info(built, resp), outcome, stage)


def _send_background_notice(
    cfg: PluginConfig,
    info: dict[str, Any] | None,
    outcome: str,
    stage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """`_background_notice` from the notice's facts (`_background_info`); also used once Hermes says what it did
    with a change its own gate stages (outcomes staged, unstaged-saved, unstaged-unknown, held)."""
    target, why = _notice_target(cfg)
    if not target:
        what = (
            "held a background review call"
            if outcome == "held-call"
            else f"{outcome} a background save"
        )
        logger.warning("sentrook %s but sent no notice: %s", what, why)
        return {"status": "unsent", "target": None, "reason": why}
    if info is None:
        return {"status": "unsent", "target": None, "reason": "notice could not be built"}
    kind = "unstaged" if outcome.startswith("unstaged") else outcome
    key = skill_review.quiet_key(kind, info["session_ref"])
    try:
        stamp = scan_failure_notice.claim(cfg.state_dir, key, datetime.now(UTC))
        if stamp is None:
            return {"status": "quiet"}
    except LockTimeout:
        return {"status": "unsent", "target": None, "reason": "notice file locked"}
    except Exception as exc:  # noqa: BLE001 - the outcome stands, just not announced
        logger.warning("sentrook could not read or write background-save notices: %s", exc)
        return {"status": "unsent", "target": None, "reason": "notice file not written"}

    def release() -> None:
        scan_failure_notice.release(cfg.state_dir, key, stamp)

    try:
        tool, shown, where = info["tool"], info["shown"], info["where"]
        call = (
            ()
            if cfg.hide_tool_calls
            else history.call_lines(
                info.get("call"), history.NOTICE_CALL_TOTAL, history.NOTICE_CALL_HEADER
            )
        )
        listed = "the review's calls are" if outcome == "held-call" else "every background save is"
        details = (
            f"Details: {commands.CMD('why')} {info['request_id'][:8]}; {listed} in "
            f"{commands.CMD('history')}."
            if cfg.traffic_log_enabled
            else None
        )
        if outcome == "held-call":
            text = skill_review.held_call_text(
                tool, shown, where, info["category"], details, call=call
            )
        elif outcome in ("blocked", "held"):
            text = skill_review.stopped_text(
                outcome, tool, shown, where, info["category"], details, call=call
            )
        elif outcome == "staged":
            stage = stage or {}  # a staged notice without its record is not built
            text = skill_review.staged_text(
                tool,
                shown,
                where,
                info["category"],
                info["rule"],
                str(stage["store"]),
                str(stage["id"]),
                details,
                by_hermes=stage.get("by") == "hermes",
                call=call,
            )
        elif outcome.startswith("unstaged"):
            text = skill_review.unstaged_text(
                tool, shown, where, details, saved=outcome == "unstaged-saved", call=call
            )
        else:
            text = skill_review.let_through_text(
                tool, shown, where, details, outcome == "allowed-snoozed", call=call
            )
    except Exception as exc:  # noqa: BLE001 - a malformed response: not announced
        logger.warning("sentrook could not build a background-save notice: %s", exc)
        release()
        return {"status": "unsent", "target": None, "reason": "notice could not be built"}
    # Not delivered: the next one of this kind in this session is announced instead.
    _deliver(cfg, target, text, on_fail=release)
    return {"status": "queued", "target": hold.target_label(target)}


def _scan_failure_notice(
    cfg: PluginConfig, built: dict[str, Any], failure: ScanFailure
) -> dict[str, Any]:
    """Tells the owner a scan failure blocked a call on an unattended run: once per cron job (or session)
    per quiet period. Returns what the scan record says about the notice. Never raises: the call is
    blocked whatever happens here."""
    target, why = _notice_target(cfg)
    if not target:
        return {"status": "unsent", "target": None, "reason": why}
    where, job_id, _source = _run_of(built)
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
    _deliver(
        cfg,
        target,
        text,
        on_fail=lambda: scan_failure_notice.release(cfg.state_dir, key, stamp),
    )
    return {"status": "queued", "target": hold.target_label(target)}


def _consent_notice(cfg: PluginConfig, client_id: str) -> dict[str, Any]:
    """Tells the owner, once for these credentials, that the identity service refuses them because consent was
    withdrawn. Kept in the state folder, so a restart does not send it again; `hermes sentrook login` resets it.
    Returns what the scan record says about the notice. Never raises: the call's outcome stands whatever happens."""
    target, why = _notice_target(cfg)
    if not target:
        return {"status": "unsent", "target": None, "reason": why}
    try:
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not consent.claim(cfg.state_dir, client_id, stamp):
            return {"status": "quiet"}
    except LockTimeout:
        return {"status": "unsent", "target": None, "reason": "notice file locked"}
    except Exception as exc:  # noqa: BLE001 - not announced, the call's outcome stands
        logger.warning("sentrook could not read or write the consent notice: %s", exc)
        return {"status": "unsent", "target": None, "reason": "notice file not written"}
    text = consent.withdrawn_text(by_hand=skill_review.host_isolated())
    # Not delivered: the next refused scan announces it instead.
    _deliver(cfg, target, text, on_fail=lambda: consent.release(cfg.state_dir, client_id))
    return {"status": "queued", "target": hold.target_label(target)}


def _hold(
    cfg: PluginConfig,
    traffic: TrafficLog,
    built: dict[str, Any],
    resp: dict[str, Any],
    *,
    sid: str = "",
    job_id: str | None = None,
    source: dict[str, str] | None = None,
    match: dict[str, Any] | None = None,
    acted: bool = False,
) -> dict[str, Any]:
    """Stores the hold and sends the owner's notice; returns what the scan record says about it. The
    call is held whatever happens here: a hold that cannot be stored only cannot be answered. A repeat of
    a waiting hold of the same job and action is counted on it, and no notice is sent. `acted`: the run had
    already sent or written something (then `allow` waits for the next run, and `allow now` is offered).
    `source`: where a run that is not a cron job came from (`_source_of`); the hold's answers are bound to it."""
    now = datetime.now(UTC)
    planir = built["planir"]
    target, why = _notice_target(cfg)
    notice: dict[str, Any] = (
        {"status": "queued", "target": hold.target_label(target)}
        if target
        else {"status": "unsent", "target": None, "reason": why}
    )
    hint = hold.grant_hint(resp, cfg.review_at) if grants.owner_sender(planir) else None
    where = _where(built)
    match = match or {}
    level = passes.offered_level(resp)
    source = None if job_id else source
    offers = passes.offers(
        job_id,
        level,
        bool(match.get("named")),
        session_allow.risk_of(resp),
        cfg.block_at,
        acted,
        source is not None,
    )
    job_digest = None
    if job_id:
        try:
            job_digest = run_now.job_digest(run_now.home(dict(os.environ)), job_id)
        except Exception as exc:  # noqa: BLE001 - not known: allow will not start the job
            logger.warning("sentrook could not read the held call's job: %s", exc)
    repeat = False
    try:
        description = hold.inert(describe(resp, built["tool"]), 160)
    except Exception:  # noqa: BLE001 - a malformed response: no description
        description = ""
    run_key = _run_identity(built)[1] if job_id else None
    if job_id and target:
        # an earlier run of the job that ended where the plugin could not see it: its end line goes out first
        try:
            for lead, members, can_all in hold.stale_groups(
                cfg.state_dir, passes.job_ref(job_id), run_key, _run_identity(built)[2], now
            ):
                _deliver(cfg, target, hold.end_line_text(lead, members, commands.CMD, can_all))
        except Exception as exc:  # noqa: BLE001 - those holds stay listed in status
            logger.warning("sentrook could not send an earlier run's end line: %s", exc)
    group: dict[str, Any] = {}
    try:
        hid, repeat = hold.create(
            cfg.state_dir,
            request_id=planir["request_id"],
            session_ref=planir["session"]["session_ref"],
            tool=built["tool"],
            where=where,
            hint=hint,
            notice=notice,
            now=now,
            record=traffic.write,
            sid=sid,
            job_id=job_id,
            source=source,
            match=match,
            level=level,
            offers=offers,
            description=description,
            job_digest=job_digest,
            acted=acted,
            run_key=run_key,
            acts=passes.acts(built.get("tool_kind"), resp),
            group_out=group,
        )
        if hid is None:
            notice = {"status": "unsent", "target": None, "reason": "holds file unreadable"}
    except LockTimeout:
        hid, notice = None, {"status": "unsent", "target": None, "reason": "holds file locked"}
    except Exception as exc:  # noqa: BLE001 - still held, just not answerable
        logger.warning("sentrook could not store a hold: %s", exc)
        hid, notice = None, {"status": "unsent", "target": None, "reason": "holds file not written"}
    if repeat:
        notice = {"status": "not_sent", "target": None, "reason": "repeat of a waiting hold"}
    elif group.get("lead"):
        # one notice per run: this call is listed in the run's end line (`hold.end_of_run`)
        notice = {
            "status": "not_sent",
            "target": None,
            "reason": "in the run's group",
            "lead": group["lead"],
        }
    elif hid is not None and target:
        try:
            text = hold.notice_text(
                resp,
                built["tool"],
                where,
                hid,
                offers,
                commands.CMD,
                scope="job" if job_id else source["kind"] if source else None,
            )
            _deliver(cfg, target, text)
        except Exception as exc:  # noqa: BLE001 - a malformed response: still held, not announced
            logger.warning("sentrook held a call but could not build its notice: %s", exc)
            notice = {"status": "unsent", "target": None, "reason": "notice could not be built"}
    else:
        logger.warning("sentrook held a call but sent no notice: %s", notice.get("reason"))
    return {
        "id": hid,
        "expires_at": (now + hold.HOLD_TTL).strftime("%Y-%m-%dT%H:%M:%SZ")
        if hid and not repeat
        else None,
        "hint": hint is not None,
        "offers": offers if hid else [],
        **({"repeat": True} if repeat else {}),
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
#: Hermes's answer that approves for the rest of the session: it sets the suggested grant for this session.
_SESSION = {"session"}


def _approval_session_key() -> str:
    """The session key Hermes gives the approval hook for the current chat (`HERMES_SESSION_KEY`, else `default`)."""
    return session_facts().get("key") or "default"


def _remember(
    cfg: PluginConfig,
    traffic: TrafficLog,
    review: dict[str, Any],
    session_key: str,
    session: str | None = None,
) -> dict[str, Any] | None:
    """Sets the suggested grant of a review approved always, as a persistent grant ending in 30 days, or approved
    for the session, as a grant bound to that session (`session`, its `session_ref`), once per review, when the
    answer came from the chat the review was asked in (`session_key`, as the approval hook reports it). Returns the
    grants change, or None when there was nothing to set or it could not be written (logged: the answer itself
    stands)."""
    grant = grants.hint_grant(review.get("hint"))
    if grant is None or review.get("session_key") != session_key:
        return None
    by = {
        "basis": ["review_session" if session else "review_always"],
        "platform": str(review.get("platform") or ""),
    }
    try:
        _reply, change = grants.add_suggested(
            cfg.state_dir,
            grant,
            by,
            datetime.now(UTC),
            hold.GRANT_TTL,
            str(review["request_id"]),
            source="from_review",
            session_ref=session,
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
        # A sub-agent's prompt in its parent's chat that nobody answered in time, or that Hermes could not show: the
        # call is held for the owner, as if the sub-agent had been unattended.
        held = None
        if review.get("child"):
            # The sub-agent's own thread answered it on the terminal surface: no chat showed the prompt (Hermes's
            # callback for a sub-agent's thread denies), so nobody was asked.
            unseen = str(kw.get("surface") or "") == "cli" and not approved
            if choice in _CHILD_FALLBACK or unseen:
                held = _child_prompt_fallback(cfg, traffic, store, str(review["request_id"]))
                if held is not None:
                    final = "held"
                elif unseen:
                    final = "blocked"  # nobody was asked: not the owner's denial"
            else:
                _child_prompts.pop(str(review["request_id"]), None)
        answer_key = str(kw.get("session_key") or "default")
        sid = review["sid"]
        remembered = (
            _remember(cfg, traffic, review, answer_key)
            if approved and choice in _ALWAYS and not review.get("on_error")
            else _remember(cfg, traffic, review, answer_key, session=session_ref(sid))
            if approved and choice in _SESSION and not review.get("on_error")
            else None
        )
        # Session also lets the rest of this job through in the chat it was asked in (`session_allow`).
        allow = review.get("allow") if isinstance(review.get("allow"), dict) else None
        allowed_on = (
            allow
            if allow is not None
            and approved
            and choice in _SESSION
            and not review.get("on_error")
            and review.get("session_key") == answer_key
            else None
        )
        # Always on an MCP tool call also lets later calls of that tool on that server through (`always_allow`).
        standing = review.get("always") if isinstance(review.get("always"), dict) else None
        always_entry = None
        if (
            standing is not None
            and approved
            and choice in _ALWAYS
            and not review.get("on_error")
            and review.get("session_key") == answer_key
        ):
            try:
                always_entry = always_allow.add(
                    cfg.state_dir,
                    k=str(standing["key"]),
                    tool=str(standing["tool"]),
                    server=str(standing["server"]),
                    identity=str(standing["identity"]),
                    risk=float(standing["risk"]),
                    seen=[str(w) for w in standing.get("warnings") or []],
                    request_id=str(review["request_id"]),
                    now=datetime.now(UTC),
                )
            except Exception as exc:  # noqa: BLE001 - the approval stands without the allowance
                logger.warning("sentrook could not keep the Always answer: %s", exc)
        with store.session_lock(sid):
            s = store.load_session(sid)
            if allowed_on is not None:
                session_allow.add(
                    s,
                    str(allowed_on["key"]),
                    float(allowed_on["risk"]),
                    [str(w) for w in allowed_on.get("warnings") or []],
                    str(review["request_id"]),
                    datetime.now(UTC),
                )
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
                **({"session_allow": True} if allowed_on is not None else {}),
                **({"always_allow": always_entry["id"]} if always_entry is not None else {}),
                **({"hold": held} if held is not None else {}),
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("post_approval_response failed: %s", exc)


#: Hermes tools that read one file whole or in part: a read `folders.attest` may vouch for.
FOLDER_READ_TOOLS = frozenset({"read_file"})


def _trusted_folder(cfg: Any, store: Store, sid: str, args: Any, result: str) -> str | None:
    """The id of the owner's folder grant that vouches for the file this read took (`folders.attest`), or None.
    `result` is the tool's result as the model saw it: `read_file` answers JSON whose `content` numbers each line."""
    path = args.get("path") if isinstance(args, dict) else None
    if not isinstance(path, str):
        return None
    try:
        body = json.loads(result)
    except ValueError:
        return None
    content = body.get("content") if isinstance(body, dict) else None
    seen = folders.numbered_lines(content) if isinstance(content, str) and content else None
    if seen is None:
        return None
    live = [
        (g["_id"], g["pattern"])
        for g in grants.effective(cfg, store.load_grants(), datetime.now(UTC), session_ref(sid))
        if g.get("kind") == "folder" and isinstance(g.get("_id"), str)
    ]
    if not live:
        return None
    try:
        return folders.attest(cfg.state_dir, live, path, home=str(Path.home()), seen=seen)
    except Exception as exc:  # noqa: BLE001 - a read the plugin cannot check is simply not vouched for
        logger.debug("folder check failed: %s", exc)
        return None


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
            # A change Hermes's own gate staged did not run: like any call that did not run, it sends no result.
            host_staged = False
            if entry.get("decision") == "host_staging":
                _host_staging_done(cfg, entry, status, result)
                host_staged = entry["decision"] == "staged"
            text = (
                result
                if isinstance(result, str)
                else json.dumps(result, ensure_ascii=False, default=str)
            )
            size = len(text.encode("utf-8"))
            ran = (
                status not in ("blocked", "cancelled")
                and not (entry["decision"] in NOT_RUN and status != "ok")
                and not host_staged
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
                trusted = (
                    _trusted_folder(cfg, store, sid, args if args else entry.get("arguments"), text)
                    if status == "ok" and entry["tool"] in FOLDER_READ_TOOLS
                    else None
                )
                s["buffer"].append(
                    {
                        **({"_trusted_grant": trusted} if trusted else {}),
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


#: What Hermes did with a change its own gate stages -> (the history decision, the resolution, the notice).
_HOST_OUTCOMES = {
    "staged": ("staged", "host_staged", "staged"),
    "saved": ("allowed", "host_saved", "unstaged-saved"),
    "unknown": ("allowed", "host_unknown", "unstaged-unknown"),
    "not_saved": ("held", "host_not_saved", "held"),
}


def _host_staging_done(cfg: PluginConfig, entry: dict[str, Any], status: str, result: Any) -> None:
    """A destructive background memory change the plugin left to Hermes's own gate has run: records what Hermes did
    (staged it, made it, or neither) truthfully and tells the owner. Never raises."""
    try:
        outcome = staging.host_outcome(status, result)
        if outcome["result"] in ("saved", "unknown"):
            # Hermes's gate did not do what the plugin relied on: hold such changes for the rest of this process.
            staging.distrust_gate()
        decision, resolution, notice_kind = _HOST_OUTCOMES[outcome["result"]]
        entry["decision"] = decision
        stage = None
        if outcome["result"] == "staged":
            stage = {
                "status": "staged",
                "store": staging.MEMORY,
                "id": outcome["id"],
                "by": "hermes",
            }
            staging.keep_private(staging.MEMORY, outcome["id"])
        info = entry.pop("_background", None)
        notice = _send_background_notice(cfg, info, notice_kind, stage)
        traffic = _state(cfg)[1]
        traffic.write(
            {
                "kind": "resolution",
                "request_id": entry["request_id"],
                "resolution": resolution,
                "decision": decision,
                **({"pending_id": outcome["id"]} if stage else {}),
                "notice": notice,
            }
        )
        if outcome["result"] != "staged":
            logger.warning(
                "sentrook left a background memory change to Hermes to stage, but Hermes did not: %s",
                outcome["result"],
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook could not record what Hermes did with a background save: %s", exc)


def _known_missing_credentials() -> bool:
    """True only when Hermes says the credentials are unset. At startup a multiplexed gateway has no active
    profile and refuses the read; that is not knowing, so no warning."""
    try:
        from agent.secret_scope import get_secret as hermes_get_secret
    except ImportError:
        return bool(auth_missing_credentials())
    try:
        values = [hermes_get_secret(name) for name in CREDENTIAL_VARS]
    except Exception:  # noqa: BLE001 - an unscoped read on a multiplexed gateway
        return False
    return not all(isinstance(v, str) and v.strip() for v in values)


def register(ctx: Any) -> None:
    global _ctx
    _ctx = ctx
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("post_api_request", on_post_api_request)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("post_approval_response", on_post_approval_response)
    try:
        ctx.register_hook("on_session_end", on_session_end)
    except Exception as exc:  # noqa: BLE001 - an older Hermes: the job's next scan tells the owner instead
        logger.info("sentrook on_session_end not registered: %s", exc)
    try:
        cli.register_cli(ctx, _settings, functools.partial(owner_command, local_cli=True))
    except Exception as exc:  # noqa: BLE001 - older hosts without plugin CLI commands
        logger.info("sentrook CLI not registered: %s", exc)
    try:
        commands.register_slash(ctx, _settings, owner_command)
    except Exception as exc:  # noqa: BLE001 - older hosts without plugin slash commands
        logger.info("/sentrook not registered: %s", exc)
    agent_skills.register(ctx)
    _register_tools(ctx)
    cfg, _ = _load()
    ep = cfg.endpoints
    try:
        _capturing(cfg, _state(cfg)[0])
    except Exception as exc:  # noqa: BLE001
        logger.warning("sentrook state not readable at startup: %s", exc)

    def show(e: Any) -> str:
        return e.url if e.ok else f"INVALID ({e.reason})"

    route, no_route = hold.send_route(callable(getattr(ctx, "dispatch_tool", None)))
    notice_retry.resume(cfg.state_dir)
    try:
        build.record_self(cfg.state_dir)
    except OSError as exc:
        logger.warning("sentrook could not record this process's plugin build: %s", exc)

    logger.info(
        "sentrook %s (build %s) registered: scan=%s issuer=%s%s mode=%s review>=%s block>=%s on_scan_error=%s "
        "skill_review=%s traffic=%s notices=%s",
        PLUGIN_VERSION,
        build.RUNNING.id,
        show(ep.scan),
        show(ep.issuer),
        " (dev endpoints)" if ep.dev else "",
        cfg.mode,
        cfg.review_at,
        cfg.block_at,
        cfg.on_scan_error,
        cfg.skill_review,
        cfg.traffic_log_path if cfg.traffic_log_enabled else "off",
        route or "none",
    )
    if _known_missing_credentials():
        logger.warning(
            "sentrook: not signed in; every tool call is stopped until you %s",
            "set Sentrook's credentials in Hermes (see the install guide) and restart Hermes"
            if skill_review.host_isolated()
            else "run hermes sentrook login on this machine (then restart Hermes)",
        )
    if not ep.scan.ok or not ep.issuer.ok:
        logger.error(
            "sentrook endpoint configuration is invalid; %s",
            invalid_endpoint_effect(cfg.mode, cfg.on_scan_error),
        )
    if cfg.skill_review_unknown is not None:
        logger.warning(
            "sentrook skill_review %r is not allow or review; reading it as allow",
            cfg.skill_review_unknown,
        )
    if skill_review.host_isolated():
        logger.warning("sentrook background saves are %s", skill_review.HOST_ISOLATION_TEXT)
    if route is None:
        logger.warning(
            "sentrook cannot send the owner's notices from this process: %s. Held calls, scan failures on "
            "unattended runs and background saves are recorded (/sentrook history), but nobody is told; see "
            "/sentrook status",
            no_route,
        )
    if unsent := grants.unsent_summary(cfg):
        logger.warning(
            "sentrook config grants never sent: %s. A config grant has no session: drop its scope to "
            "apply it in every session, or use /sentrook grant for one session; see /sentrook grants",
            unsent,
        )


def _register_tools(ctx: Any) -> None:
    """Registers the plugin's own agent tools (toolset `sentrook`): the read-only setup report and the setup proposal.
    Hermes turns plugin toolsets on everywhere, so who may call them is decided in `pre_tool_call`
    (`_own_tool_gate`). Neither sets anything Sentrook allows."""
    _own_tools.clear()
    register_tool = getattr(ctx, "register_tool", None)
    if not callable(register_tool):
        logger.info("sentrook agent tools not registered: this Hermes has no plugin tools")
        return
    tools = (
        (setup_report.TOOL, setup_report.SCHEMA, report_handler, setup_report.DESCRIPTION),
        (
            proposals.TOOL,
            proposals.schema(commands.CMD),
            propose_handler,
            proposals.description(commands.CMD),
        ),
    )
    for name, schema, handler, description in tools:
        try:
            register_tool(
                name=name,
                toolset=setup_report.TOOLSET,
                schema=schema,
                handler=handler,
                description=description,
                emoji="🪶",
            )
            _own_tools[name] = handler
        except Exception as exc:  # noqa: BLE001 - the plugin works without it
            logger.warning("sentrook tool %s not registered: %s", name, exc)


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
