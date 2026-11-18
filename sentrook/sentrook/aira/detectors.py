"""The AIRA detectors: one small function per consequence class over a `CallAnalysis`.

Each detector returns `Finding`s — an internal rule id (evidence only), the class, the reason code
the review card sees, and the contributions, floors and session flags it asserts. Values come from
`lists/weights.yaml`; every list-like thing a detector matches against comes from the other lists.
AIRA does not judge intent: a sanctioned send of credentials carries the same consequence as an
attack, and relief comes from grants and the oracle in convergence.

Classes:
  C1  credential material reached        C2  exfiltration (source × sink), plain sends
  C3  untrusted code executed            C4  self-modification and persistence
  C4* guardrail tampering (floor)        C7  destruction outside scratch (host_gated; SQL arm tier1)
  C8  privilege change (sudo arm host_gated)   C9  irreversible remote side effects
  C10 secret written into an artefact    extent: recursive / wildcard / bulk raise reach
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ..enums import Enforce, SessionFlag
from ..oracle.client import is_local_host
from ..oracle.near_miss import edit_distance_le1, registrable
from ..planir.canonical import CanonicalCall
from ..planir.models import HostApproval, ProviderKind, ToolKind
from ..prepare import Prepared
from ..prepare.entities import (
    EntityKind,
    Origin,
    Role,
    display_path,
    is_computed_package,
    normalise_path,
    normalise_remote_identity,
    provider_name,
    repos_named_in,
    resolve_token,
)
from ..prepare.secret_like import DETECTED, PLACEHOLDER, secret_carried
from ..prepare.sibling_join import sibling_writes
from ..probes.base import Contribution, Floor, SessionMark
from .analysis import CallAnalysis, EntityRef, PathRef
from .exec_shape import ExecSegment, ExecShape, derive_exec_shape
from .lists import Lists, Rule
from .path_classes import _URL_RE, locations_of
from .sensitive_paths import basename_pattern
from .stage_programs import stage_runs_stdin

SENSITIVITY = "consequence.sensitivity"
REACH = "consequence.reach"
IRREVERSIBILITY = "consequence.irreversibility"
SELF_MODIFICATION = "consequence.self_modification"
CONCEALMENT = "suspicion.concealment"

PACK_TIER1 = "tier1"
PACK_HOST_GATED = "host_gated"

#: The sensitive groups C1/C2 score, most sensitive first (the first match wins for a path).
SENSITIVE_GROUPS: tuple[str, ...] = (
    "credential_store",
    "credential_bearing_config",
    "browser_profile",
    "pii_store",
)

#: C4 path groups → (reason, weight key).
SELFMOD_GROUPS: dict[str, tuple[str, str]] = {
    "agent_config": ("selfmod.config", "config"),
    "agent_plugins": ("selfmod.plugin", "plugin"),
    "agent_scheduler": ("selfmod.scheduler", "scheduler"),
    "hooks": ("selfmod.hooks", "hooks"),
    "agent_memory": ("selfmod.memory", "memory"),
    "startup": ("selfmod.startup", "startup"),
    "host_scheduler": ("selfmod.scheduler", "host_scheduler"),
}

#: A declared self-edit's store, as the C4 finding it implies when no path or tool rule found one.
SELF_EDIT_STORES = {"skills": ("selfmod.plugin", "plugin"), "memory": ("selfmod.memory", "memory")}

_WRITE_KINDS = frozenset({ToolKind.FILE_WRITE, ToolKind.FILE_EDIT, ToolKind.MEMORY_WRITE})
_DEVNULL_RE = re.compile(r"2>\s*/dev/null|&>\s*/dev/null|>\s*/dev/null\s+2>&1", re.IGNORECASE)
_PRELOAD_EXPORT_RE = re.compile(r"\b(?:export\s+|setenv\s+)?([A-Z_][A-Z0-9_]*)=")
_GIT_WRITE_VERBS = frozenset({"add", "commit", "stage"})


@dataclass
class Context:
    prepared: Prepared
    lists: Lists
    packs: frozenset[str]
    #: Sensitivity of installing a package nothing vouches for (the convergence parameter set's
    #: `oracle.unvetted_package_sensitivity`; 0 = off).
    unvetted_package_sensitivity: float = 0.0
    #: Carry it for an owner-named package too when the install runs as root.
    unvetted_package_as_root: bool = False
    #: Ecosystems (the entity value's prefix, or `git+` for a URL install) the rule applies to.
    unvetted_package_ecosystems: tuple[str, ...] = ("npm", "pypi", "git+")

    @property
    def groups(self):
        return self.lists.path_groups

    def weight(self, *path: str, default: float = 0.0) -> float:
        return self.lists.weight(*path, default=default)

    @property
    def host_approval_granted(self) -> bool:
        return self.prepared.planir.pending_call.host_approval is HostApproval.GRANTED


@dataclass
class Finding:
    rule: str
    cls: str
    reason: str
    contributions: list[Contribution] = field(default_factory=list)
    floors: list[Floor] = field(default_factory=list)
    flags: list[SessionFlag] = field(default_factory=list)
    marks: list[SessionMark] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def holds_sensitive(self, subject: str | None) -> Finding:
        """The session now holds sensitive data, in `subject` (an entity id); None when it cannot be tied to
        a file, which keeps the session flag's weight on every later send."""
        if SessionFlag.HOLDS_SENSITIVE not in self.flags:
            self.flags.append(SessionFlag.HOLDS_SENSITIVE)
        if not any(m.subject == subject for m in self.marks):
            self.marks.append(SessionMark(judgement="sensitive", subject=subject))
        return self

    def add(self, signal: str, value: float, subject: str | None = None, reason: str | None = None):
        self.contributions.append(
            Contribution(
                signal=signal, value=_clamp(value), subject=subject, reason=reason or self.reason
            )
        )
        return self

    def to_evidence(self, call_id: str | None) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "class": self.cls,
            "reason": self.reason,
            "call_id": call_id,
            "contributions": [
                {"signal": c.signal, "value": c.value, "subject": c.subject, "reason": c.reason}
                for c in self.contributions
            ],
            "floors": [f.floor for f in self.floors],
            "flags": [f.value for f in self.flags],
            **self.detail,
        }


Detector = Callable[[CallAnalysis, Context], list[Finding]]


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(float(value), 4)))


def _match_any(rules: Iterable[re.Pattern[str]], subject: str) -> re.Match[str] | None:
    for rx in rules:
        m = rx.search(subject)
        if m:
            return m
    return None


def _tool_matches(a: CallAnalysis, lists: Lists, list_name: str, key: str) -> Rule | None:
    """Match the tool name against a list of `{pattern, reason}` rules or plain patterns, each
    allowed a namespace prefix (`gmail__send`, `server.delete_x`)."""
    prefix = str(lists.get(list_name, "tool_name_prefix", default=r"(?:\A|__|[.:/])"))
    name = a.tool or ""
    for rule in lists.rules(list_name, key):
        if re.search(prefix + rule.regex.pattern, name, re.IGNORECASE):
            return rule
    for rx in lists.patterns(list_name, key):
        if re.search(prefix + rx.pattern, name, re.IGNORECASE):
            return Rule(rx, {})
    return None


def _read_action(a: CallAnalysis, lists: Lists, list_name: str) -> bool:
    action = a.call.get("action")
    if not isinstance(action, str):
        return False
    return action.strip().lower() in {s.lower() for s in lists.strings(list_name, "read_actions")}


def _top_sensitive_group(groups: Iterable[str]) -> str | None:
    gs = set(groups)
    for g in SENSITIVE_GROUPS:
        if g in gs:
            return g
    return None


def _written_paths(a: CallAnalysis, ctx: Context) -> list[tuple[PathRef, str]]:
    """Paths this call writes, moves, deletes or redirects into, with the mechanism. For exec, a
    path counts when it is a redirect target, or a positional of a writing head (for `cp`/`rsync`/
    `install`/`ln` only the last positional is the destination)."""
    out: list[tuple[PathRef, str]] = []
    seen: set[str] = set()

    def add(ref: PathRef | None, mechanism: str) -> None:
        if ref is not None and ref.value not in seen:
            seen.add(ref.value)
            out.append((ref, mechanism))

    if a.kind in _WRITE_KINDS or a.kind in (ToolKind.MCP, ToolKind.OTHER):
        for p in a.paths:
            if p.is_destination:
                add(p, a.kind.value)
        return out
    if a.kind is not ToolKind.EXEC:
        return out

    for p in a.paths:
        if p.is_destination:
            add(p, "exec_destination")
    shape = a.shape
    if shape is None:
        return out
    writing = {h.lower() for h in ctx.lists.strings("guardrail", "writing_heads")}
    destination_only = {h.lower() for h in ctx.lists.strings("guardrail", "destination_heads")}
    for target in shape.redirect_targets:
        add(_path_ref(a, ctx, target), "redirect")
    for seg in shape.segments:
        if seg.head not in writing:
            continue
        if seg.head == "sed" and not seg.has_flag_letter("i") and "--in-place" not in seg.flags:
            continue
        positionals = [t for t in seg.positional if t != "-"]
        if seg.head in destination_only:
            positionals = positionals[-1:]
        for tok in positionals:
            add(_path_ref(a, ctx, tok), f"head:{seg.head}")
        for tok in seg.redirects:
            add(_path_ref(a, ctx, tok), "redirect")
    return out


def _path_ref(a: CallAnalysis, ctx: Context, token: str) -> PathRef | None:
    """A `PathRef` for a token, resolving through the analysis when preparation saw the path and
    classifying it on the fly otherwise."""
    tok = token.strip().strip("'\"")
    if not tok or tok.startswith("-"):
        return None
    if "=" in tok and not tok.startswith(("/", "~", ".")):
        tok = tok.rsplit("=", 1)[1]
    tok = tok.lstrip("@")
    wildcard = False
    if tok.endswith(("/*", "/**")):
        tok = tok.rsplit("/", 1)[0] or "/"
        wildcard = True
    elif "*" in tok:
        tok = tok.split("*", 1)[0].rstrip("/") or "/"
        wildcard = True
    if not tok.startswith(("/", "~", "$HOME", "./", "../")):
        if "/" not in tok and not wildcard:
            # A bare relative token: the group basenames cover the sensitive case; a location is
            # unknowable without cwd, so it resolves against cwd or the workspace.
            pass
        base = a.cwd or ctx.prepared.workspace_root
        tok = base.rstrip("/") + "/" + tok
    value = normalise_path(
        tok, home=ctx.prepared.home, workspace_root=ctx.prepared.workspace_root, cwd=a.cwd
    )
    ref = a.path(value)
    if ref is not None:
        return ref
    groups = ctx.groups
    roles = [name for name, g in groups.items() if g.search(value)]
    ent = ctx.prepared.entities.get(EntityKind.PATH, value)
    return PathRef(
        value=value,
        display=value,
        roles={Role.DATA_DESTINATION},
        groups=roles,
        locations=locations_of(value, ctx.prepared.workspace_root, ctx.prepared.home),
        entity_id=ent.id if ent else None,
    )


# =========================================================================== C1


def _reaching(a: CallAnalysis, ctx: Context) -> bool:
    lists = ctx.lists
    reach_heads = (
        lists.binary_set("reading_binaries")
        | lists.binary_set("listing_binaries")
        | lists.binary_set("fetch_binaries")
        | lists.binary_set("interpreter_binaries")
    )
    if a.heads & reach_heads:
        return True
    return _match_any(lists.patterns("egress", "file_arg_patterns"), a.scan_text) is not None


def _credential_home_file(ctx: Context, p: PathRef) -> bool:
    """The env file whose keys the call sends only to their own service (`prepare.credential_home`): read for that,
    it is not credential material leaving the machine."""
    home = getattr(ctx.prepared, "credential_home", None)
    if home is None:
        return False
    return (p.entity_id is not None and p.entity_id in home.env_files) or p.value in home.env_paths


def detect_credentials(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C1: credential material reached — a sensitive path with a reading head, a `file_read`, a
    listing of a credential directory, or an `@file` form. An env file read for a key the call sends only to its
    own service (`prepare.credential_home`) carries no sensitivity; it still joins the session's sensitive set."""
    if a.kind is ToolKind.EXEC:
        if not _reaching(a, ctx):
            return []
    elif a.kind not in (ToolKind.FILE_READ, ToolKind.MCP, ToolKind.OTHER):
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for p in a.paths:
        if a.kind is ToolKind.EXEC and p.is_destination and not p.is_source:
            continue  # a write or delete target is not a read
        if a.kind in (ToolKind.MCP, ToolKind.OTHER) and not p.is_source:
            continue
        g = _top_sensitive_group(p.groups)
        if g is None:
            continue
        f = Finding(rule=f"C1.{g}", cls="C1", reason=f"path.{g}", detail={"path": p.display})
        if _credential_home_file(ctx, p):
            f.detail["credential_home"] = True
        else:
            f.add(SENSITIVITY, ctx.weight("sensitivity", g), p.entity_id)
        f.holds_sensitive(p.entity_id)
        out.append(f)
        seen.add(g)
    # A bare basename after a `cd`, or a reference tokenisation lost: scored without a subject.
    for g in SENSITIVE_GROUPS:
        if g in a.text_groups and g not in seen and not any(g in p.groups for p in a.paths):
            f = Finding(
                rule=f"C1.{g}.text",
                cls="C1",
                reason=f"path.{g}",
                detail={"mechanism": "text_match"},
            )
            f.add(SENSITIVITY, ctx.weight("sensitivity", g))
            f.holds_sensitive(None)
            out.append(f)
            seen.add(g)
    return out


# =========================================================================== C2


@dataclass
class Sink:
    reason: str
    destinations: list[EntityRef]
    mechanism: str


@dataclass
class Source:
    reason: str
    weight: float
    subject: str | None
    detail: str


def _in_pipeline_tail(shape: ExecShape, index: int) -> bool:
    return any(index in p[1:] for p in shape.pipelines)


def _exec_sinks(a: CallAnalysis, ctx: Context) -> list[Sink]:
    sinks: list[Sink] = []
    shape = a.shape
    dests = a.destination_hosts()
    recipients = list(a.recipients)
    rules = ctx.lists.rules("egress", "exec_markers")
    seen: set[str] = set()

    def consider(seg_text: str, head: str | None, index: int | None) -> None:
        for rule in rules:
            want_head = rule.get("head")
            if want_head and head is not None and head != want_head:
                continue
            if (
                want_head
                and head is None
                and not re.search(r"\b" + re.escape(want_head) + r"\b", seg_text)
            ):
                continue
            if rule.get("requires_pipe"):
                if shape is None or index is None or not _in_pipeline_tail(shape, index):
                    continue
            if not rule.regex.search(seg_text):
                continue
            reason = str(rule.get("reason", "exfil.exec_egress"))
            if reason in seen:
                continue
            seen.add(reason)
            targets = recipients if reason == "exfil.message_send" and recipients else dests
            sinks.append(Sink(reason=reason, destinations=targets, mechanism=rule.regex.pattern))

    if shape is not None and shape.parse_ok and shape.segments:
        for i, seg in enumerate(shape.segments):
            consider(" ".join([seg.head, *seg.argv]), seg.head, i)
        if a.decoded_shape is not None and a.decoded_shape.segments:
            for i, seg in enumerate(a.decoded_shape.segments):
                consider(" ".join([seg.head, *seg.argv]), seg.head, i)
    else:
        for line in a.segment_texts():
            consider(line, None, None)
    if a.inline_code:
        consider(a.scan_text, None, None)
    return sinks


def _sinks(a: CallAnalysis, ctx: Context) -> list[Sink]:
    lists = ctx.lists
    if a.kind is ToolKind.EXEC:
        return _exec_sinks(a, ctx)
    if a.kind.value in lists.strings("egress", "sink_tool_kinds"):
        dests = [*a.recipients, *a.channels] or a.destination_hosts()
        return [Sink("exfil.message_send", dests, "tool_kind")]
    if a.kind.value in lists.strings("egress", "web_body_kinds"):
        method = str(a.call.get("method") or "GET").upper()
        if method in lists.strings("egress", "web_body_methods") or a.call.get("body"):
            return [Sink("exfil.web_post", a.destination_hosts(), "body")]
        if a.call is ctx.prepared.pending and ctx.prepared.url_carries:
            # No body, but the URL reproduces a local read: the query and path reach the server too.
            return [Sink("exfil.web_query", a.destination_hosts(), "url")]
        return []
    if a.kind in (ToolKind.MCP, ToolKind.OTHER, ToolKind.SUBAGENT_SPAWN):
        if a.kind is ToolKind.SUBAGENT_SPAWN:
            return []
        if _tool_matches(a, lists, "egress", "send_tool_name_patterns") is None:
            return []
        if a.recipients or a.channels:
            return [Sink("exfil.message_send", [*a.recipients, *a.channels], "tool_name")]
        dests = a.destination_hosts() or a.providers
        return [Sink("exfil.web_post", dests, "tool_name")]
    return []


def sole_destination_providers(a: CallAnalysis, lists: Lists) -> list[EntityRef]:
    """The MCP servers or plugins a send tool hands its data to when the call names no recipient, channel
    or host: the provider is then the only known destination of the send (the same reading `_sinks`
    makes). Empty for every other call."""
    if a.kind not in (ToolKind.MCP, ToolKind.OTHER):
        return []
    if _tool_matches(a, lists, "egress", "send_tool_name_patterns") is None:
        return []
    if a.recipients or a.channels or a.destination_hosts():
        return []
    return list(a.providers)


def _owner_asked_for_secret(ctx: Context) -> bool:
    """The owner's own words ask for a secret value to go with the send ("send the gate code to …",
    "include the env value I gave you"): the lineage rule's `secret_request_terms` and
    `secret_like_request_terms`."""
    words = ctx.prepared.request_words or ""
    return any(
        rx.search(words)
        for name in ("secret_request_terms", "secret_like_request_terms")
        for rx in ctx.lists.patterns("lineage", name, "patterns")
    )


def _placeholder_paths(ctx: Context) -> dict[str, str]:
    """Paths written with a secret, by an earlier step or by a sibling in the pending call's batch (a
    file staged for the send in the same turn), each with why (`prepare.secret_like.secret_carried`): a
    placeholder, a shape the second redaction pass masks, or a secret-like value the redactors leave
    raw. A value only the secret-like detector finds does not count when the owner asked for a secret
    to go. A later write of the same path that carries no secret does not clear an earlier one."""
    out: dict[str, str] = {}
    open_ = _placeholder(ctx)
    asked = _owner_asked_for_secret(ctx)
    home, ws = ctx.prepared.home, ctx.prepared.workspace_root

    def add(path: str, why: str | None) -> None:
        if why is not None and (out.get(path) in (None, DETECTED)):
            out[path] = why

    for h in ctx.prepared.history:
        if h.tool_kind in _WRITE_KINDS and h.path:
            why = secret_carried(str(h.get("content") or ""), open_, owner_asked=asked)
            add(normalise_path(h.path, home=home, workspace_root=ws), why)
    for s in ctx.prepared.siblings:
        for w in sibling_writes(s, home=home, workspace_root=ws):
            if w.content is not None:
                add(w.path, secret_carried(w.content, open_, owner_asked=asked))
    return out


def _secret_weight(ctx: Context, why: str) -> float:
    """A value only the secret-like detector finds is less certain than a redactor's placeholder."""
    return ctx.weight("sensitivity", "secret_like" if why == DETECTED else "placeholder")


def _sources(a: CallAnalysis, ctx: Context) -> list[Source]:
    sources: list[Source] = []
    written_with_placeholder = _placeholder_paths(ctx)
    attached = {p.value for p in a.attachments}
    for p in a.paths:
        if a.kind is ToolKind.EXEC and p.is_destination and not p.is_source:
            continue
        g = _top_sensitive_group(p.groups)
        if g is not None and _credential_home_file(ctx, p):
            continue  # its key goes only to its own service
        if g is not None:
            reason = "exfil.attachment" if p.value in attached else f"path.{g}"
            sources.append(Source(reason, ctx.weight("sensitivity", g), p.entity_id, p.display))
        elif p.value in written_with_placeholder and (p.is_source or p.value in attached):
            reason = "exfil.attachment" if p.value in attached else "exfil.placeholder_in_argv"
            why = written_with_placeholder[p.value]
            sources.append(
                Source(
                    reason,
                    _secret_weight(ctx, why),
                    p.entity_id,
                    f"{p.display} (written with a secret: {why})",
                )
            )
    covered = {s.reason.removeprefix("path.") for s in sources}
    for g in SENSITIVE_GROUPS:
        if g in a.text_groups and g not in covered and not any(g in p.groups for p in a.paths):
            sources.append(Source(f"path.{g}", ctx.weight("sensitivity", g), None, "text_match"))
    why = _secret_in_call(a, ctx)
    if why is not None:
        sources.append(Source("exfil.placeholder_in_argv", _secret_weight(ctx, why), None, why))
    session = _session_sensitive_source(ctx)
    if session is not None:
        sources.append(session)
    return sources


def _session_sensitive_source(ctx: Context) -> Source | None:
    """The session's sensitive data as a source of this send, bound to what it is about: the file or table
    the session judged sensitive when the call takes content from it; the bare session flag when the
    call has nothing to match (a raw body, a pipe) or the session holds sensitive data it could not tie to
    a file; nothing when the call takes content only from other files and tables."""
    prepared = ctx.prepared
    binding = prepared.session_binding.sensitive
    weight = ctx.weight("sensitivity", "session_holds_sensitive")
    if getattr(prepared, "credential_home", None) is not None:
        # the check found the session's sensitive data to be only the env files whose key goes to its own service
        return None
    if binding.bound:
        return Source(
            "exfil.session_holds_sensitive",
            weight,
            binding.subject(),
            "session: " + ", ".join(binding.names()),
        )
    if SessionFlag.HOLDS_SENSITIVE not in prepared.state.flags:
        return None
    if binding.identifiable and not prepared.state.sensitive_unbound:
        return None
    return Source("exfil.session_holds_sensitive", weight, None, "session flag")


def _placeholder(ctx: Context) -> str:
    return str(ctx.lists.get("egress", "placeholder", "open", default="⟦secret"))


def _secret_in_call(a: CallAnalysis, ctx: Context) -> str | None:
    """Why the call's own arguments carry a secret (`prepare.secret_like.secret_carried`), or None. The
    arguments are read as their joined text and as JSON, so a value under a key (`{"pin": "3253"}`)
    is seen with its key."""
    open_ = _placeholder(ctx)
    if a.placeholder or (a.content and open_ in a.content):
        return PLACEHOLDER
    asked = _owner_asked_for_secret(ctx)
    why = secret_carried(a.text, open_, owner_asked=asked)
    if why is None and isinstance(a.call.raw, dict) and a.call.raw:
        why = secret_carried(json.dumps(a.call.raw, ensure_ascii=False), open_, owner_asked=asked)
    return why


def detect_exfil(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C2: a sensitive source reaching a sink is exfiltration; a sink alone is a send."""
    sinks = _sinks(a, ctx)
    if not sinks:
        return []
    sources = _sources(a, ctx)
    # An env file whose key the call sends only to its own service is no source, but the session still holds it.
    home_files = [
        p.entity_id
        for p in a.paths
        if _top_sensitive_group(p.groups) is not None and _credential_home_file(ctx, p)
    ]
    out: list[Finding] = []
    if sources:
        for sink in sinks:
            f = Finding(
                rule=f"C2.{sink.reason}",
                cls="C2",
                reason=sink.reason,
                detail={
                    "mechanism": sink.mechanism,
                    "sources": [s.detail for s in sources],
                    "destinations": [d.value for d in sink.destinations],
                },
            )
            for dest in sink.destinations or [None]:
                subject = dest.entity_id if dest is not None else None
                f.add(REACH, ctx.weight("exfil", "reach"), subject)
                f.add(IRREVERSIBILITY, ctx.weight("exfil", "irreversibility"), subject)
            for src in sources:
                f.add(SENSITIVITY, src.weight, src.subject, src.reason)
                if src.reason != "exfil.session_holds_sensitive":
                    f.holds_sensitive(src.subject)
            if SessionFlag.HOLDS_SENSITIVE not in f.flags:
                f.flags.append(SessionFlag.HOLDS_SENSITIVE)
            out.append(f)
        return out
    for sink in sinks:
        f = Finding(
            rule=f"C2.send.{sink.reason.split('.')[-1]}",
            cls="C2",
            reason="send.off_host",
            detail={
                "mechanism": sink.mechanism,
                "destinations": [d.value for d in sink.destinations],
            },
        )
        for dest in sink.destinations or [None]:
            subject = dest.entity_id if dest is not None else None
            f.add(REACH, ctx.weight("send", "reach"), subject)
            f.add(IRREVERSIBILITY, ctx.weight("send", "irreversibility"), subject)
        for subject in home_files:
            f.holds_sensitive(subject)
        out.append(f)
    return out


# =========================================================================== C3


def _stage_heads(shape: ExecShape) -> list[list[ExecSegment]]:
    return [[shape.segments[i] for i in p if i < len(shape.segments)] for p in shape.pipelines]


def _fetch_to_shell(shape: ExecShape | None, ctx: Context) -> str | None:
    if shape is None:
        return None
    lists = ctx.lists
    fetch = set(lists.strings("installers", "fetch_heads"))
    shells = set(lists.strings("installers", "shell_heads"))
    interp = set(lists.strings("installers", "interpreter_heads"))
    evals = set(lists.strings("installers", "eval_heads"))
    out_flags = set(lists.strings("installers", "fetch_output_flags"))
    for stages in _stage_heads(shape):
        for i, seg in enumerate(stages):
            if seg.head in fetch and any(
                t.head in evals or (t.head in shells | interp and stage_runs_stdin(t, lists))
                for t in stages[i + 1 :]
            ):
                return "pipeline"
    heads = set(shape.heads)
    if shape.substitution and heads & fetch and heads & (shells | evals):
        return "substitution"
    fetch_segments = [
        s
        for s in shape.segments
        if s.head in fetch
        and (set(s.flags) & out_flags or any(f.startswith("-o") for f in s.flags))
    ]
    # The fetched file run directly (`./helper.bin`): the parser reports the basename as the head.
    fetched_names = {
        os.path.basename(t.rstrip("/"))
        for s in fetch_segments
        for t in s.positional
        if not _URL_RE.match(t)
    }
    if fetch_segments and any(
        s.head in shells | interp
        or (s.head == "chmod" and any("x" in f for f in [*s.flags, *s.positional[:1]]))
        or (s.head in fetched_names and s.head not in fetch)
        for s in shape.segments
    ):
        return "fetch_then_run"
    return None


def _text_fetch_to_shell(text: str, ctx: Context) -> re.Match[str] | None:
    """The text fallback, for fetch-to-shell shapes the command's parse does not show (inside a
    quoted program, a decoded URL parameter). A match whose line parses as a pipeline goes through
    the same stage check as the command, so a stage that brings its own program is silent here too;
    one that does not parse still counts."""
    for rx in ctx.lists.patterns("installers", "fetch_to_shell_patterns"):
        for m in rx.finditer(text):
            end = text.find("\n", m.start())
            shape = derive_exec_shape(
                text[m.start() : end if end >= 0 else None], ctx.lists.path_groups
            )
            if shape.parse_ok and shape.pipelines and _fetch_to_shell(shape, ctx) is None:
                continue
            return m
    return None


def _decode_to_shell(shape: ExecShape | None, ctx: Context) -> str | None:
    if shape is None:
        return None
    lists = ctx.lists
    shells = set(lists.strings("installers", "shell_heads"))
    interp = set(lists.strings("installers", "interpreter_heads"))
    evals = set(lists.strings("installers", "eval_heads"))
    decoders = {
        str(d["head"]): {str(f) for f in d.get("flags") or ()}
        for d in lists.get("installers", "decode_heads", default=[]) or []
        if isinstance(d, dict) and "head" in d
    }
    encoded_literal = lists.patterns("installers", "encoded_literal_patterns")

    def is_decoder(seg: ExecSegment) -> bool:
        flags = decoders.get(seg.head)
        if flags is not None:
            return not flags or bool(set(seg.argv) & flags)
        if seg.head in ("printf", "echo"):
            return _match_any(encoded_literal, " ".join(seg.argv)) is not None
        return False

    for stages in _stage_heads(shape):
        for i, seg in enumerate(stages):
            if is_decoder(seg) and any(t.head in shells | interp | evals for t in stages[i + 1 :]):
                return "pipeline"
    if shape.substitution and any(is_decoder(s) for s in shape.segments):
        if set(shape.heads) & (shells | evals):
            return "substitution"
    return None


def _is_listed_installer(host: str, ctx: Context) -> bool:
    host = host.lower().strip(".")
    for listed in ctx.lists.strings("installers", "installer_hosts"):
        listed = listed.lower().strip(".")
        if host == listed or host.endswith("." + listed):
            return True
    return False


def _add_unvetted_sensitivity(
    f: Finding, code_source: EntityRef | None, subject: str | None, ctx: Context
) -> None:
    """Code from a host that is not a listed installer runs with the agent's own read access: its
    sensitivity is what the agent can read (`weights.yaml` `code.sensitivity_unvetted`), whatever
    the command names. A listed installer host, or no host at all, adds nothing. A repository on a
    multi-tenant host is never a listed installer: the list vouches for hosts, and any account
    publishes there."""
    if code_source is None:
        return
    if code_source.kind is not EntityKind.REPO and _is_listed_installer(code_source.value, ctx):
        return
    weight = ctx.weight("code", "sensitivity_unvetted")
    if weight > 0:
        f.add(SENSITIVITY, weight, subject, "code.unvetted_source")


def _add_unvetted_package_sensitivity(
    f: Finding, pkg: EntityRef, ctx: Context, *, as_root: bool = False
) -> None:
    """A package's install scripts run with the agent's own read access. When the entity library
    does not know the package and neither the owner's request nor a grant names it, nobody vouched
    for that code: the install carries the unvetted-package sensitivity. A package the library
    knows, or one the owner named or granted, adds nothing (the owner's word is the vouching);
    with `unvetted_package_as_root` on, an owner-named package the library does not know carries it
    all the same when the install runs as root (`as_root`). Only in the ecosystems the library
    covers with known-good packages, and for installs from a URL: for a system package manager the
    library has no list of, "unknown" means not covered, not unvetted. An operand computed at run
    time counts in every ecosystem: no list could know it.
    Without the library's answer (the oracle off or failing) no package is known: fail closed."""
    weight = ctx.unvetted_package_sensitivity
    ent = ctx.prepared.entities.by_id(pkg.entity_id or "")
    if weight <= 0 or ent is None:
        return
    root_named = ent.sanctioned and as_root and ctx.unvetted_package_as_root
    if ent.sanctioned and not root_named:
        return
    ecosystem = "git+" if ent.value.startswith("git+") else ent.value.split(":", 1)[0]
    covered = ecosystem in ctx.unvetted_package_ecosystems or is_computed_package(ent.value)
    if not covered and not root_named:
        return
    info = ctx.prepared.oracle_entities.get(ent.id)
    if isinstance(info, dict) and info.get("verdict") != "unknown":
        return
    f.add(SENSITIVITY, weight, ent.id, "code.unvetted_package")


def _library_near_miss(code_source: EntityRef, ctx: Context) -> str | None:
    """The `known_good` library entry the code source is a near miss of, when the oracle answered
    before AIRA ran; None otherwise."""
    info = ctx.prepared.oracle_entities.get(code_source.entity_id or "")
    if not isinstance(info, dict) or info.get("verdict") != "unknown":
        return None
    near = info.get("near_miss")
    if not isinstance(near, dict) or near.get("verdict") != "known_good" or not near.get("value"):
        return None
    return str(near["value"])


def _steered_source(code_source: EntityRef, ctx: Context) -> Finding | None:
    """Fetched code from a host named in content that tried to steer the agent (it asked the agent to
    keep the action from the owner): the floor. Not when the owner
    named or granted the host, it is a listed installer or a host the library vouches for, or it is
    the agent's own machine. Without the library's answer (the oracle off or failing) a vouched-for
    host cannot be told from any other, so it is floored too: fail closed, on a degraded scan."""
    ent = ctx.prepared.entities.by_id(code_source.entity_id or "")
    if ent is None or not ent.steered or ent.sanctioned:
        return None
    if ent.kind is EntityKind.REPO and ent.value in repos_named_in(ctx.prepared.request_words):
        # The owner asked for this repository by a URL of it. That vouches for nothing (a repository the owner
        # names is still scored as an unknown code source), but the run is the owner's, not the steering
        # content's.
        return None
    if _is_listed_installer(code_source.value, ctx) or is_local_host(code_source.value):
        return None
    info = ctx.prepared.oracle_entities.get(ent.id)
    if isinstance(info, dict) and info.get("verdict") == "known_good":
        return None
    this_step = [
        seq
        for seq in sorted(ctx.prepared.steered_inputs)
        if f"input:{seq}" in (ent.origins.get(Origin.UNTRUSTED_INPUT) or ())
    ]
    markers = sorted({m for seq in this_step for m in ctx.prepared.steered_inputs[seq]})
    g = Finding(
        rule="C3.steered_source",
        cls="C3",
        reason="code.steered_source",
        detail={
            "host": code_source.value,
            "when": "this_step" if this_step else "earlier_step",
            "markers": markers,
        },
    )
    g.floors.append(
        Floor(
            floor="untrusted_code_execution",
            min_risk=ctx.weight("code", "decode_floor_min_risk", default=0.9),
            enforce=Enforce.BLOCK,
            subject=ent.id,
            reason="code.steered_source",
        )
    )
    return g


def detect_untrusted_code(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C3: fetch-to-shell, decode-to-shell (floor), install-from-URL, package install, running a
    file written since a fetch."""
    out: list[Finding] = []
    lists = ctx.lists
    if a.kind is not ToolKind.EXEC:
        return out
    # A repository on a multi-tenant host is the code source before any host: the host only serves it.
    code_source = next(
        (r for r in a.repos if Role.CODE_SOURCE in r.roles),
        next((h for h in a.hosts if Role.CODE_SOURCE in h.roles), a.hosts[0] if a.hosts else None),
    )
    host_subject = code_source.entity_id if code_source else None
    # Each repository the command takes code from carries its own sensitivity, and so does every
    # host it takes code from, so a grant on one never covers another; with no code source named,
    # the fallback host does.
    unvetted_sources = [
        *(r for r in a.repos if Role.CODE_SOURCE in r.roles),
        *(h for h in a.hosts if Role.CODE_SOURCE in h.roles),
    ] or ([code_source] if code_source is not None else [])
    reach, irr = ctx.weight("code", "reach"), ctx.weight("code", "irreversibility")
    as_root = a.shape is not None and a.shape.privileged

    # What the command does as written, and what it does once decoding is undone.
    raw_fetch = _fetch_to_shell(a.shape, ctx)
    text_fetch = _text_fetch_to_shell(a.text, ctx)
    decoded_fetch = _fetch_to_shell(a.decoded_shape, ctx)
    decoded_pipe = a.decoded_shape is not None and bool(
        set(a.decoded_shape.sinks) & {"pipe_to_shell", "pipe_to_interpreter"}
    )

    decode_mech = _decode_to_shell(a.shape, ctx)
    if (
        decode_mech is None
        and (a.encodings & {"base64", "hex"})
        and (decoded_fetch or decoded_pipe)
    ):
        decode_mech = "decoded_shape"
    if decode_mech is None and _match_any(
        lists.patterns("installers", "decode_text_patterns"), a.scan_text
    ):
        decode_mech = "text"

    fetch_mech = raw_fetch or ("text" if text_fetch else None)
    obfuscated = False
    if fetch_mech is None and decode_mech is None and decoded_fetch:
        # Visible only after undoing quote splitting (`"cu""rl" … | sh`): a fetch-to-shell whose
        # head was hidden, which is concealment but not an encoded payload.
        fetch_mech, obfuscated = decoded_fetch, True
    if fetch_mech:
        f = Finding(
            rule="C3.fetch_to_shell",
            cls="C3",
            reason="code.fetch_to_shell",
            detail={"mechanism": fetch_mech},
        )
        f.add(REACH, reach, host_subject).add(IRREVERSIBILITY, irr, host_subject)
        for source in unvetted_sources:
            _add_unvetted_sensitivity(f, source, source.entity_id, ctx)
        if obfuscated:
            f.detail["revealed_by"] = sorted(a.encodings)
            f.add(
                CONCEALMENT, ctx.weight("priv", "concealment"), None, "conceal.obfuscated_command"
            )
        out.append(f)
        # Look-alike installer host: strong evidence, the floor. The installer list, or the entity
        # library when the oracle answered first: a near miss of a host the library vouches for (the
        # library vouches for code sources only). An unlisted host that mimics nothing is scored by
        # consequence and the oracle's distrust, and floored only when it came from content that tried
        # to steer the agent (below). Every host the command takes code from is checked, so a listed
        # installer fetched first does not cover a second fetch from another host.
        sources = [h for h in a.hosts if Role.CODE_SOURCE in h.roles] or (
            [code_source] if code_source is not None and code_source.kind is EntityKind.HOST else []
        )
        for source in sources:
            subject = source.entity_id
            mimics = lookalike_of(source.value, lists.strings("installers", "installer_hosts"))
            via = "installer_list"
            if not mimics:
                mimics, via = _library_near_miss(source, ctx), "library"
            if mimics:
                g = Finding(
                    rule="C3.lookalike_installer",
                    cls="C3",
                    reason="code.lookalike_installer",
                    detail={"host": source.value, "mimics": mimics, "via": via},
                )
                g.add(
                    CONCEALMENT,
                    ctx.weight("code", "lookalike_concealment", default=0.8),
                    subject,
                )
                g.floors.append(
                    Floor(
                        floor="untrusted_code_execution",
                        min_risk=ctx.weight("code", "decode_floor_min_risk", default=0.9),
                        enforce=Enforce.BLOCK,
                        subject=subject,
                        reason="code.lookalike_installer",
                    )
                )
                out.append(g)
            else:
                steered = _steered_source(source, ctx)
                if steered is not None:
                    out.append(steered)
        # A repository on a multi-tenant host is the code source there (the host is only read from): one named in
        # steering content takes the floor as a steered host does. A repository mimics no installer host.
        for source in (r for r in a.repos if Role.CODE_SOURCE in r.roles):
            steered = _steered_source(source, ctx)
            if steered is not None:
                out.append(steered)

    if decode_mech:
        f = Finding(
            rule="C3.decode_to_shell",
            cls="C3",
            reason="code.decode_to_shell",
            detail={"mechanism": decode_mech, "encodings": sorted(a.encodings)},
        )
        f.add(REACH, reach, host_subject).add(IRREVERSIBILITY, irr, host_subject)
        f.add(
            CONCEALMENT, ctx.weight("code", "decode_concealment"), None, "conceal.encoded_payload"
        )
        f.floors.append(
            Floor(
                floor="untrusted_code_execution",
                min_risk=ctx.weight("code", "decode_floor_min_risk", default=0.9),
                enforce=Enforce.BLOCK,
                subject=host_subject,
                reason="code.decode_to_shell",
            )
        )
        out.append(f)

    from_url = _match_any(lists.patterns("installers", "install_from_url_patterns"), a.scan_text)
    url_packages = [p for p in a.packages if p.value.startswith("git+")]
    if from_url:
        subject = (url_packages[0].entity_id if url_packages else None) or host_subject
        f = Finding(
            rule="C3.install_from_url",
            cls="C3",
            reason="code.install_from_url",
            detail={"mechanism": from_url.group(0)[:80]},
        )
        f.add(REACH, reach, subject).add(IRREVERSIBILITY, irr, subject)
        for source in unvetted_sources:
            _add_unvetted_sensitivity(f, source, source.entity_id, ctx)
        for pkg in url_packages:
            _add_unvetted_package_sensitivity(f, pkg, ctx, as_root=as_root)
        out.append(f)

    install_heads = set(lists.strings("installers", "package_install_heads"))
    install_verbs = set(lists.strings("installers", "package_install_verbs"))
    installing = any(
        s.head in install_heads and (set(s.positional) & install_verbs or "-S" in s.flags)
        for s in (a.shape.segments if a.shape else [])
    ) or bool(a.heads & install_heads and set(re.split(r"\s+", a.scan_text)) & install_verbs)
    if installing:
        for pkg in a.packages:
            if pkg.kind is not EntityKind.PACKAGE or pkg.value.startswith("git+"):
                continue
            f = Finding(
                rule="C3.package_install",
                cls="C3",
                reason="code.package_install",
                detail={"package": pkg.value},
            )
            f.add(REACH, reach, pkg.entity_id).add(
                IRREVERSIBILITY, ctx.weight("code", "package_irreversibility"), pkg.entity_id
            )
            _add_unvetted_package_sensitivity(f, pkg, ctx, as_root=as_root)
            out.append(f)
        for path in a.paths:
            # A local path an installer installs (`pip install -e .`): still an install, but of what is
            # on disk, which no registry serves and no library could vouch for.
            if Role.CODE_SOURCE not in path.roles:
                continue
            f = Finding(
                rule="C3.package_install",
                cls="C3",
                reason="code.package_install",
                detail={"path": path.display},
            )
            f.add(REACH, reach, path.entity_id).add(
                IRREVERSIBILITY, ctx.weight("code", "package_irreversibility"), path.entity_id
            )
            if a.source == "pending":
                # A file the session downloaded: the host it came from supplies the code, as for an
                # install from that URL, unless the library vouches for it. Installer hosts are not
                # exempt here (a release asset is anyone's file); package registries never get this far.
                unvetted = ctx.weight("code", "sensitivity_unvetted")
                for host in ctx.prepared.downloaded_from.get(path.value, ()):
                    ent = ctx.prepared.entities.get(EntityKind.HOST, host)
                    info = ctx.prepared.oracle_entities.get(ent.id) if ent else None
                    if ent is None or (
                        isinstance(info, dict) and info.get("verdict") == "known_good"
                    ):
                        continue
                    f.detail.setdefault("downloaded_from", []).append(host)
                    if unvetted > 0:
                        f.add(SENSITIVITY, unvetted, ent.id, "code.unvetted_source")
            out.append(f)

    written = ctx.prepared.written_file
    if written is not None and a.source == "pending":
        fetch_kinds = set(lists.strings("installers", "fetch_tool_kinds"))
        fetch_heads = set(lists.strings("installers", "fetch_heads"))
        fetched_before = any(
            h.step is not None
            and h.step < written.step
            and (
                h.tool_kind.value in fetch_kinds
                or (
                    h.tool_kind is ToolKind.EXEC
                    and bool(set(re.findall(r"[A-Za-z0-9_.-]+", h.command or "")) & fetch_heads)
                )
            )
            for h in ctx.prepared.history
        )
        if fetched_before:
            ent = ctx.prepared.entities.get(EntityKind.PATH, written.path)
            f = Finding(
                rule="C3.run_written_file",
                cls="C3",
                reason="code.run_written_file",
                detail={"path": written.path, "written_step": written.step},
            )
            subject = ent.id if ent else None
            f.add(REACH, reach, subject).add(IRREVERSIBILITY, irr, subject)
            out.append(f)
    return out


def _registrable_label(host: str) -> str:
    """The label a person reads as the brand: `get.docker.com` → `docker`, `astral-sh.dev` →
    `astral-sh`, `foo.co.uk` → `foo`."""
    return registrable(host)[0]


_edit_distance_le1 = edit_distance_le1


def lookalike_of(host: str, listed_hosts: Iterable[str]) -> str | None:
    """The listed host `host` mimics, or None. A listed host itself (or a subdomain of one) is not a
    look-alike. Mimicry: the same brand label under another TLD, a hyphenated or suffixed variant
    carrying the brand (`astral-sh`, `astralsh`, `astral-install`), or one typo away."""
    host = host.lower().strip(".")
    label = _registrable_label(host)
    label_norm = re.sub(r"[^a-z0-9]", "", label)
    for listed in listed_hosts:
        listed = listed.lower().strip(".")
        if host == listed or host.endswith("." + listed):
            return None
    for listed in listed_hosts:
        listed = listed.lower().strip(".")
        brand = _registrable_label(listed)
        if len(brand) < 4:
            continue
        brand_norm = re.sub(r"[^a-z0-9]", "", brand)
        tokens = [tok for tok in re.split(r"[-_.]", label) if tok]
        if label == brand or label_norm == brand_norm:
            return listed  # same brand, another TLD or registrar
        if brand in tokens or (
            brand_norm in label_norm and len(brand_norm) >= 5 and label_norm != brand_norm
        ):
            return listed  # brand carried in a hyphenated or suffixed variant
        if len(brand_norm) >= 5 and _edit_distance_le1(label_norm, brand_norm):
            return listed  # one typo away
    return None


def provider_lookalike_of(identity: str, known: Iterable[str]) -> str | None:
    """The known provider identity `identity` mimics, or None: its package name is one edit from a
    known one's. The same name under another version (a patch bump) is that provider, not a
    look-alike, and so is any identity whose name is known."""
    name = provider_name(identity)
    known = [k for k in known if k]
    if any(provider_name(k) == name for k in known):
        return None
    if len(name.rsplit("/", 1)[-1].split(":")[-1]) < 5:
        return None
    for k in known:
        if _edit_distance_le1(name, provider_name(k)):
            return k
    return None


def detect_provider_lookalike(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C3 arm: the call goes through an MCP provider whose package name is one typo away from a
    provider the session already used (`gmai1-mcp` for `gmail-mcp`). The call's own consequence is
    scored by the other classes; the look-alike is concealment."""
    out: list[Finding] = []
    known = [
        normalise_remote_identity(h.provider.identity)
        for h in ctx.prepared.history
        if h.provider.kind is ProviderKind.MCP and h.provider.identity
    ]
    if not known:
        return out
    for ref in a.providers:
        if ref.kind is not EntityKind.MCP_SERVER or Role.TOOL_PROVIDER not in ref.roles:
            continue
        mimics = provider_lookalike_of(ref.value, known)
        if mimics is None:
            continue
        f = Finding(
            rule="C3.lookalike_provider",
            cls="C3",
            reason="code.lookalike_provider",
            detail={"provider": ref.value, "mimics": mimics},
        )
        f.add(
            CONCEALMENT,
            ctx.weight("code", "provider_lookalike_concealment", default=0.8),
            ref.entity_id,
        )
        out.append(f)
    return out


def detect_param_injection(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C3 arm: a shell command smuggled into a URL parameter of a request to a local or private
    service (RCE through an unauthenticated inspector or preview endpoint). Encoding is
    canonicalisation: the match runs over the percent-decoded text, and the signal is the shell
    metacharacter or command reaching a service, not the encoding."""
    out: list[Finding] = []
    if a.kind not in (ToolKind.EXEC, ToolKind.WEB_FETCH, ToolKind.BROWSER, ToolKind.MCP):
        return out
    lists = ctx.lists
    local = lists.patterns("installers", "local_host_patterns")
    inject = lists.patterns("installers", "param_injection_patterns")
    for m in re.finditer(r"https?://[^\s\"'<>`|]+", a.text):
        url = m.group(0)
        host = url.split("://", 1)[1].split("/", 1)[0].split("@")[-1]
        if not _match_any(local, host):
            continue
        _, _, query = url.partition("?")
        if not query:
            continue
        hit = _match_any(inject, query)
        if hit is None:
            continue
        ref = next((h for h in a.hosts if h.value == host.split(":")[0].lower()), None)
        subject = ref.entity_id if ref else None
        f = Finding(
            rule="C3.param_injection",
            cls="C3",
            reason="code.param_injection",
            detail={"host": host, "match": hit.group(0)[:80]},
        )
        f.add(REACH, ctx.weight("code", "reach"), subject)
        f.add(IRREVERSIBILITY, ctx.weight("code", "irreversibility"), subject)
        f.add(
            CONCEALMENT,
            ctx.weight("code", "param_injection_concealment", default=1.0),
            None,
            "conceal.command_in_url",
        )
        out.append(f)
        break
    return out


def detect_registry_redirect(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C3 arm: pointing a package manager at another registry (an `.npmrc`, `pip.conf`, `.pypirc`
    or cargo config write naming a URL, or `npm config set registry`). Nothing is installed yet;
    later installs come from that host, so the host carries the consequence."""
    out: list[Finding] = []
    lists = ctx.lists
    hit = None
    if a.kind in _WRITE_KINDS or a.kind in (ToolKind.MCP, ToolKind.OTHER):
        for p in a.paths:
            if _match_any(lists.patterns("installers", "registry_config_path_patterns"), p.value):
                hit = _match_any(
                    lists.patterns("installers", "registry_config_text_patterns"),
                    a.edit_text or a.content,
                )
                if hit is not None:
                    break
    if hit is None and a.kind is ToolKind.EXEC:
        hit = _match_any(lists.patterns("installers", "registry_cli_patterns"), a.scan_text)
    if hit is None:
        return out
    # The host the call sets as the registry (a code source), else the first host it names.
    others = [h for h in a.hosts if h.value not in ("registry.npmjs.org", "pypi.org")]
    host = next((h for h in others if Role.CODE_SOURCE in h.roles), others[0] if others else None)
    subject = host.entity_id if host else None
    f = Finding(
        rule="C3.registry_redirect",
        cls="C3",
        reason="code.registry_redirect",
        detail={"match": hit.group(0)[:100], "host": host.value if host else None},
    )
    f.add(REACH, ctx.weight("code", "reach"), subject)
    f.add(IRREVERSIBILITY, ctx.weight("code", "registry_irreversibility", default=0.6), subject)
    # Packages served by a registry that is not a listed installer run with the agent's own access.
    _add_unvetted_sensitivity(
        f, host if host and Role.CODE_SOURCE in host.roles else None, subject, ctx
    )
    out.append(f)
    return out


# =========================================================================== C4


def detect_selfmod(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C4: writes to agent context, scheduler, startup files, hooks, plugin/skill installs and
    config commands."""
    out: list[Finding] = []
    lists = ctx.lists
    reach, irr = ctx.weight("selfmod", "reach"), ctx.weight("selfmod", "irreversibility")
    seen: set[tuple[str, str | None]] = set()

    def emit(reason: str, weight_key: str, subject: str | None, detail: dict[str, Any]) -> None:
        key = (reason, subject)
        if key in seen:
            return
        seen.add(key)
        f = Finding(rule=f"C4.{weight_key}", cls="C4", reason=reason, detail=detail)
        f.add(SELF_MODIFICATION, ctx.weight("selfmod", weight_key), subject)
        f.add(REACH, reach, subject).add(IRREVERSIBILITY, irr, subject)
        out.append(f)

    for p, mechanism in _written_paths(a, ctx):
        for g in p.groups:
            if g in SELFMOD_GROUPS:
                reason, wkey = SELFMOD_GROUPS[g]
                if (
                    g == "agent_plugins"
                    and "workspace" in p.locations
                    and not p.value.lower().endswith(
                        tuple(lists.strings("selfmod", "workspace_skill_instruction_suffixes"))
                    )
                ):
                    # A script or data file inside a workspace skill: the owner's own
                    # project files, edited at the owner's request far more often than the agent's
                    # installed plugin tree, so it scores at `selfmod.workspace_skill`. The skill's
                    # instruction files (SKILL.md and the like) are prompt the agent loads later
                    # and keep the plugin weight.
                    reason, wkey = "selfmod.workspace_skill", "workspace_skill"
                emit(reason, wkey, p.entity_id, {"path": p.display, "mechanism": mechanism})
                break
    if a.kind is ToolKind.MEMORY_WRITE and not out:
        subject = next((p.entity_id for p in a.paths if p.is_destination), None)
        emit("selfmod.memory", "memory", subject, {"mechanism": "memory_write"})

    if a.kind is ToolKind.EXEC:
        for line in a.segment_texts():
            for rule in lists.rules("selfmod", "cli"):
                if rule.regex.search(line):
                    reason = str(rule.get("reason"))
                    wkey = str(rule.get("weight") or reason.split(".")[-1])
                    emit(reason, wkey, None, {"mechanism": "cli", "match": line[:120]})
        # A plugin or skill install names the plugin entity.
        for pkg in a.packages:
            if pkg.kind is EntityKind.PLUGIN:
                emit("selfmod.plugin", "plugin", pkg.entity_id, {"plugin": pkg.value})
    elif a.kind in (ToolKind.MCP, ToolKind.OTHER) and not _read_action(a, lists, "selfmod"):
        rule = _tool_matches(a, lists, "selfmod", "tool_names")
        if rule is not None:
            reason = str(rule.get("reason"))
            emit(reason, reason.split(".")[-1], None, {"mechanism": "tool_name", "tool": a.tool})
    # A declared self-edit modifies the agent's own store by definition, whatever the tool or path form says (a
    # host's file write may name its skill file relative to a skill folder no path rule knows). The declared store
    # supplies the finding only when no rule above found one, so a declaration can never lower a score.
    planir = ctx.prepared.planir
    if not out and a.source == "pending" and planir.is_self_edit and planir.self_edit is not None:
        store = planir.self_edit.store.value
        if store in SELF_EDIT_STORES:
            reason, wkey = SELF_EDIT_STORES[store]
            emit(reason, wkey, None, {"mechanism": "self_edit_store", "store": store})
    return out


# =========================================================================== C4*


#: The longest file name a filesystem takes (bytes on most; characters are never more).
_MAX_NAME = 255


def _guardrail_path_reason(value: str, head: str | None, ctx: Context) -> str | None:
    lists = ctx.lists
    base = os.path.basename(value.rstrip("/"))
    # A name longer than any filesystem takes is no log file (and the log patterns are not read over it).
    log_name = len(base) <= _MAX_NAME
    for seg in lists.strings("guardrail", "state_dir_segments"):
        if re.search(r"(?:\A|/)" + re.escape(seg) + r"(?:/|\Z)", value, re.IGNORECASE):
            if log_name and _match_any(lists.patterns("guardrail", "log_basename_patterns"), base):
                return "guardrail.log_tamper"
            return "guardrail.state_dir_write"
    for name in lists.strings("guardrail", "legacy_basenames"):
        if re.search(basename_pattern(name), value, re.IGNORECASE):
            if log_name and _match_any(lists.patterns("guardrail", "log_basename_patterns"), base):
                return "guardrail.log_tamper"
            return "guardrail.state_dir_write"
    if _match_any(lists.patterns("guardrail", "host_guardrail_path_patterns"), value):
        return "guardrail.host_approvals"
    return None


def _after_options(tokens: list[str], start: int) -> Iterator[int]:
    """Indices from `start` that can come after a run of options: every word before them is an
    option or the word right after one. Which options take a value is not known, so the word after
    an option is yielded and then skipped as its possible value."""
    after_option = False
    for i in range(start, len(tokens)):
        yield i
        tok = tokens[i]
        if tok.startswith("-") and len(tok) > 1:
            after_option = "=" not in tok and tok != "--"
        elif after_option:
            after_option = False
        else:
            return


def _program_name(token: str) -> str:
    """`/usr/bin/hermes` -> `hermes`, `openclaw@latest` -> `openclaw`."""
    name = os.path.basename(token).lower()
    at = name.find("@", 1)
    return name[:at] if at > 0 else name


_QUOTED_PART = re.compile(r"""'([^']*)'|"([^"]*)"|\\(.)""", re.DOTALL)


def _shell_word(word: str) -> str:
    """The word after the shell's quote removal: `sent""rook`, `'sent'rook` and `sent\\rook` all
    read as `sentrook`. An unbalanced quote is left as it is."""
    if not any(c in word for c in "'\"\\"):
        return word
    return _QUOTED_PART.sub(lambda m: next(g for g in m.groups() if g is not None), word)


def _shell_script(words: list[str], shells: set[str]) -> str | None:
    """The script of `<shell> [options] -c <script> …`: the first word that is not an option after
    a short-option cluster holding `c` (`-c`, `-lc`, `-ec`). A script file before any `-c` ends
    the shell's options (`bash run.sh -c x` passes `-c` to the script)."""
    if not words or _program_name(words[0]) not in shells:
        return None
    seen_c = False
    takes_value = False
    for tok in words[1:]:
        if tok.startswith(("-", "+")) and len(tok) > 1:
            seen_c = seen_c or (not tok.startswith("--") and "c" in tok[1:])
            takes_value = tok in {"-o", "+o", "-O", "+O"}
        elif seen_c:
            return tok
        elif takes_value:
            takes_value = False
        else:
            return None
    return None


def _cli_segments(a: CallAnalysis, lists: Lists) -> list[tuple[list[str], str]]:
    """`(words, line)` per simple command, words after quote removal, plus the commands of any
    shell `-c` script (nested up to three deep)."""
    shells = set(lists.strings("installers", "shell_heads"))
    out: list[tuple[list[str], str]] = []

    def walk(words: list[str], line: str, depth: int) -> None:
        out.append(([_shell_word(w) for w in words], line))
        script = _shell_script(words, shells)
        if script is None or depth >= 3:
            return
        shape = derive_exec_shape(script, lists.path_groups)
        if shape.parse_ok and shape.segments:
            for s in shape.segments:
                inner = [s.head, *s.argv]
                walk(inner, " ".join(inner), depth + 1)
        else:
            walk(script.split(), script, depth + 1)

    for words, line in zip(a.segment_tokens(), a.segment_texts(), strict=True):
        walk(words, line, 0)
    return out


# Runtime options after which the rest is inline code, not a script path (`node -e '…'`); a
# short-option cluster holding `e` or `p` (`-pe`) counts too.
_INLINE_CODE_FLAGS = frozenset({"-e", "--eval", "-p", "--print"})


def _cli_tokens(tokens: list[str], heads: set[str], lists: Lists) -> list[str]:
    """The words of one simple command from the CLI head on, launchers (`uv run`, `npx`, `exec`,
    `python -m <module>`, `node <entry script>`, …) and their options peeled off. Unchanged, bar
    the head's name, when the command is not a known CLI behind launchers."""
    if not tokens:
        return tokens
    launchers = [
        [str(w).lower() for w in words]
        for words in lists.get("guardrail", "cli_launchers", default=[]) or []
    ]
    runners = lists.patterns("guardrail", "cli_module_runner_patterns")
    modules = {
        str(k).lower(): str(v).lower()
        for k, v in (lists.get("guardrail", "cli_modules", default={}) or {}).items()
    }
    script_runners = lists.patterns("guardrail", "cli_script_runner_patterns")
    scripts = {
        str(head).lower(): lists.patterns("guardrail", "cli_scripts", str(head), "path_patterns")
        for head in lists.get("guardrail", "cli_scripts", default={}) or {}
    }

    def launches(name: str) -> bool:
        return (
            name in heads
            or bool(_match_any(runners, name))
            or bool(_match_any(script_runners, name))
            or any(name == words[0] for words in launchers)
        )

    current = tokens
    for _ in range(4):
        name = _program_name(current[0])
        if name in heads:
            return [name, *current[1:]]
        following: list[str] | None = None
        if _match_any(runners, name):
            for i in _after_options(current, 1):
                tok = current[i]
                if tok.startswith("-c"):
                    break  # the interpreter's options end at `-c <code>`
                if tok == "-m" and i + 1 < len(current):
                    module, rest = current[i + 1].lower(), current[i + 2 :]
                elif tok.startswith("-m") and len(tok) > 2:
                    module, rest = tok[2:].lower(), current[i + 1 :]
                else:
                    continue
                for prefix, head in modules.items():
                    if module == prefix or module.startswith(prefix + "."):
                        following = [head, *rest]
                break
        elif _match_any(script_runners, name):
            for i in _after_options(current, 1):
                tok = current[i]
                if tok.split("=", 1)[0] in _INLINE_CODE_FLAGS or (
                    tok.startswith("-") and not tok.startswith("--") and set(tok[1:]) & {"e", "p"}
                ):
                    break
                head = next((h for h, p in scripts.items() if _match_any(p, tok)), None)
                if head is not None and not tok.startswith("-"):
                    following = [head, *current[i + 1 :]]
                    break
        else:
            for words in launchers:
                n = len(words)
                if len(current) <= n or name != words[0]:
                    continue
                if [t.lower() for t in current[1:n]] != words[1:]:
                    continue
                # The last launchable word wins: in `npx -p openclaw openclaw …` the first is the
                # value of `-p`.
                for i in _after_options(current, n):
                    if launches(_program_name(current[i])):
                        following = current[i:]
                break
        if following is None:
            break
        current = following
    return [_program_name(tokens[0]), *tokens[1:]]


# ------------------------------------------------------------------ C4*: approval loosening
#
# Two tiers. A known approval setting changed to a looser value in a host file or command, or a
# broad allowlist entry, takes the block floor (`guardrail.approval_loosening`). What the scan
# can only infer (a script's loose words, a host file replaced blind, an `$include` file, an edit
# fragment whose section cannot be decided, code whose write target cannot be resolved) takes a
# review floor (`guardrail.approval_loosening_review`): the owner is always asked, and the floor
# never blocks.

BLOCK, REVIEW = "block", "review"


@dataclass(frozen=True)
class _Setting:
    #: Finds `key: value` with the key in group `k` and the value in group `v`.
    rx: re.Pattern[str]
    #: The same key in a launchd plist (`<key>K</key><string>V</string>`).
    plist: re.Pattern[str]
    keys: re.Pattern[str]
    value: re.Pattern[str]
    where: str  # env | tree | config
    host: str | None
    parents: re.Pattern[str] | None
    old_values: re.Pattern[str] | None
    bare: bool
    ambiguous: bool
    #: `key:value` pairs only this setting's section has: beside one, an `ambiguous` key in a
    #: fragment with no enclosing key counts.
    siblings: re.Pattern[str] | None = None


@dataclass(frozen=True)
class _StateDb:
    """The host's state database holding its approvals (`approval_loosening.state_db`)."""

    host: str
    files: re.Pattern[str]
    basename: re.Pattern[str]
    table: str
    #: A write statement naming any table; group `t` is the table.
    writes: re.Pattern[str]
    #: Columns as the approvals settings they hold, longest name first.
    columns: tuple[tuple[re.Pattern[str], str], ...]
    writers: re.Pattern[str]
    connect: re.Pattern[str]


@dataclass(frozen=True)
class _Tree:
    host: str
    root: str  # regex source with `{home}`


@dataclass(frozen=True)
class _LooseningRules:
    """`guardrail.approval_loosening`, compiled."""

    settings: tuple[_Setting, ...]
    #: Every setting's key at once: one pass finds where a setting can start.
    any_key: re.Pattern[str]
    allow_tree: dict[str, re.Pattern[str]]
    allow_approvals: re.Pattern[str] | None
    broad: tuple[re.Pattern[str], ...]
    trees: tuple[_Tree, ...]
    tree_exclusions: tuple[re.Pattern[str], ...]
    approvals_files: tuple[re.Pattern[str], ...]
    main_config_files: dict[str, re.Pattern[str]]
    include_files: dict[str, re.Pattern[str]]
    env_files: tuple[re.Pattern[str], ...]
    doc_files: tuple[re.Pattern[str], ...]
    loose_values: tuple[re.Pattern[str], ...]
    approval_keys: tuple[re.Pattern[str], ...]
    inplace_heads: frozenset[str]
    code_sinks: tuple[
        tuple[re.Pattern[str], str, int, bool], ...
    ]  # (regex, call|method, arg, mode)
    code_commands: tuple[re.Pattern[str], ...]
    replace_heads: frozenset[str]
    cd_heads: frozenset[str]
    blind_heads: frozenset[str]
    download_flags: frozenset[str]
    download_letters: dict[str, str]
    unset_paths: tuple[re.Pattern[str], ...]
    replaced_objects: tuple[re.Pattern[str], ...]
    approvals_cli: tuple[dict[str, Any], ...]
    launch_flags: dict[str, frozenset[str]]
    env: tuple[re.Pattern[str], ...]
    state_db: _StateDb | None = None


_LOOSENING_CACHE: dict[int, tuple[Any, _LooseningRules]] = {}
_VALUE = r"""[ \t]*[:=][ \t]*(?:&\w+[ \t]+|!!?\w+[ \t]+)*["']?(?P<v>[^\s"',;}\]#)/\\<]+)"""


def _key_regex(keys: str) -> re.Pattern[str]:
    # Keys are case-sensitive in JSON, YAML and the environment, and a case-sensitive pattern
    # lets the engine scan for its literal prefix: a large body stays fast.
    return re.compile(r"""(?<![\w-])["']?(?:""" + keys + r""")["']?[ \t]*[:=][ \t]*""")


def _loosening_rules(lists: Lists) -> _LooseningRules:
    raw = lists.get("guardrail", "approval_loosening", default={}) or {}
    cached = _LOOSENING_CACHE.get(id(raw))
    if cached is not None and cached[0] is raw:
        return cached[1]

    def rx(source: Any) -> re.Pattern[str] | None:
        return re.compile(str(source), re.IGNORECASE) if source else None

    def rxs(key: str) -> tuple[re.Pattern[str], ...]:
        return tuple(re.compile(str(p), re.IGNORECASE) for p in raw.get(key) or ())

    def by_host(key: str) -> dict[str, re.Pattern[str]]:
        return {str(h): re.compile(str(p), re.IGNORECASE) for h, p in (raw.get(key) or {}).items()}

    settings = []
    for s in raw.get("settings") or []:
        keys = str(s["key"])
        settings.append(
            _Setting(
                rx=re.compile(r"""(?<![\w-])["']?(?P<k>""" + keys + r""")["']?""" + _VALUE),
                plist=re.compile(
                    r"<key>\s*(?P<k>"
                    + keys
                    + r")\s*</key>\s*<string>\s*(?P<v>[^<\s]+)\s*</string>",
                    re.IGNORECASE,
                ),
                keys=re.compile(keys),
                value=re.compile(str(s["value"]), re.IGNORECASE),
                where=str(s.get("where", "config")),
                host=str(s["host"]) if s.get("host") else None,
                parents=rx(s.get("parents")),
                old_values=rx(s.get("old_values")),
                bare=bool(s.get("bare")),
                ambiguous=bool(s.get("ambiguous")),
                siblings=re.compile(str(s["siblings"])) if s.get("siblings") else None,
            )
        )
    keys = raw.get("allowlist_keys") or {}
    tree_keys = keys.get("tree") or {}

    def pats(key: str) -> tuple[re.Pattern[str], ...]:
        return lists.patterns("guardrail", "approval_loosening", key)

    rules = _LooseningRules(
        settings=tuple(settings),
        any_key=_key_regex("|".join(str(s["key"]) for s in raw.get("settings") or []) or "(?!)"),
        allow_tree={str(h): _key_regex(str(k)) for h, k in tree_keys.items()},
        allow_approvals=_key_regex(str(keys["approvals"])) if keys.get("approvals") else None,
        # Whole entries only: anchored, so no search ever tries them from every position.
        broad=tuple(
            re.compile(r"\A(?:" + p.pattern + r")\Z", p.flags) for p in pats("broad_entry_patterns")
        ),
        trees=tuple(_Tree(str(t["host"]), str(t["root"])) for t in raw.get("host_trees") or ()),
        tree_exclusions=rxs("tree_exclusions"),
        approvals_files=rxs("approvals_files"),
        main_config_files=by_host("main_config_files"),
        include_files=by_host("include_files"),
        env_files=rxs("env_files"),
        doc_files=rxs("doc_files"),
        loose_values=pats("loosening_value_patterns"),
        approval_keys=pats("approval_key_patterns"),
        inplace_heads=frozenset(str(h) for h in raw.get("inplace_heads") or ()),
        code_sinks=tuple(
            (
                re.compile(
                    r"(?:" + str(c["call"]) + r")\s*\("
                    if c.get("call")
                    else r"\.(?:" + str(c["method"]) + r")\s*\("
                ),
                "call" if c.get("call") else "method",
                int(c.get("arg", 1)),
                bool(c.get("mode")),
            )
            for c in raw.get("code_sinks") or ()
        ),
        code_commands=pats("code_command_patterns"),
        replace_heads=frozenset(str(h) for h in raw.get("replace_heads") or ()),
        cd_heads=frozenset(str(h) for h in raw.get("cd_heads") or ()),
        blind_heads=frozenset(str(h) for h in raw.get("blind_output_heads") or ()),
        download_flags=frozenset(str(f) for f in raw.get("download_output_flags") or ()),
        download_letters={
            str(h): str(c) for h, c in (raw.get("download_output_letters") or {}).items()
        },
        unset_paths=rxs("unset_paths"),
        replaced_objects=rxs("replaced_objects"),
        approvals_cli=tuple(raw.get("approvals_cli") or ()),
        launch_flags={
            str(head).lower(): frozenset(str(f) for f in flags or ())
            for head, flags in (raw.get("launch_flags") or {}).items()
        },
        env=pats("env_assignment_patterns"),
        state_db=_state_db_rules(raw.get("state_db")),
    )
    _LOOSENING_CACHE[id(raw)] = (raw, rules)
    return rules


# A statement that writes a table: group `t` is the table (a schema prefix and quotes skipped).
_SQL_WRITE = (
    r"""(?:\b(?:UPDATE(?:\s+OR\s+\w+)?|(?:INSERT(?:\s+OR\s+\w+)?|REPLACE)\s+INTO|DELETE\s+FROM|"""
    r"""DROP\s+TABLE(?:\s+IF\s+EXISTS)?|ALTER\s+TABLE)\s+|\.import\s+(?:--?\w+\s+)*\S+\s+)"""
    r"""(?:["`\[]?\w+["`\]]?\.)?["`\[]?(?P<t>\w+)"""
)


def _state_db_rules(raw: Any) -> _StateDb | None:
    if not raw:
        return None
    columns = sorted((raw.get("columns") or {}).items(), key=lambda kv: -len(str(kv[0])))
    return _StateDb(
        host=str(raw["host"]),
        files=re.compile(str(raw["files"]), re.IGNORECASE),
        basename=re.compile(str(raw["basename"]), re.IGNORECASE),
        table=str(raw["table"]).lower(),
        writes=re.compile(_SQL_WRITE, re.IGNORECASE),
        columns=tuple(
            (re.compile(r"\b" + re.escape(str(c)) + r"\b", re.IGNORECASE), str(k))
            for c, k in columns
        ),
        writers=re.compile(str(raw["writers"])),
        connect=re.compile(str(raw["connect"])),
    )


_SQL_LITERAL = re.compile(r"'((?:[^'\n]|'')*)'")
#: `json_set(raw_json, '$.defaults.ask', 'off')`: a path and the value set there.
_SQL_JSON_PATH = re.compile(r"""'\$\.(?P<p>[^'\n]+)'\s*,\s*(?:'(?P<v>[^'\n]*)'|(?P<n>[\w.-]+))""")
#: `json_object('security', 'full')`: a key and its value.
_SQL_PAIR = re.compile(r"""'(?P<k>[\w-]+)'\s*,\s*'(?P<v>[^'\n]*)'""")
_SQL_INSERT = re.compile(r"""\((?P<cols>[^()]*)\)\s*VALUES\s*\(""", re.IGNORECASE)
#: A database a `sqlite3` script opens or attaches.
_SQL_OPEN = re.compile(
    r"""(?:\A|[\n;])[ \t]*\.open[ \t]+(?:--?\w+[ \t]+)*["']?(?P<o>[^\s"';]+)|"""
    r"""\bATTACH[ \t]+(?:DATABASE[ \t]+)?["'](?P<a>[^"'\n]+)["']""",
    re.IGNORECASE,
)
#: `sqlite3` options that take a value (`-cmd` runs its value as SQL).
_SQLITE_VALUED = frozenset(
    {"cmd", "separator", "newline", "nullvalue", "init", "mmap", "pagecache", "lookaside", "vfs"}
    | {"maxsize", "heap", "escape"}
)
_SQL_BUDGET = 8000  # characters read per statement
#: Where a write statement's values end.
_SQL_END = re.compile(r";|\bWHERE\b|\bRETURNING\b", re.IGNORECASE)
#: A database URI (`file:/path?mode=rw`) as its path.
_SQL_URI = re.compile(r"\Afile:(?://localhost)?(?P<p>[^?#]*)")


def _sql_writes(text: str, db: _StateDb) -> list[str]:
    """The statements in `text` that write the approvals table, each up to its `;`, the end of
    the text, or its `WHERE` or `RETURNING` clause (a condition is not a value written)."""
    out: list[str] = []
    for n, m in enumerate(db.writes.finditer(text)):
        if n >= _SINK_MATCHES:
            break
        if m.group("t").lower() != db.table:
            continue
        body = text[m.start() : m.end() + _SQL_BUDGET]
        cut = _SQL_END.search(body, m.end() - m.start())
        out.append(body[: cut.start()] if cut else body)
    return out


def _sql_settings(statement: str, db: _StateDb) -> str:
    """A statement as settings text: its columns named as the settings they hold, `json_set`
    paths and `json_object` pairs as `key: value` lines, insert columns beside their values, and
    the contents of its string literals (the approvals document in `raw_json`)."""
    text = statement.replace('\\"', '"')
    for rx, key in db.columns:
        text = rx.sub(key, text)
    lines = [text]
    for m in _SQL_JSON_PATH.finditer(text):
        leaf = re.split(r"[.\[\]]+", m.group("p").strip(".[]"))[-1].strip("\"'")
        value = m.group("v") if m.group("v") is not None else m.group("n")
        lines.append(f"{leaf}: {value}")
    for n, m in enumerate(re.finditer(r"json_object\s*\(", text, re.IGNORECASE)):
        if n >= _SINK_MATCHES:
            break
        for pair in _SQL_PAIR.finditer(text, m.end(), m.end() + _SCAN_BUDGET):
            lines.append(f"{pair.group('k')}: {pair.group('v')}")
    insert = _SQL_INSERT.search(text)
    if insert:
        columns = [c.strip().strip('"`[]') for c in insert.group("cols").split(",")]
        values = _call_args(text, insert.end() - 1)
        lines += [f"{c}: {v}" for c, v in zip(columns, values, strict=False)]
    lines += [m.group(1).replace("''", "'") for m in _SQL_LITERAL.finditer(text)]
    return "\n".join(lines)


def _sqlite_cli(args: list[str]) -> tuple[str | None, list[str]]:
    """A `sqlite3` command's database and the SQL it runs (its arguments after the database,
    and `-cmd` values)."""
    db: str | None = None
    sql: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and len(a) > 1:
            name = a.lstrip("-")
            if name in _SQLITE_VALUED and i + 1 < len(args):
                if name == "cmd":
                    sql.append(args[i + 1])
                i += 2
                continue
        elif db is None:
            db = a
        else:
            sql.append(a)
        i += 1
    return db, sql


@dataclass(frozen=True)
class _Where:
    """Where a file or command sits for this floor."""

    classes: frozenset[str]  # tree, env, approvals, main, include
    host: str | None = None
    fmt: str = "auto"  # json | yaml | auto
    #: Code or content the host does not read as settings (`skills/`, `node_modules/`, …).
    excluded: bool = False

    def __bool__(self) -> bool:
        return bool(self.classes)


def _host_where(value: str, rules: _LooseningRules, ctx: Context) -> _Where:
    """`tree` (a host tree), `approvals`, `main` and `include` (host files at a tree root), and
    `env` (a file that sets the environment a host starts with, or a host tree). Documentation is
    none of them."""
    if _match_any(rules.doc_files, value):
        return _Where(frozenset())
    home = re.escape(ctx.prepared.home.rstrip("/"))
    ws = ctx.prepared.workspace_root.rstrip("/")
    # A case-insensitive file system names one file however the case is written.
    flags = re.IGNORECASE if ctx.prepared.planir.host.os in ("macos", "windows") else 0
    classes: set[str] = set()
    host: str | None = None
    excluded = False
    for tree in rules.trees:
        root = tree.root.replace("{home}", home)
        m = re.match(r"(?:" + root + r")/(?P<rel>.+)\Z", value, flags)
        if m is None:
            continue
        # The workspace excludes its files only when it sits strictly inside this tree.
        ws_in = re.match(r"(?:" + root + r")/.+\Z", ws, flags) if ws else None
        if ws_in and (value == ws or value.startswith(ws + "/")):
            continue
        rel = m.group("rel")
        host = tree.host
        excluded = _match_any(rules.tree_exclusions, rel) is not None
        classes |= {"tree"} if excluded else {"tree", "env"}
        if any(p.fullmatch(rel) for p in rules.approvals_files):
            classes.add("approvals")
        main = rules.main_config_files.get(tree.host)
        if main is not None and main.fullmatch(rel):
            classes.add("main")
        include = rules.include_files.get(tree.host)
        if include is not None and include.fullmatch(rel) and not classes & {"main", "approvals"}:
            classes.add("include")
        break
    if _match_any(rules.env_files, value):
        classes.add("env")
    ext = os.path.splitext(value)[1].lower()
    fmt = "yaml" if ext in (".yaml", ".yml") else "json" if ext in (".json", ".json5") else "auto"
    return _Where(frozenset(classes), host, fmt, excluded)


def _tree_file(
    value: str, host: str, rel: re.Pattern[str], rules: _LooseningRules, ctx: Context
) -> bool:
    """Whether `value` is the file `rel` (relative to a tree root) in one of `host`'s trees."""
    home = re.escape(ctx.prepared.home.rstrip("/"))
    flags = re.IGNORECASE if ctx.prepared.planir.host.os in ("macos", "windows") else 0
    for tree in rules.trees:
        if tree.host != host:
            continue
        m = re.match(r"(?:" + tree.root.replace("{home}", home) + r")/(?P<rel>.+)\Z", value, flags)
        if m is not None and rel.fullmatch(m.group("rel")):
            return True
    return False


_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decode(text: str) -> str:
    """`\\uXXXX` escapes decoded, so `"\\u006dode"` reads as `"mode"`."""
    if "\\u" not in text:
        return text
    return _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)


_IDENT = re.compile(r"[A-Za-z_$][\w$-]*")
#: A position inside a string or a comment: not a setting.
_INSIDE = None


def _json_contexts(text: str, positions: list[int]) -> dict[int, list[str] | None]:
    """The keys enclosing each position (nearest first) in JSON or JSON5, one forward pass:
    strings, `//` and `/* */` comments skipped, unquoted keys read. A container with no key (a
    list item) adds nothing. A position inside a string or a comment maps to `None`, except at
    a segment of a dotted key (`"tools.exec.mode": …`), where the segments before it enclose it.
    A dotted key's segments each enclose what its value holds."""
    out: dict[int, list[str] | None] = {}
    want = sorted(set(positions))
    w = 0
    last: str | None = None  # the last string or identifier, a key if `:` follows
    pending: str | None = None  # the key whose value comes next
    i, n = 0, len(text)

    flat: list[str] = []  # the enclosing keys as segments, outermost first
    sizes: list[int] = []  # per open container, the segments its key added

    def enclosing() -> list[str]:
        return flat[::-1]

    def skip_to(j: int) -> None:
        nonlocal w
        while w < len(want) and want[w] < j:
            out[want[w]] = _INSIDE
            w += 1

    while i < n and w < len(want):
        while w < len(want) and want[w] <= i:
            out[want[w]] = enclosing()
            w += 1
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            last = text[i + 1 : j]
            if "." in last and w < len(want) and want[w] <= j:
                k = j + 1
                while k < n and text[k] in " \t\r\n":
                    k += 1
                if k < n and text[k] == ":":
                    outer = enclosing()
                    while w < len(want) and want[w] <= j:
                        prefix = text[i + 1 : want[w]]
                        if prefix.endswith("."):
                            segs = [seg for seg in prefix.split(".") if seg]
                            out[want[w]] = segs[::-1] + outer
                        else:
                            out[want[w]] = _INSIDE
                        w += 1
            skip_to(j + 1)
            i = j + 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            skip_to(j)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            skip_to(j)
            i = j
            continue
        if ch == ":":
            pending, last = last, None
        elif ch in "{[":
            segs = [seg for seg in pending.split(".") if seg] if pending else []
            flat.extend(segs)
            sizes.append(len(segs))
            pending = last = None
        elif ch in "}]":
            if sizes:
                drop = sizes.pop()
                if drop:
                    del flat[-drop:]
            pending = last = None
        elif ch == ",":
            pending = last = None
        elif not ch.isspace():
            m = _IDENT.match(text, i)
            if m:
                last = m.group(0)
                i = m.end()
                continue
        i += 1
    for p in want[w:]:
        out[p] = enclosing()
    return out


_YAML_KEY = re.compile(r"""(?:-\s+)?["']?([\w$.-]+)["']?\s*:(?:\s+(.*))?\Z""")
# Anchors and tags before a value; possessive, so a failed match never backtracks into them.
_YAML_OPENER = re.compile(r"""(?:(?:&\w++|!!?[\w/]++)\s*+)*+\Z""")
_YAML_BLOCK_SCALAR = re.compile(r"""(?:(?:&\w++|!!?[\w/]++)\s*+)*+[|>][+-]?\d*\s*\Z""")


def _yaml_strip_comment(line: str) -> str:
    """The line without a `#` comment (outside quotes), the same length."""
    if "#" not in line:
        return line
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i] + " " * (len(line) - i)
    return line


def _yaml_contexts(text: str, positions: list[int]) -> dict[int, list[str] | None]:
    """The keys enclosing each position by YAML indentation (nearest first), one forward pass;
    comments, anchors (`&a`) and tags (`!!map`) skipped. A position inside a comment or a block
    scalar (`|`, `>`) maps to `None`."""
    out: dict[int, list[str] | None] = {}
    want = sorted(set(positions))
    w = 0
    stack: list[tuple[int, str]] = []
    scalar_indent: int | None = None  # inside a block scalar opened at this indent
    offset = 0
    for raw_line in text.split("\n"):
        if w >= len(want):
            break
        end = offset + len(raw_line)
        line = _yaml_strip_comment(raw_line)
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" \t"))
        if scalar_indent is not None and (not stripped or indent > scalar_indent):
            while w < len(want) and want[w] <= end:
                out[want[w]] = _INSIDE
                w += 1
            offset = end + 1
            continue
        scalar_indent = None
        if stripped:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            code_end = offset + len(line.rstrip())
            while w < len(want) and want[w] <= end:
                out[want[w]] = [k for _, k in reversed(stack)] if want[w] < code_end else _INSIDE
                w += 1
            m = _YAML_KEY.match(stripped)
            if m:
                rest = (m.group(2) or "").strip()
                if _YAML_BLOCK_SCALAR.match(rest):
                    scalar_indent = indent
                elif _YAML_OPENER.match(rest):
                    stack.append((indent, m.group(1)))
        else:
            while w < len(want) and want[w] <= end:
                out[want[w]] = [k for _, k in reversed(stack)]
                w += 1
        offset = end + 1
    for p in want[w:]:
        out[p] = []
    return out


_YAML_EXPLICIT = re.compile(
    r"^(?P<i>[ \t]*)\?[ \t]+(?P<k>[^\n]+)\n(?P=i):[ \t]*(?P<rest>[^\n]*)", re.M
)
_YAML_ANCHOR = re.compile(
    r"""^(?P<i>[ \t]*)(?:-[ \t]+)?["']?[\w$.-]+["']?[ \t]*:[ \t]*&(?P<a>[\w-]+)[ \t]*$""", re.M
)
_YAML_MERGE = re.compile(
    r"^(?P<i>[ \t]*)<<[ \t]*:[ \t]*(?P<refs>\*[\w-]+|\[[^\]\n]*\])[ \t]*$", re.M
)
_YAML_ALIAS = re.compile(
    r"""^(?P<i>[ \t]*)(?P<k>["']?[\w$.-]+["']?)[ \t]*:[ \t]*\*(?P<a>[\w-]+)[ \t]*$""", re.M
)
_YAML_EXPANSION = 20000  # characters merge keys and aliases may add


def _yaml_expand(text: str) -> str:
    """YAML whose keys the indentation pass would misread, rewritten: an explicit key
    (`? approvals` then `: mode: off`) as `approvals:` with its value nested, and a merge key
    (`<<: *b`) or an alias value (`approvals: *b`) replaced by the anchored block, one level
    deep and at most `_YAML_EXPANSION` characters added."""
    if "?" in text:
        text = _YAML_EXPLICIT.sub(
            lambda m: (
                f"{m['i']}{m['k'].rstrip()}:"
                + (f"\n{m['i']}  {m['rest']}" if m["rest"].strip() else "")
            ),
            text,
        )
    if "*" not in text or "&" not in text:
        return text
    blocks: dict[str, str] = {}
    lines = text.split("\n")
    starts = {m.start(): m for m in _YAML_ANCHOR.finditer(text)}
    offset = 0
    for n, line in enumerate(lines):
        m = starts.get(offset)
        offset += len(line) + 1
        if m is None:
            continue
        indent = len(m["i"]) + (len(line) - len(line.lstrip(" \t-")) - len(m["i"]))
        body: list[str] = []
        for following in lines[n + 1 :]:
            if following.strip() and len(following) - len(following.lstrip(" \t")) <= indent:
                break
            body.append(following)
        depth = min((len(b) - len(b.lstrip(" \t")) for b in body if b.strip()), default=0)
        blocks[m["a"]] = "\n".join(b[depth:] for b in body if b.strip())
    if not blocks:
        return text
    budget = [_YAML_EXPANSION]

    def place(names: list[str], indent: str) -> str | None:
        found = [blocks[a] for a in names if a in blocks]
        added = sum(len(b) for b in found)
        if not found or added > budget[0]:
            return None
        budget[0] -= added
        return "\n".join(indent + line for b in found for line in b.split("\n"))

    def merge(m: re.Match[str]) -> str:
        names = re.findall(r"\*([\w-]+)", m["refs"])
        return place(names, m["i"]) or m.group(0)

    def alias(m: re.Match[str]) -> str:
        block = place([m["a"]], m["i"] + "  ")
        return f"{m['i']}{m['k']}:\n{block}" if block is not None else m.group(0)

    return _YAML_ALIAS.sub(alias, _YAML_MERGE.sub(merge, text))


def _contexts(text: str, positions: list[int], fmt: str) -> dict[int, list[str] | None]:
    if not positions:
        return {}
    if fmt == "json":
        return _json_contexts(text, positions)
    lines = _yaml_contexts(text, positions)
    if fmt == "yaml" and "{" not in text:
        return lines
    # YAML may carry flow maps (`approvals: {mode: off}`): braces count once comments are gone.
    # Quotes are YAML's own here (an apostrophe in a plain scalar is not a string), so only the
    # keys come from the brace pass.
    stripped = "\n".join(_yaml_strip_comment(line) for line in text.split("\n"))
    braces = _json_contexts(stripped, positions)
    out: dict[int, list[str] | None] = {}
    for p in positions:
        if lines.get(p) is _INSIDE and fmt == "yaml":
            out[p] = _INSIDE
        else:
            out[p] = braces.get(p) or lines.get(p) or []
    return out


def _brackets(text: str) -> dict[int, int]:
    """Each `[` mapped to its closing `]`, one pass (an unclosed one is left out)."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for i, ch in enumerate(text):
        if ch == "[":
            stack.append(i)
        elif ch == "]" and stack:
            pairs[stack.pop()] = i
    return pairs


_LIST_BUDGET = 4000  # characters read per list value
_LIST_MATCHES = 200  # allowlist keys read per text


def _list_value(text: str, start: int, brackets: dict[int, int]) -> str:
    """The value that starts at `start`: a bracketed list (to its closing bracket), a YAML block
    list on the following lines, or one scalar; at most `_LIST_BUDGET` characters."""
    if text.startswith("[", start):
        end = brackets.get(start)
        stop = start + _LIST_BUDGET if end is None else min(end + 1, start + _LIST_BUDGET)
        return text[start:stop]
    rest = text[start : start + _LIST_BUDGET]
    line, _, after = rest.partition("\n")
    if line.strip() and not line.strip().startswith("#"):
        return line
    items: list[str] = []
    for item in after.splitlines():
        if not item.strip():
            continue
        if not item.lstrip().startswith("-"):
            break
        items.append(item)
    return "\n".join(items)


def _entries(value: str) -> list[str]:
    """The entries of a list value: quoted strings, comma-separated words and YAML items."""
    out = [m.group(1) or m.group(2) for m in re.finditer(r'"([^"]*)"|\'([^\']*)\'', value)]
    for part in re.split(r"[,\n]", value):
        word = part.strip().lstrip("-").strip().strip("[]{}").strip().strip("\"'").strip()
        if word:
            out.append(word)
    return out


def _broad(entry: str, rules: _LooseningRules) -> bool:
    return any(b.fullmatch(entry.strip()) for b in rules.broad)


Hit = tuple[str, str, str]  # (key, value, tier)


def _loosening_hits(
    text: str,
    old: str,
    rules: _LooseningRules,
    where: _Where,
    *,
    parents: list[str] | None = None,
    fragment: bool = False,
) -> set[Hit]:
    """The loosening settings `text` holds where a file or command sits, as (key, value, tier).
    `old` is the text it replaces (for `old_values`); `parents` stands in for the enclosing keys
    when the text shows none (a config command's path); `fragment` marks an edit's text, whose
    top level is not the file's."""
    hits: set[Hit] = set()
    if not text or not where:
        return hits
    if where.fmt != "json":
        text = _yaml_expand(text)
    classes = where.classes
    found: list[tuple[_Setting, str, str, int]] = []
    active = [
        s
        for s in rules.settings
        if not (s.host is not None and where.host is not None and s.host != where.host)
        and not (s.where == "env" and "env" not in classes)
        and not (s.where == "tree" and ("tree" not in classes or where.excluded))
        and not (s.where == "config" and not classes & {"approvals", "main", "include"})
    ]
    if active:
        for start in rules.any_key.finditer(text):
            for s in active:
                m = s.rx.match(text, start.start())
                if m and s.value.fullmatch(m.group("v")):
                    found.append((s, m.group("k"), m.group("v"), m.start()))
        if "<key>" in text:
            for s in active:
                if s.where == "env":
                    for m in s.plist.finditer(text):
                        if s.value.fullmatch(m.group("v")):
                            found.append((s, m.group("k"), m.group("v"), m.start()))
    contexts = _contexts(text, [at for _, _, _, at in found], where.fmt) if found else {}
    # An `$include` file's top level is wherever the config includes it: a fragment.
    fragment = fragment or "include" in classes
    top_level: list[str] | None = None  # `key:value` at the fragment's top level, read once

    def beside(s: _Setting) -> bool:
        nonlocal top_level
        if s.siblings is None:
            return False
        if top_level is None:
            pairs = [
                (m.start(), m.group(1), m.group(2))
                for _, m in zip(range(_LIST_MATCHES), _SIBLING_KEY.finditer(text), strict=False)
            ]
            ctx_at = _contexts(text, [at for at, _, _ in pairs], where.fmt)
            top_level = [f"{k}:{v}" for at, k, v in pairs if ctx_at.get(at) == []]
        return any(s.siblings.fullmatch(kv) for kv in top_level)

    for s, key, value, at in found:
        enclosing = contexts.get(at, [])
        if enclosing is _INSIDE:
            continue  # inside a string, a comment or a block scalar
        tier = REVIEW if "include" in classes and s.where == "config" else BLOCK
        if s.where == "config" and "approvals" not in classes:
            enclosing = enclosing or (parents or [])
            if enclosing:
                if s.parents is None or not s.parents.fullmatch(enclosing[0]):
                    continue
            elif s.bare and "main" in classes:
                pass
            elif s.old_values is not None and any(
                m.group("k").lower() == key.lower() and s.old_values.fullmatch(m.group("v"))
                for m in s.rx.finditer(old)
            ):
                pass
            elif fragment and not s.ambiguous:
                tier = REVIEW  # a fragment that cannot be decided: ask, do not stay silent
            elif fragment and beside(s):
                pass  # beside a key only this setting's section has
            else:
                continue  # the top level of a whole file, or a key both hosts use elsewhere
        hits.add((key, value.lower(), tier))
    key_rxs: list[re.Pattern[str]] = []
    if "tree" in classes and not where.excluded:
        key_rxs += [k for h, k in rules.allow_tree.items() if where.host in (None, h)]
    if "approvals" in classes and rules.allow_approvals is not None:
        key_rxs.append(rules.allow_approvals)
    if key_rxs:
        brackets: dict[int, int] | None = None
        seen = 0
        for key_rx in key_rxs:
            for m in key_rx.finditer(text):
                seen += 1
                if seen > _LIST_MATCHES:
                    break
                if brackets is None:
                    brackets = _brackets(text)
                for entry in _entries(_list_value(text, m.end(), brackets)):
                    if _broad(entry, rules):
                        hits.add((m.group(0).strip(" \t:=\"'"), entry.strip(), BLOCK))
    return hits


#: A `key: value` pair, the key quoted or not; the value's first word.
_SIBLING_KEY = re.compile(
    r"""(?<![\w$-])["']?([A-Za-z_$][\w$-]*)["']?[ \t]*:[ \t]*["']?([^\s"',}\]]*)"""
)


def _loosened(
    pairs: list[tuple[str, str]], rules: _LooseningRules, where: _Where, *, fragment: bool
) -> set[Hit]:
    """The loosening settings the new text of each (old, new) pair holds and its old text does
    not (compared without the tier)."""
    out: set[Hit] = set()
    for old, new in pairs:
        old, new = _decode(old), _decode(new)
        before = {
            (k.lower(), v) for k, v, _ in _loosening_hits(old, "", rules, where, fragment=fragment)
        }
        out |= {
            h
            for h in _loosening_hits(new, old, rules, where, fragment=fragment)
            if (h[0].lower(), h[1]) not in before
        }
    return out


# A key path assigned a value in a script: `jq`/`yq` (`.tools.exec.mode = "full"`), Python
# subscripts (`d['defaults']['ask'] = 'off'`), JavaScript members (`c.tools.exec.mode = 'full'`).
_SCRIPT_VALUE = r"""\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|(?P<bare>[\w.-]+))"""
_JQ_ASSIGN = re.compile(
    r"""(?<![\w\]\)])\.(?P<path>[\w$-]+(?:\.[\w$-]+|\["[^"\n]+"\])*)\s*\|?=(?!=)""" + _SCRIPT_VALUE
)
_SUBSCRIPT_ASSIGN = re.compile(
    r"""\b[A-Za-z_]\w*(?P<path>(?:\[\s*["'][^"'\n]+["']\s*\])+)\s*=(?!=)""" + _SCRIPT_VALUE
)
_MEMBER_ASSIGN = re.compile(
    r"""(?<![\w$.?])[A-Za-z_$][\w$]*(?P<path>(?:\??\.[A-Za-z_$][\w$]*)+)\s*=(?!=)""" + _SCRIPT_VALUE
)
_PATH_PART = re.compile(r"""[\w$-]+""")


def _script_assignments(text: str) -> list[tuple[list[str], str]]:
    """(key path, value) of each assignment the script makes."""
    out: list[tuple[list[str], str]] = []
    for rx in (_JQ_ASSIGN, _SUBSCRIPT_ASSIGN, _MEMBER_ASSIGN):
        for m in rx.finditer(text):
            parts = _PATH_PART.findall(m.group("path"))
            value = m.group("dq") if m.group("dq") is not None else m.group("sq")
            value = value if value is not None else m.group("bare")
            if parts and value is not None:
                out.append((parts, value))
    return out


def _assignment_hits(text: str, rules: _LooseningRules, where: _Where) -> tuple[set[Hit], bool]:
    """Block-tier hits from the script's assignments read as config paths, and whether any
    assignment names an approval key (then the script is decided and the loose-word check
    does not apply)."""
    hits: set[Hit] = set()
    decided = False
    for parts, value in _script_assignments(text):
        leaf = parts[-1]
        if _match_any(rules.approval_keys, leaf) or any(
            s.keys.fullmatch(leaf) for s in rules.settings
        ):
            decided = True
        hits |= _loosening_hits(f"{leaf}: {value}", "", rules, where, parents=parts[-2::-1])
    return {(k, v, BLOCK) for k, v, _ in hits}, decided


def _script_hits(text: str, rules: _LooseningRules, where: _Where) -> set[Hit]:
    """Review tier: a script writes a host approvals or config file and its text is not settings
    the scan can read (`s/deny/full/`, `.replace('mode: smart', 'mode: off')`). A loosening value
    counts anywhere in an approvals file; in a config file next to an approval key, or after the
    same key with an approvals value."""
    if not where.classes & {"approvals", "main", "include"}:
        return set()
    # Text in settings syntax (`"mode": "full"`) was read by the precise check; what it decided
    # stands.
    for s in rules.settings:
        if any(s.value.fullmatch(m.group("v")) for m in s.rx.finditer(text)):
            return set()
    loose = _match_any(rules.loose_values, text)
    if loose is None:
        return set()
    if "approvals" in where.classes or _match_any(rules.approval_keys, text):
        return {("script", loose.group(0).strip("'\""), REVIEW)}
    return set()


_PATCH_FILE = re.compile(
    r"^(?:\*\*\* (?:Update|Add) File:|\+\+\+ (?:b/)?)[ \t]*(\S(?:.*\S)?)[ \t]*$", re.M
)


def _patch_sections(text: str) -> list[tuple[str, str, str]]:
    """(path, removed text, added text) per file of a patch (`*** Begin Patch` or unified diff)."""
    out: list[tuple[str, str, str]] = []
    heads = list(_PATCH_FILE.finditer(text))
    for i, m in enumerate(heads):
        body = text[m.end() : heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        old, new = [], []
        for line in body.splitlines():
            if line.startswith(("+++", "---", "***")):
                continue
            if line.startswith("+"):
                new.append(line[1:])
            elif line.startswith("-"):
                old.append(line[1:])
            elif line.startswith(" "):
                # Context lines tie a setting to its section; they are in both texts.
                old.append(line[1:])
                new.append(line[1:])
        out.append((m.group(1), "\n".join(old), "\n".join(new)))
    return out


# One `{"path": …, "value": …}` item of `config set --batch-json`, quotes optional.
_BATCH_ITEM = re.compile(
    r"""["']?path["']?\s*:\s*["']?([\w.\[\]-]+)["']?\s*,\s*["']?value["']?\s*:\s*"""
    r"""("[^"]*"|'[^']*'|\[[^\]]*\]|\{[^}]*\}|[^,}\s]+)"""
)
# The two branches never match the same character (a backslash only starts an escape), so the
# loop cannot backtrack exponentially on a long run of escapes.
_SED_SUBST = re.compile(r"""(?<![\w])s([/|#,:@])((?:\\.|(?!\1)[^\\])*)\1""")
#: After a separator, whitespace other than a newline (a newline is a separator of its own), so a
#: long run of newlines is read once.
_ASSIGNMENT = re.compile(
    r"""(?:\A|[;&|\n(][^\S\n]*|\bexport\s+)([A-Za-z_]\w*)=(["']?)([^\s;&|'"]+)\2"""
)
_VAR_REF = re.compile(r"\$\{(\w+)\}|\$(\w+)")
_TILDE_USER = re.compile(r"\A~([A-Za-z_][\w.-]*)(?=/|\Z)")
# Inline code: the home directory however it is spelled, variables, and string literals
# (f-strings, raw strings and JavaScript template literals included).
_CODE_HOME = re.compile(
    r"""Path\.home\(\)|os\.path\.expanduser\(\s*["']~["']\s*\)|"""
    r"""os\.environ\s*\[\s*["']HOME["']\s*\]|os\.environ\.get\(\s*["']HOME["'][^)]*\)|"""
    r"""os\.getenv\(\s*["']HOME["'][^)]*\)|process\.env\.HOME|process\.env\[\s*["']HOME["']\s*\]|"""
    r"""(?:(?<!\w)\w+|require\(\s*["']os["']\s*\))\.homedir\(\)"""
)
_CODE_TOKEN = re.compile(
    r"""(?P<lit>[fFrRbB]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|`[^`]*`)|(?P<name>[A-Za-z_$][\w$]*)"""
)
_CODE_ASSIGN = re.compile(
    r"""(?:^|[;\n{])[ \t]*(?:const[ \t]+|let[ \t]+|var[ \t]+)?(?P<name>[A-Za-z_$][\w$]*)[ \t]*=(?!=)(?P<expr>[^;\n]*)""",
    re.M,
)
_PLACEHOLDER = re.compile(r"""\$?\{([^{}]*)\}""")
_HOME_MARK = "\x00HOME\x00"
_CODE_KEYWORDS = frozenset(
    {"True", "False", "None", "true", "false", "null", "undefined", "new", "await", "with", "as"}
)
_CODE_IGNORED = frozenset({"w", "a", "x", "r", "wb", "ab", "w+", "a+", "utf8", "utf-8", "HOME"})


def _sed_split(text: str) -> tuple[str, str]:
    """(old, new) text of a command with `s/…/…/` substitutions (`sed`, `perl`): the search
    patterns are the old text; the rest of the command is the new text."""
    old = [m.group(2) for m in _SED_SUBST.finditer(text)]
    return "\n".join(old), _SED_SUBST.sub(lambda m: "s" + m.group(1), text)


_REPLACE_CALL = re.compile(
    r"""\.replace(?:All)?\(\s*(?P<old>"[^"\n]*"|'[^'\n]*')\s*,\s*(?P<new>"[^"\n]*"|'[^'\n]*')\s*\)"""
)


def _split_script(text: str) -> tuple[str, str]:
    """(old, new) text of a script: `s/…/…/` search patterns and `.replace(a, b)` first
    arguments are the old text; the rest of the script, with them taken out, is the new text."""
    old_sed, text = _sed_split(text)
    olds = [old_sed] if old_sed else []
    olds += [m.group("old")[1:-1] for m in _REPLACE_CALL.finditer(text)]
    text = _REPLACE_CALL.sub(lambda m: ".replace(" + m.group("new") + ")", text)
    return "\n".join(olds), text


def _unescape(text: str) -> str:
    """Backslash escapes as `printf` and `echo -e` read them."""
    table = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": ""}
    return re.sub(r"\\(.)", lambda m: table.get(m.group(1), "\\" + m.group(1)), text)


_WRITE_MODE = re.compile(r"""(?:mode\s*=\s*)?[fbrFBR]?["'][wax]\+?[bt]?["']""")
_SCAN_BUDGET = 2000  # characters read per call or receiver
_SINK_MATCHES = 200  # sink calls read per script


def _call_args(text: str, open_paren: int) -> list[str]:
    """The top-level arguments of the call whose `(` is at `open_paren` (strings and nested
    brackets skipped), at most `_SCAN_BUDGET` characters."""
    args: list[str] = []
    depth = 0
    quote = ""
    start = i = open_paren + 1
    end = min(len(text), open_paren + _SCAN_BUDGET)
    while i < end:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(text[start:i].strip())
                return [a for a in args if a]
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return [a for a in args if a]


def _receiver(text: str, end: int) -> str:
    """The expression that ends at `end` (a method's receiver): a bracketed group with the
    name before it (`Path(...)`, `(Path.home() / 'x')`), or a dotted name."""
    if end > 0 and text[end - 1] == ")":
        depth = 0
        j = end - 1
        while j >= 0 and end - j < _SCAN_BUDGET:
            if text[j] == ")":
                depth += 1
            elif text[j] == "(":
                depth -= 1
                if depth == 0:
                    break
            j -= 1
        name = re.search(r"[\w.]*\Z", text[max(0, j - 200) : j])
        return text[j - (len(name.group(0)) if name else 0) : end]
    name = re.search(r"[\w.]+\Z", text[max(0, end - 200) : end])
    return name.group(0) if name else ""


def _code_sink_targets(text: str, rules: _LooseningRules) -> list[str]:
    """The expression each write sink in inline code names as its file."""
    out: list[str] = []
    for rx, kind, argn, needs_mode in rules.code_sinks:
        for n, m in enumerate(rx.finditer(text)):
            if n >= _SINK_MATCHES:
                break
            args = _call_args(text, m.end() - 1)
            if needs_mode and not any(
                _WRITE_MODE.fullmatch(a) for a in args[(1 if kind == "call" else 0) :]
            ):
                continue
            if kind == "call":
                if len(args) >= argn:
                    out.append(args[argn - 1])
            else:
                receiver = _receiver(text, m.start())
                if receiver:
                    out.append(receiver)
    return out


def _code_path(expr: str, variables: dict[str, str]) -> str | None:
    """The path a code expression names, or None when it cannot be told: string literals
    joined in order (`Path.home() / '.openclaw' / 'x.json'`, `os.path.join(d, 'x.json')`,
    `f"{os.environ['HOME']}/.hermes/config.yaml"`, `` `${process.env.HOME}/x` ``), the home
    directory however it is spelled, and variables assigned earlier."""
    expr = _CODE_HOME.sub(lambda m: "'" + _HOME_MARK + "'", expr.strip())
    parts: list[str] = []
    for m in _CODE_TOKEN.finditer(expr):
        if m.group("name") is not None:
            name = m.group("name")
            after = expr[m.end() :].lstrip()[:1]
            before = expr[: m.start()].rstrip()[-1:]
            if after in ("(", ".", "=") or before == "." or name in _CODE_KEYWORDS:
                continue
            if name not in variables:
                return None  # a value the scan cannot see
            parts.append(variables[name])
            continue
        if m.group("lit"):
            lit = m.group("lit").lstrip("fFrRbB")[1:-1]

            def fill(p: re.Match[str]) -> str:
                inner = p.group(1).strip()
                if _HOME_MARK in inner:
                    return _HOME_MARK
                return variables.get(inner, "\x00?\x00")

            lit = _PLACEHOLDER.sub(fill, lit)
            if "\x00?\x00" in lit:
                return None
            if lit in _CODE_IGNORED or not lit:
                continue
            parts.append(lit)
    if not parts:
        return None
    joined = "/".join(p.strip("/") if i else p.rstrip("/") for i, p in enumerate(parts))
    return joined.replace(_HOME_MARK, "~") or None


def _code_variables(code: str) -> dict[str, str]:
    """Variables the code assigns a path, a path part or the home directory."""
    variables: dict[str, str] = {}
    for m in _CODE_ASSIGN.finditer(code):
        expr = m.group("expr").strip()
        if not expr:
            continue
        home = _CODE_HOME.fullmatch(expr)
        if home:
            variables[m.group("name")] = "~"
            continue
        path = _code_path(expr, variables)
        if path:
            variables[m.group("name")] = path
            continue
        lit = re.fullmatch(r"""[fr]?(["'])([\w.~/-]+)\1""", expr)
        if lit:
            variables[m.group("name")] = lit.group(2)
    return variables


def _code_commands(code: str, rules: _LooseningRules, variables: dict[str, str]) -> list[str]:
    """Commands inline code runs (`os.system`, `subprocess.*`, `child_process.exec*`), as text.
    A list's elements are literals or paths the code builds."""
    out: list[str] = []
    for rx in rules.code_commands:
        for n, m in enumerate(rx.finditer(code)):
            if n >= _SINK_MATCHES:
                break
            arg = m.group("c").strip()
            if arg.startswith("[") or re.match(r"""["'][\w./-]+["']\s*,""", arg):
                elements: list[str] = []
                # `[a, b]`, or `'sed', [a, b]` (a program and its argument list): one level
                # of bracket-aware splitting each.
                parts: list[str] = []
                for part in _call_args("(" + (arg[1:-1] if arg.startswith("[") else arg) + ")", 0):
                    if part.startswith("[") and part.endswith("]"):
                        parts.extend(_call_args("(" + part[1:-1] + ")", 0))
                    else:
                        parts.append(part)
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue
                    lit = re.fullmatch(r"""[fr]?(["'])(.*)\1""", part)
                    if lit and "{" not in lit.group(2):
                        elements.append(lit.group(2))
                    else:
                        elements.append(_code_path(part, variables) or part)
                out.append(" ".join(shlex.quote(e) for e in elements))
            else:
                lit = re.fullmatch(r"""[fr]?(["'`])(.*)\1""", arg, re.DOTALL)
                if lit:
                    out.append(lit.group(2))
    return out


def _approval_loosening(
    a: CallAnalysis, ctx: Context
) -> list[tuple[str, str | None, dict[str, Any]]]:
    """Changes that loosen the host's approval or allowlist policy, as (tier, subject, detail)."""
    lists = ctx.lists
    rules = _loosening_rules(lists)
    if not rules.settings and not rules.allow_tree:
        return []
    out: list[tuple[str, str | None, dict[str, Any]]] = []
    home = ctx.prepared.home.rstrip("/")
    ws = ctx.prepared.workspace_root

    def report(hits: set[Hit], subject: str | None, detail: dict[str, Any]) -> None:
        if not hits:
            return
        tier = BLOCK if any(t == BLOCK for _, _, t in hits) else REVIEW
        settings = sorted(f"{k}={v}" for k, v, t in hits if t == tier)
        out.append((tier, subject, {**detail, "settings": settings[:4]}))

    def resolve(path: str, cwd: str | None = None) -> str:
        path = path.strip().strip("'\"")
        path = path.replace("${HOME}", "~").replace("$HOME", "~")
        m = _TILDE_USER.match(path)
        if m:
            user = m.group(1)
            base = home if os.path.basename(home) == user else os.path.dirname(home) + "/" + user
            path = base + path[m.end() :]
        base = cwd or a.cwd or ws
        if path and not path.startswith(("/", "~", "$")):
            # `normalise_path` keeps a bare or `../` relative path as it is; this floor anchors on
            # the host trees, so it resolves one against the cwd (or the workspace) first.
            base_abs = normalise_path(base, home=home, workspace_root=ws, cwd=None)
            path = os.path.join(base_abs, path)
        value = normalise_path(path, home=home, workspace_root=ws, cwd=base)
        return os.path.normpath(value) if value.startswith("/") else value

    def display(value: str) -> str:
        return display_path(value, home)

    # 1. File tools: write, edit, patch (also MCP and other tools that name the path).
    if a.kind in _WRITE_KINDS | {ToolKind.MCP, ToolKind.OTHER}:
        raw = a.call.raw if isinstance(a.call.raw, dict) else {}
        patch = next(
            (
                raw[k]
                for k in ("input", "patch", "diff")
                if isinstance(raw.get(k), str) and _PATCH_FILE.search(raw[k])
            ),
            None,
        )
        if patch is not None:
            for path, old, new in _patch_sections(patch):
                value = resolve(path)
                p = a.path(value)
                where = _host_where(value, rules, ctx)
                report(
                    _loosened([(old, new)], rules, where, fragment=True),
                    p.entity_id if p else None,
                    {"path": display(value), "mechanism": "patch"},
                )
        edits = [e for e in a.call.get("edits") or [] if isinstance(e, dict)]
        if edits:
            pairs = [(str(e.get("old") or ""), str(e.get("new") or "")) for e in edits]
        else:
            # A write replaces the whole file and the call does not show what it held, so a
            # loosening setting the file already had (`"exec": {"mode": "full"}` in openclaw.json,
            # also OpenClaw's gateway default) fires again on a rewrite. Accepted for now: an agent
            # rewriting the host's config whole is rare, and telling an unchanged setting from a
            # new one would need the file's earlier content.
            pairs = [("", a.content)]
        raw_path = a.call.get("path")
        targets = {resolve(p.value): (p.entity_id, p.display, m) for p, m in _written_paths(a, ctx)}
        if isinstance(raw_path, str) and raw_path:
            value = resolve(raw_path)
            targets.setdefault(value, (None, display(value), a.kind.value))
        for value, (subject, shown, mechanism) in targets.items():
            where = _host_where(value, rules, ctx)
            report(
                _loosened(pairs, rules, where, fragment=bool(edits)),
                subject,
                {"path": shown, "mechanism": mechanism},
            )
        return out

    if a.kind is not ToolKind.EXEC or not a.command:
        return out

    config_cli = lists.get("guardrail", "config_cli", default=[]) or []
    cli_heads = {str(e.get("head")).lower() for e in config_cli}
    cli_heads |= {str(e.get("head")).lower() for e in rules.approvals_cli}
    cli_heads |= set(rules.launch_flags)
    shells = set(lists.strings("installers", "shell_heads"))
    writing = {h.lower() for h in lists.strings("guardrail", "writing_heads")} - {"echo", "printf"}

    def judge(
        value: str,
        mechanism: str,
        *,
        content: str | None,
        old: str = "",
        script: str | None = None,
    ) -> None:
        """One file a command writes. `content` is what it writes when the scan can read it
        (an `echo`, `printf` or heredoc, a substitution's replacement); `script` is the text of
        a writer whose output the scan cannot read (`jq`, inline code), for the script checks."""
        where = _host_where(value, rules, ctx)
        if not where:
            return
        hits: set[Hit] = set()
        if content is not None:
            hits = _loosened([(old, content)], rules, where, fragment=False)
        if not hits and script is not None:
            old_s, new_s = _split_script(_decode(script))
            hits = _loosened([(old_s, new_s)], rules, where, fragment=False)
            if not hits:
                # The text a script writes as string literals (`.write('approvals:\\n  mode: off')`).
                literals = "\n".join(
                    _unescape(t.group("lit").lstrip("fFrRbB")[1:-1])
                    for t in _CODE_TOKEN.finditer(new_s)
                    if t.group("lit")
                )
                hits = _loosened([(old_s, literals)], rules, where, fragment=False)
            decided = False
            if not hits:
                hits, decided = _assignment_hits(new_s, rules, where)
            if not hits and not decided:
                hits = _script_hits(new_s, rules, where)
        report(hits, None, {"path": display(value), "mechanism": mechanism})

    def cli_where(head: str, *extra: str) -> _Where:
        return _Where(frozenset({"tree", "env", "main", *extra}), head, "auto")

    def cli_hit(line: str, mechanism: str, hits: set[Hit]) -> None:
        report(hits, None, {"match": line[:120], "mechanism": mechanism})

    def sqlite_write(text: str, dbs: list[str | None], cwd: str | None, mechanism: str) -> None:
        """SQL that writes the host's approvals table. In a host tree's state DB a loosening
        value blocks and any other write is reviewed; a database the scan cannot place (a
        variable, a state DB outside the trees) is reviewed; another database is not the
        host's."""
        db = rules.state_db
        if db is None or db.table not in text.lower():
            return
        statements = _sql_writes(text, db)
        if not statements:
            return
        # Each database named: in a host tree, one the scan cannot place, or another one.
        places: list[tuple[str, str]] = []
        for path in dbs:
            uri = _SQL_URI.match(path) if path else None
            path = uri.group("p") if uri else path
            if path == ":memory:":
                continue  # an in-memory database: what it attaches is what counts
            if not path or any(c in path for c in "$`{}"):
                places.append(("unknown", "an unplaced database"))
                continue
            value = resolve(path, cwd)
            if _tree_file(value, db.host, db.files, rules, ctx):
                places.append(("tree", display(value)))
            elif db.basename.fullmatch(os.path.basename(value)):
                places.append(("unknown", display(value)))
            else:
                places.append(("other", display(value)))
        kinds = {k for k, _ in places}
        if not kinds & {"tree", "unknown"}:
            return
        # The scan does not bind a statement to a connection: a tree DB opened beside another
        # database is not known to be the one written, so it is asked, not blocked.
        place = "tree" if kinds == {"tree"} else "unknown"
        shown = next(sh for k, sh in places if k in ("tree", "unknown"))
        where = _Where(frozenset({"approvals"}), db.host, "auto")
        hits: set[Hit] = set()
        for statement in statements:
            hits |= _loosening_hits(_sql_settings(statement, db), "", rules, where)
        if place != "tree" or not hits:
            hits = {(k, v, REVIEW) for k, v, _ in hits} | {("sqlite write", db.table, REVIEW)}
        report(hits, None, {"path": shown, "mechanism": mechanism})

    def set_value(head: str, path: str, value: str) -> set[Hit]:
        """`<path> <value>` of a config command, read as `<last segment>: <value>` with the
        path's other segments as the enclosing keys."""
        if value.startswith("@"):
            # Read from a file the call does not show: the session decides, not this floor.
            return set()
        segments = [s.strip("'\"") for s in path.split(".") if s.strip("'\"")]
        if not segments:
            return set()

        text = f"{segments[-1]}: {value}"
        return _loosening_hits(text, "", rules, cli_where(head), parents=segments[-2::-1])

    def drops_policy(path: str, value: str, merge: bool) -> bool:
        """`config set` of the exec settings that leaves OpenClaw on its looser defaults."""
        path = path.strip("'\"")
        if value.strip().lower() == "null" and _match_any(rules.unset_paths, path):
            return True
        if merge or not _match_any(rules.replaced_objects, path):
            return False
        if not value.lstrip().startswith("{"):
            return False
        names = {w.lower() for w in re.findall(r"[A-Za-z]+", value)}
        if path.strip() == "tools" and "exec" not in names:
            return True
        return "mode" not in names and not {"security", "ask"} <= names

    def cli(tokens: list[str], line: str, command: str) -> None:
        """The host CLIs: config commands, approvals commands, launch flags."""
        head = tokens[0]
        flags = rules.launch_flags.get(head, frozenset())
        if flags and any(t in flags for t in tokens[1:]):
            cli_hit(line, "launch_flag", {(t, "on", BLOCK) for t in tokens[1:] if t in flags})
        for at in _after_options(tokens, 1):
            sub = tokens[at].lower()
            verbs = [(v, tokens[v].lower()) for v in _after_options(tokens, at + 1)]
            for entry in config_cli:
                if head != entry.get("head") or sub != entry.get("subcommand"):
                    continue
                for v, verb in verbs:
                    if verb not in {str(x).lower() for x in entry.get("mutating_verbs", [])}:
                        continue
                    args = tokens[v + 1 :]
                    positional = [t for t in args if not t.startswith("-")]
                    hits: set[Hit] = set()
                    removes = verb in ("unset", "rm", "remove", "delete", "del")
                    if removes and head == "openclaw":
                        hits = {
                            (path, "unset", BLOCK)
                            for path in positional[:1]
                            if _match_any(rules.unset_paths, path.strip("'\""))
                        }
                    if verb == "patch":
                        hits |= _loosening_hits(
                            _heredocs(command) or command, "", rules, cli_where(head)
                        )
                    if "--dry-run" not in args:
                        # Content the call does not show: a patch or batch file, or a patch
                        # read on stdin from a file.
                        for i, t in enumerate(args):
                            name, eq, val = t.partition("=")
                            if name in ("--file", "--batch-file") and (
                                verb == "patch" or name == "--batch-file"
                            ):
                                val = val if eq else (args[i + 1] if i + 1 < len(args) else "")
                                # `-` (dropped from the words) is stdin: a heredoc there is read.
                                if val and val != "-":
                                    hits.add(("read from", val, REVIEW))
                        if (
                            verb == "patch"
                            and "--stdin" in args
                            and not _heredocs(command)
                            and _STDIN_FILE.search(command)
                        ):
                            hits.add(("read from", "stdin", REVIEW))
                    if any(t.split("=", 1)[0] == "--batch-json" for t in args):
                        for m in _BATCH_ITEM.finditer(command):
                            hits |= set_value(head, m.group(1), m.group(2).strip("'\""))
                    if not removes and len(positional) >= 2:
                        hits |= set_value(head, positional[0], positional[1])
                        if head == "openclaw" and drops_policy(
                            positional[0], positional[1], "--merge" in args
                        ):
                            hits.add((positional[0], "policy dropped", BLOCK))
                    elif not removes and len(positional) == 1 and "=" in positional[0]:
                        path, _, value = positional[0].partition("=")
                        hits |= set_value(head, path, value)
                    if hits:
                        cli_hit(line, f"{head} {sub} {verb}", hits)
            for entry in rules.approvals_cli:
                if head != entry.get("head") or sub != entry.get("subcommand"):
                    continue
                for v, verb in verbs:
                    if verb != entry.get("verb"):
                        continue
                    args = tokens[v + 1 :]
                    mech = f"{head} {sub} {verb}"
                    presets = {str(p).lower() for p in entry.get("presets") or []}
                    if presets and any(t.lower() in presets for t in args):
                        cli_hit(
                            line, mech, {("preset", t, BLOCK) for t in args if t.lower() in presets}
                        )
                    flag_rx = entry.get("flags") or {}
                    found: set[Hit] = set()
                    for i, t in enumerate(args):
                        name, eq, val = t.partition("=")
                        if name in flag_rx:
                            val = val if eq else (args[i + 1] if i + 1 < len(args) else "")
                            if re.fullmatch(str(flag_rx[name]), val, re.IGNORECASE):
                                found.add((name, val, BLOCK))
                    if found:
                        cli_hit(line, mech, found)
                    if entry.get("content"):
                        doc = _heredocs(command) or command
                        hits = _loosening_hits(doc, "", rules, cli_where(head, "approvals"))
                        if hits:
                            cli_hit(line, mech, hits)
                    file_flag = entry.get("file_flag")
                    for i, t in enumerate(args):
                        name, eq, val = t.partition("=")
                        if file_flag and name == file_flag:
                            val = val if eq else (args[i + 1] if i + 1 < len(args) else "")
                            src = resolve(val)
                            if val and not _host_where(src, rules, ctx).classes & {"approvals"}:
                                cli_hit(line, mech, {("read from", display(src), REVIEW)})
                    add = entry.get("allowlist_add")
                    if add and args and args[0].lower() == str(add):
                        # Entries: the words after the options; an option's value is skipped.
                        entries: list[str] = []
                        skip = False
                        for t in args[1:]:
                            if skip:
                                skip = False
                            elif t.startswith("-"):
                                skip = "=" not in t
                            else:
                                entries.append(t)
                        broad = {("allowlist", e, BLOCK) for e in entries if _broad(e, rules)}
                        if broad:
                            cli_hit(line, mech, broad)

    def code(text: str, cwd: str, depth: int) -> None:
        """Inline code (`python -c`, `node -e`, Hermes `execute_code`, a script in a heredoc):
        each write sink's target, the commands it runs, and the review backstop for a target
        the scan cannot resolve in code that names a host approvals or main config file."""
        variables = _code_variables(text)
        db = rules.state_db
        if db is not None and db.writers.search(text) and db.table in text.lower():
            connects = [
                _call_args(text, m.end() + text[m.end() :].index("("))
                for n, m in enumerate(db.connect.finditer(text))
                if n < _SINK_MATCHES and "(" in text[m.end() : m.end() + 3]
            ]
            dbs = [_code_path(args[0], variables) if args else None for args in connects]
            dbs += [m.group("a") for m in _SQL_OPEN.finditer(text) if m.group("a")]
            # A connection the scan does not recognise is a database it cannot place.
            sqlite_write(_decode(text), dbs or [None], cwd, "inline_code")
        unresolved = False
        for target in _code_sink_targets(text, rules):
            path = _code_path(target, variables)
            if path is None:
                unresolved = True
                continue
            judge(resolve(path, cwd), "inline_code", content=None, script=text)
        if depth < 3:
            for command in _code_commands(text, rules, variables):
                shell(command, cwd, depth + 1)
        if unresolved and not any(t == BLOCK for t, _, _ in out):
            named = _CODE_HOME.sub("~", text)
            for m in re.finditer(r"""\.(?:openclaw|hermes)[\w.-]*['"/ ,+]""", named):
                tail = named[m.start() : m.start() + 200]
                host_file = re.search(
                    r"""exec-approvals\.json|openclaw\.json|config\.ya?ml""", tail
                )
                if host_file:
                    report(
                        {("unresolved write", host_file.group(0), REVIEW)},
                        None,
                        {"mechanism": "inline_code", "match": tail[:80]},
                    )
                    break

    def shell(command: str, cwd: str, depth: int) -> None:
        """A shell command: what each segment writes, the host CLIs it runs, and the scripts
        and inline code it carries. `cd`/`pushd` move the cwd; `bash -c` scripts recurse."""
        command = _decode(command)
        shape = derive_exec_shape(command, lists.path_groups, workspace_root=ws, home=home)
        variables = {m.group(1): m.group(3) for m in _ASSIGNMENT.finditer(command)}
        links: dict[str, str] = {}

        def expand(token: str) -> str:
            def var(m: re.Match[str]) -> str:
                name = m.group(1) or m.group(2)
                return "~" if name == "HOME" else variables.get(name, m.group(0))

            token = _VAR_REF.sub(var, token)
            for alias, target in links.items():
                if token == alias or token.startswith(alias + "/"):
                    token = target + token[len(alias) :]
            return token

        heredocs = _heredocs(command)
        produced: list[str] = []  # what earlier `echo`/`printf` segments printed (a pipe source)
        previous = ""  # the text of the segment before (a pipe's writer)
        written_content: dict[str, str | None] = {}
        written_script: dict[str, str] = {}  # the writer's text, when its output is not read
        written_blind: set[str] = set()  # written from content the scan cannot read
        segments = shape.segments if shape.parse_ok else []
        for seg in segments:
            head = seg.head
            words = [head, *[expand(w) for w in seg.argv]]
            line = " ".join(words)
            args = [expand(t) for t in seg.positional]
            if head in rules.cd_heads:
                if args:
                    cwd = resolve(args[0], cwd)
                continue
            script = _shell_script([_shell_word(w) for w in words], shells)
            if script is not None and depth < 3:
                shell(script, cwd, depth + 1)
            rendered = _render(head, seg, heredocs)
            if head == "ln" and args and len(args) >= 2 and (seg.has_flag_letter("s")):
                links[args[-1].rstrip("/")] = args[-2].rstrip("/")
            if head == "sqlite3":
                db_arg, sql = _sqlite_cli(words[1:])
                sql_text = ";\n".join([*sql, _heredocs_after(command, "sqlite3"), *produced])
                opened = [m.group("o") or m.group("a") for m in _SQL_OPEN.finditer(sql_text)]
                dbs = [d for d in (db_arg, *opened) if d]
                if dbs:
                    sqlite_write(sql_text, list(dbs), cwd, "sqlite3")
            # Redirects: an `echo`/`printf`/heredoc is read; a blind head is a replacement.
            for target in seg.redirects:
                inner = re.fullmatch(r">\((.*)\)", target, re.DOTALL)
                if inner is not None:
                    # Process substitution: the inner command reads this segment's output.
                    if depth < 3:
                        source = " ".join(shlex.quote(w) for w in words)
                        shell(source + " | " + inner.group(1), cwd, depth + 1)
                    continue
                value = resolve(expand(target), cwd)
                sources = [t for t in args if not t.startswith("-")]
                piped_in = "\n".join(produced) if produced else None
                if head == "cat" and not sources and rendered is None:
                    judge(value, "redirect", content=piped_in, script=previous or None)
                    written_content[value] = piped_in
                elif head in rules.blind_heads and rendered is None:
                    # A file, a download or decoded input the scan cannot read.
                    src = (
                        resolve(sources[0], cwd) if sources and head not in ("curl", "wget") else ""
                    )
                    if src and src in written_content and src not in written_blind:
                        judge(
                            value,
                            "redirect",
                            content=written_content[src],
                            script=written_script.get(src),
                        )
                    else:
                        blind(value, sources[0] if src else "unreadable input")
                        written_blind.add(value)
                    written_content[value] = None
                else:
                    judge(
                        value,
                        "redirect",
                        content=rendered,
                        script=None if rendered is not None else line,
                    )
                    written_content[value] = rendered
                written_script[value] = line
            # Pipe writers: `tee`, `sponge`, `dd of=`.
            piped = "\n".join(produced) if produced else None
            if head in ("tee", "sponge"):
                for tok in args:
                    value = resolve(tok, cwd)
                    judge(value, f"head:{head}", content=rendered or piped, script=previous or None)
                    written_content[value] = rendered or piped
            elif head == "dd":
                for tok in args:
                    if tok.startswith("of="):
                        value = resolve(tok[3:], cwd)
                        judge(value, "head:dd", content=piped, script=previous or None)
            elif head in rules.inplace_heads and (
                seg.has_flag_letter("i") or "--in-place" in seg.flags or "--inplace" in seg.flags
            ):
                old, new = _sed_split(line)
                for tok in args:
                    if _SED_SUBST.search(tok) or re.search(r"[\s=]", tok) or tok.startswith("."):
                        continue
                    judge(resolve(tok, cwd), f"in_place:{head}", content=new, old=old, script=line)
            elif head in writing and head not in rules.replace_heads and head != "dd":
                for tok in args:
                    judge(resolve(tok, cwd), f"head:{head}", content=None, script=line)
            if head in rules.replace_heads:
                replace(seg, args, cwd, written_content, written_script, written_blind)
            if head in ("curl", "wget"):
                letter = rules.download_letters.get(head, "")
                for i, f in enumerate(seg.argv):
                    name, eq, val = f.partition("=")
                    takes = name in rules.download_flags or (
                        letter
                        and f.startswith("-")
                        and not f.startswith("--")
                        and f.endswith(letter)
                    )
                    if takes and not eq:
                        val = seg.argv[i + 1] if i + 1 < len(seg.argv) else ""
                    if takes and val and val != "-":
                        blind(resolve(expand(val), cwd), "a download")
            tokens = _cli_tokens([_shell_word(w) for w in words], cli_heads, lists)
            if tokens and tokens[0] in cli_heads:
                cli(tokens, line, command)
            if rendered is not None:
                produced.append(rendered)
            previous = line
        # Inline code anywhere in the command (`python3 -c`, `node -e`, a heredoc script).
        code(command, cwd, depth)
        env = _match_any(rules.env, command)
        if env:
            cli_hit(
                env.group(0).strip(), "environment", {("environment", env.group(0).strip(), BLOCK)}
            )

    def blind(value: str, source: str) -> None:
        if _host_where(value, rules, ctx).classes & {"approvals", "main"}:
            shown = (
                source if source in ("a download", "unreadable input") else display(resolve(source))
            )
            report(
                {("replaced from", shown, REVIEW)},
                None,
                {"path": display(value), "mechanism": "replace"},
            )

    def replace(
        seg: ExecSegment,
        args: list[str],
        cwd: str,
        written_content: dict[str, str | None],
        written_script: dict[str, str],
        written_blind: set[str],
    ) -> None:
        """`cp`, `mv`, `install`, `rsync`, `ln` onto a host approvals or main config file."""
        target_dir = None
        for i, f in enumerate(seg.argv):
            if f in ("-t", "--target-directory") and i + 1 < len(seg.argv):
                target_dir = seg.argv[i + 1]
            elif f.startswith("--target-directory="):
                target_dir = f.split("=", 1)[1]
        # Option values are not files: `install -m 600`, `-o user`, `-g group`, `-S .bak`.
        valued = {"-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix", "-t"}
        skip = {seg.argv[i + 1] for i, f in enumerate(seg.argv[:-1]) if f in valued}
        words = [t for t in args if t != target_dir and t not in skip]
        if target_dir is not None:
            sources, dests = words, [target_dir.rstrip("/") + "/"] * len(words)
        elif len(words) >= 2:
            sources, dests = words[:-1], [words[-1]] * (len(words) - 1)
        else:
            return
        for src, dest in zip(sources, dests, strict=True):
            src_value = resolve(src, cwd)
            dest_value = resolve(dest.replace("${HOME}", "~").replace("$HOME", "~"), cwd)
            if dest.endswith("/") or not os.path.splitext(dest_value)[1]:
                dest_value = dest_value.rstrip("/") + "/" + os.path.basename(src_value)
            if src_value in written_blind:
                blind(dest_value, src)
                continue
            if src_value in written_content:
                # Written by this command: judge what it wrote (or the writer's script).
                content = written_content[src_value]
                judge(
                    dest_value,
                    f"head:{seg.head}",
                    content=content,
                    script=written_script.get(src_value) if content is None else None,
                )
                continue
            if _host_where(src_value, rules, ctx).classes & {"approvals", "main", "include"}:
                continue  # another host config or approvals file
            blind(dest_value, src)

    if a.inline_code:
        code(_decode(a.command), a.cwd or ws, 0)
        env = _match_any(rules.env, a.command)
        if env:
            report(
                {("environment", env.group(0).strip(), BLOCK)}, None, {"mechanism": "environment"}
            )
    else:
        shell(a.command, a.cwd or ws, 0)
    return out


#: An input redirect from a file (`< patch.json5`), not a heredoc or process substitution.
_STDIN_FILE = re.compile(
    r"\bpatch\b[^;&|\n]*(?<![<\d])<(?![<(&])[ \t]*[^\s<]",
)
_HEREDOC_START = re.compile(r"""<<-?[ \t]*(?P<q>['"]?)(?P<tag>\w+)(?P=q)[^\n]*\n""")


def _heredocs_after(command: str, head: str) -> str:
    """The bodies of the heredocs fed to `head`: those whose `<<` follows the word in the same
    simple command."""
    bodies: list[str] = []
    pos = 0
    while True:
        m = _HEREDOC_START.search(command, pos)
        if m is None:
            break
        end = re.compile(r"^[ \t]*" + re.escape(m.group("tag")) + r"[ \t]*$", re.M).search(
            command, m.end()
        )
        if end is None:
            break
        start = max(command.rfind(c, 0, m.start()) for c in "\n;|&") + 1
        if re.search(r"(?:\A|[\s/])" + re.escape(head) + r"(?:\s|\Z)", command[start : m.start()]):
            bodies.append(command[m.end() : max(m.end(), end.start() - 1)])
        pos = end.end()
    return "\n".join(bodies)


def _heredocs(command: str) -> str:
    """The bodies of a command's heredocs, joined. Each body ends at a line holding only its tag;
    the search goes on after it, so the text is read once."""
    bodies: list[str] = []
    pos = 0
    while True:
        m = _HEREDOC_START.search(command, pos)
        if m is None:
            break
        end = re.compile(r"^[ \t]*" + re.escape(m.group("tag")) + r"[ \t]*$", re.M).search(
            command, m.end()
        )
        if end is None:
            break  # unterminated: nothing after it is a body
        bodies.append(command[m.end() : max(m.end(), end.start() - 1)])
        pos = end.end()
    return "\n".join(bodies)


def _render(head: str, seg: ExecSegment, heredocs: str) -> str | None:
    """What a segment prints, when the scan can read it: `echo` (`-e` escapes), `printf` (its
    format with escapes and `%s` filled), or a heredoc read by `cat`/`tee`."""
    if head == "echo":
        # Double-quoted words keep the shell's escapes in the parse (`"{\\"a\\": 1}"`).
        words = [re.sub(r'\\(["\\$`])', r"\1", w) for w in seg.argv]
        escapes = False
        while words and re.fullmatch(r"-[neE]+", words[0]):
            escapes = escapes or "e" in words[0]
            words.pop(0)
        text = " ".join(words)
        return _unescape(text) if escapes else text
    if head == "printf":
        words = [w for w in seg.argv if w != "--"]
        if not words:
            return None
        fmt, rest = _unescape(words[0]), iter(words[1:])
        return re.sub(r"%[sb%]", lambda m: "%" if m.group(0) == "%%" else next(rest, ""), fmt)
    if (
        head in ("cat", "tee")
        and heredocs
        and not [t for t in seg.positional if not t.startswith("-") and head == "cat"]
    ):
        return heredocs
    return None


def detect_guardrail(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C4*: guardrail tampering per `guardrail.yaml`. Never fires on reads, lists, restart or
    reload."""
    out: list[Finding] = []
    lists = ctx.lists
    seen: set[tuple[str, str | None]] = set()

    def emit(reason: str, subject: str | None, detail: dict[str, Any]) -> None:
        key = (reason, subject or detail.get("match"))
        if key in seen:
            return
        seen.add(key)
        if reason == "guardrail.approval_loosening_review":
            # The review tier: the owner is always asked; the floor adds no score and never blocks.
            f = Finding(
                rule="C4star.approval_loosening_review", cls="C4*", reason=reason, detail=detail
            )
            f.floors.append(
                Floor(
                    floor="guardrail_tampering",
                    min_risk=ctx.weight("guardrail", "review_floor_min_risk", default=0.5),
                    enforce=Enforce.REVIEW,
                    subject=subject,
                    reason=reason,
                )
            )
            out.append(f)
            return
        if reason == "guardrail.host_approvals":
            # Changing the host's own approval or allowlist settings is scored, not floored: the
            # floor covers Sentrook's state, its plugin entry and the gateway.
            f = Finding(
                rule="C4.host_approvals", cls="C4", reason="selfmod.host_approvals", detail=detail
            )
            f.add(SELF_MODIFICATION, ctx.weight("selfmod", "host_approvals", default=1.0), subject)
            f.add(REACH, ctx.weight("selfmod", "reach"), subject)
            out.append(f)
            return
        f = Finding(rule=f"C4star.{reason.split('.')[-1]}", cls="C4*", reason=reason, detail=detail)
        f.add(SELF_MODIFICATION, ctx.weight("guardrail", "self_modification"), subject)
        f.floors.append(
            Floor(
                floor="guardrail_tampering",
                min_risk=ctx.weight("guardrail", "floor_min_risk", default=1.0),
                enforce=Enforce.BLOCK,
                subject=subject,
                reason=reason,
            )
        )
        out.append(f)

    plugin_ids = [s.lower() for s in lists.strings("guardrail", "plugin_ids")]

    def names_plugin(text: str) -> bool:
        low = text.lower()
        return any(pid in low for pid in plugin_ids)

    # 1. Writes into guardrail paths (file tools, exec destinations, redirects, moves, deletes).
    config_files = lists.patterns("guardrail", "config_file_patterns")
    for p, mechanism in _written_paths(a, ctx):
        reason = _guardrail_path_reason(p.value, None, ctx)
        if reason is not None:
            emit(reason, p.entity_id, {"path": p.display, "mechanism": mechanism})
            continue
        if _match_any(config_files, p.value) and a.kind in _WRITE_KINDS | {
            ToolKind.MCP,
            ToolKind.OTHER,
        }:
            # Content-aware: the edit must name the plugin, or set a host approval.
            if names_plugin(a.edit_text):
                emit(
                    "guardrail.config_entry",
                    p.entity_id,
                    {"path": p.display, "mechanism": "edit_text_match"},
                )
            elif _match_any(
                lists.patterns("guardrail", "host_approvals", "content_patterns"), a.edit_text
            ):
                emit(
                    "guardrail.host_approvals",
                    p.entity_id,
                    {"path": p.display, "mechanism": "edit_text_match"},
                )

    # Loosening the host's approval or allowlist policy, by any route.
    # One finding per call, however many routes and settings it takes: the block tier when any
    # route is precise, else the review tier.
    loosening = _approval_loosening(a, ctx)
    if loosening:
        tier = BLOCK if any(t == BLOCK for t, _, _ in loosening) else REVIEW
        chosen = [(subject, detail) for t, subject, detail in loosening if t == tier]
        subject, detail = chosen[0]
        settings = sorted({s for _, d in chosen for s in d.get("settings", [])})
        reason = "guardrail.approval_loosening" + ("" if tier == BLOCK else "_review")
        emit(reason, subject, {**detail, "settings": settings[:6]})

    if a.kind is not ToolKind.EXEC:
        return out

    # 2. Inline interpreter code (Hermes `execute_code`, `python -c`): a guardrail path plus a
    #    write marker in the same text.
    if a.inline_code or (a.shape is not None and a.shape.inline_eval):
        markers = lists.patterns("guardrail", "content_write_marker_patterns")
        if _match_any(markers, a.scan_text):
            for m in re.finditer(r"[\w~$./-]*(?:/|\A)sentrook(?:/[\w./-]*)?", a.scan_text):
                reason = _guardrail_path_reason(m.group(0), None, ctx)
                if reason:
                    emit(reason, None, {"path": m.group(0), "mechanism": "content_match"})
                    break

    # 3. CLI forms: plugin disable/remove, the plugin's own commands, config entry, gateway stop,
    #    host approvals, process kill. `<head> [options] <subcommand> [options] <verb> …`,
    #    launchers peeled off (`cli_launchers`), shell `-c` scripts read as commands.
    plugin_cli = lists.get("guardrail", "plugin_cli", default=[]) or []
    command_cli = lists.get("guardrail", "plugin_command_cli", default=[]) or []
    config_cli = lists.get("guardrail", "config_cli", default=[]) or []
    gateway_cli = lists.get("guardrail", "gateway_cli", default=[]) or []
    cli_heads = {
        str(e.get("head")).lower() for e in (*plugin_cli, *command_cli, *config_cli, *gateway_cli)
    }
    for words, line in _cli_segments(a, lists):
        tokens = _cli_tokens(words, cli_heads, lists)
        if not tokens:
            continue
        head = tokens[0]
        for at in _after_options(tokens, 1):
            sub = tokens[at].lower()
            # The verb is found like the subcommand: each word that can follow the options, with
            # the words after it.
            verbs = [
                (tokens[v].lower(), " ".join(tokens[v + 1 :]))
                for v in _after_options(tokens, at + 1)
            ]
            for entry in plugin_cli:
                if head == entry.get("head") and sub == entry.get("subcommand"):
                    blocked = {v.lower() for v in entry.get("blocked_verbs", [])}
                    if any(verb in blocked and names_plugin(rest) for verb, rest in verbs):
                        emit("guardrail.plugin_disable", None, {"match": line[:120]})
            for entry in command_cli:
                if head == entry.get("head") and sub == entry.get("subcommand"):
                    # Any word that could be the verb and is not an allowed one; no verb at all is
                    # the help text.
                    allowed = {v.lower() for v in entry.get("allowed_verbs", [])}
                    if any(not verb.startswith("-") and verb not in allowed for verb, _ in verbs):
                        emit("guardrail.plugin_command", None, {"match": line[:120]})
            for entry in config_cli:
                if head == entry.get("head") and sub == entry.get("subcommand"):
                    mutating = {v.lower() for v in entry.get("mutating_verbs", [])}
                    for verb, rest in verbs:
                        if verb not in mutating:
                            continue
                        if _match_any(
                            lists.patterns("guardrail", "host_approvals", "config_set_patterns"),
                            rest,
                        ):
                            emit("guardrail.host_approvals", None, {"match": line[:120]})
                        elif _match_any(lists.patterns("guardrail", "config_key_patterns"), rest):
                            emit("guardrail.config_entry", None, {"match": line[:120]})
            for entry in gateway_cli:
                if head == entry.get("head") and sub == entry.get("subcommand"):
                    blocked = {v.lower() for v in entry.get("blocked_verbs", [])}
                    if any(verb in blocked for verb, _ in verbs):
                        emit("guardrail.gateway_stop", None, {"match": line[:120]})
        if _match_any(lists.patterns("guardrail", "process_kill_patterns"), line):
            emit("guardrail.gateway_stop", None, {"match": line[:120], "mechanism": "process_kill"})
    if _match_any(lists.patterns("guardrail", "process_kill_patterns"), a.scan_text):
        emit(
            "guardrail.gateway_stop",
            None,
            {"match": (a.command or a.scan_text)[:120], "mechanism": "process_kill"},
        )
    return out


# =========================================================================== C7


def _resolve_target(tok: str, cwd: str, ctx: Context) -> tuple[str, bool]:
    """Resolve a destructive-head argument against the running cwd; returns (path, wildcard)."""
    return resolve_token(
        tok, cwd, home=ctx.prepared.home, workspace_root=ctx.prepared.workspace_root
    )


def is_scratch(value: str, workspace_root: str, lists: Lists) -> bool:
    """Inside the workspace, or in an absolute temporary directory (`/tmp`, `/var/tmp`, `/dev/shm`)."""
    ws = workspace_root.rstrip("/")
    if value == ws or value.startswith(ws + "/"):
        return True
    if _match_any(lists.patterns("destructive", "scratch", "tmp_patterns"), value):
        return True
    seg = lists.get("destructive", "scratch", "workspace_segment")
    return bool(seg and re.search(str(seg), value, re.IGNORECASE))


def _is_scratch(value: str, ctx: Context) -> bool:
    return is_scratch(value, ctx.prepared.workspace_root, ctx.lists)


def detect_destruction(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C7: a destructive verb with at least one path outside scratch (pack `host_gated`). The
    workspace root itself, or `workspace/*`, is workspace-wide. With the host's approval already
    granted the evidence is recorded and nothing is contributed. Destructive SQL is the separate
    `detect_sql_destruction` (pack `tier1`)."""
    out: list[Finding] = []
    lists = ctx.lists
    heads = set(lists.strings("destructive", "heads"))
    prefixes = tuple(lists.strings("destructive", "head_prefixes"))
    verbs = lists.rules("destructive", "verbs")
    ignore = lists.patterns("destructive", "ignore_path_patterns")
    # The host's approval of the pending call covers the agent-written file that call runs.
    granted = ctx.host_approval_granted and a.source in ("pending", "written_file")
    ws = ctx.prepared.workspace_root.rstrip("/")

    targets: list[tuple[str, bool, str]] = []  # (path, wildcard, mechanism)
    if a.kind is ToolKind.EXEC and a.shape is not None:
        cwd = a.cwd or ws
        if a.shape.parse_ok and a.shape.segments:
            for seg in a.shape.segments:
                if seg.head == "cd" and seg.positional:
                    cwd, _ = _resolve_target(seg.positional[0], cwd, ctx)
                    continue
                seg_text = " ".join([seg.head, *seg.argv])
                if seg.head in heads or seg.head.startswith(prefixes):
                    for tok in seg.positional:
                        if tok == "-":
                            continue
                        p, wild = _resolve_target(tok, cwd, ctx)
                        targets.append((p, wild, seg.head))
                for rule in verbs:
                    m = rule.regex.search(seg_text)
                    if not m:
                        continue
                    mode = rule.get("paths", "argv")
                    if mode == "cwd":
                        targets.append((cwd, False, str(rule.get("note", "verb"))))
                    elif m.groups():
                        p, wild = _resolve_target(m.group(1), cwd, ctx)
                        targets.append((p, wild, str(rule.get("note", "verb"))))
                    else:
                        for tok in seg.positional:
                            if tok.startswith(("/", "~", ".", "$HOME")) or "/" in tok:
                                p, wild = _resolve_target(tok, cwd, ctx)
                                targets.append((p, wild, str(rule.get("note", "verb"))))
        elif a.heads & heads or any(h.startswith(prefixes) for h in a.heads):
            for p in a.paths:
                if p.is_destination:
                    targets.append((p.value, "*" in a.text, "unparsed"))

    seen: set[str] = set()
    for value, wildcard, mechanism in targets:
        if value in seen or _match_any(ignore, value):
            continue
        seen.add(value)
        ent = ctx.prepared.entities.get(EntityKind.PATH, value)
        subject = ent.id if ent else None
        if value == ws or (wildcard and value == ws):
            reason, reach_key = "destroy.workspace_wide", "reach_workspace"
        elif _is_scratch(value, ctx):
            continue
        else:
            reason, reach_key = "destroy.outside_scratch", "reach_host"
        f = Finding(
            rule=f"C7.{reason.split('.')[-1]}",
            cls="C7",
            reason=reason,
            detail={
                "path": value,
                "wildcard": wildcard,
                "mechanism": mechanism,
                "host_approval_granted": granted,
            },
        )
        if not granted:
            f.add(IRREVERSIBILITY, ctx.weight("destroy", "irreversibility"), subject)
            f.add(REACH, ctx.weight("destroy", reach_key), subject)
        out.append(f)
    return out


def detect_sql_destruction(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C7, the SQL arm (pack `tier1`): a destructive SQL statement in exec text or in a query
    argument destroys data in a live store, which no host-side approval of the shell command
    gates, so it stays on when file destruction is left to the host. With the host's approval
    already granted the evidence is recorded and nothing is contributed."""
    sql_text = a.scan_text if a.kind is ToolKind.EXEC else a.content
    if not sql_text:
        return []
    granted = ctx.host_approval_granted and a.source in ("pending", "written_file")
    out: list[Finding] = []
    for rx in ctx.lists.patterns("destructive", "sql_patterns"):
        m = rx.search(sql_text)
        if m is None:
            continue
        detail: dict[str, Any] = {
            "mechanism": m.group(0)[:80],
            "host_approval_granted": granted,
        }
        if m.groups() and m.group(1):
            detail["target"] = m.group(1).strip('"`;')
        f = Finding(rule="C7.sql", cls="C7", reason="destroy.sql", detail=detail)
        if not granted:
            f.add(IRREVERSIBILITY, ctx.weight("destroy", "irreversibility"))
            f.add(REACH, ctx.weight("destroy", "reach_host"))
        out.append(f)
        break  # one finding per call: the statement, not every verb in it
    return out


# =========================================================================== C8


def _privileged_group_switches(a: CallAnalysis, lists: Lists) -> list[str]:
    """The root-equivalent groups the command switches into with `sg` or `newgrp`: the group is the first
    word after the head that is not `-` or a flag (`sg docker -c cmd`, `newgrp - docker`). A group the
    command does not write out (a substitution, a variable) is not read here; the command resolved
    through a sibling's write is analysed as a call of its own."""
    heads = set(lists.strings("privilege", "group_switch_heads"))
    privileged = {g.lower() for g in lists.strings("privilege", "root_equivalent_groups")}
    out: list[str] = []
    for shape in (a.shape, a.decoded_shape):
        if shape is None or not shape.parse_ok:
            continue
        for seg in shape.segments:
            if seg.head not in heads:
                continue
            group = next((t for t in seg.argv if not t.startswith("-")), None)
            if group is not None and group.lower() in privileged and group.lower() not in out:
                out.append(group.lower())
    return out


def detect_privilege(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C8: sudo/doas/su (pack `host_gated`), a switch into a root-equivalent group, setuid/setcap,
    loader preload and PATH shadowing."""
    out: list[Finding] = []
    if a.kind is not ToolKind.EXEC:
        return out
    lists = ctx.lists
    reach, conceal = ctx.weight("priv", "reach"), ctx.weight("priv", "concealment")
    shape = a.shape
    elevation_heads = set(lists.strings("privilege", "elevation_heads"))
    elevated = (shape is not None and shape.privileged) or bool(a.heads & elevation_heads)
    if elevated:
        f = Finding(
            rule="C8.sudo",
            cls="C8",
            reason="priv.sudo",
            detail={"wrappers": list(shape.wrappers) if shape else [], "pack": PACK_HOST_GATED},
        )
        if PACK_HOST_GATED in ctx.packs:
            f.add(REACH, reach)
        else:
            f.detail["skipped"] = "pack host_gated not enabled"
        out.append(f)
    groups = _privileged_group_switches(a, lists)
    if groups:
        # A member switches group with no password, so the host does not gate this as it gates sudo.
        f = Finding(
            rule="C8.group_switch",
            cls="C8",
            reason="priv.group_switch",
            detail={"groups": groups},
        )
        f.add(REACH, reach)
        out.append(f)
    if _match_any(lists.patterns("privilege", "setuid_patterns"), a.scan_text):
        f = Finding(rule="C8.setuid", cls="C8", reason="priv.setuid")
        f.add(REACH, reach)
        out.append(f)
    preload = {v.upper() for v in lists.strings("privilege", "preload_vars")}
    shadow = {v.upper() for v in lists.strings("privilege", "shadowing_vars")}
    assigned: list[str] = list(shape.env_assignments) if shape else []
    assigned.extend(m.group(0) for m in _PRELOAD_EXPORT_RE.finditer(a.scan_text))
    vars_seen = {s.split("=", 1)[0].split()[-1].upper() for s in assigned if "=" in s}
    if vars_seen & preload:
        f = Finding(
            rule="C8.preload",
            cls="C8",
            reason="priv.preload",
            detail={"vars": sorted(vars_seen & preload)},
        )
        f.add(REACH, reach).add(CONCEALMENT, conceal)
        out.append(f)
    shadowing = bool(vars_seen & shadow)
    utilities = set(lists.strings("privilege", "system_utilities"))
    system_dirs = tuple(lists.strings("privilege", "system_dirs"))
    odd_heads = [
        hp
        for hp in (shape.head_paths if shape else [])
        if os.path.basename(hp).lower() in utilities
        and not os.path.dirname(hp).startswith(system_dirs)
    ]
    if shadowing or odd_heads:
        f = Finding(
            rule="C8.shadowing",
            cls="C8",
            reason="priv.shadowing",
            detail={"path_assignment": shadowing, "head_paths": odd_heads},
        )
        f.add(REACH, reach).add(CONCEALMENT, conceal)
        out.append(f)
    return out


# =========================================================================== C9


def detect_remote(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C9: irreversible remote side effects — remote deletes, force pushes, payments, account
    changes — on the remote or recipient entity when there is one."""
    out: list[Finding] = []
    lists = ctx.lists
    irr, reach = ctx.weight("remote", "irreversibility"), ctx.weight("remote", "reach")

    def subject_for() -> str | None:
        for group in (a.recipients, a.destination_hosts(), a.providers):
            for ref in group:
                if ref.entity_id:
                    return ref.entity_id
        return None

    seen: set[str] = set()
    if a.kind is ToolKind.EXEC:
        for line in a.segment_texts():
            for rule in lists.rules("remote_destructive", "cli"):
                m = rule.regex.search(line)
                if not m:
                    continue
                reason = str(rule.get("reason"))
                if reason in seen:
                    continue
                seen.add(reason)
                f = Finding(
                    rule=f"C9.{reason.split('.')[-1]}",
                    cls="C9",
                    reason=reason,
                    detail={"match": m.group(0)[:100]},
                )
                subject = subject_for()
                f.add(IRREVERSIBILITY, irr, subject).add(REACH, reach, subject)
                out.append(f)
        return out
    if a.kind not in (ToolKind.MCP, ToolKind.OTHER):
        return out
    if _read_action(a, lists, "remote_destructive"):
        return out
    rule = _tool_matches(a, lists, "remote_destructive", "tool_names")
    amount_key = str(
        lists.get("remote_destructive", "payment_args", "amount_key", default="amount")
    )
    need_recipient = bool(
        lists.get("remote_destructive", "payment_args", "require_recipient", default=True)
    )
    payment_shaped = a.call.get(amount_key) is not None and (
        not need_recipient or bool(a.recipients or a.call.get("recipients"))
    )
    reason = str(rule.get("reason")) if rule else ("remote.payment" if payment_shaped else None)
    if reason is None:
        return out
    f = Finding(
        rule=f"C9.{reason.split('.')[-1]}",
        cls="C9",
        reason=reason,
        detail={"tool": a.tool, "payment_shaped": payment_shaped},
    )
    subject = subject_for()
    f.add(IRREVERSIBILITY, irr, subject).add(REACH, reach, subject)
    out.append(f)
    return out


# =========================================================================== C10


def detect_artefact(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C10: a secret placeholder written into a workspace or repo artefact, a sensitive basename
    staged or committed, or a push after a placeholder was written into the repo."""
    out: list[Finding] = []
    weight = ctx.weight("sensitivity", "artefact")
    placeholder = _placeholder(ctx)

    if a.kind in _WRITE_KINDS or a.kind is ToolKind.EXEC:
        text = a.content if a.kind in _WRITE_KINDS else a.scan_text
        if placeholder in text:
            for p, mechanism in _written_paths(a, ctx):
                if p.in_group("credential_store"):
                    continue  # a secret written where secrets belong is not an artefact leak
                f = Finding(
                    rule="C10.placeholder_in_write",
                    cls="C10",
                    reason="artefact.placeholder_in_write",
                    detail={"path": p.display, "mechanism": mechanism},
                )
                f.add(SENSITIVITY, weight, p.entity_id)
                f.holds_sensitive(p.entity_id)
                out.append(f)

    if a.kind is not ToolKind.EXEC or a.shape is None:
        return out
    groups = ctx.groups
    for seg in a.shape.segments:
        if seg.head != "git" or not seg.positional:
            continue
        verb = seg.positional[0]
        if verb in _GIT_WRITE_VERBS:
            seg_text = " ".join(seg.argv[1:])
            hit = _top_sensitive_group(
                [g for g in SENSITIVE_GROUPS if groups[g].search(seg_text)]
                if all(g in groups for g in SENSITIVE_GROUPS)
                else []
            )
            if hit or (verb == "commit" and "-a" in seg.flags and a.text_groups):
                subject = next(
                    (p.entity_id for p in a.paths if p.in_group(*SENSITIVE_GROUPS)), None
                )
                f = Finding(
                    rule="C10.sensitive_basename_committed",
                    cls="C10",
                    reason="artefact.sensitive_basename_committed",
                    detail={"verb": verb, "group": hit},
                )
                f.add(SENSITIVITY, weight, subject)
                f.holds_sensitive(subject)
                out.append(f)
        elif verb == "push" and SessionFlag.HOLDS_SENSITIVE in ctx.prepared.state.flags:
            if _placeholder_paths(ctx):
                f = Finding(
                    rule="C10.push_with_secret",
                    cls="C10",
                    reason="artefact.push_with_secret",
                    detail={"mechanism": "holds_sensitive + placeholder written in history"},
                )
                f.add(SENSITIVITY, weight)
                out.append(f)
    return out


# =========================================================================== concealment


def detect_concealment(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """Output suppression on a network call. Encoding alone contributes nothing: decoding is
    canonicalisation (the URL-encoded benign query must produce no contribution), and an encoded
    payload that reaches an interpreter is scored by C3."""
    out: list[Finding] = []
    if a.kind is not ToolKind.EXEC or a.shape is None:
        return out
    fetch = ctx.lists.binary_set("fetch_binaries")
    if a.heads & fetch and _DEVNULL_RE.search(a.command or ""):
        f = Finding(rule="conceal.quiet_network", cls="conceal", reason="conceal.output_suppressed")
        f.add(CONCEALMENT, ctx.weight("conceal", "quiet_network"))
        out.append(f)
    return out


# =========================================================================== extent


def apply_extent(findings: list[Finding], a: CallAnalysis, ctx: Context) -> list[str]:
    """Raise every reach contribution of the call for recursive, wildcard or bulk forms, and add
    the extent reason. Returns the extent reasons applied."""
    lists = ctx.lists
    reasons: list[str] = []
    shape = a.shape
    if a.kind is ToolKind.EXEC and shape is not None:
        rec_heads = set(lists.strings("extent", "recursive_heads"))
        letters = set(lists.strings("extent", "recursive_short_letters"))
        longs = set(lists.strings("extent", "recursive_long_flags"))
        if any(
            s.head in rec_heads
            and (any(s.has_flag_letter(ch) for ch in letters) or set(s.flags) & longs)
            for s in shape.segments
        ):
            reasons.append("extent.recursive")
        command_no_urls = _URL_RE.sub(" ", a.command or "")
        if _match_any(lists.patterns("extent", "wildcard_patterns"), command_no_urls):
            reasons.append("extent.wildcard")
        if _match_any(lists.patterns("extent", "bulk_patterns"), a.command or ""):
            if "extent.recursive" not in reasons:
                reasons.append("extent.recursive")
    limit = int(lists.get("extent", "bulk_recipients", default=5) or 5)
    if len(a.call.recipients) > limit:
        reasons.append("extent.bulk_recipients")
    if not reasons:
        return []
    bonus = ctx.weight("extent", "bonus", default=0.25)
    bumped = False
    top = 0.0
    for f in findings:
        for c in f.contributions:
            if c.signal == REACH and c.value > 0:
                c.value = _clamp(c.value + bonus)
                top = max(top, c.value)
                bumped = True
    if not bumped:
        return []
    f = Finding(rule="extent", cls="extent", reason=reasons[0], detail={"reasons": reasons})
    for r in reasons:
        f.add(REACH, top, None, r)
    findings.append(f)
    return reasons


# =========================================================================== runner

#: (detector, class label, pack). Order is the order findings appear in evidence.
DETECTORS: tuple[tuple[Detector, str, str], ...] = (
    (detect_credentials, "C1", PACK_TIER1),
    (detect_exfil, "C2", PACK_TIER1),
    (detect_untrusted_code, "C3", PACK_TIER1),
    (detect_param_injection, "C3", PACK_TIER1),
    (detect_registry_redirect, "C3", PACK_TIER1),
    (detect_provider_lookalike, "C3", PACK_TIER1),
    (detect_guardrail, "C4*", PACK_TIER1),
    (detect_selfmod, "C4", PACK_TIER1),
    (detect_destruction, "C7", PACK_HOST_GATED),
    (detect_sql_destruction, "C7", PACK_TIER1),
    (detect_privilege, "C8", PACK_TIER1),  # the sudo arm gates itself on host_gated
    (detect_remote, "C9", PACK_TIER1),
    (detect_artefact, "C10", PACK_TIER1),
    (detect_concealment, "conceal", PACK_TIER1),
)


def run_detectors(a: CallAnalysis, ctx: Context) -> tuple[list[Finding], list[str]]:
    """Run every enabled detector over one call, then the extent modifier. Returns the findings and
    the class labels skipped because their pack is off."""
    findings: list[Finding] = []
    skipped: list[str] = []
    for detector, label, pack in DETECTORS:
        if pack not in ctx.packs:
            skipped.append(label)
            continue
        findings.extend(detector(a, ctx))
    apply_extent(findings, a, ctx)
    return findings, skipped


def call_label(call: CanonicalCall) -> str:
    return call.call_id or call.source
