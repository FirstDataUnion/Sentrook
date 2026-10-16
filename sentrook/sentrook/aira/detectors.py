"""The AIRA detectors: one small function per consequence class over a `CallAnalysis`.

Each detector returns `Finding`s — an internal rule id (evidence only), the class, the reason code
the review card sees, and the contributions, floors and session flags it asserts. Values come from
`lists/weights.yaml`; every list-like thing a detector matches against comes from the other lists.
AIRA does not judge intent: a sanctioned send of credentials carries the same consequence as an
attack, and relief comes from grants and the oracle in convergence.

Classes (build plan section 6.3):
  C1  credential material reached        C2  exfiltration (source × sink), plain sends
  C3  untrusted code executed            C4  self-modification and persistence
  C4* guardrail tampering (floor)        C7  destruction outside scratch (pack host_gated)
  C8  privilege change (sudo arm host_gated)   C9  irreversible remote side effects
  C10 secret written into an artefact    extent: recursive / wildcard / bulk raise reach
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ..enums import Enforce, SessionFlag
from ..planir.canonical import CanonicalCall
from ..planir.models import HostApproval, ProviderKind, ToolKind
from ..prepare import Prepared
from ..prepare.entities import EntityKind, Role, normalise_path
from ..probes.base import Contribution, Floor
from .analysis import CallAnalysis, EntityRef, PathRef
from .exec_shape import ExecSegment, ExecShape
from .lists import Lists, Rule
from .path_classes import _URL_RE, locations_of
from .sensitive_paths import basename_pattern

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

_WRITE_KINDS = frozenset({ToolKind.FILE_WRITE, ToolKind.FILE_EDIT, ToolKind.MEMORY_WRITE})
_DEVNULL_RE = re.compile(r"2>\s*/dev/null|&>\s*/dev/null|>\s*/dev/null\s+2>&1", re.IGNORECASE)
_PRELOAD_EXPORT_RE = re.compile(r"\b(?:export\s+|setenv\s+)?([A-Z_][A-Z0-9_]*)=")
_GIT_WRITE_VERBS = frozenset({"add", "commit", "stage"})


@dataclass
class Context:
    prepared: Prepared
    lists: Lists
    packs: frozenset[str]

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
    detail: dict[str, Any] = field(default_factory=dict)

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


def detect_credentials(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C1: credential material reached — a sensitive path with a reading head, a `file_read`, a
    listing of a credential directory, or an `@file` form."""
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
        f.add(SENSITIVITY, ctx.weight("sensitivity", g), p.entity_id)
        f.flags.append(SessionFlag.HOLDS_SENSITIVE)
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
            f.flags.append(SessionFlag.HOLDS_SENSITIVE)
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


def _history_placeholder_paths(ctx: Context) -> set[str]:
    out: set[str] = set()
    open_ = str(ctx.lists.get("egress", "placeholder", "open", default="⟦secret"))
    for h in ctx.prepared.history:
        if h.tool_kind in _WRITE_KINDS and h.path and open_ in str(h.get("content") or ""):
            out.add(
                normalise_path(
                    h.path, home=ctx.prepared.home, workspace_root=ctx.prepared.workspace_root
                )
            )
    return out


def _sources(a: CallAnalysis, ctx: Context) -> list[Source]:
    sources: list[Source] = []
    written_with_placeholder = _history_placeholder_paths(ctx)
    attached = {p.value for p in a.attachments}
    for p in a.paths:
        if a.kind is ToolKind.EXEC and p.is_destination and not p.is_source:
            continue
        g = _top_sensitive_group(p.groups)
        if g is not None:
            reason = "exfil.attachment" if p.value in attached else f"path.{g}"
            sources.append(Source(reason, ctx.weight("sensitivity", g), p.entity_id, p.display))
        elif p.value in written_with_placeholder and (p.is_source or p.value in attached):
            reason = "exfil.attachment" if p.value in attached else "exfil.placeholder_in_argv"
            sources.append(
                Source(
                    reason,
                    ctx.weight("sensitivity", "placeholder"),
                    p.entity_id,
                    f"{p.display} (written with a placeholder)",
                )
            )
    covered = {s.reason.removeprefix("path.") for s in sources}
    for g in SENSITIVE_GROUPS:
        if g in a.text_groups and g not in covered and not any(g in p.groups for p in a.paths):
            sources.append(Source(f"path.{g}", ctx.weight("sensitivity", g), None, "text_match"))
    if a.placeholder or (a.content and _placeholder(ctx) in a.content):
        sources.append(
            Source(
                "exfil.placeholder_in_argv",
                ctx.weight("sensitivity", "placeholder"),
                None,
                "placeholder",
            )
        )
    if SessionFlag.HOLDS_SENSITIVE in ctx.prepared.state.flags:
        sources.append(
            Source(
                "exfil.session_holds_sensitive",
                ctx.weight("sensitivity", "session_holds_sensitive"),
                None,
                "session flag",
            )
        )
    return sources


def _placeholder(ctx: Context) -> str:
    return str(ctx.lists.get("egress", "placeholder", "open", default="⟦secret"))


def detect_exfil(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C2: a sensitive source reaching a sink is exfiltration; a sink alone is a send."""
    sinks = _sinks(a, ctx)
    if not sinks:
        return []
    sources = _sources(a, ctx)
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
        heads = [s.head for s in stages]
        for i, h in enumerate(heads):
            if h in fetch and any(t in shells | interp | evals for t in heads[i + 1 :]):
                return "pipeline"
    heads = set(shape.heads)
    if shape.substitution and heads & fetch and heads & (shells | evals):
        return "substitution"
    fetched_file = any(
        s.head in fetch and (set(s.flags) & out_flags or any(f.startswith("-o") for f in s.flags))
        for s in shape.segments
    )
    if fetched_file and any(
        s.head in shells | interp or (s.head == "chmod" and any("x" in f for f in s.flags))
        for s in shape.segments
    ):
        return "fetch_then_run"
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


def detect_untrusted_code(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C3: fetch-to-shell, decode-to-shell (floor), install-from-URL, package install, running a
    file written since a fetch."""
    out: list[Finding] = []
    lists = ctx.lists
    if a.kind is not ToolKind.EXEC:
        return out
    code_source = next(
        (h for h in a.hosts if Role.CODE_SOURCE in h.roles), a.hosts[0] if a.hosts else None
    )
    host_subject = code_source.entity_id if code_source else None
    reach, irr = ctx.weight("code", "reach"), ctx.weight("code", "irreversibility")

    # What the command does as written, and what it does once decoding is undone.
    raw_fetch = _fetch_to_shell(a.shape, ctx)
    text_fetch = _match_any(lists.patterns("installers", "fetch_to_shell_patterns"), a.text)
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
        if obfuscated:
            f.detail["revealed_by"] = sorted(a.encodings)
            f.add(
                CONCEALMENT, ctx.weight("priv", "concealment"), None, "conceal.obfuscated_command"
            )
        out.append(f)
        # Look-alike installer host: strong evidence, the floor (RUBRIC decision 8). An unlisted host
        # that mimics nothing is scored by consequence and the oracle's distrust, never floored.
        if code_source is not None:
            mimics = lookalike_of(code_source.value, lists.strings("installers", "installer_hosts"))
            if mimics:
                g = Finding(
                    rule="C3.lookalike_installer",
                    cls="C3",
                    reason="code.lookalike_installer",
                    detail={"host": code_source.value, "mimics": mimics},
                )
                g.add(
                    CONCEALMENT,
                    ctx.weight("code", "lookalike_concealment", default=0.8),
                    host_subject,
                )
                g.floors.append(
                    Floor(
                        floor="untrusted_code_execution",
                        min_risk=ctx.weight("code", "decode_floor_min_risk", default=0.9),
                        enforce=Enforce.BLOCK,
                        subject=host_subject,
                        reason="code.lookalike_installer",
                    )
                )
                out.append(g)

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


_TLDS_2 = frozenset({"co", "com", "org", "net", "ac", "gov", "edu"})


def _registrable_label(host: str) -> str:
    """The label a person reads as the brand: `get.docker.com` → `docker`, `astral-sh.dev` →
    `astral-sh`, `foo.co.uk` → `foo`."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _TLDS_2 and len(parts[-1]) == 2:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(b) > len(a):
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(a) - i) + (len(b) - j) <= 1


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


_PROVIDER_VERSION_RE = re.compile(r"@[^@/:\s]+$")


def _provider_name(identity: str) -> str:
    """A provider identity without its version: `npm:@acme/gmail-mcp@1.4.2` → `npm:@acme/gmail-mcp`.
    The scope's `@` is kept because a version never contains `/`."""
    identity = identity.strip().lower()
    name = _PROVIDER_VERSION_RE.sub("", identity)
    return name if name and not name.endswith(":") else identity


def provider_lookalike_of(identity: str, known: Iterable[str]) -> str | None:
    """The known provider identity `identity` mimics, or None: its package name is one edit from a
    known one's. The same name under another version (a patch bump) is that provider, not a
    look-alike, and so is any identity whose name is known."""
    name = _provider_name(identity)
    known = [k for k in known if k]
    if any(_provider_name(k) == name for k in known):
        return None
    if len(name.rsplit("/", 1)[-1].split(":")[-1]) < 5:
        return None
    for k in known:
        if _edit_distance_le1(name, _provider_name(k)):
            return k
    return None


def detect_provider_lookalike(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C3 arm: the call goes through an MCP provider whose package name is one typo away from a
    provider the session already used (`gmai1-mcp` for `gmail-mcp`). The call's own consequence is
    scored by the other classes; the look-alike is concealment."""
    out: list[Finding] = []
    known = [
        h.provider.identity
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
    host = next((h for h in a.hosts if h.value not in ("registry.npmjs.org", "pypi.org")), None)
    subject = host.entity_id if host else None
    f = Finding(
        rule="C3.registry_redirect",
        cls="C3",
        reason="code.registry_redirect",
        detail={"match": hit.group(0)[:100], "host": host.value if host else None},
    )
    f.add(REACH, ctx.weight("code", "reach"), subject)
    f.add(IRREVERSIBILITY, ctx.weight("code", "registry_irreversibility", default=0.6), subject)
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
                    # A script or data file inside a workspace skill (WP8 item 4): the owner's own
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
    return out


# =========================================================================== C4*


def _guardrail_path_reason(value: str, head: str | None, ctx: Context) -> str | None:
    lists = ctx.lists
    base = os.path.basename(value.rstrip("/"))
    for seg in lists.strings("guardrail", "state_dir_segments"):
        if re.search(r"(?:\A|/)" + re.escape(seg) + r"(?:/|\Z)", value, re.IGNORECASE):
            if _match_any(lists.patterns("guardrail", "log_basename_patterns"), base):
                return "guardrail.log_tamper"
            return "guardrail.state_dir_write"
    for name in lists.strings("guardrail", "legacy_basenames"):
        if re.search(basename_pattern(name), value, re.IGNORECASE):
            if _match_any(lists.patterns("guardrail", "log_basename_patterns"), base):
                return "guardrail.log_tamper"
            return "guardrail.state_dir_write"
    if _match_any(lists.patterns("guardrail", "host_guardrail_path_patterns"), value):
        return "guardrail.host_approvals"
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
        if reason == "guardrail.host_approvals":
            # Changing the host's own approval or allowlist settings is scored, not floored: the
            # floor covers Sentrook's state, its plugin entry and the gateway (RUBRIC decision 14).
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

    # 3. CLI forms: plugin disable/remove, config entry, gateway stop, host approvals, process kill.
    for line in a.segment_texts():
        tokens = line.split()
        if not tokens:
            continue
        head = os.path.basename(tokens[0]).lower()
        sub = tokens[1].lower() if len(tokens) > 1 else ""
        verb = tokens[2].lower() if len(tokens) > 2 else ""
        rest = " ".join(tokens[3:])
        for entry in lists.get("guardrail", "plugin_cli", default=[]) or []:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                if verb in {v.lower() for v in entry.get("blocked_verbs", [])} and names_plugin(
                    rest
                ):
                    emit("guardrail.plugin_disable", None, {"match": line[:120]})
        for entry in lists.get("guardrail", "config_cli", default=[]) or []:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                if verb in {v.lower() for v in entry.get("mutating_verbs", [])}:
                    if _match_any(
                        lists.patterns("guardrail", "host_approvals", "config_set_patterns"), rest
                    ):
                        emit("guardrail.host_approvals", None, {"match": line[:120]})
                    elif _match_any(lists.patterns("guardrail", "config_key_patterns"), rest):
                        emit("guardrail.config_entry", None, {"match": line[:120]})
        for entry in lists.get("guardrail", "gateway_cli", default=[]) or []:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                if verb in {v.lower() for v in entry.get("blocked_verbs", [])}:
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
    tok = tok.strip().strip("'\"")
    wildcard = False
    if tok.endswith(("/*", "/**")):
        tok = tok.rsplit("/", 1)[0] or "/"
        wildcard = True
    elif "*" in tok or "?" in tok:
        tok = re.split(r"[*?]", tok, maxsplit=1)[0]
        tok = tok.rsplit("/", 1)[0] if "/" in tok else tok
        wildcard = True
        if not tok:
            tok = "."
    if not tok.startswith(("/", "~", "$HOME")):
        tok = cwd.rstrip("/") + "/" + tok.removeprefix("./") if tok not in (".", "./") else cwd
    return (
        normalise_path(tok, home=ctx.prepared.home, workspace_root=ctx.prepared.workspace_root),
        wildcard,
    )


def _is_scratch(value: str, ctx: Context) -> bool:
    ws = ctx.prepared.workspace_root.rstrip("/")
    if value == ws or value.startswith(ws + "/"):
        return True
    if _match_any(ctx.lists.patterns("destructive", "scratch", "tmp_patterns"), value):
        return True
    seg = ctx.lists.get("destructive", "scratch", "workspace_segment")
    return bool(seg and re.search(str(seg), value, re.IGNORECASE))


def detect_destruction(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C7: a destructive verb with at least one path outside scratch (pack `host_gated`). The
    workspace root itself, or `workspace/*`, is workspace-wide. With the host's approval already
    granted the evidence is recorded and nothing is contributed."""
    out: list[Finding] = []
    lists = ctx.lists
    heads = set(lists.strings("destructive", "heads"))
    prefixes = tuple(lists.strings("destructive", "head_prefixes"))
    verbs = lists.rules("destructive", "verbs")
    ignore = lists.patterns("destructive", "ignore_path_patterns")
    granted = ctx.host_approval_granted and a.source == "pending"
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

    sql_text = a.scan_text if a.kind is ToolKind.EXEC else a.content
    sql = _match_any(lists.patterns("destructive", "sql_patterns"), sql_text) if sql_text else None
    if sql is not None:
        f = Finding(
            rule="C7.sql",
            cls="C7",
            reason="destroy.sql",
            detail={"mechanism": sql.group(0)[:80], "host_approval_granted": granted},
        )
        if not granted:
            f.add(IRREVERSIBILITY, ctx.weight("destroy", "irreversibility"))
            f.add(REACH, ctx.weight("destroy", "reach_host"))
        out.append(f)

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


# =========================================================================== C8


def detect_privilege(a: CallAnalysis, ctx: Context) -> list[Finding]:
    """C8: sudo/doas/su (pack `host_gated`), setuid/setcap, loader preload and PATH shadowing."""
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
                f.flags.append(SessionFlag.HOLDS_SENSITIVE)
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
                f.flags.append(SessionFlag.HOLDS_SENSITIVE)
                out.append(f)
        elif verb == "push" and SessionFlag.HOLDS_SENSITIVE in ctx.prepared.state.flags:
            if _history_placeholder_paths(ctx):
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
