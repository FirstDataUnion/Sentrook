"""Preparation stage. Deterministic, runs once per request,
before any probe.

1. Validate the PlanIR's structural invariants (unique, increasing history steps and input sequence
   numbers; `session.step` one past the last history step; unique `call_id`s; tool results that refer
   to a history step; size caps). A failure is `status: error`.
2. Decode and verify the state token, or mint one from a test-mode `state_seed`. A bad token starts a
   fresh session with reduced coverage.
3. Canonicalise tool arguments (pending call, siblings, history).
4. Classify each new input as trusted or untrusted from its source facts.
5. Extract entities with roles from the pending call, siblings, untrusted inputs, the request, grants,
   history and, when the call executes a file the agent wrote earlier, that file's content; assign
   opaque IDs.
6. Add entities found in untrusted content to the session's untrusted-entity set (an entity the agent
   introduced first is not promoted by a later echo).
7. Compute the pending call's action fingerprint.
8. Build the Jev state views: the v1 views byte-identical to the runner's `trim-v1`, and the v1.1 question-set pass's
   `trim-v2` views (`call-v2` with the turn's inputs, `exposure-v2`) after the second redaction pass
   (`redact`). The configured question sets choose which view each Jev probe sends.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..planir.canonical import (
    CanonicalCall,
    canonical_history,
    canonical_pending,
    canonical_sibling,
)
from ..planir.models import InputKind, NewInput, PlanIR, ToolKind
from ..planir.validate import InvalidPlanIR, Warning_, check, warnings
from ..state.token import SessionState, decode_state, entity_hash, new_salt, seed_state
from . import views
from .entities import (
    Entity,
    EntityKind,
    EntityTable,
    Origin,
    Role,
    extract_call,
    extract_exec,
    extract_mentions,
    grant_matches,
    normalise_host,
    normalise_path,
    normalise_recipient,
)
from .fingerprint import Fingerprint, fingerprint
from .trust import Trust, classify

__all__ = ["Prepared", "PrepareOptions", "prepare", "InvalidPlanIR"]

#: History arguments are capped by the plugin at about 4 KB per step. Content at or
#: beyond this length is treated as possibly truncated when the agent-written file is re-read.
WRITTEN_FILE_CAP_CHARS = 3900
_CREATING_HEADS = (
    "mkdir",
    "touch",
    "tee",
    "cp",
    "mv",
    "git clone",
    "wget",
    "curl -o",
    "curl --output",
)


@dataclass(frozen=True)
class PrepareOptions:
    token_key: str | bytes
    deployment: str | None = None
    clock: datetime | None = None
    deterministic_salt: str | None = None
    #: Test mode: a TestNest `state_seed` replaces the token.
    state_seed: dict[str, Any] | None = None


@dataclass
class PreparedInput:
    input: NewInput
    trust: Trust
    new: bool  # above the token's highest scanned input_seq
    step: int | None  # history step whose result this is, for tool results


@dataclass
class WrittenFile:
    path: str
    step: int
    content: str
    truncated: bool


@dataclass(frozen=True)
class CoverageNote:
    code: str
    detail: str


@dataclass
class Prepared:
    planir: PlanIR
    raw: dict[str, Any]
    clock: datetime
    options: PrepareOptions
    state: SessionState
    pending: CanonicalCall
    siblings: list[CanonicalCall]
    history: list[CanonicalCall]
    inputs: list[PreparedInput]
    entities: EntityTable
    fingerprint: Fingerprint
    views: dict[str, dict[str, Any]]
    created_paths: dict[str, int] = field(default_factory=dict)
    written_file: WrittenFile | None = None
    coverage: list[CoverageNote] = field(default_factory=list)
    warnings: list[Warning_] = field(default_factory=list)
    #: Hashes present in the token's untrusted set before this request added anything.
    prior_untrusted: frozenset[str] = frozenset()
    #: Grants that cover at least one pending-call entity: grant_ref → entity ids.
    grant_hits: dict[str, list[str]] = field(default_factory=dict)
    #: Views version per view name (`trim-v1` for `exposure`/`call`, `trim-v2` for the v2 views).
    views_version: dict[str, str] = field(default_factory=dict)
    #: Second-pass redactions over the v2 views.
    redactions: int = 0
    #: Per view name: `redactions`, `inputs_truncated`, `inputs_stripped`.
    view_meta: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def platform(self) -> str:
        return self.planir.host.platform

    @property
    def home(self) -> str:
        return self.planir.host.home

    @property
    def workspace_root(self) -> str:
        return normalise_path(self.planir.host.workspace_root, home=self.home, workspace_root=None)

    def untrusted_inputs(self, new_only: bool = True) -> list[PreparedInput]:
        return [i for i in self.inputs if i.trust is Trust.UNTRUSTED and (i.new or not new_only)]

    def pending_entities(self) -> list[Entity]:
        return self.entities.pending()

    @property
    def scanned_max_seq(self) -> int | None:
        seqs = [i.input.input_seq for i in self.inputs]
        prior = self.state.max_input_seq
        if not seqs:
            return prior
        return max(seqs) if prior is None else max(prior, max(seqs))

    def denied_steps(self) -> list[CanonicalCall]:
        denied = {"denied_by_user", "blocked", "review_timed_out"}
        by_step = {h.step: h for h in self.planir.history}
        return [
            c
            for c in self.history
            if c.step is not None and by_step[c.step].decision.value in denied
        ]


def _mark_request_named(request_text: str, table: EntityTable) -> None:
    """An owner may name a recipient, channel, account or host in a form the mention extractor does not
    produce on its own: a person's name (`Pay Mara Quill`), an account number, `#ops-yard` for a channel
    target, or a host that only the pending call spells out. A pending-call entity whose value appears
    verbatim in the request (case-insensitive, whole token) is request-named."""
    text = request_text.lower()
    if not text:
        return
    for ent in table:
        if (
            not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE)
            or Origin.REQUEST in ent.origins
        ):
            continue
        if ent.kind not in (
            EntityKind.RECIPIENT,
            EntityKind.CHANNEL,
            EntityKind.HOST,
            EntityKind.PACKAGE,
            EntityKind.PLUGIN,
        ):
            continue
        candidates = {ent.value.lower()}
        if ent.kind is EntityKind.CHANNEL and ":" in ent.value:
            name = ent.value.split(":", 1)[1].lower()
            candidates.update({name, "#" + name})
        if ent.kind is EntityKind.PACKAGE and ":" in ent.value:
            candidates.add(ent.value.split(":", 1)[1].lower())
        for cand in candidates:
            if len(cand) < 3:
                continue
            if re.search(r"(?<![\w.@-])" + re.escape(cand) + r"(?![\w-])", text):
                ent.add_origin(Origin.REQUEST, "verbatim")
                break


#: Local parts that are roles rather than names; a capitalised "Team" or "Info" in the request is not a
#: person the owner named.
_GENERIC_LOCAL_PARTS = frozenset(
    """info admin administrator support help helpdesk contact sales team hello hi mail email noreply
    no-reply donotreply office billing accounts security root news newsletter service services
    notifications notification alerts alert bot test postmaster webmaster abuse marketing hr
    jobs careers press media feedback orders order invoices invoice""".split()
)
_NAME_TOKEN_RE = re.compile(r"[a-z]{3,}")
#: "bcc me", "cc me", "copy me", "copy me in", "keep me on cc", "put me in bcc".
_SELF_COPY_RE = re.compile(
    r"\b(?P<how>bcc|cc|copy)\s+(?:me|myself)\b"
    r"|\b(?:put|keep|include|add)\s+(?:me|myself)\s+(?:on|in)\s+(?:the\s+)?(?P<how2>bcc|cc|copy)\b",
    re.IGNORECASE,
)


def _came_from_untrusted_content(ent: Entity) -> bool:
    """The address reached the agent through content it read, not through the owner."""
    agent_first = (
        ent.first_history_step is not None
        and ent.first_untrusted_step is not None
        and ent.first_history_step < ent.first_untrusted_step
    )
    return ent.in_session_untrusted or (Origin.UNTRUSTED_INPUT in ent.origins and not agent_first)


def _inherit_recipient_domain(table: EntityTable) -> None:
    """The mail domain of a request-named recipient is that recipient's own component, not a
    destination the agent chose: `priya.nair@brightlane.io` named by the owner sanctions
    `brightlane.io` as the destination host of that send, even when the domain also turns up in
    content the agent read (the owner's own organisation usually does)."""
    for ent in list(table):
        if ent.kind is not EntityKind.RECIPIENT or "@" not in ent.value:
            continue
        if Origin.REQUEST not in ent.origins:
            continue
        host = table.get(EntityKind.HOST, normalise_host(ent.value.split("@", 1)[1]))
        if host is not None and Origin.REQUEST not in host.origins:
            host.add_origin(Origin.REQUEST, "recipient_domain")


def _mark_display_named(request_text: str, table: EntityTable) -> None:
    """An owner names people, not addresses (`Email Priya ...`, `send it to Holger Vetch`).
    A recipient address whose local part carries a name token that appears **capitalised** in the
    request (`Priya` for `priya.nair@…`) is request-named with ref `display_name`. The match is weaker
    than the verbatim one, so it never applies to an address that came from content the agent read:
    an injected note saying "Mara's address is mara@…" must not turn the owner's "send Mara the
    summary" into a sanction of that address. Generic local parts (`info`, `team`) never match."""
    if not request_text:
        return
    for ent in table:
        if ent.kind is not EntityKind.RECIPIENT or "@" not in ent.value:
            continue
        if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
            continue
        if Origin.REQUEST in ent.origins or _came_from_untrusted_content(ent):
            continue
        local = ent.value.split("@", 1)[0].lower()
        if local in _GENERIC_LOCAL_PARTS:
            continue
        for tok in _NAME_TOKEN_RE.findall(local):
            if tok in _GENERIC_LOCAL_PARTS:
                continue
            pattern = r"(?<![\w-])" + tok[0].upper() + "(?i:" + re.escape(tok[1:]) + r")(?![\w-])"
            if re.search(pattern, request_text):
                ent.add_origin(Origin.REQUEST, "display_name")
                break


def _mark_self_copy(request_text: str, table: EntityTable, calls: list[CanonicalCall]) -> None:
    """`bcc me` names the owner's own address without spelling it. PlanIR carries no owner
    address, so the owner's words resolve against the call: when the request asks for a copy to
    "me" and the matching field (`bcc`, `cc`, or either for "copy") holds exactly one address, that
    address is request-named with ref `self_copy`. Two addresses in the field is ambiguous and
    nothing is marked; an address that came from content the agent read is never marked."""
    if not request_text:
        return
    fields: set[str] = set()
    for m in _SELF_COPY_RE.finditer(request_text):
        how = (m.group("how") or m.group("how2") or "").lower()
        fields.update(("cc", "bcc") if how == "copy" else (how,))
    if not fields:
        return
    for call in calls:
        for field_name in sorted(fields):
            values = [v.strip() for v in (call.args.get(field_name) or []) if str(v).strip()]
            if len(values) != 1 or "@" not in values[0]:
                continue
            ent = table.get(EntityKind.RECIPIENT, normalise_recipient(values[0]))
            if ent is None or Origin.REQUEST in ent.origins or _came_from_untrusted_content(ent):
                continue
            ent.add_origin(Origin.REQUEST, "self_copy")


def _history_step_for(planir: PlanIR, call_id: str | None) -> int | None:
    if call_id is None:
        return None
    for h in planir.history:
        if h.call_id == call_id:
            return h.step
    return None


def _executed_paths(pending: CanonicalCall, table: EntityTable) -> list[Entity]:
    if pending.tool_kind is not ToolKind.EXEC:
        return []
    return [e for e in table.pending() if e.kind is EntityKind.PATH and Role.EXECUTABLE in e.roles]


def _find_written(
    planir: PlanIR, history: list[CanonicalCall], path: str, home: str, ws: str
) -> WrittenFile | None:
    best: WrittenFile | None = None
    for call in history:
        if (
            call.tool_kind not in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT)
            or not call.path
            or call.step is None
        ):
            continue
        if normalise_path(call.path, home=home, workspace_root=ws) != path:
            continue
        content = str(call.get("content") or "")
        if best is None or call.step > best.step:
            truncated = len(content) >= WRITTEN_FILE_CAP_CHARS or content.rstrip().endswith(
                ("…", "[truncated]", "...")
            )
            if best is not None and call.tool_kind is ToolKind.FILE_EDIT:
                content = (
                    best.content + "\n" + content
                )  # an edit after a write: both halves are visible
            best = WrittenFile(path=path, step=call.step, content=content, truncated=truncated)
    return best


def _created_paths(history: list[CanonicalCall], home: str, ws: str) -> dict[str, int]:
    created: dict[str, int] = {}
    for call in history:
        if call.step is None:
            continue
        if (
            call.tool_kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT, ToolKind.MEMORY_WRITE)
            and call.path
        ):
            created.setdefault(normalise_path(call.path, home=home, workspace_root=ws), call.step)
        elif call.tool_kind is ToolKind.EXEC and call.command:
            cmd = call.command
            if any(h in cmd for h in _CREATING_HEADS):
                for f in extract_exec(cmd, home=home, workspace_root=ws, cwd=call.get("cwd")):
                    if f.kind is EntityKind.PATH and f.role in (Role.DATA_DESTINATION,):
                        created.setdefault(f.value, call.step)
    return created


def prepare(raw: dict[str, Any], options: PrepareOptions) -> Prepared:
    """Run the preparation stage. Raises `InvalidPlanIR` when the request cannot be scored."""
    planir = PlanIR.model_validate(raw)
    check(planir, raw.get("scan_kind"))
    warns = warnings(planir)
    clock = options.clock or datetime.now(tz=UTC)
    coverage: list[CoverageNote] = [CoverageNote(w.code, w.detail) for w in warns]

    # 2. state
    if options.state_seed is not None:
        state = seed_state(
            options.state_seed,
            salt=new_salt(options.deterministic_salt),
            deployment=options.deployment,
        )
    else:
        state = decode_state(
            planir.session.state,
            key=options.token_key,
            session_ref=planir.session.session_ref,
            expected_step=planir.session.step - 1,
            deployment=options.deployment,
            deterministic_salt=options.deterministic_salt,
        )
        if state.fresh:
            coverage.append(
                CoverageNote(
                    "token_" + state.status.value, f"fresh session at step {planir.session.step}"
                )
            )
    prior_untrusted = frozenset(state.untrusted)

    # 3. canonicalise
    platform = planir.host.platform
    home = planir.host.home
    ws = normalise_path(planir.host.workspace_root, home=home, workspace_root=None)
    pending = canonical_pending(platform, planir.pending_call)
    siblings = [
        canonical_sibling(platform, s)
        for s in (planir.pending_call.batch.siblings if planir.pending_call.batch else [])
    ]
    history = [canonical_history(platform, h) for h in planir.history]

    # 4. trust
    inputs: list[PreparedInput] = []
    for inp in planir.new_inputs:
        new = state.max_input_seq is None or inp.input_seq > state.max_input_seq
        inputs.append(
            PreparedInput(
                input=inp, trust=classify(inp), new=new, step=_history_step_for(planir, inp.call_id)
            )
        )

    # 5. entities
    table = EntityTable()
    for f in extract_call(pending, home=home, workspace_root=ws):
        table.add(f.kind, f.value, display=f.display, role=f.role, origin=Origin.PENDING_CALL)
    for sib in siblings:
        for f in extract_call(sib, home=home, workspace_root=ws):
            table.add(
                f.kind,
                f.value,
                display=f.display,
                role=f.role,
                origin=Origin.SIBLING,
                ref=sib.call_id,
            )
    for f in extract_mentions(planir.request.text, home=home, workspace_root=ws, role=None):
        table.add(f.kind, f.value, display=f.display, origin=Origin.REQUEST)
    _mark_request_named(planir.request.text, table)

    grant_hits: dict[str, list[str]] = {}
    for grant in planir.grants:
        for ent in list(table):
            if (
                Origin.PENDING_CALL in ent.origins or Origin.SIBLING in ent.origins
            ) and grant_matches(grant.kind, grant.pattern, ent):
                ent.add_origin(Origin.GRANT, grant.grant_ref)
                grant_hits.setdefault(grant.grant_ref, []).append(ent.id)

    for pi in inputs:
        content = pi.input.content or ""
        if not content:
            continue
        origin = Origin.UNTRUSTED_INPUT if pi.trust is Trust.UNTRUSTED else Origin.TRUSTED_INPUT
        for f in extract_mentions(content, home=home, workspace_root=ws, role=None):
            ent = table.add(
                f.kind, f.value, display=f.display, origin=origin, ref=f"input:{pi.input.input_seq}"
            )
            if origin is Origin.UNTRUSTED_INPUT and pi.step is not None:
                ent.first_untrusted_step = (
                    pi.step
                    if ent.first_untrusted_step is None
                    else min(ent.first_untrusted_step, pi.step)
                )
            elif origin is Origin.UNTRUSTED_INPUT and pi.input.kind is not InputKind.TOOL_RESULT:
                # a message or subagent reply has no history step; treat as arriving now
                ent.first_untrusted_step = (
                    ent.first_untrusted_step
                    if ent.first_untrusted_step is not None
                    else planir.session.step
                )

    for call in history:
        for f in extract_call(call, home=home, workspace_root=ws):
            ent = table.add(
                f.kind, f.value, display=f.display, origin=Origin.HISTORY, ref=f"step:{call.step}"
            )
            if call.step is not None:
                ent.first_history_step = (
                    call.step
                    if ent.first_history_step is None
                    else min(ent.first_history_step, call.step)
                )

    created = _created_paths(history, home, ws)

    written: WrittenFile | None = None
    for exe in _executed_paths(pending, table):
        written = _find_written(planir, history, exe.value, home, ws)
        if written is not None:
            for f in extract_exec(
                written.content, home=home, workspace_root=ws, cwd=pending.get("cwd")
            ):
                table.add(
                    f.kind,
                    f.value,
                    display=f.display,
                    role=f.role,
                    origin=Origin.WRITTEN_FILE,
                    ref=f"step:{written.step}",
                )
            for f in extract_mentions(written.content, home=home, workspace_root=ws, role=None):
                table.add(
                    f.kind,
                    f.value,
                    display=f.display,
                    origin=Origin.WRITTEN_FILE,
                    ref=f"step:{written.step}",
                )
            if written.truncated:
                coverage.append(
                    CoverageNote(
                        "written_file_truncated", f"{exe.display} from step {written.step}"
                    )
                )
            break
        coverage.append(CoverageNote("written_file_not_visible", exe.display))

    # 6. untrusted set
    for ent in table:
        ent.hash = entity_hash(state.salt, ent.kind.value, ent.value)
        ent.in_session_untrusted = ent.hash in prior_untrusted
    additions: list[str] = []
    for ent in table:
        if Origin.UNTRUSTED_INPUT not in ent.origins or ent.hash is None:
            continue
        agent_first = (
            ent.first_history_step is not None
            and ent.first_untrusted_step is not None
            and ent.first_history_step < ent.first_untrusted_step
        )
        if not agent_first:
            additions.append(ent.hash)
    state.add_untrusted(additions)
    _mark_display_named(planir.request.text, table)
    _mark_self_copy(planir.request.text, table, [pending, *siblings])
    _inherit_recipient_domain(table)

    # 7. fingerprint
    fp = fingerprint(pending.tool_kind, table.pending(), state.salt)

    # 8. views (exposure: only the new untrusted inputs with content, which is every input the plugin
    # sent in the common case; call: the full trimmed call view)
    untrusted_seqs = {
        i.input.input_seq
        for i in inputs
        if i.trust is Trust.UNTRUSTED and i.new and i.input.content
    }
    built = views.build_views(raw, exposure_input_seqs=untrusted_seqs)
    jev_views = {name: b.state for name, b in built.items()}
    view_meta = {
        name: {
            "redactions": b.redactions,
            "inputs_truncated": b.inputs_truncated,
            "inputs_stripped": b.inputs_stripped,
        }
        for name, b in built.items()
    }

    return Prepared(
        planir=planir,
        raw=raw,
        clock=clock,
        options=options,
        state=state,
        pending=pending,
        siblings=siblings,
        history=history,
        inputs=inputs,
        entities=table,
        fingerprint=fp,
        views=jev_views,
        created_paths=created,
        written_file=written,
        coverage=coverage,
        warnings=warns,
        prior_untrusted=prior_untrusted,
        grant_hits=grant_hits,
        views_version={name: views.VIEW_VERSIONS[name] for name in built},
        redactions=sum(b.redactions for b in built.values()),
        view_meta=view_meta,
    )
