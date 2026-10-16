"""Preparation stage (skeleton section 2; build plan 6.2). Deterministic, runs once per request,
before any probe.

1. Validate the PlanIR against the 1.7 invariants (a failure is `status: error`).
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
8. Build the Jev state views (v1: byte-identical to the runner's `trim-v1`; the second redaction pass
   is a no-op here, see `views`).
"""

from __future__ import annotations

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
    normalise_path,
)
from .fingerprint import Fingerprint, fingerprint
from .trust import Trust, classify

__all__ = ["Prepared", "PrepareOptions", "prepare", "InvalidPlanIR"]

#: History arguments are capped by the plugin at about 4 KB per step (skeleton 1.6). Content at or
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

    # 7. fingerprint
    fp = fingerprint(pending.tool_kind, table.pending(), state.salt)

    # 8. views
    jev_views = {views.EXPOSURE: views.exposure_view(raw), views.CALL: views.call_view(raw)}

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
    )
