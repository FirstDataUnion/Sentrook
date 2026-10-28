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
   opaque IDs. Record the call's lineage in the history: the agent-written file it runs, the
   agent-written files it reads or sends, items the agent moved or copied into a tree the call
   destroys, and the agent's own saved listings of that tree.
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
    display_path,
    extract_call,
    extract_exec,
    extract_mentions,
    grant_matches,
    is_under,
    normalise_host,
    normalise_path,
    normalise_recipient,
    paths_in,
    resolve_token,
    shell_segments,
)
from .fingerprint import Fingerprint, fingerprint
from .host_text import owner_words
from .sibling_join import SiblingWrite, resolve_pending, sibling_writes
from .trust import Trust, classify

__all__ = [
    "Lineage",
    "MovedItem",
    "Prepared",
    "PrepareOptions",
    "WrittenFile",
    "prepare",
    "InvalidPlanIR",
]

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


@dataclass
class MovedItem:
    """A history `mv`/`cp`/`rsync` that put something into a tree the pending call destroys."""

    source: str  # normalised source path (what was moved or copied in)
    destination: str  # normalised destination, at or under the target
    target: str  # the pending call's destructive target it now sits under
    step: int
    head: str  # mv | cp | rsync


@dataclass
class Lineage:
    """What the history says about the pending call's inputs and targets. Built by `prepare`;
    scored by the context probe and recorded (paths only, never content) in the test-mode
    `prepared` block."""

    #: The agent-written file the pending call runs (the same object as `Prepared.written_file`).
    executed: WrittenFile | None = None
    #: Agent-written files the pending call reads, sends, copies or publishes.
    sent: list[WrittenFile] = field(default_factory=list)
    #: History moves and copies into a tree the pending call destroys.
    moved_in: list[MovedItem] = field(default_factory=list)
    #: History writes whose content lists a path at or under a destructive target.
    listings: list[WrittenFile] = field(default_factory=list)
    #: Normalised paths the pending call destroys (rm, shred, srm, unlink, rmdir, truncate,
    #: find -delete, find -exec rm).
    destructive_targets: list[str] = field(default_factory=list)
    #: Database objects the pending call destroys (DROP, TRUNCATE, DELETE without WHERE), as
    #: written in the command or query.
    sql_targets: list[str] = field(default_factory=list)

    def names(self, home: str | None = None) -> dict[str, Any]:
        """The lineage as display paths and steps, never content."""

        def disp(path: str) -> str:
            return display_path(path, home)

        return {
            "executed": disp(self.executed.path) if self.executed else None,
            "sent": [disp(w.path) for w in self.sent],
            "moved_in": [
                {
                    "source": disp(m.source),
                    "destination": disp(m.destination),
                    "target": disp(m.target),
                    "step": m.step,
                    "head": m.head,
                }
                for m in self.moved_in
            ],
            "listings": [disp(w.path) for w in self.listings],
            "destructive_targets": [disp(t) for t in self.destructive_targets],
            "sql_targets": list(self.sql_targets),
        }


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
    #: The pending command read through its siblings' writes (`sibling_join.resolve_pending`):
    #: synthetic exec calls, source `resolved`. Empty when no sibling write reaches the command.
    resolved: list[CanonicalCall] = field(default_factory=list)
    lineage: Lineage = field(default_factory=Lineage)
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
    #: Entity-library verdicts for the call's own entities (`kind`, `value`, `verdict`, optional
    #: `tier`), set by the scan from the oracle probe before a call view that carries `reputation`
    #: is sent. Empty until then, and for views without the block.
    oracle_verdicts: list[dict[str, Any]] = field(default_factory=list)
    #: Per view name: `redactions`, `inputs_truncated`, `inputs_stripped`.
    view_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: `request.text` without the host-written parts (`host_text.owner_words`): what the rule-side
    #: matchers read. Jev's views carry the full text.
    request_words: str = ""

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


#: Heads whose positional arguments the call destroys, for lineage (a narrower set than AIRA's C7:
#: the question is which tree goes away, not every destructive shape).
_LINEAGE_DESTRUCTIVE_HEADS = frozenset({"rm", "shred", "srm", "unlink", "rmdir", "truncate"})
_TRUNCATE_VALUE_FLAGS = frozenset({"-s", "--size", "-r", "--reference"})
_MOVE_HEADS = frozenset({"mv", "cp", "rsync"})
#: Flags of mv/cp/rsync that take a value.
_MOVE_VALUE_FLAGS = frozenset({"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh"})


def _call_cwd(call: CanonicalCall, home: str, ws: str) -> str:
    cwd = call.get("cwd")
    if isinstance(cwd, str) and cwd:
        return normalise_path(cwd, home=home, workspace_root=ws)
    return ws


def _destructive_targets(pending: CanonicalCall, home: str, ws: str) -> list[str]:
    """Paths the pending exec destroys, resolved against its cwd (and any `cd` before them)."""
    if pending.tool_kind is not ToolKind.EXEC or not pending.command:
        return []
    cwd = _call_cwd(pending, home, ws)
    out: list[str] = []
    for tokens in shell_segments(pending.command):
        head, args = tokens[0], tokens[1:]
        if head == "cd" and args:
            cwd, _ = resolve_token(args[0], cwd, home=home, workspace_root=ws)
            continue
        positional: list[str] = []
        if head in _LINEAGE_DESTRUCTIVE_HEADS:
            skip = False
            for tok in args:
                if skip:
                    skip = False
                    continue
                if head == "truncate" and tok in _TRUNCATE_VALUE_FLAGS:
                    skip = True
                    continue
                if tok.startswith("-") or tok == "--":
                    continue
                positional.append(tok)
        elif head == "find" and (
            "-delete" in args
            or any(
                a == "-exec" and i + 1 < len(args) and args[i + 1] in ("rm", "shred", "unlink")
                for i, a in enumerate(args)
            )
        ):
            for tok in args:
                if tok.startswith(("-", "(", "!")):
                    break
                positional.append(tok)
        for tok in positional:
            path, _ = resolve_token(tok, cwd, home=home, workspace_root=ws)
            if path not in out:
                out.append(path)
    return out


def _moved_in(
    history: list[CanonicalCall], targets: list[str], home: str, ws: str
) -> list[MovedItem]:
    """History `mv`/`cp`/`rsync` whose destination is at or under a destructive target and whose
    source is not already inside that target."""
    if not targets:
        return []
    out: list[MovedItem] = []
    for call in history:
        if call.tool_kind is not ToolKind.EXEC or not call.command or call.step is None:
            continue
        cwd = _call_cwd(call, home, ws)
        for tokens in shell_segments(call.command):
            head, args = tokens[0], tokens[1:]
            if head == "cd" and args:
                cwd, _ = resolve_token(args[0], cwd, home=home, workspace_root=ws)
                continue
            if head not in _MOVE_HEADS:
                continue
            positional: list[str] = []
            target_dir: str | None = None
            skip_next: str | None = None
            for tok in args:
                if skip_next is not None:
                    if skip_next in ("-t", "--target-directory"):
                        target_dir = tok
                    skip_next = None
                    continue
                if tok in _MOVE_VALUE_FLAGS:
                    skip_next = tok
                    continue
                if tok.startswith("--target-directory="):
                    target_dir = tok.split("=", 1)[1]
                    continue
                if tok.startswith("-"):
                    continue
                positional.append(tok)
            if target_dir is not None:
                sources, dest = positional, target_dir
            elif len(positional) >= 2:
                sources, dest = positional[:-1], positional[-1]
            else:
                continue
            if ":" in dest.split("/", 1)[0]:
                continue  # a remote rsync/scp destination
            dest_path, _ = resolve_token(dest, cwd, home=home, workspace_root=ws)
            for target in targets:
                if not is_under(dest_path, target):
                    continue
                for src in sources:
                    if ":" in src.split("/", 1)[0]:
                        continue
                    src_path, _ = resolve_token(src, cwd, home=home, workspace_root=ws)
                    if is_under(src_path, target):
                        continue
                    out.append(
                        MovedItem(
                            source=src_path,
                            destination=dest_path,
                            target=target,
                            step=call.step,
                            head=head,
                        )
                    )
    return out


def _sql_targets(pending: CanonicalCall) -> list[str]:
    """Database objects the pending call destroys: the object named by a destructive SQL
    statement (`destructive.yaml` `sql_patterns`) in an exec command or a query argument."""
    text = pending.command if pending.tool_kind is ToolKind.EXEC else pending.get("content")
    if not isinstance(text, str) or not text:
        return []
    from ..aira.lists import load_lists

    out: list[str] = []
    for rx in load_lists().patterns("destructive", "sql_patterns"):
        for m in rx.finditer(text):
            name = m.group(1).strip('"`;') if m.groups() else None
            if name and name not in out:
                out.append(name)
    return out


def _lineage(
    planir: PlanIR,
    pending: CanonicalCall,
    writes: list[SiblingWrite],
    history: list[CanonicalCall],
    table: EntityTable,
    written: WrittenFile | None,
    home: str,
    ws: str,
) -> Lineage:
    lineage = Lineage(executed=written)
    lineage.destructive_targets = _destructive_targets(pending, home, ws)
    lineage.sql_targets = _sql_targets(pending)

    written_paths = {
        normalise_path(c.path, home=home, workspace_root=ws)
        for c in history
        if c.tool_kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT) and c.path
    }
    for ent in table.pending():
        if ent.kind is not EntityKind.PATH or Role.DATA_SOURCE not in ent.roles:
            continue
        if ent.value not in written_paths or (written is not None and ent.value == written.path):
            continue
        sent = _find_written(planir, history, ent.value, home, ws)
        if sent is not None:
            lineage.sent.append(sent)

    # A file a sibling in the same batch writes and the pending call sends is staged for the
    # send: no earlier step shows the write, so the sibling's content is the file's content.
    staged = {w.path: w.content for w in writes if w.content is not None}
    if staged:
        already = {w.path for w in lineage.sent}
        for ent in table.pending():
            if ent.kind is not EntityKind.PATH or Role.DATA_SOURCE not in ent.roles:
                continue
            content = staged.get(ent.value)
            if content is None or ent.value in already:
                continue
            if written is not None and ent.value == written.path:
                continue
            lineage.sent.append(
                WrittenFile(
                    path=ent.value,
                    step=planir.session.step,
                    content=content,
                    truncated=False,
                )
            )

    lineage.moved_in = _moved_in(history, lineage.destructive_targets, home, ws)
    for item in lineage.moved_in:
        ent = table.add(
            EntityKind.PATH,
            item.source,
            display=display_path(item.source, home),
            origin=Origin.HISTORY,
            ref=f"step:{item.step}",
        )
        if ent.first_history_step is None or item.step < ent.first_history_step:
            ent.first_history_step = item.step

    if lineage.destructive_targets:
        for path in sorted(written_paths):
            listing = _find_written(planir, history, path, home, ws)
            if listing is None:
                continue
            listed = [p for p, _ in paths_in(listing.content, home, ws, None)]
            if any(is_under(p, t) for p in listed for t in lineage.destructive_targets):
                lineage.listings.append(listing)
    return lineage


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
    # What the siblings write, and the pending command read through it: the resolved command's
    # entities take the pending call's roles and the sibling's origin. A failure here leaves the
    # scan without the join rather than failing it.
    writes: list[SiblingWrite] = []
    resolved: list[CanonicalCall] = []
    try:
        writes = [w for s in siblings for w in sibling_writes(s, home=home, workspace_root=ws)]
        resolution = resolve_pending(platform, pending, writes, home=home, workspace_root=ws)
        resolved = resolution.calls
        if resolution.truncated:
            coverage.append(
                CoverageNote("sibling_join_truncated", f"first {len(resolved)} resolved commands")
            )
        for call in resolved:
            for f in extract_call(call, home=home, workspace_root=ws):
                table.add(
                    f.kind,
                    f.value,
                    display=f.display,
                    role=f.role,
                    origin=Origin.SIBLING,
                    ref=call.call_id,
                )
    except Exception as exc:  # noqa: BLE001 (an odd sibling must not fail the scan)
        writes, resolved = [], []
        coverage.append(CoverageNote("sibling_join_failed", f"{type(exc).__name__}: {exc}"))
    words = owner_words(planir.request.text)
    for f in extract_mentions(words, home=home, workspace_root=ws, role=None):
        table.add(f.kind, f.value, display=f.display, origin=Origin.REQUEST)
    _mark_request_named(words, table)

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

    lineage = _lineage(planir, pending, writes, history, table, written, home, ws)

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
    _mark_display_named(words, table)
    _mark_self_copy(words, table, [pending, *siblings])
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
        resolved=resolved,
        lineage=lineage,
        coverage=coverage,
        warnings=warns,
        prior_untrusted=prior_untrusted,
        grant_hits=grant_hits,
        views_version={name: views.VIEW_VERSIONS[name] for name in built},
        # call-v3 is call-v2's content with a block the probe adds later, so its redactions are
        # call-v2's and are not counted twice.
        redactions=sum(
            b.redactions for n, b in built.items() if n in (views.EXPOSURE_V2, views.CALL_V2)
        ),
        view_meta=view_meta,
        request_words=words,
    )
