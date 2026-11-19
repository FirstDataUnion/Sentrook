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
   history and, when the call executes a file the agent wrote earlier (or a copy of one, `copies`)
   or is a scheduler tool call naming such a file as the job's script, that file's content; assign
   opaque IDs. Record the call's lineage in the history: the agent-written file it runs, the
   agent-written files it reads or sends, items the agent moved or copied into a tree the call
   destroys, and the agent's own saved listings of that tree.
6. Add entities found in untrusted content to the session's untrusted-entity set (an entity the agent
   introduced first is not promoted by a later echo, nor a path by the receipt of the step that wrote it). Entities from a scanned read of the agent's own
   config or instruction files (one the agent did not write in this session, and not tainted) are the
   owner's: they join the token's trusted set instead. Bind the pending call to the token's sensitive
   and tainted sets (`session_sets`): the files and tables it reads, runs or applies that the sets hold,
   and what an injected result in this request came from.
   Mark the hosts and repositories named in an untrusted input that tries to steer the agent (it asks
   the agent to keep the action from the owner, `steering`) as steered, and keep them in the
   token's steered set; one already in that set is steered on this step too.
7. Compute the pending call's action fingerprint.
8. Build the Jev state views: the v1 views byte-identical to the runner's `trim-v1`, and the v1.1 question-set pass's
   `trim-v2` views (`call-v2` with the turn's inputs, `exposure-v2`) after the second redaction pass
   (`redact`). The configured question sets choose which view each Jev probe sends.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..planir.bounds import MAX_CALL_CHARS, bound_text
from ..planir.canonical import (
    CanonicalCall,
    canonical_history,
    canonical_pending,
    canonical_sibling,
)
from ..planir.models import (
    DecidedBy,
    Decision,
    InputKind,
    NewInput,
    PlanIR,
    ProviderKind,
    ResultStatus,
    ToolKind,
)
from ..planir.validate import InvalidPlanIR, Warning_, check, warnings
from ..state.token import SessionState, decode_state, entity_hash, new_salt, seed_state
from . import views
from .copies import CopyHistory, copy_history
from .entities import (
    Entity,
    EntityKind,
    EntityTable,
    Found,
    Origin,
    Role,
    channel_names,
    display_path,
    extract_call,
    extract_exec,
    extract_mentions,
    host_of_url,
    install_walk,
    is_computed_package,
    is_under,
    normalise_host,
    normalise_path,
    normalise_recipient,
    normalise_remote_identity,
    paths_in,
    platform_targets,
    provider_counterpart,
    provider_name,
    repos_named_in,
    resolve_token,
    send_platform,
    shell_segments,
)
from .fingerprint import Fingerprint, fingerprint
from .grants import (
    GRANT_KINDS,
    grant_matches,
    lapse,
    path_actions,
    sends_off_host,
    tool_covers,
)
from .host_text import owner_words
from .own_store import memory_path_spellings, own_store_read
from .session_sets import (
    SessionBinding,
    acts,
    bind,
    call_artefacts,
    owner_config_path,
    producer_artefacts,
)
from .sibling_join import Resolution, SiblingWrite, resolve_pending, sibling_writes
from .skill_steps import skill_step_calls
from .steering import steering_marks, steers
from .trust import Trust, classify
from .url_carry import CarriedText, url_carries_local
from .written_selfmod import PlantedFile, WrittenText, future_entities, written_selfmod_texts

__all__ = [
    "Lineage",
    "MovedItem",
    "PLUGIN_CUT_MARKER",
    "Prepared",
    "PrepareOptions",
    "WrittenFile",
    "prepare",
    "sql_targets",
    "InvalidPlanIR",
]

#: The plugins cap each history step's arguments at about 4 KB, giving every string a share of it and cutting
#: a longer string head and tail around this marker. A written file is treated as cut when its content carries
#: the marker; content that merely fills the cap arrived whole.
PLUGIN_CUT_MARKER = re.compile(r"…\[sentrook: \d+ bytes cut\]…")
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
    #: Token budgets for the call views and the self-edit view: the room the question sets that send them leave in
    #: the model's context. None uses the default reserves in `views`.
    call_budget_tokens: int | None = None
    selfedit_budget_tokens: int | None = None


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
    #: What was over preparation's bounds when the content was cut to them (`bounds.bound_text`).
    too_large: str | None = None


#: Room a written file's content leaves for the call that wraps it (AIRA reads it as the command of
#: a call with the pending call's cwd), so that call is within the bounds too.
_WRAPPER_ROOM = 1024


def _bounded(written: WrittenFile | None) -> WrittenFile | None:
    return None if written is None else _bounded_file(written)


def _bounded_file(written: WrittenFile, room: int = _WRAPPER_ROOM) -> WrittenFile:
    """`written` with its content cut to preparation's bounds less `room`, read as a shell script (a file
    the agent assembled from several history writes and edits can be far larger than any one step)."""
    content, over = bound_text(written.content, shell=True, max_chars=MAX_CALL_CHARS - room)
    if over is None:
        return written
    return WrittenFile(
        path=written.path,
        step=written.step,
        content=content,
        truncated=written.truncated,
        too_large=written.too_large or over,
    )


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


#: The label the approval salt is derived under; a new label gives every action a new approval fingerprint.
APPROVAL_SALT_LABEL = b"sentrook approval fingerprint v1"


def approval_salt(token_key: str | bytes) -> str:
    """The salt of the approval fingerprint: derived from the scanner's state-token key (HMAC under a versioned
    label), so it is the same in every session of a deployment, is never the key itself, and cannot be computed
    without the key."""
    key = token_key.encode() if isinstance(token_key, str) else token_key
    return hmac.new(key, APPROVAL_SALT_LABEL, hashlib.sha256).hexdigest()[:32]


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
    #: The pending call's entities hashed with `approval_salt` instead of the session's salt: the same action has
    #: the same approval fingerprint in every session, so a plugin can remember an owner's "Always" for it. Used
    #: for nothing else (not scoring, retry matching or the token).
    approval_fingerprint: str = ""
    created_paths: dict[str, int] = field(default_factory=dict)
    written_file: WrittenFile | None = None
    #: The pending command read through its siblings' writes (`sibling_join.resolve_pending`):
    #: synthetic exec calls, source `resolved`. Empty when no sibling write reaches the command.
    resolved: list[CanonicalCall] = field(default_factory=list)
    lineage: Lineage = field(default_factory=Lineage)
    #: The history's copies and moves (`copies.copy_history`): which file a path is a copy of.
    copies: CopyHistory = field(default_factory=CopyHistory)
    coverage: list[CoverageNote] = field(default_factory=list)
    warnings: list[Warning_] = field(default_factory=list)
    #: Hashes present in the token's untrusted set before this request added anything.
    prior_untrusted: frozenset[str] = frozenset()
    #: New tool results that read the agent's own skills or memory (`own_store.own_store_read`): left out of the
    #: exposure probe, untrusted for everything else.
    own_store_inputs: frozenset[int] = frozenset()
    #: Untrusted inputs that try to steer the agent: input_seq → the marker families they match.
    steered_inputs: dict[int, list[str]] = field(default_factory=dict)
    #: The pending call against the token's sensitive and tainted sets as they stood before this request.
    session_binding: SessionBinding = field(default_factory=SessionBinding)
    #: Per new tool result: hashes of the files and tables its call named. If the result is judged
    #: injected, they join the tainted set.
    producer_artefacts: dict[int, list[str]] = field(default_factory=dict)
    #: Per input read from the owner's config: hashes it added to the trusted set (withdrawn if the
    #: same scan judges that input injected).
    trusted_by_input: dict[int, list[str]] = field(default_factory=dict)
    #: Local paths the pending call installs that a download in this command or an earlier step that ran
    #: saved (or a copy or move of one): normalised path → the download's hosts, each a code source of
    #: the call (`_downloaded_installs`).
    downloaded_from: dict[str, list[str]] = field(default_factory=dict)
    #: The entity oracle's answer per entity id (`verdict`, `near_miss`, ...), set by the scan when
    #: the oracle runs before the other probes. Empty when it did not run or failed.
    oracle_entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: The credential-home check (`credential_home.check`): set by the scan after the oracle runs when the convergence
    #: parameters turn the relief on. None: the check did not run or did not hold (`credential_home_check` says why).
    credential_home: Any = None
    credential_home_check: str | None = None
    #: Grants that cover at least one pending-call entity: grant_ref → entity ids.
    grant_hits: dict[str, list[str]] = field(default_factory=dict)
    #: What the pending call does to each path a file grant pattern matched: entity id → actions.
    grant_actions: dict[str, frozenset[str]] = field(default_factory=dict)
    #: Grants that cover the whole call (a `tool` grant covering every command it runs).
    call_grants: list[str] = field(default_factory=list)
    #: Grants that do not apply to this request: grant_ref → `expired`, `unbound_session` or
    #: `other_session` (`grants.lapse`).
    grants_lapsed: dict[str, str] = field(default_factory=dict)
    #: Views version per view name (`trim-v1` for `exposure`/`call`, `trim-v2` for the v2 views).
    views_version: dict[str, str] = field(default_factory=dict)
    #: Second-pass redactions over the v2 views.
    redactions: int = 0
    #: Entity-library verdicts for the call's own entities (`kind`, `value`, `verdict`, optional
    #: `tier`), set by the scan from the oracle probe before a call view that carries `reputation`
    #: is sent. Empty until then, and for views without the block.
    oracle_verdicts: list[dict[str, Any]] = field(default_factory=list)
    #: Per view name: `redactions`, `inputs_truncated`, `inputs_stripped`, `history_cut`, `history_dropped`,
    #: `request_cut`.
    view_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: `request.text` without the host-written parts (`host_text.owner_words`): what the rule-side
    #: matchers read. Jev's views carry the full text.
    request_words: str = ""
    #: The parts of the pending fetch's URL that reproduce a local read in this request (`url_carry`): a fetch
    #: with no body that carries local data out all the same. Empty for every other call.
    url_carries: list[CarriedText] = field(default_factory=list)
    #: The values the sibling join put in place of the pending command's substitutions
    #: (`Resolution.values`). Empty when nothing was substituted.
    sibling_values: tuple[str, ...] = ()
    #: New inputs read from the owner's own configuration: owner-supplied, not untrusted content.
    owner_config_inputs: frozenset[int] = frozenset()

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

    def provider_from_untrusted(self, ent: Entity) -> bool:
        """The provider's identity reached the agent through content it read: the provider entity, or the
        host or package its identity names, is in the session's untrusted set from earlier steps or came
        in through this request's untrusted inputs. The earlier set is read as it was before this request
        added to it, so a request full of untrusted entities cannot push the counterpart out of it."""
        if ent.in_session_untrusted or Origin.UNTRUSTED_INPUT in ent.origins:
            return True
        counterpart = provider_counterpart(ent.value)
        if counterpart is None:
            return False
        kind, value = counterpart
        other = self.entities.get(kind, value)
        if other is not None and (
            other.in_session_untrusted or Origin.UNTRUSTED_INPUT in other.origins
        ):
            return True
        return entity_hash(self.state.salt, kind.value, value) in self.prior_untrusted

    def provider_switched_from(self, ent: Entity) -> str | None:
        """The provider an earlier step of this session called the pending call's tool through, when the
        pending call routes the same tool name through `ent`, a different MCP server or plugin. Another
        version of the same package is the same provider. None when no earlier step called that tool, or
        every one that did went through `ent`."""
        prov = self.pending.provider
        if prov.kind not in (ProviderKind.MCP, ProviderKind.PLUGIN) or not prov.identity:
            return None
        if ent.kind not in (EntityKind.MCP_SERVER, EntityKind.PLUGIN):
            return None  # another kind of entity that happens to share the provider's name
        if normalise_remote_identity(prov.identity) != ent.value:
            return None  # not the pending call's own provider
        here = (prov.kind, provider_name(ent.value))
        for h in self.history:
            if h.tool != self.pending.tool or not h.provider.identity:
                continue
            earlier = normalise_remote_identity(h.provider.identity)
            if (h.provider.kind, provider_name(earlier)) != here:
                return earlier
        return None

    def denied_steps(self) -> list[CanonicalCall]:
        denied = {"denied_by_user", "blocked", "review_timed_out"}
        by_step = {h.step: h for h in self.planir.history}
        return [
            c
            for c in self.history
            if c.step is not None and by_step[c.step].decision.value in denied
        ]

    def unanswered_review(self, step: int | None) -> bool:
        """History step `step` was sent to review and nobody answered it: the review timed out (or is held), or
        the host's own review loop denied it unseen (`blocked` with `decided_by: review_loop`). A retry of such
        a step may ask the owner, never block on its own (`converge.retry_cap`)."""
        h = next((h for h in self.planir.history if h.step == step), None)
        if h is None:
            return False
        if h.decision is Decision.REVIEW_TIMED_OUT:
            return True
        return h.decision is Decision.BLOCKED and h.decided_by is DecidedBy.REVIEW_LOOP


def _mark_request_named(
    request_text: str, table: EntityTable, roots: tuple[str | None, ...] = ()
) -> None:
    """An owner may name a recipient, channel, account or host in a form the mention extractor does not
    produce on its own: a person's name (`Pay Mara Quill`), an account number, `#ops-yard` for a channel
    target, or a host that only the pending call spells out. A pending-call entity whose value appears
    verbatim in the request (case-insensitive, whole token) is request-named. A PyPI name is folded on
    extraction, so the request may spell each `-` of it as any run of `-`, `_` and `.`, as PyPI does.
    A local path an installer installs (`pip install /work/wheels/x.whl`) is also named by its path under
    one of `roots` (the workspace, home, the call's working directory), as an owner writes it."""
    text = request_text.lower()
    if not text:
        return
    for ent in table:
        if (
            not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE)
            or Origin.REQUEST in ent.origins
        ):
            continue
        installed = ent.kind is EntityKind.PATH and Role.CODE_SOURCE in ent.roles
        if not installed and ent.kind not in (
            EntityKind.RECIPIENT,
            EntityKind.CHANNEL,
            EntityKind.HOST,
            EntityKind.PACKAGE,
            EntityKind.PLUGIN,
        ):
            continue
        if _value_named(ent, text, roots):
            ent.add_origin(Origin.REQUEST, "verbatim")


def _value_named(ent: Entity, text: str, roots: tuple[str | None, ...] = ()) -> bool:
    """The entity's value appears in the lower-cased `text` as a whole token: verbatim, a channel by
    its shorter names, a package also without its ecosystem prefix (a PyPI name spelt as PyPI allows),
    a package installed from a URL by that URL's host and path. A path is named by its path under one
    of `roots`, or its `~/` form; a bare file name is not enough, since another file may carry it."""
    if ent.kind is EntityKind.PATH:
        name = ent.value.lower()
        relative: set[str] = set()
        for i, root in enumerate(roots):
            prefix = (root or "").lower().rstrip("/") + "/"
            if len(prefix) > 1 and name.startswith(prefix) and "/" in name[len(prefix) :]:
                relative.add(name[len(prefix) :])
            if i == 1 and len(prefix) > 1 and name.startswith(prefix):
                relative.add("~/" + name[len(prefix) :])
        # A relative path is named only as a whole path, not as the tail of a longer one.
        return any(
            re.search(r"(?<![\w./~-])" + re.escape(rel) + r"(?![\w/-])", text) for rel in relative
        )
    candidates = {ent.value.lower()}
    if ent.kind is EntityKind.CHANNEL:
        candidates.update(channel_names(ent.value))
    if ent.kind is EntityKind.PACKAGE and ent.value.startswith("git+"):
        # Installed from a URL: named by that URL, whatever scheme the owner wrote before the host.
        candidates.add(ent.value[4:].lower())
    elif ent.kind is EntityKind.PACKAGE and ":" in ent.value:
        candidates.add(ent.value.split(":", 1)[1].lower())
    pypi = ent.kind is EntityKind.PACKAGE and ent.value.startswith("pypi:")
    for cand in candidates:
        if len(cand) < 3:
            continue
        body = "[-_.]+".join(map(re.escape, cand.split("-"))) if pypi else re.escape(cand)
        if re.search(r"(?<![\w.@-])" + body + r"(?![\w-])", text):
            return True
    return False


def _mark_code_named_in_content(
    inputs: list[PreparedInput], owner_config: set[int], table: EntityTable, now: int
) -> None:
    """A document can name a package without an installer command the extractor reads: in a sentence
    ("Install kiln-rowcount."), a list, or a command inside backticks. A package the pending call, a
    sibling or the script it runs installs, whose name appears as a whole token in an untrusted input,
    came from that input. A repository on a multi-tenant host came from an untrusted input that holds a
    URL naming the same repository (`repo_of_url`, so the raw, archive and web URLs of one repository
    name it alike); the host alone, or another repository on it, does not. Not when the agent's own call
    named the package or repository at or before the step that produced the input: a result that names
    it back (an install's own output) echoes the agent's choice. An operand computed at run time has no
    name to find."""
    for pi in inputs:
        content = pi.input.content or ""
        if not content or pi.trust is not Trust.UNTRUSTED or pi.input.input_seq in owner_config:
            continue
        text = content.lower()
        ref = f"input:{pi.input.input_seq}"
        arrived = pi.step if pi.step is not None else now
        repos: set[str] | None = None  # the repositories the input's URLs name, read once
        for ent in table:
            if ent.kind not in (EntityKind.PACKAGE, EntityKind.PLUGIN, EntityKind.REPO):
                continue
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            if ref in (ent.origins.get(Origin.UNTRUSTED_INPUT) or ()):
                continue
            if ent.kind is not EntityKind.REPO and is_computed_package(ent.value):
                continue
            if ent.first_history_step is not None and ent.first_history_step <= arrived:
                continue
            if ent.kind is EntityKind.REPO:
                if repos is None:
                    repos = repos_named_in(content)
                if ent.value not in repos:
                    continue
            elif not _value_named(ent, text):
                continue
            ent.add_origin(Origin.UNTRUSTED_INPUT, ref)
            ent.first_untrusted_step = (
                arrived
                if ent.first_untrusted_step is None
                else min(ent.first_untrusted_step, arrived)
            )


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
    return ent.in_session_untrusted or (
        Origin.UNTRUSTED_INPUT in ent.origins and not ent.agent_first
    )


def _inherit_recipient_domain(table: EntityTable) -> None:
    """The mail domain of a request-named recipient is that recipient's own component, not a
    destination the agent chose: `priya.nair@brightlane.io` named by the owner sanctions
    `brightlane.io` as the destination host of that send, even when the domain also turns up in
    content the agent read (the owner's own organisation usually does). Not when a call names the
    host in its own right (a URL, a command target): that use is the agent's, not the owner's."""
    for ent in list(table):
        if ent.kind is not EntityKind.RECIPIENT or "@" not in ent.value:
            continue
        if Origin.REQUEST not in ent.origins:
            continue
        host = table.get(EntityKind.HOST, normalise_host(ent.value.split("@", 1)[1]))
        if host is not None and host.named_in_own_right:
            continue  # a call also sends to or names the host itself: naming the address is not naming it
        if host is not None and Origin.REQUEST not in host.origins:
            host.add_origin(Origin.REQUEST, "recipient_domain")


def _named_verbatim(value: str, text: str) -> bool:
    """`value` appears in `text` as a whole token, not as the part of an email address after its `@`."""
    return bool(re.search(r"(?<![\w.@-])" + re.escape(value.lower()) + r"(?![\w-])", text.lower()))


def _address_only_hosts(request_text: str, table: EntityTable) -> None:
    """Naming an email address sanctions mail to it, not other traffic to its host. A host the request
    reaches only through an address on it (`desk@coppicedown.net`), that a call uses in its own right (posts
    to it, fetches from it, runs code from it), is not request-named: it keeps its own distrust and origin
    and gets no request-named relief. It is still a host the owner named, for the look-alike check. A host
    the owner also wrote bare, as a URL or verbatim stays request-named; so does one the call only mails
    or merely mentions (a signature, a link in the message)."""
    for ent in table:
        if ent.kind is not EntityKind.HOST or not ent.own_right_roles - {Role.MENTIONED}:
            continue
        refs = ent.origins.get(Origin.REQUEST)
        if not refs or set(refs) != {"address"} or _named_verbatim(ent.value, request_text):
            continue
        del ent.origins[Origin.REQUEST]
        ent.owner_named_via_address = True


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


#: The build manifests an install of a local directory runs: a Python build's `setup.py` (or the build
#: its `pyproject.toml` or `setup.cfg` names) and an npm package's `package.json` scripts.
_BUILD_MANIFESTS = ("setup.py", "pyproject.toml", "setup.cfg", "package.json")


def _run_targets(
    pending: CanonicalCall, table: EntityTable, home: str
) -> list[tuple[str, str, bool]]:
    """The files the pending command runs whose content an agent's write may show, as (path, display,
    whether a missing write is a coverage gap): the executables it names, then the build manifests of
    each local directory an installer installs, which run only when they exist."""
    targets = [(e.value, e.display, True) for e in _executed_paths(pending, table)]
    if pending.tool_kind is ToolKind.EXEC:
        for ent in table.pending():
            if ent.kind is EntityKind.PATH and Role.CODE_SOURCE in ent.roles:
                for name in _BUILD_MANIFESTS:
                    path = ent.value.rstrip("/") + "/" + name
                    targets.append((path, display_path(path, home), False))
    return targets


def _find_written(
    planir: PlanIR,
    history: list[CanonicalCall],
    path: str,
    home: str,
    ws: str,
    *,
    after: int | None = None,
    before: int | None = None,
) -> WrittenFile | None:
    """The agent's own writes and edits of `path` in the history (optionally only the steps after
    `after` and before `before`), as one file."""
    best: WrittenFile | None = None
    for call in history:
        if (
            call.tool_kind not in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT)
            or not call.path
            or call.step is None
        ):
            continue
        if (after is not None and call.step <= after) or (
            before is not None and call.step >= before
        ):
            continue
        if normalise_path(call.path, home=home, workspace_root=ws) != path:
            continue
        content = str(call.get("content") or "")
        if best is None or call.step > best.step:
            truncated = bool(PLUGIN_CUT_MARKER.search(content)) or content.rstrip().endswith(
                ("…", "[truncated]", "...")
            )
            if best is not None and call.tool_kind is ToolKind.FILE_EDIT:
                # an edit after a write: both halves are visible, and a cut in the earlier one still applies
                content = best.content + "\n" + content
                truncated = truncated or best.truncated
            best = WrittenFile(path=path, step=call.step, content=content, truncated=truncated)
    return _bounded(best)


def _downloaded_installs(
    pending: CanonicalCall,
    siblings: list[CanonicalCall],
    history: list[CanonicalCall],
    not_run: frozenset[int],
    copies: CopyHistory,
    table: EntityTable,
    now: int,
    home: str,
    ws: str,
) -> dict[str, list[str]]:
    """The local paths the pending command installs (path entities with the code-source role) that a
    download saved: earlier in the same command, in a sibling call of the batch, or in an earlier step
    that ran, at that path or at one it was copied or moved from. Each maps to the download's hosts, less
    package registries (`installers.package_registry_hosts`), which serve only published packages."""
    if pending.tool_kind is not ToolKind.EXEC:
        return {}
    installs = [
        e.value
        for e in table.pending()
        if e.kind is EntityKind.PATH and Role.CODE_SOURCE in e.roles
    ]
    if not installs:
        return {}
    walk = install_walk(pending.command or "", home=home, workspace_root=ws, cwd=pending.get("cwd"))
    earlier: dict[str, set[str]] = {}
    ran = [c for c in history if c.step is not None and c.step not in not_run]
    for call in (*siblings, *ran):
        cmd = call.command or "" if call.tool_kind is ToolKind.EXEC else ""
        if "curl" not in cmd and "wget" not in cmd:
            continue
        saved = install_walk(cmd, home=home, workspace_root=ws, cwd=call.get("cwd")).downloaded
        for path, hosts in saved.items():
            earlier.setdefault(path, set()).update(hosts)
    out: dict[str, set[str]] = {p: set(h) for p, h in walk.installed.items()}
    for path in installs:
        for origin in (path, *copies.ancestors(path, now)):
            if origin in earlier:
                out.setdefault(path, set()).update(earlier[origin])
    charged = {p: sorted(h for h in hosts if not _package_registry(h)) for p, hosts in out.items()}
    return {p: hosts for p, hosts in charged.items() if hosts}


def _package_registry(host: str) -> bool:
    from ..aira.lists import load_lists

    host = host.lower().strip(".")
    registries = load_lists().strings("installers", "package_registry_hosts")
    return any(
        host == r or host.endswith("." + r) for r in (h.lower().strip(".") for h in registries)
    )


#: Arguments of a scheduler tool that name what the job runs.
_SCHEDULED_SCRIPT_KEYS = ("script", "script_path")
_SCHEDULED_COMMAND_KEYS = ("command", "cmd")


def _scheduled_scripts(
    pending: CanonicalCall, history: list[CanonicalCall], home: str, ws: str
) -> list[str]:
    """The agent-written files a scheduler tool call names as what the job runs (its `script` or
    `command` argument), in the order they were last written. The job runs later with nobody
    asked, so creating it is running the file. A path names its file; a bare name (the host looks
    it up in its own scripts directory) names every file of that name written this session. Empty
    for other tools, for a read-only action and for a name no step wrote."""
    if pending.tool_kind not in (ToolKind.OTHER, ToolKind.MCP):
        return []
    from ..aira.lists import load_lists

    lists = load_lists()
    prefix = str(lists.get("selfmod", "tool_name_prefix", default=r"(?:\A|__|[.:/])"))
    if not any(
        rule.get("reason") == "selfmod.scheduler"
        and re.search(prefix + rule.regex.pattern, pending.tool or "", re.IGNORECASE)
        for rule in lists.rules("selfmod", "tool_names")
    ):
        return []
    action = pending.raw.get("action")
    if isinstance(action, str) and action.strip().lower() in {
        a.lower() for a in lists.strings("selfmod", "read_actions")
    }:
        return []
    written: dict[str, int] = {}
    for call in history:
        if (
            call.tool_kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT)
            and call.path
            and call.step is not None
        ):
            written[normalise_path(call.path, home=home, workspace_root=ws)] = call.step
    if not written:
        return []
    found: list[str] = []
    for keys, is_command in ((_SCHEDULED_SCRIPT_KEYS, False), (_SCHEDULED_COMMAND_KEYS, True)):
        for key in keys:
            value = pending.raw.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            for tokens in shell_segments(value):
                for tok in tokens:
                    if tok.startswith("-"):
                        continue
                    if tok.startswith(("/", "~", "$HOME")):
                        path = normalise_path(tok, home=home, workspace_root=ws)
                        matches = [path] if path in written else []
                    else:
                        name = tok.removeprefix("./")
                        if is_command and "/" not in name and "." not in name:
                            continue  # a command word (`sh`, `echo`), not a file
                        matches = [w for w in written if w.endswith("/" + name)]
                    found.extend(m for m in matches if m not in found)
    return sorted(found, key=lambda path: written[path])


def _find_executed(
    planir: PlanIR,
    history: list[CanonicalCall],
    copies: CopyHistory,
    path: str,
    home: str,
    ws: str,
) -> WrittenFile | None:
    """The content of the file at `path` as the agent made it: its own writes, or, when the file
    was copied or moved there, the writes of the file it was copied from (as they stood at the
    copy) followed by any edits made to the copy. None when no step shows the content."""
    now = planir.session.step
    link = copies.onto(path, now)
    if link is None:
        return _find_written(planir, history, path, home, ws)
    later = _find_written(planir, history, path, home, ws, after=link.step)
    source: WrittenFile | None = None
    at = link.step
    for origin in (link.source, *copies.ancestors(link.source, link.step + 1)):
        behind = copies.onto(origin, at + 1)
        source = _find_written(
            planir, history, origin, home, ws, after=behind.step if behind else None, before=at + 1
        )
        if source is not None or behind is None:
            break
        at = behind.step
    if source is None:
        return later  # a copy of a file no step wrote: only the edits made to the copy are visible
    if later is None:
        return WrittenFile(
            path=path,
            step=source.step,
            content=source.content,
            truncated=source.truncated,
            too_large=source.too_large,
        )
    return _bounded_file(
        WrittenFile(
            path=path,
            step=later.step,
            content=source.content + "\n" + later.content,
            truncated=source.truncated or later.truncated,
            too_large=source.too_large or later.too_large,
        )
    )


def _own_store_inputs(
    planir: PlanIR, inputs: list[PreparedInput], state: SessionState, *, home: str, ws: str
) -> frozenset[int]:
    """The new tool results that read the agent's own skills or memory (`own_store.own_store_read`): a host tool
    that succeeded, by both the input and its history step, with that step's arguments. A memory file the session's
    tainted set holds, under any spelling lineage may have recorded, is not one."""
    steps = {h.call_id: h for h in planir.history if h.call_id}
    prior_tainted = frozenset(state.tainted)
    platform = planir.host.platform
    out: set[int] = set()
    for pi in inputs:
        item = pi.input
        if (
            not pi.new
            or item.kind is not InputKind.TOOL_RESULT
            or item.status is not ResultStatus.OK
        ):
            continue
        if item.provider is None or item.provider.kind is not ProviderKind.HOST:
            continue
        step = steps.get(item.call_id)
        if (
            step is None
            or step.provider.kind is not ProviderKind.HOST
            or (step.result is not None and step.result.status is not ResultStatus.OK)
        ):
            continue
        args = step.arguments or {}
        kind = own_store_read(platform, item.tool, args, home=home, workspace_root=ws)
        if kind is None:
            continue
        spellings = memory_path_spellings(platform, item.tool, args, home=home, workspace_root=ws)
        if any(entity_hash(state.salt, "path", p) in prior_tainted for p in spellings):
            continue
        out.add(item.input_seq)
    return frozenset(out)


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


def sql_targets(pending: CanonicalCall) -> list[str]:
    """Database objects a call destroys: the object named by a destructive SQL
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
    lineage.sql_targets = sql_targets(pending)

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


def _session_binding(
    pending: CanonicalCall,
    table: EntityTable,
    state: SessionState,
    lineage: Lineage,
    *,
    home: str,
    workspace_root: str,
) -> SessionBinding:
    """The pending call against the token's sensitive and tainted sets as they stood before this request."""
    ids = {e.value: e.id for e in table if e.kind is EntityKind.PATH}
    arts = call_artefacts(
        pending, state.salt, home=home, workspace_root=workspace_root, entity_ids=ids
    )
    sensitive, tainted = bind(
        arts, sensitive=frozenset(state.sensitive), tainted=frozenset(state.tainted)
    )
    off_host = sends_off_host(pending, table.pending())
    destroys = bool(lineage.destructive_targets or lineage.sql_targets)
    return SessionBinding(
        sensitive=sensitive,
        tainted=tainted,
        off_host=off_host,
        acts=acts(pending, off_host, destroys, home=home, workspace_root=workspace_root),
        takes=[a.hash for a in arts if a.takes],
        writes=[a.hash for a in arts if a.writes and a.kind == "path"],
    )


#: Coverage note: part of what this request asks to run was over preparation's bounds and was read
#: only in part (the head and tail). Convergence holds such a call for review.
INPUT_TOO_LARGE = "input_too_large"


def _as_analysed(
    raw: dict[str, Any],
    pending: CanonicalCall,
    siblings: list[CanonicalCall],
    history: list[CanonicalCall],
) -> dict[str, Any]:
    """The request with each call that was over preparation's bounds carrying the arguments preparation analysed
    (its head and tail), so the views send no more of a call than was read. The request itself when no call was."""
    if not any(c.too_large for c in (pending, *siblings, *history)):
        return raw
    out = dict(raw)
    pc = dict(raw["pending_call"])
    if pending.too_large:
        pc["arguments"] = pending.raw
    batch = pc.get("batch")
    if isinstance(batch, dict) and isinstance(batch.get("siblings"), list):
        sibs = batch["siblings"]
        if len(sibs) == len(siblings):
            batch = dict(batch)
            batch["siblings"] = [
                {**s, "arguments": c.raw} if c.too_large else s
                for s, c in zip(sibs, siblings, strict=True)
            ]
            pc["batch"] = batch
    out["pending_call"] = pc
    steps = raw.get("history")
    if isinstance(steps, list) and len(steps) == len(history):
        out["history"] = [
            {**h, "arguments": c.raw} if c.too_large else h
            for h, c in zip(steps, history, strict=True)
        ]
    return out


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
    prior_steered = frozenset(state.steered)

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
    for call in (pending, *siblings, *history):
        where = call.source if call.step is None else f"{call.source} step {call.step}"
        if call.dropped:
            coverage.append(
                CoverageNote("argument_dropped", f"{where} {call.tool}: {', '.join(call.dropped)}")
            )
        if call.too_large:
            # Only the head and tail of the call were analysed. A history step was judged when it
            # was the pending call, so only the calls of this request take the review floor.
            coverage.append(
                CoverageNote(
                    "history_input_too_large" if call.source == "history" else INPUT_TOO_LARGE,
                    f"{where} {call.tool}: {call.too_large}; analysed its head and tail",
                )
            )

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
    # What the siblings write, and the pending command read through it: the resolved command's
    # entities take the pending call's roles and the sibling's origin. A failure here leaves the
    # scan without the join rather than failing it.
    writes: list[SiblingWrite] = []
    resolved: list[CanonicalCall] = []
    resolution = Resolution()
    try:
        writes = [w for s in siblings for w in sibling_writes(s, home=home, workspace_root=ws)]
        resolution = resolve_pending(platform, pending, writes, home=home, workspace_root=ws)
        resolved = resolution.calls
        if resolution.truncated:
            coverage.append(
                CoverageNote("sibling_join_truncated", f"first {len(resolved)} resolved commands")
            )
    except Exception as exc:  # noqa: BLE001 (an odd sibling must not fail the scan)
        writes, resolved, resolution = [], [], Resolution()
        coverage.append(CoverageNote("sibling_join_failed", f"{type(exc).__name__}: {exc}"))
    for f in extract_call(pending, home=home, workspace_root=ws):
        if resolution.substituted and is_computed_package(f.value):
            # The resolved commands name what this operand computes; one they leave computed
            # comes back through them.
            continue
        table.add_found(f, Origin.PENDING_CALL)
    # Copies and moves that ran: a denied or blocked step copied nothing.
    not_run = frozenset(
        h.step
        for h in planir.history
        if h.decision.value in ("denied_by_user", "blocked", "review_timed_out", "blocked_on_error")
    )
    copies = CopyHistory()
    try:
        copies = copy_history(history, not_run, home=home, workspace_root=ws)
    except Exception as exc:  # noqa: BLE001 (an odd command must not fail the scan)
        coverage.append(CoverageNote("copy_history_failed", f"{type(exc).__name__}: {exc}"))

    # Self-modification content the call writes (a cron line, a hook, a skill, a job prompt) runs later: the hosts
    # that run sends to or runs code from take those roles as future roles, never as roles of this call. A file a
    # sibling or an earlier step that ran wrote is read where the call copies it into place or the content runs it.
    ran = [h for h in history if h.step not in not_run]

    def planted(path: str) -> PlantedFile | None:
        for w in reversed(writes):
            if w.path == path and w.content:
                return PlantedFile(w.content, w.call_id, sibling=True)
        found = _find_executed(planir, ran, copies, path, home, ws)
        return PlantedFile(found.content, f"step:{found.step}") if found is not None else None

    # (found, origin, ref): a planted file's hosts come from the call that wrote it, not from this call.
    written_selfmod: list[tuple[Found, Origin, str | None]] = []
    try:
        texts = written_selfmod_texts(pending, home=home, workspace_root=ws, planted=planted)
        groups: dict[PlantedFile | None, list[WrittenText]] = {}
        for wt in texts:
            groups.setdefault(wt.planted, []).append(wt)
        for source, group in groups.items():
            origin = (
                Origin.PENDING_CALL
                if source is None
                else Origin.SIBLING
                if source.sibling
                else Origin.WRITTEN_FILE
            )
            written_selfmod.extend(
                (f, origin, None if source is None else source.ref)
                for f in future_entities(group, home=home, workspace_root=ws)
            )
    except Exception as exc:  # noqa: BLE001 (odd content must not fail the scan)
        written_selfmod = []
        coverage.append(CoverageNote("written_selfmod_failed", f"{type(exc).__name__}: {exc}"))
    for f, origin, ref in written_selfmod:
        new = table.get(f.kind, f.value) is None
        ent = table.add(f.kind, f.value, display=f.display, origin=origin, ref=ref)
        if new:
            ent.roles.add(Role.MENTIONED)
            ent.only_in_written_selfmod = True
        if f.role is not None:
            ent.future_roles.add(f.role)
    for sib in siblings:
        for f in extract_call(sib, home=home, workspace_root=ws):
            table.add_found(f, Origin.SIBLING, sib.call_id)
    try:
        for call in resolved:
            for f in extract_call(call, home=home, workspace_root=ws):
                table.add_found(f, Origin.SIBLING, call.call_id).in_resolved_command = True
    except Exception as exc:  # noqa: BLE001 (an odd sibling must not fail the scan)
        writes, resolved = [], []
        coverage.append(CoverageNote("sibling_join_failed", f"{type(exc).__name__}: {exc}"))
    # A self-edit that writes a skill: the skill's commands run later with nobody asked, so they are judged now as
    # exec calls of their own.
    # Their entities are not added with roles: an unknown package in an ordinary skill would then read as an
    # unvetted code source on its own; the risky-step suspicion and the self-edit questions judge them instead.
    if planir.is_self_edit:
        try:
            steps = skill_step_calls(platform, pending, planir.self_edit.store.value)
            resolved = [*resolved, *steps]
        except Exception as exc:  # noqa: BLE001
            coverage.append(CoverageNote("skill_steps_failed", f"{type(exc).__name__}: {exc}"))
    # The commands built from this request's calls (read through the siblings' writes, or a saved
    # skill's steps) are bounded like any call; one that was cut was not read in full either.
    for call in resolved:
        if call.too_large:
            coverage.append(
                CoverageNote(
                    INPUT_TOO_LARGE,
                    f"{call.source} {call.call_id or call.tool}: {call.too_large}; "
                    "analysed its head and tail",
                )
            )
    words = owner_words(planir.request.text)
    # A fetch whose URL reproduces a local read sends that text whatever its method: the host it names
    # receives data. A failure here leaves the call a read rather than failing the scan.
    url_carries: list[CarriedText] = []
    try:
        url_carries = url_carries_local(
            pending, inputs, {c.step: c for c in history if c.step is not None}, words
        )
    except Exception as exc:  # noqa: BLE001
        coverage.append(CoverageNote("url_carry_failed", f"{type(exc).__name__}: {exc}"))
    if url_carries:
        carried_to = host_of_url(str(pending.get("url") or ""))
        if carried_to:
            table.add_found(
                Found(EntityKind.HOST, carried_to, carried_to, Role.DATA_DESTINATION),
                Origin.PENDING_CALL,
            )
    for f in extract_mentions(words, home=home, workspace_root=ws, role=None):
        ref = None
        if f.kind is EntityKind.HOST:
            ref = "address" if f.domain_of is not None else "mention"
        table.add(f.kind, f.value, display=f.display, origin=Origin.REQUEST, ref=ref)
    pending_cwd = pending.get("cwd")
    _mark_request_named(
        words,
        table,
        (
            ws,
            home,
            normalise_path(pending_cwd, home=home, workspace_root=ws)
            if isinstance(pending_cwd, str) and pending_cwd
            else None,
        ),
    )

    grant_hits: dict[str, list[str]] = {}
    call_grants: list[str] = []
    grant_actions: dict[str, frozenset[str]] = {}
    grants_lapsed: dict[str, str] = {}
    grant_reach: dict[str, frozenset[str]] = {}
    off_host = sends_off_host(pending, table.pending())
    # The chat platform the batch's sends name in their own argument: a pattern naming it covers their
    # channel targets (`platform_targets`), nothing else. Only when every send in the batch names the
    # same one, so a target on one platform is never covered by a pattern naming another send's.
    sends = [c for c in (pending, *siblings) if c.tool_kind is ToolKind.MESSAGE_SEND]
    platforms = {send_platform(c) for c in sends}
    platform = next(iter(platforms)) if len(platforms) == 1 else None
    targets = {t for c in sends for t in platform_targets(c)} if platform else set()
    for grant in planir.grants:
        spec = GRANT_KINDS.get(grant.kind)
        if spec is None or (spec.local_only and off_host):
            continue  # a file grant sanctions access, never sending the data off the host
        why = lapse(grant, planir)
        if why is not None:
            grants_lapsed[grant.grant_ref] = why
            continue
        allowed = spec.allows(grant)
        if spec.actions and not spec.entity_kinds:
            if "exec" in allowed and tool_covers(grant.pattern, pending):
                call_grants.append(grant.grant_ref)
            continue
        for ent in list(table):
            if not (
                Origin.PENDING_CALL in ent.origins or Origin.SIBLING in ent.origins
            ) or not grant_matches(
                grant.kind,
                grant.pattern,
                ent,
                host_os=planir.host.os,
                platform=platform if (ent.kind, ent.value) in targets else None,
            ):
                continue
            if spec.actions:
                if ent.id not in grant_actions:
                    grant_actions[ent.id], grant_reach[ent.id] = path_actions(
                        pending, ent, home=home, workspace_root=ws, host_os=planir.host.os
                    )
                if not grant_actions[ent.id] <= allowed:
                    continue
                if not all(
                    grant_matches(
                        grant.kind,
                        grant.pattern,
                        Entity("", EntityKind.PATH, g, display_path(g, home)),
                        host_os=planir.host.os,
                    )
                    for g in grant_reach[ent.id]
                ):
                    continue  # a wildcard in the call reaches beyond what the grant covers
            ent.add_origin(Origin.GRANT, grant.grant_ref)
            grant_hits.setdefault(grant.grant_ref, []).append(ent.id)

    # The owner's own configuration: a scanned read of an agent config or instruction file that the
    # agent did not write in this session and that is not tainted.
    created = _created_paths(history, home, ws)
    hist_by_step = {c.step: c for c in history if c.step is not None}
    prior_tainted = frozenset(state.tainted)
    owner_config: set[int] = set()
    for pi in inputs:
        call = hist_by_step.get(pi.step) if pi.input.kind is InputKind.TOOL_RESULT else None
        if call is None:
            continue
        cfg = owner_config_path(call, home=home, workspace_root=ws)
        if (
            cfg is not None
            and cfg not in created
            and entity_hash(state.salt, "path", cfg) not in prior_tainted
        ):
            owner_config.add(pi.input.input_seq)

    for pi in inputs:
        content = pi.input.content or ""
        if not content:
            continue
        if pi.input.input_seq in owner_config:
            origin = Origin.OWNER_CONFIG
        else:
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

    written: WrittenFile | None = None
    for exe_path, exe_display, required in _run_targets(pending, table, home):
        written = _find_executed(planir, history, copies, exe_path, home, ws)
        if written is not None:
            # AIRA reads the file as the command of a call with the pending call's cwd: leave room for it.
            written = _bounded_file(written, _WRAPPER_ROOM + len(str(pending.get("cwd") or "")))
            for f in extract_exec(
                written.content, home=home, workspace_root=ws, cwd=pending.get("cwd")
            ):
                table.add_found(f, Origin.WRITTEN_FILE, f"step:{written.step}")
            for f in extract_mentions(written.content, home=home, workspace_root=ws, role=None):
                table.add_found(f, Origin.WRITTEN_FILE, f"step:{written.step}")
            if written.truncated:
                coverage.append(
                    CoverageNote(
                        "written_file_truncated", f"{exe_display} from step {written.step}"
                    )
                )
            break
        if required:
            coverage.append(CoverageNote("written_file_not_visible", exe_display))
    if written is None:
        # A scheduler tool call that names a script the agent wrote: the job runs that file later,
        # so its content is read as the content of a file the call runs.
        try:
            scheduled = _scheduled_scripts(pending, history, home, ws)
        except Exception as exc:  # noqa: BLE001 (an odd argument must not fail the scan)
            scheduled = []
            coverage.append(CoverageNote("scheduled_script_failed", f"{type(exc).__name__}: {exc}"))
        parts = [
            w
            for w in (_find_executed(planir, history, copies, s, home, ws) for s in scheduled)
            if w is not None
        ]
        if parts:
            written = _bounded_file(
                WrittenFile(
                    path=parts[-1].path,
                    step=max(w.step for w in parts),
                    content="\n".join(w.content for w in parts),
                    truncated=any(w.truncated for w in parts),
                    too_large=next((w.too_large for w in parts if w.too_large), None),
                ),
                _WRAPPER_ROOM + len(str(pending.get("cwd") or "")),
            )
            for w in parts:
                table.add(
                    EntityKind.PATH,
                    w.path,
                    display=display_path(w.path, home),
                    role=Role.EXECUTABLE,
                    origin=Origin.PENDING_CALL,
                )
            for f in extract_exec(written.content, home=home, workspace_root=ws, cwd=None):
                table.add_found(f, Origin.WRITTEN_FILE, f"step:{written.step}")
            for f in extract_mentions(written.content, home=home, workspace_root=ws, role=None):
                table.add_found(f, Origin.WRITTEN_FILE, f"step:{written.step}")
            if written.truncated:
                coverage.append(
                    CoverageNote(
                        "written_file_truncated",
                        f"{display_path(written.path, home)} from step {written.step}",
                    )
                )
            if len(parts) > 1:
                # A bare name several written files share: all of them are read.
                coverage.append(
                    CoverageNote(
                        "scheduled_script_ambiguous",
                        ", ".join(display_path(w.path, home) for w in parts),
                    )
                )

    downloaded_from: dict[str, list[str]] = {}
    try:
        downloaded_from = _downloaded_installs(
            pending, siblings, history, not_run, copies, table, planir.session.step, home, ws
        )
    except Exception as exc:  # noqa: BLE001 (an odd command must not fail the scan)
        coverage.append(CoverageNote("download_join_failed", f"{type(exc).__name__}: {exc}"))
    for path, hosts in downloaded_from.items():
        for h in hosts:
            table.add(
                EntityKind.HOST,
                h,
                display=h,
                role=Role.CODE_SOURCE,
                origin=Origin.PENDING_CALL,
                ref=f"download:{display_path(path, home)}",
            )

    lineage = _lineage(planir, pending, writes, history, table, written, home, ws)
    # A file the agent wrote over several steps and this call runs, sends or lists: only its head
    # and tail were read when it was over the bounds.
    seen_files: set[str] = set()
    for w in (written, *lineage.sent, *lineage.listings):
        if w is not None and w.too_large and w.path not in seen_files:
            seen_files.add(w.path)
            coverage.append(
                CoverageNote(
                    INPUT_TOO_LARGE,
                    f"written file {display_path(w.path, home)} from step {w.step}: {w.too_large}; "
                    "analysed its head and tail",
                )
            )
    _mark_code_named_in_content(inputs, owner_config, table, planir.session.step)

    # 6. untrusted set
    prior_trusted = frozenset(state.trusted)
    for ent in table:
        ent.hash = entity_hash(state.salt, ent.kind.value, ent.value)
        ent.in_session_untrusted = ent.hash in prior_untrusted
        ent.in_prior_trusted = ent.hash in prior_trusted
        ent.in_session_trusted = ent.in_prior_trusted or Origin.OWNER_CONFIG in ent.origins
    additions: list[str] = []
    for ent in table:
        if Origin.UNTRUSTED_INPUT not in ent.origins or ent.hash is None:
            continue
        if not ent.agent_first:
            additions.append(ent.hash)
    state.add_untrusted(additions)
    trusted_by_input: dict[int, list[str]] = {}
    for ent in table:
        for ref in ent.origins.get(Origin.OWNER_CONFIG) or ():
            if ent.hash is not None:
                trusted_by_input.setdefault(int(ref.removeprefix("input:")), []).append(ent.hash)
    state.add_trusted([h for hashes in trusted_by_input.values() for h in hashes])
    binding = _session_binding(pending, table, state, lineage, home=home, workspace_root=ws)
    produced = {
        pi.input.input_seq: producer_artefacts(
            hist_by_step[pi.step], state.salt, home=home, workspace_root=ws
        )
        for pi in inputs
        if pi.new and pi.input.kind is InputKind.TOOL_RESULT and pi.step in hist_by_step
    }
    # The step each steering input arrived at: its history step, or now for a message or reply.
    steered_at: dict[str, int] = {}
    steered_inputs: dict[int, list[str]] = {}
    for pi in inputs:
        if pi.trust is not Trust.UNTRUSTED:
            continue
        marks = steering_marks(pi.input.content or "")
        if steers(marks):
            steered_inputs[pi.input.input_seq] = marks
            steered_at[f"input:{pi.input.input_seq}"] = (
                pi.step if pi.step is not None else planir.session.step
            )
    steered_additions: list[str] = []
    for ent in table:
        if ent.kind not in (EntityKind.HOST, EntityKind.REPO) or ent.hash is None:
            continue
        if ent.hash in prior_steered:
            ent.steered = True
            continue
        arrived = [
            steered_at[ref]
            for ref in ent.origins.get(Origin.UNTRUSTED_INPUT) or ()
            if ref in steered_at
        ]
        if not arrived:
            continue
        # The agent used the host itself before the steering content named it: not steered by it.
        if ent.first_history_step is not None and ent.first_history_step < min(arrived):
            continue
        ent.steered = True
        steered_additions.append(ent.hash)
    # A repository a new steering input names that no call uses yet (content names repositories only by URL, and
    # only a call makes the entity): kept in the token's untrusted and steered sets, so a later step that runs code
    # from it takes the floor as a steered host does. Only steering inputs: a page of ordinary repository links
    # must not crowd the bounded untrusted set. Not one the agent's own call used at or before the step that
    # produced the input.
    repo_untrusted: list[str] = []
    for pi in inputs:
        if not pi.new or f"input:{pi.input.input_seq}" not in steered_at:
            continue
        arrived_at = steered_at[f"input:{pi.input.input_seq}"]
        for repo in sorted(repos_named_in(pi.input.content or "")):
            ent = table.get(EntityKind.REPO, repo)
            if ent is not None and (
                ent.first_history_step is not None and ent.first_history_step <= arrived_at
            ):
                continue
            h = entity_hash(state.salt, EntityKind.REPO.value, repo)
            repo_untrusted.append(h)
            if h not in steered_additions:
                steered_additions.append(h)
    state.add_untrusted(repo_untrusted)
    state.add_steered(steered_additions)
    _mark_display_named(words, table)
    _mark_self_copy(words, table, [pending, *siblings])
    _inherit_recipient_domain(table)
    _address_only_hosts(words, table)

    # 7. fingerprint, and the session-independent approval fingerprint of the same entities
    fp = fingerprint(pending.tool_kind, table.pending(), state.salt)
    approval_fp = fingerprint(
        pending.tool_kind, table.pending(), approval_salt(options.token_key)
    ).render()

    # 8. views (exposure: only the new untrusted inputs with content, which is every input the plugin
    # sent in the common case, less reads of the agent's own skills and memory; call: the full trimmed call view)
    own_store_inputs = _own_store_inputs(planir, inputs, state, home=home, ws=ws)
    untrusted_seqs = {
        i.input.input_seq
        for i in inputs
        if i.trust is Trust.UNTRUSTED
        and i.new
        and i.input.content
        and i.input.input_seq not in own_store_inputs
    }
    built = views.build_views(
        _as_analysed(raw, pending, siblings, history),
        exposure_input_seqs=untrusted_seqs,
        call_budget_tokens=options.call_budget_tokens,
        selfedit_budget_tokens=options.selfedit_budget_tokens,
    )
    jev_views = {name: b.state for name, b in built.items()}
    view_meta = {
        name: {
            "redactions": b.redactions,
            "inputs_truncated": b.inputs_truncated,
            "inputs_stripped": b.inputs_stripped,
            "history_cut": b.history_cut,
            "history_dropped": b.history_dropped,
            "request_cut": b.request_cut,
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
        approval_fingerprint=approval_fp,
        views=jev_views,
        created_paths=created,
        written_file=written,
        resolved=resolved,
        lineage=lineage,
        copies=copies,
        downloaded_from=downloaded_from,
        coverage=coverage,
        warnings=warns,
        prior_untrusted=prior_untrusted,
        steered_inputs=steered_inputs,
        session_binding=binding,
        producer_artefacts={k: v for k, v in produced.items() if v},
        trusted_by_input=trusted_by_input,
        grant_hits=grant_hits,
        grant_actions=grant_actions,
        call_grants=call_grants,
        grants_lapsed=grants_lapsed,
        views_version={name: views.VIEW_VERSIONS[name] for name in built},
        # call-v3 is call-v2's content with a block the probe adds later, so its redactions are
        # call-v2's and are not counted twice.
        redactions=sum(
            b.redactions for n, b in built.items() if n in (views.EXPOSURE_V2, views.CALL_V2)
        ),
        view_meta=view_meta,
        request_words=words,
        own_store_inputs=own_store_inputs,
        url_carries=url_carries,
        sibling_values=resolution.values,
        owner_config_inputs=frozenset(owner_config),
    )
