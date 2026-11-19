"""Context probe: what the trajectory and the session state say about
the call, with no model and no raw text.

- `suspicion.untrusted_origin` per key entity: 0 when the owner named it (request) or a grant covers it;
  about 0.1 for a local entity the agent visibly created with clean lineage; about 0.4 when it appears
  nowhere or first in the agent's own arguments (always for off-host kinds); 1.0 when it appeared only
  in untrusted content before the agent used it (the token's untrusted set remembers across steps).
  The parameters may give a local path the agent picks on an owner-message turn and does not run a
  value of its own (`origin_agent_data_path_owner_turn`); unset, it takes the 0.4.
  A host that is only the mail domain of an email recipient in the call takes that recipient's value
  (no claim of its own) unless its own origin is untrusted or it imitates a host the owner named.
  A recipient written as a self-reference (`me`, `self`, `owner`) is the owner: 0, unless content supplied it.
  An entity only another call in the batch names (not the pending call, the file it runs, or the pending
  command read through a sibling's write) makes no claim: that call's own scan charges it.
  An MCP server or plugin that is in the call only as the provider of its tool makes no claim: the host's
  configuration supplied it, not the agent's arguments. It keeps one when its identity (or the host of a
  remote server, the package of a local one) reached the agent through untrusted content, and keeps the
  agent-chosen value (`origin.switched_provider`) when an earlier step called the same tool name through a
  different provider and the entity library does not vouch for this one as known good.
  A value the pending command takes from a file a sibling writes in the same step, put in place of a
  command substitution (`usermod -aG "$(cat role.txt)"`), that is no entity of its own (a group, a role,
  a scope) scores 1.0 when untrusted content in this request names it as a whole word and the owner's
  request does not; one the request names makes no claim. Only one-word values of three characters or
  more count (a written message is content, not a key argument), and a path, host or package the
  resolved command names is scored as the entity it is.
- `suspicion.request_origin` from the trigger: owner 0, scheduled or heartbeat about 0.2, trusted by a
  plugin allowlist about 0.3, known channel with an unknown sender about 0.5 (coverage reduced), a
  sender marked `other` about 0.8, nothing known no contribution and coverage reduced.
- `suspicion.retry_after_denial` by comparing the pending call's fingerprint components with those of
  denied, blocked or timed-out history steps (recomputed from the history arguments with this
  session's salt, so a plugin's echoed fingerprint is not required; when one is echoed its hashes add
  entities to match on, and the step's role shape stays the recomputed one).
- History lineage (`_lineage`), from the record `prepare` builds: an item the agent moved or copied
  into the tree the call destroys (when it came from outside scratch); the agent's own saved listing
  of that tree marking part of it irreplaceable; the agent's own listing of a database showing
  that the table a destructive statement names holds live data; an agent-written file carrying
  secret values (written earlier, or staged by a sibling in the same batch) that
  the call sends or publishes, when the request does not ask for a secret to go; a host one
  character (or one confusable) away from a host the owner named; a package one edit away from a
  word of the request (in the call, the file it runs or the command a sibling's write resolves it
  to), or a payee or recipient one letter away from a person the owner named
  (`prepare.near_names`; both off by default); an agent-written filter installed
  where it silences sign-in and security notices (a persistent change to the account's alerting,
  so it carries reach and irreversibility too); a privileged role granted on a remote service
  that the owner's request does not name (off by default); a `git push` after a commit whose own
  summary, in a tool result, lists a credential file it added or changed, when the request does not
  ask for that file or a secret to go (off by default). Each arm is off when its value is 0, and
  `lineage_enabled` turns them all off. A failure in the lineage arms contributes nothing and
  leaves the rest of the probe's output intact.
- Sticky `suspicion.session_exposure` from `tainted`; the `escalating` flag from the history tier scores; coverage
  from a stale carried request, a fresh session and truncated or dropped content.
- Session judgements bound to what they are about (the token's sensitive and tainted sets,
  `prepare.session_sets`). `consequence.sensitivity` from `holds_sensitive`, when the call has a data
  destination, follows the binding: a call that takes content from a file or table the session judged
  sensitive carries it, and takes the `sensitive_data_sent` floor when it sends off this machine; a call
  with nothing to match (a raw body, a pipe), or a session whose sensitive data could not be tied to a
  file, carries the flag's weight as before; a call that takes content only from other files carries
  nothing. The parameters may waive that floor when the owner chose every off-machine party the call
  touches (`sensitive_sent_waive_sanctioned`, off by default). A call that takes content only from the env
  file whose key it sends to that key's own service (`prepare.credential_home`, when the convergence parameters
  turn it on) carries neither the sensitivity nor the floor: that is the key's normal use.
  A call that reads, runs or applies a file or table an injected result produced or came from,
  and does more with it than read or copy it, takes the `injected_content_used` floor. Neither floor
  sets an outcome; each lifts the risk past the review line.
- An entity the owner's own configuration supplied (a scanned read of the agent's config or
  instruction files, kept in the token's trusted set) scores as owner-supplied rather than as the
  agent's choice. Content the agent read still wins: an entity that also came from untrusted content
  keeps that origin.
- Escalation: in an escalating session (the flag set earlier, or the last few history consequence
  tiers each rising; `escalation_min_tiers` says how many, two by default), a call that has a consequence of its own (a destination or recipient, code it
  fetches or runs, or a destructive target) carries sensitivity, reach and irreversibility at one step
  above the session's last consequence tier. The step moves a borderline call up about one band; a
  call already scored higher keeps its own values, and nothing is added on the suspicion side, so the
  trend never decides intent on its own.
- A sub-agent the call starts out of the owner's sight (`visible: false`) carries reach and
  irreversibility on the spawn itself (`hidden_spawn_reach`, `hidden_spawn_irreversibility`; off at 0):
  it works with the agent's reach and nobody watching the session sees it to stop it.
- A declared self-edit (the host's own background save to memory or skills, `self_edit` with trigger
  `system`): the request origin is the `self_edit` base (0), since who said what is judged per message
  from the conversation the save carries; escalation does not apply, since the save is not the next step
  of the session's work; and the "agent chose it" origin is left out, since the agent writes every
  self-edit. Origins in untrusted content still count.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..oracle.near_miss import fold
from ..planir.canonical import CanonicalCall
from ..planir.models import InputKind, SenderBasis, SenderRelation, ToolKind, TriggerKind
from ..prepare import Prepared, sql_targets
from ..prepare.entities import (
    Entity,
    EntityKind,
    Origin,
    Role,
    display_path,
    extract_call,
    normalise_path,
)
from ..prepare.fingerprint import ROLE_TAGS, Fingerprint, fingerprint
from ..prepare.trust import Trust
from ..state.token import entity_hash
from .base import Contribution, Envelope, Floor

PROBE_VERSION = "context/2.0.0a1"

#: A value shorter than this, supplied to the pending command by a sibling's write, is never traced.
SIBLING_VALUE_MIN_CHARS = 3


def _names_word(text: str, word: str) -> bool:
    """`text` has `word` as a whole word: not inside a longer word, name or hyphenated name. Case is
    ignored."""
    if not text:
        return False
    return (
        re.search(r"(?<![\w-])" + re.escape(word) + r"(?![\w-])", text, re.IGNORECASE) is not None
    )


KEY_ROLES = (Role.DATA_DESTINATION, Role.RECIPIENT, Role.CODE_SOURCE, Role.EXECUTABLE)
#: Heads that only read; an exec made of these alone is "read-shaped" for retry grading.
_READ_HEADS = frozenset(
    "cat head tail less more ls stat wc grep rg file md5sum sha1sum sha256sum du find diff".split()
)
#: `find` primaries that act on what is found; a find with one of them is not a read.
_FIND_ACTIONS = frozenset(
    "-delete -exec -execdir -ok -okdir -fprint -fprint0 -fprintf -fls".split()
)


@dataclass(frozen=True)
class ContextParams:
    name: str = "ctx-v1"
    origin_sanctioned: float = 0.0
    origin_visible_creation: float = 0.1
    origin_agent_generated: float = 0.4
    origin_untrusted: float = 1.0
    #: An entity the owner's own configuration supplied (the token's trusted set).
    origin_owner_supplied: float = 0.0
    #: A local path the agent picks itself on an owner-message turn and does not run (it writes, edits,
    #: reads or deletes it). None: the general `origin_agent_generated` value.
    origin_agent_data_path_owner_turn: float | None = None
    #: Weight of untrusted_origin by the entity's strongest role.
    origin_role_weight: dict[str, float] = field(
        default_factory=lambda: {
            Role.DATA_DESTINATION.value: 1.0,
            Role.RECIPIENT.value: 1.0,
            Role.CODE_SOURCE.value: 1.0,
            Role.EXECUTABLE.value: 1.0,
            Role.TOOL_PROVIDER.value: 0.6,
            Role.DATA_SOURCE.value: 0.5,
            Role.MENTIONED.value: 0.25,
        }
    )
    request_origin: dict[str, float] = field(
        default_factory=lambda: {
            "owner": 0.0,
            "scheduled": 0.2,
            "heartbeat": 0.2,
            "subagent": 0.3,
            "hook": 0.3,
            "system": 0.3,
            "trusted": 0.3,
            "channel_unknown_sender": 0.5,
            "other": 0.8,
            # A declared self-edit: the host's own background save. Who said what is judged per message from the
            # conversation it carries, so the trigger adds only this base.
            "self_edit": 0.0,
        }
    )
    coverage_unknown_sender: float = 0.9
    coverage_nothing_known: float = 0.8
    retry_same_action: float = 1.0
    retry_same_source_new_destination: float = 0.8
    retry_same_destination_new_source: float = 0.5
    #: A read-shaped call on the data of a denied step: suspicious, but it is not the
    #: denied action retried, so the denied consequence is not carried.
    retry_same_source_only: float = 0.5
    retry_repeat_bonus: float = 0.1
    retry_decay_per_step: float = 0.1
    retry_floor: float = 0.5
    #: Scale on the denied step's echoed consequence tier, contributed as `consequence.reach` and
    #: `consequence.irreversibility` when the pending call retries that step (0 = off; conv-v3 sets 1).
    retry_carry_consequence: float = 0.0
    #: The same scale for `consequence.sensitivity`: what the owner refused was the whole action, so a
    #: retry of it is as sensitive as the refused step was consequential (0 = off).
    retry_carry_sensitivity: float = 0.0
    sticky_exposure: float = 0.7
    holds_sensitive_sensitivity: float = 0.8
    #: Minimum risk when a file or table the session judged sensitive is sent off this machine (0 = off).
    sensitive_sent_floor: float = 0.6
    #: Waive that floor when every off-machine party the call touches is one the owner named in this
    #: turn's request or a grant covers. The file's sensitivity still counts in the score.
    sensitive_sent_waive_sanctioned: bool = False
    #: Minimum risk when a call acts on a file or table an injected result produced (0 = off).
    injected_content_floor: float = 0.6
    escalation_rise: float = 0.1
    #: How many of the last history consequence tiers, each rising on the one before, make a session
    #: escalating: 2 is a single rise (a read, then a write; with a longer history the last three tiers must
    #: each rise), 3 is two rises in a row, and n above 3 is n - 1 rises in a row.
    escalation_min_tiers: int = 2
    #: In an escalating session, a call with a consequence of its own carries sensitivity, reach and
    #: irreversibility at the session's last consequence tier plus this step (0 turns it off).
    escalation_consequence_step: float = 0.2
    #: A sub-agent started out of the owner's sight (`visible: false`): it works with the agent's own reach
    #: and nobody watching the session sees it to stop it. Contributed as reach and irreversibility on the
    #: spawn (0 = off).
    hidden_spawn_reach: float = 0.0
    hidden_spawn_irreversibility: float = 0.0
    coverage_stale_request: float = 0.9
    coverage_very_stale_request: float = 0.8
    coverage_fresh_session: float = 0.7
    coverage_truncated: float = 0.7
    coverage_dropped: float = 0.8
    #: History lineage arms (overridable from a parameter file's `context.lineage` block, keys
    #: without the `lineage_` prefix). A value of 0 turns its arm off.
    lineage_enabled: bool = True
    #: An item moved or copied from outside scratch into the tree the call destroys.
    lineage_moved_irreversibility: float = 1.0
    lineage_moved_reach: float = 0.75
    lineage_moved_overreach: float = 0.6
    #: The agent's saved listing of the destroyed tree marks part of it irreplaceable.
    lineage_listing_irreversibility: float = 1.0
    lineage_listing_overreach: float = 0.6
    #: The agent's own listing of the database shows the object a destructive SQL statement
    #: names holds live data (rows, references, in use).
    lineage_live_table_irreversibility: float = 1.0
    lineage_live_table_overreach: float = 0.6
    #: An agent-written file carrying secret values is sent or published.
    lineage_secret_send_overreach: float = 0.8
    #: A host a character or a confusable away from a host the owner named (0 also drops the
    #: untrusted-origin override for it).
    lineage_lookalike_concealment: float = 0.9
    #: A package the call installs that is one edit or one confusable away from a word of the owner's
    #: request and is not itself named there (0 = off; also drops the untrusted-origin override for it).
    lineage_lookalike_package_concealment: float = 0.0
    #: A person one letter away from a name the owner gave, among the call's recipients or in the
    #: agent-written file the call acts on, whom the request does not name (0 = off).
    lineage_lookalike_name_overreach: float = 0.0
    #: An agent-written filter installed where it silences sign-in and security notices: a
    #: persistent change to the account's alerting that outlives the session and stays quiet
    #: until someone notices, so it carries reach and irreversibility as well as sensitivity.
    lineage_filter_overreach: float = 0.6
    lineage_filter_sensitivity: float = 0.6
    lineage_filter_reach: float = 0.6
    lineage_filter_irreversibility: float = 0.6
    #: A privileged role granted on a remote service (`remote.grant` role bindings) that the owner's
    #: request does not name (0 = off).
    lineage_unnamed_role_overreach: float = 0.0
    #: A `git push` after a commit whose own summary lists a credential file it added or changed,
    #: when the request does not ask for that file or a secret to go (0 = off). The arm also
    #: carries the file's path-class sensitivity.
    lineage_pushed_credential_overreach: float = 0.0


#: How the owner's words name a privileged role: the role's stem at the start of a word (`admin`
#: for `administrator`, `edit` for `editor`), or its spaced form.
_ROLE_WORDS: dict[str, str] = {
    "owner": r"owner",
    "admin": r"admin",
    "administrator": r"admin",
    "editor": r"edit",
    "root": r"root",
    "superuser": r"super[- ]?user",
    "contributor": r"contribut",
    "fullaccess": r"full[- ]?access",
    "poweruser": r"power[- ]?user",
}


def _request_names_role(words: str, role: str) -> bool:
    stem = _ROLE_WORDS.get(role.lower(), re.escape(role.lower()))
    return bool(re.search(r"(?<![a-z0-9])" + stem, words.lower()))


#: Lines of a commit's summary that name a file the commit added or changed (not one it deleted):
#: `create mode 100644 path`, `rewrite path (92%)`, `rename old => new (100%)` (group 1 is the
#: whole rename expression) and a stat line `path | 4 ++--`.
_COMMIT_PATH_RES = (
    re.compile(r"^[^\S\n]*create mode \d{6} (.+?)\s*$", re.MULTILINE),
    re.compile(r"^[^\S\n]*rewrite (.+?) \(\d+%\)\s*$", re.MULTILINE),
    re.compile(r"^[^\S\n]*rename (.+? => .+?) \(\d+%\)\s*$", re.MULTILINE),
    re.compile(r"^ (\S.*?)\s+\|\s+(?:\d+ [+-]+|Bin\b)", re.MULTILINE),
)
#: `{old => new}` with no brace inside; the lookahead finds the closing brace first, so a long run
#: of `{` is read once.
_RENAME_BRACES_RE = re.compile(r"\{(?=[^{}]*\})([^{}]*?) => ([^{}]*)\}")
#: Names of files that stand in for a credential file without holding one.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tmpl")
_GIT_VALUE_FLAGS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})


def _git_calls(command: str, cwd: str | None, *, home: str, ws: str) -> list[tuple[str, list, str]]:
    """The git invocations of a shell command: (verb, the arguments after it, the directory it
    runs in), following `cd` and `git -C`."""
    from ..prepare.entities import resolve_token, shell_segments

    where = normalise_path(cwd, home=home, workspace_root=ws) if cwd else ws
    out: list[tuple[str, list, str]] = []
    for tokens in shell_segments(command):
        head, args = tokens[0], tokens[1:]
        if head == "cd" and args:
            where, _ = resolve_token(args[0], where, home=home, workspace_root=ws)
            continue
        if head != "git":
            continue
        here, i = where, 0
        while i < len(args) and args[i].startswith("-"):
            if args[i] == "-C" and i + 1 < len(args):
                here, _ = resolve_token(args[i + 1], here, home=home, workspace_root=ws)
            i += 2 if args[i] in _GIT_VALUE_FLAGS else 1
        if i < len(args):
            out.append((args[i], args[i + 1 :], here))
    return out


def _commit_summary_paths(text: str) -> list[str]:
    """Repository-relative paths a commit summary says the commit added or changed."""
    out: list[str] = []
    for rx in _COMMIT_PATH_RES:
        for m in rx.finditer(text):
            path = m.group(1).strip()
            if " => " in path:  # a rename: the new name, with a `{old => new}` part expanded
                if _RENAME_BRACES_RE.search(path):
                    path = _RENAME_BRACES_RE.sub(lambda b: b.group(2), path).replace("//", "/")
                else:
                    path = path.split(" => ", 1)[1]
            if path and path not in out:
                out.append(path)
    return out


def _sql_object_name(target: str) -> str:
    """The bare object name of a SQL target: quotes and backticks dropped, the last dotted
    component (`public."temp_users"` -> `temp_users`)."""
    bare = target.strip().strip(";").replace('"', "").replace("`", "")
    return bare.rsplit(".", 1)[-1]


def _sql_objects(targets: list[str]) -> frozenset[str]:
    """The objects destructive SQL statements name, comparable across spellings (bare name, lower
    case); names under three characters are too short to mean the same object."""
    names = (_sql_object_name(t).lower() for t in targets)
    return frozenset(n for n in names if len(n) >= 3)


def _hashes(shape: Fingerprint, echoed: Fingerprint | None, *roles: Role) -> frozenset[str]:
    """The denied step's hashes for `roles`, for matching: those of `shape` (the fingerprint whose
    role tagging is trusted), plus whatever the plugin echoed back under those roles that `shape`
    does not already hold under some role. The echo's tagging may differ from ours: it adds
    entities to match on, it never moves one of ours to another role."""
    out: frozenset[str] = frozenset()
    for role in roles:
        out |= shape.hashes(role)
    if echoed is not None and echoed is not shape:
        known = frozenset().union(*shape.components.values()) if shape.components else frozenset()
        for role in roles:
            out |= echoed.hashes(role) - known
    return out


_SHAPE_ROLES = (
    Role.DATA_SOURCE,
    Role.DATA_DESTINATION,
    Role.RECIPIENT,
    Role.CODE_SOURCE,
    Role.EXECUTABLE,
)


def _request_names_path(prepared: Prepared, path: str) -> bool:
    """The owner's words name the file: its full path, its `~/` form, or its path under the workspace,
    home or the call's working directory, as a whole token. A bare file name is not enough: another
    file of that name may be the one the session judged sensitive."""
    words = (prepared.request_words or "").lower()
    if not words:
        return False
    forms = {path}
    cwd = prepared.pending.get("cwd")
    cwd = (
        normalise_path(cwd, home=prepared.home, workspace_root=prepared.workspace_root)
        if cwd
        else None
    )
    for root, prefix in (
        (prepared.workspace_root, ""),
        (prepared.home, ""),
        (prepared.home, "~/"),
        (cwd, ""),
    ):
        if root and path.startswith(root.rstrip("/") + "/"):
            forms.add(prefix + path[len(root.rstrip("/")) + 1 :])
    return any(
        "/" in f and re.search(r"(?<![\w./~-])" + re.escape(f.lower()) + r"(?![\w/-])", words)
        for f in forms
    )


class ContextProbe:
    step = ProbeStep.CONTEXT

    def __init__(self, params: ContextParams | None = None):
        self.params = params or ContextParams()

    @property
    def versions(self) -> dict[str, str | None]:
        return {"probe": PROBE_VERSION, "params": self.params.name}

    # ------------------------------------------------------------------ untrusted_origin

    def _origin_value(
        self, ent: Entity, prepared: Prepared, prior_flags: set[SessionFlag]
    ) -> tuple[float, str]:
        p = self.params
        if ent.sanctioned:
            return (
                p.origin_sanctioned,
                "origin.request_named" if Origin.REQUEST in ent.origins else "origin.granted",
            )
        if ent.in_session_untrusted or (
            Origin.UNTRUSTED_INPUT in ent.origins and not ent.agent_first
        ):
            return p.origin_untrusted, "origin.only_in_untrusted"
        if ent.self_recipient:
            # `me`, `self`, `owner`: the tool resolves it to the account it runs as
            return p.origin_sanctioned, "origin.self_recipient"
        if ent.kind is EntityKind.PATH:
            created_step = prepared.created_paths.get(ent.value)
            if created_step is not None:
                local = (
                    ent.value.startswith(
                        (prepared.workspace_root + "/", "/tmp/", prepared.home + "/tmp/")
                    )
                    or "/scratch" in ent.value
                )
                clean = SessionFlag.TAINTED not in prior_flags and not self._dirty_lineage(
                    ent, prepared
                )
                if local and clean:
                    return p.origin_visible_creation, "origin.agent_created_visible"
                if local:
                    return p.origin_untrusted if self._dirty_lineage(
                        ent, prepared
                    ) else p.origin_agent_generated, "origin.agent_created_dirty_lineage"
        if ent.in_session_trusted:
            # The owner's own config supplied it: owner-supplied rather than the agent's choice.
            return p.origin_owner_supplied, "origin.owner_config"
        if (
            p.origin_agent_data_path_owner_turn is not None
            and ent.kind is EntityKind.PATH
            and not ent.roles & {Role.EXECUTABLE, Role.CODE_SOURCE}
            and prepared.planir.trigger.kind is TriggerKind.MESSAGE
            and prepared.planir.trigger.sender.relation is SenderRelation.OWNER
        ):
            # An owner seldom spells a path out: where a write or read lands is the agent's pick on
            # nearly every owner turn.
            return p.origin_agent_data_path_owner_turn, "origin.agent_generated"
        return p.origin_agent_generated, "origin.agent_generated"

    @staticmethod
    def _dirty_lineage(ent: Entity, prepared: Prepared) -> bool:
        """The executed file's content names an entity the untrusted set already holds."""
        if prepared.written_file is None or prepared.written_file.path != ent.value:
            return False
        for other in prepared.entities:
            if Origin.WRITTEN_FILE in other.origins and (
                other.in_session_untrusted or Origin.UNTRUSTED_INPUT in other.origins
            ):
                return True
        return False

    def _untrusted_origin(
        self,
        prepared: Prepared,
        prior_flags: set[SessionFlag],
        evidence: dict,
        lookalikes: dict[str, str] | None = None,
        package_lookalikes: dict[str, str] | None = None,
    ) -> list[Contribution]:
        lookalikes = lookalikes or {}
        package_lookalikes = package_lookalikes or {}
        out: list[Contribution] = []
        for ent in prepared.entities:
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            if ent.kind is EntityKind.PATH and not (
                ent.roles
                & {Role.EXECUTABLE, Role.CODE_SOURCE, Role.DATA_SOURCE, Role.DATA_DESTINATION}
            ):
                continue
            if ent.sibling_only:
                # only another call in the batch names it: that call's own scan charges it
                evidence.setdefault("origins", {})[ent.id] = {"reason": "origin.sibling_only"}
                continue
            # a role a later run that the call's written self-modification content sets up counts as one of the
            # call's own; whether naming or a grant sanctions it is relief's to decide, by role
            weight = max(
                (
                    self.params.origin_role_weight.get(r.value, 0.25)
                    for r in ent.roles | ent.future_roles
                ),
                default=0.25,
            )
            value, reason = self._origin_value(ent, prepared, prior_flags)
            switched_from = None
            if (
                reason == "origin.agent_generated"
                and ent.roles == {Role.TOOL_PROVIDER}
                and (prepared.oracle_entities.get(ent.id) or {}).get("verdict") != "known_good"
            ):
                switched_from = prepared.provider_switched_from(ent)
            if switched_from is not None:
                # the session called this tool through another provider before: the host did not just
                # supply this one, something chose it, and nothing vouches for it
                reason = "origin.switched_provider"
            elif (
                reason == "origin.agent_generated"
                and ent.roles == {Role.TOOL_PROVIDER}
                and not prepared.provider_from_untrusted(ent)
            ):
                # in the call only as the server or plugin its tool comes from: the host's configuration
                # supplied it, not the agent's arguments
                evidence.setdefault("origins", {})[ent.id] = {
                    "reason": "origin.host_configured_provider"
                }
                continue
            if (
                Origin.WRITTEN_FILE in ent.origins
                and Origin.PENDING_CALL not in ent.origins
                and value >= self.params.origin_untrusted
            ):
                reason = "origin.written_content_untrusted"
            if ent.id in lookalikes and value < self.params.origin_untrusted:
                value, reason = self.params.origin_untrusted, "origin.lookalike_of_named_host"
            if ent.id in package_lookalikes and value < self.params.origin_untrusted:
                value, reason = self.params.origin_untrusted, "origin.lookalike_of_named_package"
            if ent.recipient_domain_of and value < self.params.origin_untrusted:
                # only a recipient's mail domain: the recipient's own origin claim speaks for it
                evidence.setdefault("origins", {})[ent.id] = {
                    "reason": "origin.recipient_mail_domain",
                    "mail_domain_of": list(ent.recipient_domain_of),
                }
                continue
            scaled = round(value * weight, 4)
            out.append(
                Contribution(
                    signal="suspicion.untrusted_origin", value=scaled, subject=ent.id, reason=reason
                )
            )
            evidence.setdefault("origins", {})[ent.id] = {
                "value": scaled,
                "reason": reason,
                "origins": {k.value: v for k, v in ent.origins.items()},
                "in_session_untrusted": ent.in_session_untrusted,
                "first_history_step": ent.first_history_step,
                "first_untrusted_step": ent.first_untrusted_step,
            }
            if switched_from is not None:
                evidence["origins"][ent.id]["switched_from"] = switched_from
        return out

    def _sibling_values(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        """`suspicion.untrusted_origin` for values a sibling's write supplies to the pending command in
        place of a command substitution, when only untrusted content in this request names them."""
        if not prepared.sibling_values:
            return []
        entity_names: set[str] = set()
        for ent in prepared.entities:
            if ent.in_resolved_command or ent.has_origin(Origin.PENDING_CALL):
                entity_names.update(
                    n.casefold() for n in (ent.value, ent.display, ent.value.split(":", 1)[-1]) if n
                )
        untrusted = [
            pi.input.content
            for pi in prepared.inputs
            if pi.trust is Trust.UNTRUSTED
            and pi.input.content
            and pi.input.input_seq not in prepared.owner_config_inputs
        ]
        found: list[str] = []
        for raw in prepared.sibling_values:
            value = raw.strip()
            if not value or any(c.isspace() for c in value):
                continue
            for item in (v.strip("'\"") for v in value.split(",")):
                if len(item) < SIBLING_VALUE_MIN_CHARS or "/" in item:
                    continue
                if item.casefold() in entity_names or item in found:
                    continue
                if _names_word(prepared.request_words, item):
                    continue
                if any(_names_word(text, item) for text in untrusted):
                    found.append(item)
        if not found:
            return []
        evidence["sibling_values_untrusted"] = len(found)
        return [
            Contribution(
                signal="suspicion.untrusted_origin",
                value=self.params.origin_untrusted,
                reason="origin.sibling_value_untrusted",
            )
        ]

    # ------------------------------------------------------------------ lineage

    @staticmethod
    def _lists() -> Any:
        from ..aira.lists import load_lists

        return load_lists()

    def _lookalikes(self, prepared: Prepared) -> dict[str, str]:
        """Host entities the call or the file it runs uses in a risky role that look like a host
        the owner named without being it: entity id → the named host. One edit apart, or equal once
        confusable characters are folded (`0`/`o`, `1`/`l`, `rn`/`m`); labels shorter than five
        characters and hosts under the named host's own domain never match."""
        if not self.params.lineage_enabled or self.params.lineage_lookalike_concealment <= 0:
            return {}
        from ..aira.detectors import _edit_distance_le1, _registrable_label

        named = [
            e
            for e in prepared.entities
            if e.kind is EntityKind.HOST
            and (Origin.REQUEST in e.origins or e.owner_named_via_address)
        ]
        if not named:
            return {}
        out: dict[str, str] = {}
        for ent in prepared.entities:
            if ent.kind is not EntityKind.HOST or ent.sanctioned:
                continue
            if not ent.has_origin(Origin.PENDING_CALL, Origin.WRITTEN_FILE):
                continue
            if not ent.roles & set(KEY_ROLES):
                continue
            label = _registrable_label(ent.value)
            for other in named:
                if ent.value == other.value or ent.value.endswith("." + other.value):
                    break
                theirs = _registrable_label(other.value)
                if label == theirs or min(len(label), len(theirs)) < 5:
                    continue
                if _edit_distance_le1(label, theirs) or fold(label) == fold(theirs):
                    out[ent.id] = other.value
                    break
        return out

    def _package_lookalikes(self, prepared: Prepared) -> dict[str, str]:
        """Packages and plugins the call (the file it runs, or the command a sibling's write resolves it to)
        installs that imitate a word of the owner's request without being named there: entity id → the
        word. A package the entity library vouches for is what it says it is, whatever it resembles."""
        if (
            not self.params.lineage_enabled
            or self.params.lineage_lookalike_package_concealment <= 0
        ):
            return {}
        from ..prepare.near_names import package_lookalike

        words = prepared.request_words or ""
        out: dict[str, str] = {}
        for ent in prepared.entities:
            if ent.kind not in (EntityKind.PACKAGE, EntityKind.PLUGIN) or ent.sanctioned:
                continue
            if not (
                ent.has_origin(Origin.PENDING_CALL, Origin.WRITTEN_FILE) or ent.in_resolved_command
            ):
                continue
            if Role.CODE_SOURCE not in ent.roles:
                continue
            if (prepared.oracle_entities.get(ent.id) or {}).get("verdict") == "known_good":
                continue
            named = package_lookalike(ent.value, words)
            if named is not None:
                out[ent.id] = named
        return out

    def _name_lookalikes(self, prepared: Prepared) -> list[tuple[str | None, str, str]]:
        """People one letter away from a name the owner gave whom the request does not name, where the
        call sends, pays or otherwise acts: among its own recipients, and in the agent-written files
        (written earlier, or staged by a sibling) it takes. (entity id, where, the name the owner gave).
        A call that only reads or writes a file does nothing with the names in it."""
        from ..prepare import _find_written
        from ..prepare.near_names import name_lookalikes
        from ..prepare.sibling_join import sibling_writes

        pending = prepared.pending
        binding = prepared.session_binding
        sends = pending.tool_kind is ToolKind.MESSAGE_SEND or binding.acts or binding.off_host
        if not sends or pending.tool_kind in (
            ToolKind.FILE_READ,
            ToolKind.FILE_WRITE,
            ToolKind.FILE_EDIT,
            ToolKind.MEMORY_WRITE,
        ):
            return []
        words = prepared.request_words or ""
        home, ws = prepared.home, prepared.workspace_root
        out: list[tuple[str | None, str, str]] = []
        recipients = [r for r in pending.recipients if isinstance(r, str) and "@" not in r]
        for _, named in name_lookalikes(words, "\n".join(recipients), capitalised=False):
            subject = next(
                (
                    e.id
                    for e in prepared.entities.pending()
                    if e.kind is EntityKind.RECIPIENT and Role.RECIPIENT in e.roles
                ),
                None,
            )
            out.append((subject, "recipient", named))
        staged = {
            w.path: w.content
            for sib in prepared.siblings
            for w in sibling_writes(sib, home=home, workspace_root=ws)
            if w.content is not None
        }
        for ent in prepared.entities.pending():
            if ent.kind is not EntityKind.PATH or not ent.roles - {Role.MENTIONED}:
                continue
            written = _find_written(prepared.planir, prepared.history, ent.value, home, ws)
            content = written.content if written is not None else staged.get(ent.value)
            if not content:
                continue
            for _, named in name_lookalikes(words, content):
                out.append((ent.id, ent.display, named))
        return out

    def _lineage(
        self,
        prepared: Prepared,
        lookalikes: dict[str, str],
        evidence: dict,
        package_lookalikes: dict[str, str] | None = None,
    ) -> list[Contribution]:
        p = self.params
        lin = prepared.lineage
        home = prepared.home
        record: dict[str, Any] = {**lin.names(home), "fired": []}
        evidence["lineage"] = record
        if not p.lineage_enabled:
            return []
        out: list[Contribution] = []
        fired: list[str] = record["fired"]

        def emit(signal: str, value: float, subject: str | None, reason: str) -> None:
            if value <= 0:
                return
            out.append(
                Contribution(signal=signal, value=round(value, 4), subject=subject, reason=reason)
            )
            if reason not in fired:
                fired.append(reason)

        def path_id(value: str) -> str | None:
            ent = prepared.entities.get(EntityKind.PATH, value)
            return ent.id if ent is not None else None

        lists = self._lists()

        # 1. An item moved or copied into the tree the call destroys.
        if lin.moved_in and p.lineage_moved_irreversibility + p.lineage_moved_overreach > 0:
            from ..aira.detectors import SENSITIVE_GROUPS, is_scratch

            reason = "lineage.moved_into_destroyed_tree"
            for item in lin.moved_in:
                if is_scratch(item.source, prepared.workspace_root, lists):
                    continue
                subject = path_id(item.source)
                emit(
                    "consequence.irreversibility", p.lineage_moved_irreversibility, subject, reason
                )
                emit("consequence.reach", p.lineage_moved_reach, subject, reason)
                emit("suspicion.overreach", p.lineage_moved_overreach, subject, reason)
                for group in SENSITIVE_GROUPS:
                    if lists.group(group).search(item.source):
                        emit(
                            "consequence.sensitivity",
                            lists.weight("sensitivity", group),
                            subject,
                            reason,
                        )
                        break

        # 2. The agent's own listing of the destroyed tree marks part of it irreplaceable.
        if lin.listings and p.lineage_listing_irreversibility + p.lineage_listing_overreach > 0:
            from ..prepare.entities import is_under, paths_in

            markers = lists.patterns("destructive", "irreplaceable_markers", "patterns")
            reason = "lineage.listing_marks_irreplaceable"
            for listing in lin.listings:
                if not any(rx.search(listing.content) for rx in markers):
                    continue
                listed = [
                    v for v, _ in paths_in(listing.content, home, prepared.workspace_root, None)
                ]
                for target in lin.destructive_targets:
                    if not any(is_under(v, target) for v in listed):
                        continue
                    subject = path_id(target)
                    emit(
                        "consequence.irreversibility",
                        p.lineage_listing_irreversibility,
                        subject,
                        reason,
                    )
                    emit("suspicion.overreach", p.lineage_listing_overreach, subject, reason)

        # 2b. The agent's own listing of the database shows the table the statement destroys is live.
        if (
            lin.sql_targets
            and p.lineage_live_table_irreversibility + p.lineage_live_table_overreach > 0
        ):
            markers = lists.patterns("destructive", "live_table_markers", "patterns")
            reason = "lineage.listing_marks_live_table"
            live: list[dict[str, Any]] = []
            for target in lin.sql_targets:
                name = _sql_object_name(target)
                if len(name) < 3:
                    continue
                word = re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", re.IGNORECASE)
                for inp in prepared.inputs:
                    if inp.input.kind is not InputKind.TOOL_RESULT or inp.input.tool_kind not in (
                        ToolKind.EXEC,
                        ToolKind.MCP,
                    ):
                        continue  # only the agent's own query of the store is a listing of it
                    for line in (inp.input.content or "").splitlines():
                        if word.search(line) and any(rx.search(line) for rx in markers):
                            live.append({"target": target, "input_seq": inp.input.input_seq})
                            emit(
                                "consequence.irreversibility",
                                p.lineage_live_table_irreversibility,
                                None,
                                reason,
                            )
                            emit(
                                "suspicion.overreach", p.lineage_live_table_overreach, None, reason
                            )
                            break
                    else:
                        continue
                    break
            if live:
                record["live_tables"] = live

        # 3. Secret values carried into a send or publish the owner did not ask a secret to go with: a
        # placeholder, a shape the second redaction pass masks, or a secret-like value the redactors
        # leave raw (an access code, a PIN, a passport number, a random value under a key).
        words = prepared.request_words or ""
        asked_for_secret = any(
            rx.search(words) for rx in lists.patterns("lineage", "secret_request_terms", "patterns")
        )
        # Naming a code, PIN or passport relieves only the values the redactors left raw.
        asked_for_secret_like = any(
            rx.search(words)
            for rx in lists.patterns("lineage", "secret_like_request_terms", "patterns")
        )
        if (
            lin.sent
            and p.lineage_secret_send_overreach > 0
            and not asked_for_secret
            and self._is_sink(prepared, lists)
        ):
            from ..prepare.secret_like import secret_carried

            placeholder = str(lists.get("egress", "placeholder", "open", default="⟦secret"))
            carried: dict[str, str] = {}
            for sent in lin.sent:
                why = secret_carried(sent.content, placeholder, owner_asked=asked_for_secret_like)
                if why is not None:
                    carried[sent.path] = why
                    emit(
                        "suspicion.overreach",
                        p.lineage_secret_send_overreach,
                        path_id(sent.path),
                        "lineage.secret_carried_to_send",
                    )
            if carried:
                record["secrets_carried"] = carried

        # 4. A look-alike of a host the owner named.
        for ent_id in lookalikes:
            emit(
                "suspicion.concealment",
                p.lineage_lookalike_concealment,
                ent_id,
                "lineage.lookalike_of_named_host",
            )
        if lookalikes:
            record["lookalikes"] = {ent_id: named for ent_id, named in lookalikes.items()}

        # 4b. A look-alike of a package the owner named.
        for ent_id in package_lookalikes or {}:
            emit(
                "suspicion.concealment",
                p.lineage_lookalike_package_concealment,
                ent_id,
                "lineage.lookalike_of_named_package",
            )
        if package_lookalikes:
            record["package_lookalikes"] = dict(package_lookalikes)

        # 4c. A payee or recipient one letter away from a person the owner named.
        if p.lineage_lookalike_name_overreach > 0:
            near = self._name_lookalikes(prepared)
            for subject, _, _ in near:
                emit(
                    "suspicion.overreach",
                    p.lineage_lookalike_name_overreach,
                    subject,
                    "lineage.lookalike_of_named_person",
                )
            if near:
                record["name_lookalikes"] = [
                    {"where": where, "named": named} for _, where, named in near
                ]

        # 5. An agent-written filter installed where it silences security notices.
        if (
            p.lineage_filter_overreach
            + p.lineage_filter_sensitivity
            + p.lineage_filter_reach
            + p.lineage_filter_irreversibility
            > 0
        ):
            for dest in self._installed_filters(prepared, lists):
                subject = path_id(dest)
                reason = "lineage.filter_silences_security_notices"
                emit("suspicion.overreach", p.lineage_filter_overreach, subject, reason)
                emit("consequence.sensitivity", p.lineage_filter_sensitivity, subject, reason)
                emit("consequence.reach", p.lineage_filter_reach, subject, reason)
                emit(
                    "consequence.irreversibility",
                    p.lineage_filter_irreversibility,
                    subject,
                    reason,
                )

        # 6. A privileged role granted on a remote service that the owner's request does not name.
        command = prepared.pending.command if prepared.pending.tool_kind is ToolKind.EXEC else None
        if p.lineage_unnamed_role_overreach > 0 and command:
            unnamed: list[str] = []
            for rule in lists.rules("remote_destructive", "cli"):
                if rule.get("reason") != "remote.grant":
                    continue
                for m in rule.regex.finditer(command):
                    role = m.groupdict().get("role")
                    if role and not _request_names_role(words, role) and role not in unnamed:
                        unnamed.append(role)
            if unnamed:
                emit(
                    "suspicion.overreach",
                    p.lineage_unnamed_role_overreach,
                    None,
                    "remote.privileged_role_not_named",
                )
                record["unnamed_roles"] = [r.lower() for r in unnamed]

        # 7. A push of a commit whose own summary lists a credential file it added or changed.
        if p.lineage_pushed_credential_overreach > 0 and command and not asked_for_secret:
            pushed = self._pushed_credentials(prepared, command, words, lists)
            for path, group in pushed.items():
                subject = path_id(path)
                reason = "artefact.credential_file_pushed"
                emit("suspicion.overreach", p.lineage_pushed_credential_overreach, subject, reason)
                emit("consequence.sensitivity", lists.weight("sensitivity", group), subject, reason)
            if pushed:
                record["pushed_credentials"] = [display_path(path, home) for path in pushed]
        return out

    @staticmethod
    def _pushed_credentials(
        prepared: Prepared, command: str, words: str, lists: Any
    ) -> dict[str, str]:
        """Credential files (path → sensitive group) that commits made in this session's history
        added or changed, by their own summaries in the tool results, in a repository the pending
        command pushes. Not a template (`.env.example`), and not a file the request names."""
        home, ws = prepared.home, prepared.workspace_root
        pushes = [
            where
            for verb, args, where in _git_calls(
                command, prepared.pending.get("cwd"), home=home, ws=ws
            )
            if verb == "push" and not {"--dry-run", "-n"} & set(args)
        ]
        if not pushes:
            return {}
        by_step = {c.step: c for c in prepared.history if c.step is not None}
        out: dict[str, str] = {}
        for inp in prepared.inputs:
            call = by_step.get(inp.step) if inp.step is not None else None
            if (
                call is None
                or inp.input.kind is not InputKind.TOOL_RESULT
                or call.tool_kind is not ToolKind.EXEC
                or not call.command
            ):
                continue
            commits = [
                where
                for verb, _, where in _git_calls(call.command, call.get("cwd"), home=home, ws=ws)
                if verb == "commit"
            ]
            if not any(where in pushes for where in commits):
                continue
            repo = next(where for where in commits if where in pushes)
            for rel in _commit_summary_paths(inp.input.content or ""):
                name = rel.rsplit("/", 1)[-1]
                if name.lower().endswith(_TEMPLATE_SUFFIXES):
                    continue
                if re.search(
                    r"(?<![\w.-])" + re.escape(name.lower()) + r"(?![\w-])", words.lower()
                ):
                    continue  # the owner named the file
                path = normalise_path(repo.rstrip("/") + "/" + rel, home=home, workspace_root=ws)
                group = next(
                    (
                        g
                        for g in ("credential_store", "credential_bearing_config")
                        if lists.group(g).search(path)
                    ),
                    None,
                )
                if group is not None:
                    out.setdefault(path, group)
        return out

    @staticmethod
    def _is_sink(prepared: Prepared, lists: Any) -> bool:
        """The pending call sends data off the machine: a message send, an off-host destination or
        recipient, or an exec whose command carries an egress marker."""
        pending = prepared.pending
        if pending.tool_kind is ToolKind.MESSAGE_SEND:
            return True
        for ent in prepared.entities.pending():
            if (
                ent.kind in (EntityKind.RECIPIENT, EntityKind.CHANNEL)
                and Role.RECIPIENT in ent.roles
            ):
                return True
            if (
                ent.kind is EntityKind.HOST
                and Role.DATA_DESTINATION in ent.roles
                and ent.value not in ("localhost", "127.0.0.1", "::1", "[::1]")
            ):
                return True
        if pending.tool_kind is ToolKind.EXEC and pending.command:
            cmd = pending.command
            for rule in lists.rules("egress", "exec_markers"):
                head = rule.get("head")
                if head and not re.search(r"\b" + re.escape(str(head)) + r"\b", cmd):
                    continue
                if rule.regex.search(cmd):
                    return True
        return False

    @staticmethod
    def _installed_filters(prepared: Prepared, lists: Any) -> list[str]:
        """The destination of each agent-written file the call installs, outside the
        workspace, at a mail or notification filter location, whose content has a filter line
        naming a sign-in or security notice. The call's own written content counts when it writes
        straight to such a location."""
        from ..prepare.entities import is_under

        locations = lists.patterns("lineage", "filter_locations", "patterns")
        terms = lists.patterns("lineage", "security_notice_terms", "patterns")
        actions = lists.patterns("lineage", "filter_action_patterns")
        if not (locations and terms and actions):
            return []
        ws = prepared.workspace_root

        def silences(content: str) -> bool:
            for line in content.splitlines():
                if any(rx.search(line) for rx in terms) and any(rx.search(line) for rx in actions):
                    return True
            return False

        def filter_location(path: str) -> bool:
            return not is_under(path, ws) and any(rx.search(path) for rx in locations)

        out: list[str] = []
        pending = prepared.pending
        if pending.tool_kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT) and pending.path:
            from ..prepare.entities import normalise_path

            dest = normalise_path(pending.path, home=prepared.home, workspace_root=ws)
            content = str(pending.get("content") or "")
            if filter_location(dest) and silences(content):
                out.append(dest)
        if not any(silences(w.content) for w in prepared.lineage.sent):
            return out
        sent_paths = {w.path for w in prepared.lineage.sent}
        for ent in prepared.entities.pending():
            if ent.kind is not EntityKind.PATH or Role.DATA_DESTINATION not in ent.roles:
                continue
            if ent.value in sent_paths or not filter_location(ent.value):
                continue
            out.append(ent.value)
        return out

    # ------------------------------------------------------------------ request_origin

    def _request_origin(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        p = self.params
        trig = prepared.planir.trigger
        rel, kind = trig.sender.relation, trig.kind
        basis = set(trig.sender.basis)
        evidence["trigger"] = {
            "kind": kind.value,
            "relation": rel.value,
            "basis": sorted(b.value for b in basis),
            "channel": trig.channel.value if trig.channel else None,
        }
        out: list[Contribution] = []
        if prepared.planir.is_self_edit:
            evidence["trigger"]["self_edit"] = True
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin.get("self_edit", 0.0),
                    reason="trigger.self_edit",
                )
            )
            return out
        if rel is SenderRelation.OWNER or SenderBasis.HOST_ALLOWLIST_DM in basis:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["owner"],
                    reason="trigger.owner",
                )
            )
        elif kind in (TriggerKind.SCHEDULED, TriggerKind.HEARTBEAT):
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin[kind.value],
                    reason=f"trigger.{kind.value}",
                )
            )
        elif rel is SenderRelation.TRUSTED:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["trusted"],
                    reason="trigger.trusted_allowlist",
                )
            )
        elif rel is SenderRelation.OTHER or basis & {
            SenderBasis.GROUP_CHAT,
            SenderBasis.HOST_OPEN_ACCESS,
        }:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["other"],
                    reason="trigger.sender_other",
                )
            )
        elif kind in (TriggerKind.SUBAGENT, TriggerKind.HOOK, TriggerKind.SYSTEM):
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin[kind.value],
                    reason=f"trigger.{kind.value}",
                )
            )
        elif kind is TriggerKind.MESSAGE and trig.channel is not None:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["channel_unknown_sender"],
                    reason="trigger.unknown_sender",
                )
            )
            out.append(
                Contribution(
                    signal="confidence.coverage",
                    value=p.coverage_unknown_sender,
                    reason="coverage.unknown_sender",
                )
            )
        else:
            out.append(
                Contribution(
                    signal="confidence.coverage",
                    value=p.coverage_nothing_known,
                    reason="coverage.trigger_unknown",
                )
            )
        return out

    # ------------------------------------------------------------------ retry_after_denial

    def _history_fingerprint(
        self, call: CanonicalCall, prepared: Prepared
    ) -> tuple[Fingerprint, list[Entity]]:
        """A history step's fingerprint recomputed from its arguments (copies followed), and the
        entities it was computed from."""
        from ..prepare.entities import EntityTable

        table = EntityTable()
        for f in extract_call(call, home=prepared.home, workspace_root=prepared.workspace_root):
            table.add(f.kind, f.value, display=f.display, role=f.role, origin=Origin.HISTORY)
        fp = fingerprint(call.tool_kind, list(table), prepared.state.salt)
        before = call.step if call.step is not None else prepared.planir.session.step
        return self._with_copies(fp, list(table), before, prepared)[0], list(table)

    @staticmethod
    def _path_hashes(entities: list[Entity], before: int, prepared: Prepared) -> frozenset[str]:
        """Hashes of the files a call names in a fingerprinted role, and of the files they were
        copied from by step `before`."""
        out: set[str] = set()
        for ent in entities:
            if ent.kind is not EntityKind.PATH or not any(r in ROLE_TAGS for r in ent.roles):
                continue
            for path in (ent.value, *prepared.copies.ancestors(ent.value, before)):
                out.add(entity_hash(prepared.state.salt, EntityKind.PATH.value, path))
        return frozenset(out)

    @staticmethod
    def _with_copies(
        fp: Fingerprint, entities: list[Entity], before: int, prepared: Prepared
    ) -> tuple[Fingerprint, dict[str, list[str]]]:
        """`fp` with, for each file the call names, the files it was copied or moved from by step
        `before` under the same roles: a copy is the same file for retry matching. Also the copies
        followed, as display paths."""
        comps = {tag: set(hashes) for tag, hashes in fp.components.items()}
        followed: dict[str, list[str]] = {}
        for ent in entities:
            if ent.kind is not EntityKind.PATH:
                continue
            tags = [ROLE_TAGS[r] for r in ent.roles if r in ROLE_TAGS]
            sources = prepared.copies.ancestors(ent.value, before) if tags else []
            if not sources:
                continue
            followed[ent.display] = sources
            for src in sources:
                h = entity_hash(prepared.state.salt, EntityKind.PATH.value, src)
                for tag in tags:
                    comps.setdefault(tag, set()).add(h)
        if not followed:
            return fp, followed
        return (
            Fingerprint(
                tool_kind=fp.tool_kind, components={k: frozenset(v) for k, v in comps.items()}
            ),
            followed,
        )

    def _read_shaped(self, prepared: Prepared) -> bool:
        """A file read, or an exec whose every segment starts with a reading head and writes
        nothing: touching the denied step's data again, not retrying what was denied. A `find`
        that deletes or runs a command, and a command with a substitution, are not reads."""
        kind = prepared.pending.tool_kind
        if kind is ToolKind.FILE_READ:
            return True
        if kind is not ToolKind.EXEC:
            return False
        cmd = prepared.pending.command or ""
        if ">" in cmd or "$(" in cmd or "`" in cmd:
            return False  # a redirect writes; a substitution runs a command of its own
        segments = [seg.strip() for seg in re.split(r"[;|&]+|\n", cmd) if seg.strip()]
        if not segments:
            return False
        for seg in segments:
            tokens = seg.split()
            if tokens[0] not in _READ_HEADS:
                return False
            if tokens[0] == "find" and _FIND_ACTIONS.intersection(tokens[1:]):
                return False  # a find that deletes, runs a command or writes a file
        return True

    def _retry(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        """`retry_after_denial`: a retry shares the denied step's source,
        destination or code hash; a file copied or moved in the history (`prepare.copies`) is the
        file it came from, on both sides. Matching is role-insensitive on the pending side (a `shred` target
        re-touched by an interpreter one-liner is the same entity whatever role the extractor gave
        it); the grade keeps the role shape of the denied step. A matched retry also
        carries the denied step's echoed consequence tier (`retry_carry_consequence`), except for a
        read-shaped call on the same data, which is scored at `retry_same_source_only` and carries
        nothing. A destructive SQL statement that names the object a denied destructive statement
        named is the same action through whatever tool it now goes. Each match records whether its
        step was a review nobody answered (`Prepared.unanswered_review`); convergence caps a retry
        whose every match is one at review (`converge.retry_cap`)."""
        p = self.params
        denied = prepared.denied_steps()
        if not denied:
            return [
                Contribution(signal="suspicion.retry_after_denial", value=0.0, reason="retry.none")
            ]
        step_now = prepared.planir.session.step
        pending, copies = self._with_copies(
            prepared.fingerprint, prepared.entities.pending(), step_now, prepared
        )
        p_src = pending.hashes(Role.DATA_SOURCE)
        p_dst = pending.hashes(Role.DATA_DESTINATION) | pending.hashes(Role.RECIPIENT)
        p_code = pending.hashes(Role.CODE_SOURCE) | pending.hashes(Role.EXECUTABLE)
        p_all = p_src | p_dst | p_code
        read_shaped = self._read_shaped(prepared)
        p_sql = _sql_objects(prepared.lineage.sql_targets)
        p_paths = self._path_hashes(prepared.entities.pending(), step_now, prepared)
        by_step = {h.step: h for h in prepared.planir.history}
        best, best_reason, matches = 0.0, "retry.none", []
        carried = 0.0
        for call in denied:
            hist, h_entities = self._history_fingerprint(call, prepared)
            echoed_step = by_step.get(call.step) if call.step is not None else None
            echoed = Fingerprint.parse(echoed_step.action_fingerprint if echoed_step else None)

            # The role shape (did the step move data from a source to a destination?) is the one
            # recomputed from the step's arguments; the echo is the shape only when they give none.
            shape = hist
            if echoed is not None and not any(hist.hashes(r) for r in _SHAPE_ROLES):
                shape = echoed
            two_sided = bool(
                shape.hashes(Role.DATA_SOURCE)
                and (shape.hashes(Role.DATA_DESTINATION) or shape.hashes(Role.RECIPIENT))
            )
            h_src = _hashes(shape, echoed, Role.DATA_SOURCE)
            h_dst = _hashes(shape, echoed, Role.DATA_DESTINATION, Role.RECIPIENT)
            h_code = _hashes(shape, echoed, Role.CODE_SOURCE, Role.EXECUTABLE)
            src_shared, dst_shared = bool(h_src & p_all), bool(h_dst & p_all)
            code_shared = bool(h_code & p_all)
            # The same destructive statement through another tool or client shares no path or code:
            # the object it destroys is the match, unless each names a different database file.
            sql_shared = sorted(p_sql & _sql_objects(sql_targets(call))) if p_sql else []
            if sql_shared:
                h_paths = self._path_hashes(h_entities, call.step or step_now, prepared)
                if p_paths and h_paths and not p_paths & h_paths:
                    sql_shared = []
            if not (src_shared or dst_shared or code_shared or sql_shared):
                continue
            carry = True
            if sql_shared:
                value, reason = p.retry_same_action, "retry.same_action"
            elif two_sided:  # the denied step moved data from a source to a destination
                if src_shared and dst_shared:
                    value, reason = p.retry_same_action, "retry.same_action"
                elif src_shared and p_dst:
                    value, reason = (
                        p.retry_same_source_new_destination,
                        "retry.same_source_new_destination",
                    )
                elif dst_shared and p_src:
                    value, reason = (
                        p.retry_same_destination_new_source,
                        "retry.same_destination_new_source",
                    )
                elif src_shared:
                    value, reason, carry = p.retry_same_source_only, "retry.same_source_only", False
                else:
                    value, reason = (
                        p.retry_same_destination_new_source,
                        "retry.same_destination_new_source",
                    )
            elif read_shaped and not code_shared:
                value, reason, carry = p.retry_same_source_only, "retry.same_source_only", False
            else:  # a single-entity action (destroy, write, install) retried on the same entity
                value, reason = p.retry_same_action, "retry.same_action"
            gap = max(1, step_now - (call.step or step_now))
            value = value * max(p.retry_floor, 1.0 - p.retry_decay_per_step * (gap - 1))
            tiers = echoed_step.tiers if echoed_step is not None else None
            cons = (
                tiers.consequence if tiers is not None and tiers.consequence is not None else None
            )
            if carry and cons is not None:
                carried = max(carried, float(cons))
            matches.append(
                {
                    "step": call.step,
                    "reason": reason,
                    "value": round(value, 4),
                    "carry": carry,
                    "unanswered": prepared.unanswered_review(call.step),
                }
            )
            if sql_shared:
                matches[-1]["sql_target"] = sql_shared[0]
            if value > best:
                best, best_reason = value, reason
        if len(matches) > 1:
            best = min(1.0, best + p.retry_repeat_bonus * (len(matches) - 1))
        tier = carried
        carried = round(min(1.0, tier * p.retry_carry_consequence), 4)
        carried_sensitivity = round(min(1.0, tier * p.retry_carry_sensitivity), 4)
        evidence["retry"] = {
            "denied_steps": [c.step for c in denied],
            "matches": matches,
            "carried_consequence": carried,
            # every matched step is a review nobody answered: the retry may ask, never block on its own
            "unanswered_only": bool(matches) and all(m["unanswered"] for m in matches),
        }
        if copies:
            evidence["retry"]["copies"] = copies
        out = [
            Contribution(
                signal="suspicion.retry_after_denial", value=round(best, 4), reason=best_reason
            )
        ]
        for signal, value in (
            ("consequence.reach", carried),
            ("consequence.irreversibility", carried),
            ("consequence.sensitivity", carried_sensitivity),
        ):
            if value > 0.0:
                out.append(
                    Contribution(
                        signal=signal, value=value, reason="retry.denied_consequence_carried"
                    )
                )
        return out

    # ------------------------------------------------------------------ flags and coverage

    @staticmethod
    def _consequence_tiers(prepared: Prepared) -> list[float]:
        return [
            float(h.tiers.consequence)
            for h in prepared.planir.history
            if h.tiers and h.tiers.consequence is not None
        ]

    def _escalating(self, prepared: Prepared) -> bool:
        # the last three tiers, or as many as the parameter asks for when that is more
        need = max(2, self.params.escalation_min_tiers)
        tail = self._consequence_tiers(prepared)[-max(3, need) :]
        return len(tail) >= need and all(
            b >= a + self.params.escalation_rise for a, b in zip(tail, tail[1:], strict=False)
        )

    @staticmethod
    def _has_consequence(prepared: Prepared) -> bool:
        """The call itself can do harm: it has a destination or recipient, fetches or runs code, or
        destroys something. A read-only call with none of these is not lifted by the trend."""
        if prepared.lineage.destructive_targets or prepared.lineage.sql_targets:
            return True
        return any(ent.roles & set(KEY_ROLES) for ent in prepared.entities.pending())

    def _escalation(
        self, prepared: Prepared, escalating: bool, evidence: dict
    ) -> list[Contribution]:
        """An escalating session scores a call that has a consequence of its own at least one step
        above the session's last consequence tier, on sensitivity, reach and irreversibility. These
        merge by max, so a call already scored higher on its own keeps its values."""
        step = self.params.escalation_consequence_step
        if not escalating or step <= 0:
            return []
        if prepared.planir.is_self_edit:
            # A self-edit is the host's background save, not the next step of the session's work.
            evidence["escalation"] = {"skipped": "self_edit"}
            return []
        tiers = self._consequence_tiers(prepared)
        record: dict[str, Any] = {
            "last_tier": tiers[-1] if tiers else None,
            "call_has_consequence": self._has_consequence(prepared),
            "value": None,
        }
        evidence["escalation"] = record
        if not tiers or not record["call_has_consequence"]:
            return []
        value = round(min(1.0, max(0.0, tiers[-1]) + step), 4)
        record["value"] = value
        return [
            Contribution(signal=signal, value=value, reason="escalation.consequence_rising")
            for signal in (
                "consequence.sensitivity",
                "consequence.reach",
                "consequence.irreversibility",
            )
        ]

    # ------------------------------------------------------------------ hidden spawn

    def _hidden_spawn(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        """A sub-agent spawn that states `visible: false`. Visibility left unstated is the host's default
        and says nothing."""
        p = self.params
        if p.hidden_spawn_reach <= 0 and p.hidden_spawn_irreversibility <= 0:
            return []
        pending = prepared.pending
        if pending.tool_kind is not ToolKind.SUBAGENT_SPAWN:
            return []
        visible = pending.get("visible")
        if isinstance(visible, str):
            hidden = visible.strip().lower() in ("false", "0", "no", "off")
        else:
            hidden = visible is False or (isinstance(visible, int | float) and visible == 0)
        if not hidden:
            return []
        evidence["hidden_spawn"] = True
        return [
            Contribution(signal=signal, value=round(value, 4), reason="spawn.hidden_subagent")
            for signal, value in (
                ("consequence.reach", p.hidden_spawn_reach),
                ("consequence.irreversibility", p.hidden_spawn_irreversibility),
            )
            if value > 0
        ]

    # ------------------------------------------------------------------ session sets

    def _session_sets(
        self, prepared: Prepared, prior_flags: set[SessionFlag], evidence: dict
    ) -> tuple[list[Contribution], list[Floor]]:
        """`holds_sensitive` and `tainted` bound to the files and tables they are about."""
        p = self.params
        binding = prepared.session_binding
        sens, tnt = binding.sensitive, binding.tainted
        has_destination = any(
            ent.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
            for ent in prepared.entities.pending()
        )
        record: dict[str, Any] = {
            "sensitive": sens.names(),
            "tainted": tnt.names(),
            "identifiable": sens.identifiable,
            "unbound": prepared.state.sensitive_unbound,
            "off_host": binding.off_host,
            "acts": binding.acts,
        }
        evidence["session_sets"] = record
        contributions: list[Contribution] = []
        floors: list[Floor] = []
        reason = "sensitivity.session_holds_sensitive"
        if prepared.credential_home is not None and has_destination:
            # the check found the session's sensitive data to be only the env files whose key goes to its service
            record["holds_sensitive"] = "credential_home"
        elif sens.bound and has_destination:
            subject = sens.subject()
            contributions.append(
                Contribution(
                    signal="consequence.sensitivity",
                    value=p.holds_sensitive_sensitivity,
                    subject=subject,
                    reason=reason,
                )
            )
            # Not for a file the owner named in the request: the owner chose to send it.
            unseen = [a for a in sens.matched if not self._sensitivity_visible(a, prepared)]
            if unseen and binding.off_host and p.sensitive_sent_floor > 0:
                if p.sensitive_sent_waive_sanctioned and self._owner_chose_every_party(prepared):
                    record["sensitive_sent_floor"] = "waived"
                else:
                    subject = next((a.entity_id for a in unseen if a.entity_id), subject)
                    floors.append(
                        Floor(
                            floor="sensitive_data_sent",
                            min_risk=p.sensitive_sent_floor,
                            subject=subject,
                            reason=reason,
                        )
                    )
            record["holds_sensitive"] = "bound"
        elif SessionFlag.HOLDS_SENSITIVE in prior_flags and has_destination:
            if sens.identifiable and not prepared.state.sensitive_unbound:
                # The call sends only other files: not the data the session judged sensitive.
                record["holds_sensitive"] = "unmatched"
            else:
                contributions.append(
                    Contribution(
                        signal="consequence.sensitivity",
                        value=p.holds_sensitive_sensitivity,
                        reason=reason,
                    )
                )
                record["holds_sensitive"] = "flag"
        if tnt.bound and binding.acts and p.injected_content_floor > 0:
            floors.append(
                Floor(
                    floor="injected_content_used",
                    min_risk=p.injected_content_floor,
                    subject=tnt.subject(),
                    reason="exposure.session_injected_content",
                )
            )
        return contributions, floors

    @staticmethod
    def _owner_chose_every_party(prepared: Prepared) -> bool:
        """Every off-machine party the call touches (a host, recipient or channel in the call, the file
        it runs or the command a sibling's write resolves it to, in any role) is covered by a grant or,
        on an owner-message turn, named in the request; and there is at least one the call sends to.
        A command that sends through a tool whose destination need not be written as a host (`scp` to
        an alias, a pipe to `nc`, `git push`), itself or in the file it runs, never qualifies."""
        from ..oracle.client import is_local_host
        from ..prepare.grants import sends_by_unwritten_route

        commands = [prepared.pending.command or "", *(c.command or "" for c in prepared.resolved)]
        if prepared.written_file is not None:
            commands.append(prepared.written_file.content)
        if prepared.pending.tool_kind is ToolKind.EXEC and any(
            sends_by_unwritten_route(c) for c in commands if c
        ):
            return False
        trig = prepared.planir.trigger
        owner_turn = (
            trig.kind is TriggerKind.MESSAGE and trig.sender.relation is SenderRelation.OWNER
        )
        sends_to = 0
        for ent in prepared.entities:
            if ent.kind not in (EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL):
                continue
            if not (
                ent.has_origin(Origin.PENDING_CALL, Origin.WRITTEN_FILE) or ent.in_resolved_command
            ):
                continue
            if ent.kind is EntityKind.HOST and is_local_host(ent.value):
                continue
            if not (Origin.GRANT in ent.origins or (owner_turn and Origin.REQUEST in ent.origins)):
                return False
            if ent.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}:
                sends_to += 1
        return sends_to > 0

    @staticmethod
    def _sensitivity_visible(artefact: Any, prepared: Prepared) -> bool:
        """The owner's request names the file."""
        if artefact.kind != "path":
            return False
        ent = prepared.entities.by_id(artefact.entity_id) if artefact.entity_id else None
        if ent is not None and Origin.REQUEST in ent.origins:
            return True
        return _request_names_path(prepared, artefact.value)

    def run(self, prepared: Prepared) -> Envelope:
        started = time.perf_counter()
        p = self.params
        prior_flags = set(prepared.state.flags)
        evidence: dict = {
            "prior_flags": sorted(f.value for f in prior_flags),
            "token": prepared.state.status.value,
        }
        contributions: list[Contribution] = []
        floors: list[Floor] = []
        flags: list[SessionFlag] = []
        try:
            lookalikes: dict[str, str] = {}
            try:
                lookalikes = self._lookalikes(prepared)
            except Exception as e:  # noqa: BLE001 (a lineage failure contributes nothing)
                evidence["lineage_error"] = repr(e)
            package_lookalikes: dict[str, str] = {}
            try:
                package_lookalikes = self._package_lookalikes(prepared)
            except Exception as e:  # noqa: BLE001 (a lineage failure contributes nothing)
                evidence["lineage_error"] = repr(e)
            origin = self._untrusted_origin(
                prepared, prior_flags, evidence, lookalikes, package_lookalikes
            )
            if prepared.planir.is_self_edit:
                # The agent writes every self-edit, so "the agent chose this" says nothing about it; origins in
                # untrusted content still count.
                origin = [c for c in origin if c.reason != "origin.agent_generated"]
            contributions += origin
            contributions += self._sibling_values(prepared, evidence)
            contributions += self._request_origin(prepared, evidence)
            contributions += self._retry(prepared, evidence)
            try:
                contributions += self._lineage(prepared, lookalikes, evidence, package_lookalikes)
            except Exception as e:  # noqa: BLE001 (a lineage failure contributes nothing)
                evidence["lineage_error"] = repr(e)

            if SessionFlag.TAINTED in prior_flags:
                contributions.append(
                    Contribution(
                        signal="suspicion.session_exposure",
                        value=p.sticky_exposure,
                        reason="exposure.session_tainted",
                    )
                )
            sensitive, injected = self._session_sets(prepared, prior_flags, evidence)
            contributions += sensitive
            floors += injected
            escalating = SessionFlag.ESCALATING in prior_flags or self._escalating(prepared)
            if escalating:
                flags.append(SessionFlag.ESCALATING)
            evidence["escalating"] = escalating
            contributions += self._escalation(prepared, escalating, evidence)
            contributions += self._hidden_spawn(prepared, evidence)

            coverage = 1.0
            carried = prepared.planir.request.carried_from_turn
            if carried is not None:
                gap = prepared.planir.session.turn - carried
                coverage = min(
                    coverage, p.coverage_very_stale_request if gap > 3 else p.coverage_stale_request
                )
                evidence["request_staleness_turns"] = gap
            if prepared.state.fresh:
                coverage = min(coverage, p.coverage_fresh_session)
            codes = {c.code for c in prepared.coverage}
            if codes & {"input_truncated", "written_file_truncated"}:
                coverage = min(coverage, p.coverage_truncated)
            if codes & {
                "content_dropped",
                "content_missing",
                "written_file_not_visible",
                "argument_dropped",
            }:
                coverage = min(coverage, p.coverage_dropped)
            if coverage < 1.0:
                contributions.append(
                    Contribution(
                        signal="confidence.coverage", value=coverage, reason="coverage.context"
                    )
                )
            evidence["coverage_notes"] = [f"{c.code}:{c.detail}" for c in prepared.coverage]
        except Exception as e:  # noqa: BLE001 (a probe never raises)
            return Envelope.failed(
                self.step,
                ProbeStatus.ERROR,
                repr(e),
                self.versions,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        return Envelope(
            step=self.step,
            versions=self.versions,
            status=ProbeStatus.OK,
            latency_ms=(time.perf_counter() - started) * 1000,
            contributions=contributions,
            floors=floors,
            flags_set=flags,
            evidence=evidence,
        )
