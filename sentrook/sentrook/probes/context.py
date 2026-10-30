"""Context probe: what the trajectory and the session state say about
the call, with no model and no raw text.

- `suspicion.untrusted_origin` per key entity: 0 when the owner named it (request) or a grant covers it;
  about 0.1 for a local entity the agent visibly created with clean lineage; about 0.4 when it appears
  nowhere or first in the agent's own arguments (always for off-host kinds); 1.0 when it appeared only
  in untrusted content before the agent used it (the token's untrusted set remembers across steps).
- `suspicion.request_origin` from the trigger: owner 0, scheduled or heartbeat about 0.2, trusted by a
  plugin allowlist about 0.3, known channel with an unknown sender about 0.5 (coverage reduced), a
  sender marked `other` about 0.8, nothing known no contribution and coverage reduced.
- `suspicion.retry_after_denial` by comparing the pending call's fingerprint components with those of
  denied, blocked or timed-out history steps (recomputed from the history arguments with this
  session's salt, so a plugin's echoed fingerprint is not required).
- History lineage (`_lineage`), from the record `prepare` builds: an item the agent moved or copied
  into the tree the call destroys (when it came from outside scratch); the agent's own saved listing
  of that tree marking part of it irreplaceable; the agent's own listing of a database showing
  that the table a destructive statement names holds live data; an agent-written file carrying
  secret values (written earlier, or staged by a sibling in the same batch) that
  the call sends or publishes, when the request does not ask for a secret to go; a host one
  character (or one confusable) away from a host the owner named; an agent-written filter installed
  where it silences sign-in and security notices (a persistent change to the account's alerting,
  so it carries reach and irreversibility too). Each arm is off when its value is 0, and
  `lineage_enabled` turns them all off. A failure in the lineage arms contributes nothing and
  leaves the rest of the probe's output intact.
- Sticky `suspicion.exposure` from `tainted`; `consequence.sensitivity` from `holds_sensitive` when
  the call has a data destination; the `escalating` flag from the history tier scores; coverage from a
  stale carried request, a fresh session and truncated or dropped content.
- Escalation: in an escalating session (the flag set earlier, or the last few history consequence
  tiers each rising), a call that has a consequence of its own (a destination or recipient, code it
  fetches or runs, or a destructive target) carries sensitivity, reach and irreversibility at one step
  above the session's last consequence tier. The step moves a borderline call up about one band; a
  call already scored higher keeps its own values, and nothing is added on the suspicion side, so the
  trend never decides intent on its own.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..planir.canonical import CanonicalCall
from ..planir.models import InputKind, SenderBasis, SenderRelation, ToolKind, TriggerKind
from ..prepare import Prepared
from ..prepare.entities import Entity, EntityKind, Origin, Role, extract_call
from ..prepare.fingerprint import Fingerprint, fingerprint
from .base import Contribution, Envelope

PROBE_VERSION = "context/2.0.0a1"

KEY_ROLES = (Role.DATA_DESTINATION, Role.RECIPIENT, Role.CODE_SOURCE, Role.EXECUTABLE)
#: Heads that only read; an exec made of these alone is "read-shaped" for retry grading.
_READ_HEADS = frozenset(
    "cat head tail less more ls stat wc grep rg file md5sum sha1sum sha256sum du find diff".split()
)


@dataclass(frozen=True)
class ContextParams:
    name: str = "ctx-v1"
    origin_sanctioned: float = 0.0
    origin_visible_creation: float = 0.1
    origin_agent_generated: float = 0.4
    origin_untrusted: float = 1.0
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
    sticky_exposure: float = 0.7
    holds_sensitive_sensitivity: float = 0.8
    escalation_rise: float = 0.1
    #: In an escalating session, a call with a consequence of its own carries sensitivity, reach and
    #: irreversibility at the session's last consequence tier plus this step (0 turns it off).
    escalation_consequence_step: float = 0.2
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
    #: An agent-written filter installed where it silences sign-in and security notices: a
    #: persistent change to the account's alerting that outlives the session and stays quiet
    #: until someone notices, so it carries reach and irreversibility as well as sensitivity.
    lineage_filter_overreach: float = 0.6
    lineage_filter_sensitivity: float = 0.6
    lineage_filter_reach: float = 0.6
    lineage_filter_irreversibility: float = 0.6


_CONFUSABLES = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("i", "l"),
    ("3", "e"),
    ("5", "s"),
)


def _sql_object_name(target: str) -> str:
    """The bare object name of a SQL target: quotes and backticks dropped, the last dotted
    component (`public."temp_users"` -> `temp_users`)."""
    bare = target.strip().strip(";").replace('"', "").replace("`", "")
    return bare.rsplit(".", 1)[-1]


def _fold(label: str) -> str:
    """A host label with confusable characters folded together, hyphens dropped."""
    out = label.lower().replace("-", "")
    for a, b in _CONFUSABLES:
        out = out.replace(a, b)
    return out


def _hashes(hist: Fingerprint, echoed: Fingerprint | None, *roles: Role) -> frozenset[str]:
    """The denied step's hashes for `roles`: recomputed with this session's salt, plus whatever the
    plugin echoed back (its tagging may differ from ours)."""
    out: frozenset[str] = frozenset()
    for role in roles:
        out |= hist.hashes(role)
        if echoed is not None:
            out |= echoed.hashes(role)
    return out


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
        agent_first = (
            ent.first_history_step is not None
            and ent.first_untrusted_step is not None
            and ent.first_history_step < ent.first_untrusted_step
        )
        if ent.in_session_untrusted or (Origin.UNTRUSTED_INPUT in ent.origins and not agent_first):
            return p.origin_untrusted, "origin.only_in_untrusted"
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
    ) -> list[Contribution]:
        lookalikes = lookalikes or {}
        out: list[Contribution] = []
        for ent in prepared.entities:
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            if ent.kind is EntityKind.PATH and not (
                ent.roles & {Role.EXECUTABLE, Role.DATA_SOURCE, Role.DATA_DESTINATION}
            ):
                continue
            weight = max(
                (self.params.origin_role_weight.get(r.value, 0.25) for r in ent.roles), default=0.25
            )
            value, reason = self._origin_value(ent, prepared, prior_flags)
            if (
                Origin.WRITTEN_FILE in ent.origins
                and Origin.PENDING_CALL not in ent.origins
                and value >= self.params.origin_untrusted
            ):
                reason = "origin.written_content_untrusted"
            if ent.id in lookalikes and value < self.params.origin_untrusted:
                value, reason = self.params.origin_untrusted, "origin.lookalike_of_named_host"
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
        return out

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
            if e.kind is EntityKind.HOST and Origin.REQUEST in e.origins
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
                if _edit_distance_le1(label, theirs) or _fold(label) == _fold(theirs):
                    out[ent.id] = other.value
                    break
        return out

    def _lineage(
        self, prepared: Prepared, lookalikes: dict[str, str], evidence: dict
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

        # 3. Secret values carried into a send or publish the owner did not ask a secret to go with.
        asked_for_secret = any(
            rx.search(prepared.request_words or "")
            for rx in lists.patterns("lineage", "secret_request_terms", "patterns")
        )
        if (
            lin.sent
            and p.lineage_secret_send_overreach > 0
            and not asked_for_secret
            and self._is_sink(prepared, lists)
        ):
            from ..prepare.redact import redact_text

            placeholder = str(lists.get("egress", "placeholder", "open", default="⟦secret"))
            for sent in lin.sent:
                if placeholder in sent.content or redact_text(sent.content)[1] > 0:
                    emit(
                        "suspicion.overreach",
                        p.lineage_secret_send_overreach,
                        path_id(sent.path),
                        "lineage.secret_carried_to_send",
                    )

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

    def _history_fingerprint(self, call: CanonicalCall, prepared: Prepared) -> Fingerprint:
        from ..prepare.entities import EntityTable

        table = EntityTable()
        for f in extract_call(call, home=prepared.home, workspace_root=prepared.workspace_root):
            table.add(f.kind, f.value, display=f.display, role=f.role, origin=Origin.HISTORY)
        return fingerprint(call.tool_kind, list(table), prepared.state.salt)

    def _read_shaped(self, prepared: Prepared) -> bool:
        """A file read, or an exec whose every segment starts with a reading head and writes
        nothing: touching the denied step's data again, not retrying what was denied."""
        kind = prepared.pending.tool_kind
        if kind is ToolKind.FILE_READ:
            return True
        if kind is not ToolKind.EXEC:
            return False
        cmd = prepared.pending.command or ""
        if ">" in cmd:
            return False
        segments = [seg.strip() for seg in re.split(r"[;|&]+|\n", cmd) if seg.strip()]
        return bool(segments) and all((seg.split() or [""])[0] in _READ_HEADS for seg in segments)

    def _retry(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        """`retry_after_denial`: a retry shares the denied step's source,
        destination or code hash. Matching is role-insensitive on the pending side (a `shred` target
        re-touched by an interpreter one-liner is the same entity whatever role the extractor gave
        it); the grade keeps the role shape of the denied step. A matched retry also
        carries the denied step's echoed consequence tier (`retry_carry_consequence`), except for a
        read-shaped call on the same data, which is scored at `retry_same_source_only` and carries
        nothing."""
        p = self.params
        denied = prepared.denied_steps()
        if not denied:
            return [
                Contribution(signal="suspicion.retry_after_denial", value=0.0, reason="retry.none")
            ]
        pending = prepared.fingerprint
        p_src = pending.hashes(Role.DATA_SOURCE)
        p_dst = pending.hashes(Role.DATA_DESTINATION) | pending.hashes(Role.RECIPIENT)
        p_code = pending.hashes(Role.CODE_SOURCE) | pending.hashes(Role.EXECUTABLE)
        p_all = p_src | p_dst | p_code
        read_shaped = self._read_shaped(prepared)
        by_step = {h.step: h for h in prepared.planir.history}
        best, best_reason, matches = 0.0, "retry.none", []
        carried = 0.0
        step_now = prepared.planir.session.step
        for call in denied:
            hist = self._history_fingerprint(call, prepared)
            echoed_step = by_step.get(call.step) if call.step is not None else None
            echoed = Fingerprint.parse(echoed_step.action_fingerprint if echoed_step else None)

            h_src = _hashes(hist, echoed, Role.DATA_SOURCE)
            h_dst = _hashes(hist, echoed, Role.DATA_DESTINATION, Role.RECIPIENT)
            h_code = _hashes(hist, echoed, Role.CODE_SOURCE, Role.EXECUTABLE)
            src_shared, dst_shared = bool(h_src & p_all), bool(h_dst & p_all)
            code_shared = bool(h_code & p_all)
            if not (src_shared or dst_shared or code_shared):
                continue
            carry = True
            if h_src and h_dst:  # the denied step moved data from a source to a destination
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
                {"step": call.step, "reason": reason, "value": round(value, 4), "carry": carry}
            )
            if value > best:
                best, best_reason = value, reason
        if len(matches) > 1:
            best = min(1.0, best + p.retry_repeat_bonus * (len(matches) - 1))
        carried = round(min(1.0, carried * p.retry_carry_consequence), 4)
        evidence["retry"] = {
            "denied_steps": [c.step for c in denied],
            "matches": matches,
            "carried_consequence": carried,
        }
        out = [
            Contribution(
                signal="suspicion.retry_after_denial", value=round(best, 4), reason=best_reason
            )
        ]
        if carried > 0.0:
            for signal in ("consequence.reach", "consequence.irreversibility"):
                out.append(
                    Contribution(
                        signal=signal, value=carried, reason="retry.denied_consequence_carried"
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
        tail = self._consequence_tiers(prepared)[-3:]
        return len(tail) >= 2 and all(
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

    def run(self, prepared: Prepared) -> Envelope:
        started = time.perf_counter()
        p = self.params
        prior_flags = set(prepared.state.flags)
        evidence: dict = {
            "prior_flags": sorted(f.value for f in prior_flags),
            "token": prepared.state.status.value,
        }
        contributions: list[Contribution] = []
        flags: list[SessionFlag] = []
        try:
            lookalikes: dict[str, str] = {}
            try:
                lookalikes = self._lookalikes(prepared)
            except Exception as e:  # noqa: BLE001 (a lineage failure contributes nothing)
                evidence["lineage_error"] = repr(e)
            contributions += self._untrusted_origin(prepared, prior_flags, evidence, lookalikes)
            contributions += self._request_origin(prepared, evidence)
            contributions += self._retry(prepared, evidence)
            try:
                contributions += self._lineage(prepared, lookalikes, evidence)
            except Exception as e:  # noqa: BLE001 (a lineage failure contributes nothing)
                evidence["lineage_error"] = repr(e)

            if SessionFlag.TAINTED in prior_flags:
                contributions.append(
                    Contribution(
                        signal="suspicion.exposure",
                        value=p.sticky_exposure,
                        reason="exposure.session_tainted",
                    )
                )
            has_destination = any(
                ent.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
                for ent in prepared.entities.pending()
            )
            if SessionFlag.HOLDS_SENSITIVE in prior_flags and has_destination:
                contributions.append(
                    Contribution(
                        signal="consequence.sensitivity",
                        value=p.holds_sensitive_sensitivity,
                        reason="sensitivity.session_holds_sensitive",
                    )
                )
            escalating = SessionFlag.ESCALATING in prior_flags or self._escalating(prepared)
            if escalating:
                flags.append(SessionFlag.ESCALATING)
            evidence["escalating"] = escalating
            contributions += self._escalation(prepared, escalating, evidence)

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
            flags_set=flags,
            evidence=evidence,
        )
