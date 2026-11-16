"""The attended-owner ceiling: in a chat the owner is attending, a call is never blocked on its score alone.

When the owner is in the conversation and asked for the work, a review reaches them and they can approve or deny
it; a block leaves them no way to approve a change they asked for. So in an attended owner session the response
carries a verdict ceiling of `review` unless the call carries an independent strong signal. The risk stays as
scored: the plugin decides from risk and its own lines, lowers that to the ceiling, then raises it to `enforced`.
The strong signals:

- a floor applied (guardrail tampering, a known-bad entity, untrusted code, sensitive data sent, injected content
  acted on, a look-alike code source), which also covers every `enforced` decision;
- a key argument that came only from content the agent read (`origin.only_in_untrusted` and the other untrusted
  origins), on an entity in a role that acts: a destination, recipient, code source, executable or tool provider
  (`untrusted_origin_min`), or a code source named in content that tried to steer the agent;
- a known-bad entity in the call;
- a credential or sensitive file leaving to a destination it does not belong to: a call that sends off the host
  and carries a sensitive source (sensitivity at least `sent_sensitivity_min`) or a file the agent wrote a secret
  into, where some destination is covered by no grant, owner request, owner configuration or library entry (or is
  not written as an entity at all); and a push that publishes a secret or a credential file;
- an unknown host or repository nobody named (not the owner's request, a grant or the owner's own configuration)
  that a later run, set up by self-modification content the call writes (a cron line, a hook, a skill, a job
  prompt), sends to or runs code from (`reputation.unknown_in_written_selfmod`).

Three further strong signals are parameters, off unless a parameter set switches them on: a look-alike of a
vouched-for entry or of a host, package or person the owner named (`lookalike`); a retry of an action the owner
denied (`retry_min`); and this request's new untrusted content judged to instruct the agent while the call is judged
not to follow from the owner's request (`fresh_injection`, model judgements only).

Attended is derived from the PlanIR, not from a plugin flag: the turn is a message (not scheduled, heartbeat,
hook, sub-agent, system or unknown), the sender is the owner outside a group chat or open host (sender basis not
`group_chat` or `host_open_access`) and the agent is the main agent. Unattended runs, other senders, group chats and
unknown triggers are unchanged. No ceiling is set on a scan that is not fully
informed: a probe errored, timed out or fell back, the context or rule-based probe did not answer, the entity oracle
was unavailable, new content went unjudged, the session state was lost, or the scan is otherwise degraded.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..enums import ProbeStatus, ProbeStep
from ..planir.models import AgentRole, Channel, PlanIR, SenderBasis, SenderRelation, TriggerKind
from ..prepare import Prepared
from ..prepare.entities import EntityKind, Role
from ..prepare.grants import sends_off_host
from ..probes.base import Envelope
from .merge import Claim
from .params import ConvergenceParams

#: Origins that mean the value came from content the agent read rather than from the owner.
UNTRUSTED_ORIGIN_REASONS = frozenset(
    {
        "origin.only_in_untrusted",
        "origin.written_content_untrusted",
        "origin.agent_created_dirty_lineage",
        "origin.lookalike_of_named_host",
        "origin.lookalike_of_named_package",
        "origin.sibling_value_untrusted",
    }
)
#: Reasons that are strong signals by themselves, whatever their value.
STRONG_REASONS = frozenset(
    {
        "code.steered_source",
        "exposure.session_injected_content",
        "artefact.push_with_secret",
        "artefact.credential_file_pushed",
    }
)
#: An unknown host nobody named in self-modification content the call writes, which a later run contacts.
WRITTEN_SELFMOD_REASONS = frozenset({"reputation.unknown_in_written_selfmod"})
KNOWN_BAD_PREFIX = "reputation.known_bad_"
#: Look-alikes of an entry the library vouches for or of a host, package or person the owner named
#: (`attended_owner_cap.lookalike`), including a look-alike installer host or tool provider.
LOOKALIKE_PREFIXES = ("reputation.near_miss_", "lineage.lookalike_of_named_", "code.lookalike_")
#: Sinks that send data off the host. The `exfil.*` sinks carry a sensitive source; `send.off_host` does not.
EXFIL_SINKS = frozenset(
    {
        "exfil.exec_egress",
        "exfil.message_send",
        "exfil.web_post",
        "exfil.web_query",
        "exfil.raw_socket",
    }
)
SEND_SINKS = EXFIL_SINKS | {"send.off_host"}
#: Sensitive sources a send can carry. The session-wide sensitive flag counts only when it is tied to a file
#: or table (the claim has a subject): the bare flag says the session read something sensitive, not that this
#: call sends it.
SENT_SOURCE_REASONS = frozenset({"exfil.placeholder_in_argv", "exfil.attachment"})
SENT_SOURCE_PREFIX = "path."
SESSION_SENT_SOURCE = "exfil.session_holds_sensitive"
#: An agent-written file carrying a secret that the call sends.
SECRET_CARRIED = "lineage.secret_carried_to_send"
#: Relief that says a destination belongs: a grant, the owner's request or configuration, or the library.
DESTINATION_RELIEF = frozenset(
    {
        "relief.destination_grant",
        "relief.request_named_destination",
        "relief.owner_config_destination",
        "relief.known_good_destination",
        "relief.repo_grant",
    }
)


#: Sender bases that put the owner's message in a room others can write to: a group, channel or thread, or a
#: host open to anyone. The owner is there, but so is everyone else, and a review there is everyone's.
SHARED_BASIS = frozenset({SenderBasis.GROUP_CHAT, SenderBasis.HOST_OPEN_ACCESS})
#: The probes the strong signals come from: without their answer nobody looked for one.
SIGNAL_PROBES = (ProbeStep.CONTEXT, ProbeStep.AIRA)
#: The plugins' default block line, on the 0-1 scale: above it the ceiling is what decides the outcome there, so
#: its reason leads.
DEFAULT_BLOCK_LINE = 0.8


def attended_owner(planir: PlanIR) -> bool:
    """The owner is in the conversation: a message turn from the owner, on the main agent, not in a group chat."""
    return (
        planir.trigger.kind is TriggerKind.MESSAGE
        and planir.trigger.sender.relation is SenderRelation.OWNER
        and not SHARED_BASIS & set(planir.trigger.sender.basis)
        # an unrecognised channel: on OpenClaw its own system-agent chat, where host-marker turns arrive too
        and planir.trigger.channel is not Channel.OTHER
        and planir.session.agent_role is AgentRole.MAIN
        # a self-edit block says the host's own background process made the call, whatever the trigger says
        and planir.self_edit is None
    )


def withheld(
    envelopes: Iterable[Envelope],
    *,
    degraded: bool,
    state_lost: bool,
    exposure_unjudged: bool,
) -> list[str]:
    """Why no ceiling may be set even without a strong signal: the evidence a strong signal comes from is missing.

    - `probe_failed`: a probe errored or timed out, a lookup fell back, or the context or rule-based probe did not
      answer;
    - `oracle_unavailable`: the entity oracle did not run or had no library (the null oracle), so no known-bad
      or look-alike entity could be found;
    - `exposure_unjudged`: the request brings new untrusted content and the exposure judge did not read it;
    - `state_lost`: the session state token was missing, invalid or stale, so earlier denials and flags are gone;
    - `degraded`: anything else that makes the scan degraded (content dropped or truncated, an argument dropped).
    """
    envelopes = list(envelopes)
    out: list[str] = []
    answered = {env.step for env in envelopes if env.status is ProbeStatus.OK}
    if (
        any(env.status in (ProbeStatus.ERROR, ProbeStatus.TIMEOUT) for env in envelopes)
        or any(env.evidence.get("fallback") for env in envelopes)
        or not all(step in answered for step in SIGNAL_PROBES)
    ):
        out.append("probe_failed")
    oracle = [env for env in envelopes if env.step is ProbeStep.ENTITY_ORACLE]
    if any(
        env.status is not ProbeStatus.OK or env.evidence.get("available") is False for env in oracle
    ) or (not oracle and ProbeStep.ENTITY_ORACLE in {env.step for env in envelopes}):
        out.append("oracle_unavailable")
    if exposure_unjudged:
        out.append("exposure_unjudged")
    if state_lost:
        out.append("state_lost")
    if degraded and not out:
        out.append("degraded")
    return out


@dataclass
class CapCheck:
    attended: bool
    strong: list[str] = field(default_factory=list)

    @property
    def applies(self) -> bool:
        """Attended and no strong signal; `withheld` may still keep the ceiling off."""
        return self.attended and not self.strong


def _send_destinations(claims: list[Claim], prepared: Prepared) -> list[str | None] | None:
    """The call's off-host destinations (entity ids; None for a send whose destination is not written as an
    entity), or None when the call sends nothing off the host."""
    from ..oracle.client import is_local_host

    sinks = [c for c in claims if c.signal == "consequence.reach" and c.reason in SEND_SINKS]
    pending = prepared.entities.pending()
    named = [
        e
        for e in pending
        if e.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
        and e.kind in (EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL)
        and not (e.kind is EntityKind.HOST and is_local_host(e.value))
    ]
    if not sinks and not sends_off_host(prepared.pending, pending):
        return None
    out: list[str | None] = [c.subject for c in sinks]
    out.extend(e.id for e in named)
    return out or [None]


def _sent_unbelonging(
    claims: list[Claim], relieved: set[str], prepared: Prepared, min_sensitivity: float
) -> bool:
    sources = [
        c
        for c in claims
        if c.signal == "consequence.sensitivity"
        and c.value >= min_sensitivity
        and (
            c.reason in SENT_SOURCE_REASONS
            or (c.reason or "").startswith(SENT_SOURCE_PREFIX)
            or (c.reason == SESSION_SENT_SOURCE and c.subject is not None)
        )
    ]
    secret_carried = any(c.reason == SECRET_CARRIED and c.value > 0 for c in claims)
    if not sources and not secret_carried:
        return False
    destinations = _send_destinations(claims, prepared)
    if destinations is None:
        return False
    for dest in destinations:
        if dest is None:
            return True  # a send with no destination written as an entity: nothing says it belongs
        if dest in relieved:
            continue
        ent = prepared.entities.by_id(dest)
        if ent is not None and ent.self_recipient:
            continue
        return True
    return False


def check(
    prepared: Prepared,
    claims: Iterable[Claim],
    kept: Iterable[Claim],
    relief_subjects: Iterable[tuple[str | None, str]],
    floors: list[str],
    params: ConvergenceParams,
) -> CapCheck:
    """`claims`: every claim before relief; `kept`: the claims relief left; `relief_subjects`: (subject, reason)
    per relief applied; `floors`: the floors applied. Returns whether the call is in an attended owner session
    and which strong signals it carries (empty: the cap applies)."""
    out = CapCheck(attended=attended_owner(prepared.planir))
    if not out.attended:
        return out
    claims, kept = list(claims), list(kept)
    strong: list[str] = []
    if floors:
        strong.extend(f"floor.{f}" for f in floors)
    if any(
        c.signal == "suspicion.untrusted_origin"
        and c.reason in UNTRUSTED_ORIGIN_REASONS
        and c.value >= params.attended_owner_untrusted_origin_min
        for c in kept
    ):
        strong.append("untrusted_origin")
    if any((c.reason or "") in STRONG_REASONS for c in kept):
        strong.append("untrusted_content")
    if any((c.reason or "").startswith(KNOWN_BAD_PREFIX) for c in claims):
        strong.append("known_bad")
    if any((c.reason or "") in WRITTEN_SELFMOD_REASONS for c in kept):
        strong.append("written_selfmod_host")
    relieved = {
        s for s, reason in relief_subjects if s is not None and reason in DESTINATION_RELIEF
    }
    if _sent_unbelonging(kept, relieved, prepared, params.attended_owner_sent_sensitivity_min):
        strong.append("sensitive_sent")
    if params.attended_owner_lookalike and any(
        (c.reason or "").startswith(LOOKALIKE_PREFIXES) for c in claims
    ):
        strong.append("lookalike")
    if params.attended_owner_retry_min is not None and any(
        c.signal == "suspicion.retry_after_denial" and c.value >= params.attended_owner_retry_min
        for c in kept
    ):
        strong.append("retry_after_denial")
    if params.attended_owner_injection_exposure_min is not None:
        exposure = max((c.value for c in kept if c.signal == "suspicion.exposure"), default=0.0)
        misalignment = max(
            (c.value for c in kept if c.signal == "suspicion.misalignment"), default=0.0
        )
        if (
            exposure >= params.attended_owner_injection_exposure_min
            and misalignment >= params.attended_owner_injection_misalignment_min
        ):
            strong.append("fresh_injection")
    out.strong = list(dict.fromkeys(strong))
    return out
