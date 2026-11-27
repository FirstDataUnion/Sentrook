"""Granted-send relief: a send whose every destination the owner granted (parameter `granted_send`, off by default, on
in `conv-v11`).

A matched destination grant removes its subject's distrust and untrusted origin (`relief`). In the owner's own chat
those are often 0 already, so the grant changed nothing the owner could see: the call stayed in review on the call
judge's reading of the request, on a retry's carried consequence, and on the reach of any off-host send. When the
owner granted every place the call sends to, this relief also:

- holds the call judge's misalignment to `cap`, when it is below `max_misalignment` (a send the judge clearly reads
  as off-request keeps its full value: the grant covers where the data goes, never what is sent);
- drops the consequence a retry carried from an earlier stopped call, unless one of the matched earlier steps was
  denied by the owner (a review nobody answered, or the scanner's own block, is not the owner's refusal);
- holds the call's reach to `reach` and the call judge's sensitivity to `sensitivity` (the rule-based sensitivity of
  a credential stays, and so does every floor), again only below `max_misalignment`: the place is the owner's own.

**Coverage.** The call sends off the host and names at least one host, recipient or channel in a sending role; every
such entity (in the call, a sibling, a file the call writes, or a later run's roles) is covered by a matched
`destination` grant (a `credential` grant alone ties a key to a host, not what else is sent there). Not covered: a call,
sibling or written file that sends by a route whose destination need not be written as a host (`git push origin`,
`rsync`, `aws s3 cp`, a socket opened in code), or builds an address at run time.

**Gate.** No floor fired; concealment is below `concealment_below` and the new content's exposure below
`exposure_below`; the session is not tainted (before or in this scan). A session that holds sensitive data passes
only when everything it judged sensitive is an env file the credential-home check reads this call's key from, with
no sensitive read left unbound: the key going to its own home is the send the owner granted.

Grants sanction where data goes; this never clears session flags and never lowers a floor.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..planir.models import Decision
from ..prepare import Prepared
from ..prepare.entities import EntityKind, Origin, Role
from ..prepare.grants import sends_off_host
from ..probes.base import Envelope
from .merge import Claim, Merged
from .params import GrantedSendParams
from .relief import Relief, granted_send_relief
from .retry_cap import CARRIED_REASON

_SEND_ROLES = frozenset({Role.DATA_DESTINATION, Role.RECIPIENT})
_SEND_KINDS = frozenset({EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL})

CAP_REASON = "relief.granted_send_cap"
RETRY_REASON = "relief.granted_send_retry"
CONSEQUENCE_REASON = "relief.granted_send_consequence"
REASONS = (CAP_REASON, RETRY_REASON, CONSEQUENCE_REASON)


@dataclass
class GrantedSend:
    """The claims with the relief applied, and one `Relief` per part that changed a claim."""

    claims: list[Claim]
    relief: list[Relief]


def covering_grants(prepared: Prepared) -> list[str] | None:
    """The grant refs that cover every place the call sends to, or None when the call is not a fully granted send."""
    sends = [
        e
        for e in prepared.entities
        if e.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE)
        and (e.roles | e.future_roles) & _SEND_ROLES
        and e.kind in _SEND_KINDS
    ]
    if not sends or not sends_off_host(prepared.pending, prepared.entities.pending()):
        return None
    if _unwritten_route(prepared):
        return None
    kinds = {g.grant_ref: g.kind for g in prepared.planir.grants}
    by_entity: dict[str, list[str]] = {}
    for ref, eids in prepared.grant_hits.items():
        if kinds.get(ref) == "destination":
            for eid in eids:
                by_entity.setdefault(eid, []).append(ref)
    refs: list[str] = []
    for ent in sends:
        found = by_entity.get(ent.id)
        if not found:
            return None
        refs.extend(r for r in found if r not in refs)
    return refs


def _unwritten_route(prepared: Prepared) -> bool:
    """The call, a sibling or a file the call writes sends by a route whose destination need not be written as a host,
    or builds an address at run time: its entities may not show every place it reaches."""
    from ..prepare.credential_home import _BUILT_ADDRESS_RE, _code_sends_by_unwritten_route
    from ..prepare.grants import sends_by_unwritten_route
    from ..probes.aira import written_file_call

    calls = [prepared.pending, *prepared.resolved]
    written = written_file_call(prepared)
    if written is not None:
        calls.append(written)
    for call in calls:
        text = call.command or ""
        if text and (
            sends_by_unwritten_route(text)
            or _code_sends_by_unwritten_route(text)
            or _BUILT_ADDRESS_RE.search(text)
        ):
            return True
    return False


def _flags(prepared: Prepared, envelopes: Iterable[Envelope]) -> set[SessionFlag]:
    flags = set(prepared.state.flags)
    for env in envelopes:
        if env.status is ProbeStatus.OK:
            flags.update(env.flags_set)
    return flags


def _only_the_key_held(prepared: Prepared, envelopes: Iterable[Envelope]) -> bool:
    """Everything the session judged sensitive (before or in this scan) is an env file the credential-home check
    reads this call's key from, and no sensitive read was left unbound."""
    home = prepared.credential_home
    if home is None or not home.env_files or prepared.state.sensitive_unbound:
        return False
    env_files = set(home.env_files)
    homes = {e.hash for e in prepared.entities if e.id in env_files}
    held = set(prepared.state.sensitive)
    for env in envelopes:
        if env.status is not ProbeStatus.OK:
            continue
        for mark in env.marks:
            if mark.judgement != "sensitive":
                continue
            ent = prepared.entities.by_id(mark.subject) if mark.subject else None
            if ent is None:
                return False
            held.add(ent.hash)
    return bool(homes) and bool(held) and held <= homes


def _gate(
    prepared: Prepared, merged: Merged, envelopes: list[Envelope], p: GrantedSendParams
) -> bool:
    if any(env.floors for env in envelopes if env.status is ProbeStatus.OK):
        return False
    if merged.value_or("suspicion.concealment", 0.0) >= p.concealment_below:
        return False
    if merged.value_or("suspicion.exposure", 0.0) >= p.exposure_below:
        return False
    flags = _flags(prepared, envelopes)
    if SessionFlag.TAINTED in flags:
        return False
    return SessionFlag.HOLDS_SENSITIVE not in flags or _only_the_key_held(prepared, envelopes)


def _owner_denied(prepared: Prepared, envelopes: Iterable[Envelope]) -> bool:
    """One of the earlier steps this call retries was denied by the owner."""
    steps: set[object] = set()
    for env in envelopes:
        if env.step is not ProbeStep.CONTEXT or env.status is not ProbeStatus.OK:
            continue
        retry = env.evidence.get("retry")
        if isinstance(retry, dict):
            steps |= {m.get("step") for m in retry.get("matches") or [] if isinstance(m, dict)}
    return any(
        h.step in steps and h.decision is Decision.DENIED_BY_USER for h in prepared.planir.history
    )


def granted_send(
    prepared: Prepared,
    claims: list[Claim],
    merged: Merged,
    envelopes: list[Envelope],
    p: GrantedSendParams,
) -> GrantedSend | None:
    """`claims` and `merged`: after the other relief. None when the call is not a fully granted send, the gate does
    not hold, or no part changes a claim."""
    refs = covering_grants(prepared)
    if refs is None or not _gate(prepared, merged, envelopes, p):
        return None
    ref = refs[0]
    mis = merged.value_or("suspicion.misalignment", 0.0)
    out = list(claims)
    relief: list[Relief] = []

    def held(signal: str, limit: float, step: str | None = None) -> bool:
        nonlocal out
        changed = False
        new: list[Claim] = []
        for c in out:
            if c.signal == signal and c.value > limit and (step is None or c.step == step):
                c = Claim(c.signal, limit, c.step, c.subject, c.reason)
                changed = True
            new.append(c)
        out = new
        return changed

    if mis < p.max_misalignment and held("suspicion.misalignment", p.cap):
        relief.append(granted_send_relief(ref, "misalignment", CAP_REASON))

    if not _owner_denied(prepared, envelopes):
        kept = [c for c in out if c.reason != CARRIED_REASON]
        if len(kept) != len(out):
            out = kept
            relief.append(granted_send_relief(ref, "retry_carry", RETRY_REASON))

    if mis < p.max_misalignment:
        reach = held("consequence.reach", p.reach)
        sens = held("consequence.sensitivity", p.sensitivity, ProbeStep.JEV_CALL.value)
        if reach or sens:
            effect = "+".join(x for x, on in (("reach", reach), ("sensitivity", sens)) if on)
            relief.append(granted_send_relief(ref, effect, CONSEQUENCE_REASON))

    return GrantedSend(out, relief) if relief else None


#: The parts of the score, in plain words, for the owner's view of what grants did not change.
PART_TEXT: dict[str, str] = {
    "suspicion.misalignment": "the request does not clearly ask for this call",
    "suspicion.overreach": "the call does more than the request asks",
    "suspicion.concealment": "the call hides part of what it does",
    "suspicion.distrust": "a party Sentrook does not know",
    "suspicion.untrusted_origin": "a place only content the agent read named",
    "suspicion.exposure": "content the agent read gives it instructions",
    "suspicion.session_exposure": "content the agent read earlier gave it instructions",
    "suspicion.request_origin": "the request did not come from the owner",
    "suspicion.retry_after_denial": "it repeats a call that was stopped",
    "consequence.reach": "it sends data off this machine",
    "consequence.irreversibility": "it cannot be undone",
    "consequence.sensitivity": "the data is sensitive",
    "consequence.self_modification": "it changes the agent's own setup",
}
