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
sibling or written file whose sends are not all written out: a shell command must be local commands and `curl` with
a short list of options and every URL written out (no `git push`, `rsync`, `scp`, `docker push`, `wget`, interpreter,
background job, process or command substitution, proxy, redirect following or address from a variable or config file),
and Python must aim every request at a URL written in the code. Nor is it covered when the call, a sibling, a written
file or any earlier step of the session sets a proxy (`https_proxy=`, `ProxyHandler`, `proxies=`) or names curl's
config file: HTTP clients read both, so a send written out to a granted host may still go through somewhere else.

**Gate.** No floor fired; concealment is below `concealment_below` and the new content's exposure below
`exposure_below`; the session is not tainted (before or in this scan). A session that holds sensitive data passes
only when everything it judged sensitive is an env file the credential-home check reads this call's key from, with
no sensitive read left unbound: the key going to its own home is the send the owner granted.

Grants sanction where data goes; this never clears session flags and never lowers a floor.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..planir.models import Decision, ToolKind
from ..prepare import Prepared
from ..prepare.entities import (
    EntityKind,
    Origin,
    Role,
    call_code_reach,
    is_code_call,
    shell_segments,
)
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


def covering_grants(prepared: Prepared, extra: dict[str, str] | None = None) -> list[str] | None:
    """The grant refs that cover every place the call sends to, or None when the call is not a fully granted send.
    `extra`: entity id -> grant ref for a destination grant the owner has not set yet (a hint's re-score)."""
    sends = [
        e
        for e in prepared.entities
        if e.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE)
        and (e.roles | e.future_roles) & _SEND_ROLES
        and e.kind in _SEND_KINDS
    ]
    if not sends or not sends_off_host(prepared.pending, prepared.entities.pending()):
        return None
    if not _routes_known(prepared) or _proxy_configured(prepared):
        return None
    kinds = {g.grant_ref: g.kind for g in prepared.planir.grants}
    by_entity: dict[str, list[str]] = {}
    for ref, eids in prepared.grant_hits.items():
        if kinds.get(ref) == "destination":
            for eid in eids:
                by_entity.setdefault(eid, []).append(ref)
    for eid, ref in (extra or {}).items():
        by_entity.setdefault(eid, []).append(ref)
    refs: list[str] = []
    for ent in sends:
        found = by_entity.get(ent.id)
        if not found:
            return None
        refs.extend(r for r in found if r not in refs)
    return refs


#: Shell commands that act on local data only; with `curl` (written URLs, a short list of options) the only heads a
#: covered command may run. Interpreters, `sed` and `awk` (which can run commands or open sockets), `xargs`, `find`,
#: `wget` (it follows redirects by default) and every other tool are left out: their destinations need not be written
#: as a host.
_LOCAL_HEADS = frozenset(
    "cat echo printf jq grep egrep fgrep head tail wc sort uniq cut tr date ls pwd cd test [ true false mkdir touch "
    "tee cp mv base64 sha256sum md5sum basename dirname realpath sleep".split()
)
#: curl options that take no value and send nowhere new; short ones may be clustered (`-sS`).
_CURL_FLAGS = frozenset(
    {
        "--silent",
        "--show-error",
        "--fail",
        "--fail-with-body",
        "--verbose",
        "--compressed",
        "--include",
    }
)
_CURL_FLAG_LETTERS = frozenset("sSfvi")
#: curl options whose value is data, a header, a method, a local file or a limit, never an address.
_CURL_VALUE_OPTIONS = frozenset(
    {
        "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json",
        "-H", "--header", "-X", "--request", "-T", "--upload-file", "-F", "--form",
        "-o", "--output", "-u", "--user", "-A", "--user-agent", "-m", "--max-time",
        "--connect-timeout", "--retry", "-w", "--write-out", "-b", "--cookie", "-c", "--cookie-jar",
    }
)  # fmt: skip
_CURL_SHORT_VALUE = frozenset(o[1] for o in _CURL_VALUE_OPTIONS if len(o) == 2)
_LITERAL_URL = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:[/?#][^\s$`{}]*)?\Z", re.IGNORECASE)
#: Background jobs, process substitution, command substitution and socket paths: what a segment split does not see.
_SHELL_HIDDEN = re.compile(r"(?<![&>])&(?![&>])|[<>]\(|\$\(|`|/dev/(?:tcp|udp)/|/inet/")


def _curl_known(args: list[str]) -> bool:
    """Every option is on the short list and every other argument is a URL written out in full."""
    urls = 0
    i = 0
    while i < len(args):
        a = args[i]
        if a in _CURL_FLAGS:
            pass
        elif a.startswith("--"):
            name = a.split("=", 1)[0]
            if name not in _CURL_VALUE_OPTIONS:
                return False
            if "=" not in a:
                i += 1
        elif a.startswith("-") and len(a) > 1:
            letters = a[1:]
            if set(letters) <= _CURL_FLAG_LETTERS:
                pass
            elif letters[0] in _CURL_SHORT_VALUE:
                if len(letters) == 1:
                    i += 1  # the value is the next token; attached (`-HX: y`) otherwise
            else:
                return False
        elif _LITERAL_URL.match(a):
            urls += 1
        else:
            return False  # curl reads any other argument as a URL, even without a scheme
        i += 1
    return urls > 0


def _shell_routes_known(command: str) -> bool:
    """Every simple command is a local one, or a `curl` whose options are on the short list and whose URLs are
    written out: nothing run in the background or through process or command substitution, no socket path."""
    if _SHELL_HIDDEN.search(command):
        return False
    segments = shell_segments(command)
    if not segments:
        return False
    for tokens in segments:
        head = posixpath.basename(tokens[0]).lower()
        if head in _LOCAL_HEADS:
            continue
        if head != "curl" or not _curl_known(tokens[1:]):
            return False
    return True


#: A proxy variable set, or curl's config file named: HTTP clients (curl, Python's urllib and requests) read both,
#: so a send written out to a granted host may still go through somewhere else.
_PROXY_SETTING = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:https?|all|ftp|socks|no)_proxy\s*=|curlrc|CURL_HOME|ProxyHandler|proxies\s*="
)


def _proxy_configured(prepared: Prepared) -> bool:
    """The call, its siblings, a file it writes or any earlier step of the session sets a proxy variable, a proxy in
    code, or names curl's config file."""
    from ..probes.aira import written_file_call

    texts = [
        json.dumps(c.raw, default=str)
        for c in (prepared.pending, *prepared.siblings, *prepared.resolved)
    ]
    written = written_file_call(prepared)
    if written is not None:
        texts.append(written.command or "")
    texts += [json.dumps(h.arguments, default=str) for h in prepared.planir.history]
    return any(_PROXY_SETTING.search(t) for t in texts)


def _routes_known(prepared: Prepared) -> bool:
    """Every place the call, its siblings and a file it writes can send to is written out, so the entities show
    them all: a tool's own destination arguments, a shell command of local commands and literal `curl` / `wget`
    URLs (`_shell_routes_known`), or Python whose every request is aimed at a URL written in the code."""
    from ..probes.aira import written_file_call

    calls = [prepared.pending, *prepared.siblings, *prepared.resolved]
    written = written_file_call(prepared)
    if written is not None:
        calls.append(written)
    for call in calls:
        if call.tool_kind is not ToolKind.EXEC:
            continue
        if is_code_call(call):
            reach = call_code_reach(call, local=True)
            if reach is None or (reach.network and reach.targets is None):
                return False
        elif not _shell_routes_known(call.command or ""):
            return False
    return True


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
    *,
    extra: dict[str, str] | None = None,
) -> GrantedSend | None:
    """`claims` and `merged`: after the other relief. None when the call is not a fully granted send, the gate does
    not hold, or no part changes a claim. `extra`: as for `covering_grants`."""
    refs = covering_grants(prepared, extra)
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
