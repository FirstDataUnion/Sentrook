"""The credential grant hint: the `credential` grant that would let a reviewed key-to-its-service send through.

The grant hints (`hints`) never name a call that took a floor, and a credential sent off the machine takes the
sensitive-data-sent floor. The credential-home check (`prepare.credential_home`) clears that floor for a key read
from the agent's env file and sent only to its own service, but only where the entity library or the owner's
`credential` grant says which service the key belongs to. When the check fails only because that service is
unlisted, the owner is offered one `credential` grant, `NAME@host`, built from the call itself.

Offered only when all of this holds:

- the convergence parameters turn the credential-home relief and grant hints on;
- the check failed with `unlisted_host`, and with any name granted on one host of the call it would hold, for one
  credential name (a call needing two grants gets none);
- the call is at or above the review line, with no `enforced` decision and no floor but the sensitive-data-sent one;
- the turn is the owner's (`hints.owner_turn`), the scan is fully informed (`attended.withheld` finds nothing), the
  session is not tainted, and no fetch carries text from a local read (`prepare.url_carry`);
- the host is not known-bad, a near miss or a look-alike by any probe's account, nor a look-alike of a host the
  owner's own `credential` or `destination` grants name (`api.example.com.evil.net` beside a grant for
  `api.example.com`); not one content the agent read supplied or steered it to, and not one the call or a later run
  takes code from.

Verification: the call is scored again with the grant in place, on a copy of the preparation (the session state the
response carries is the real scan's): the credential-home check runs again, the rule-based probes (AIRA and the
context probe, which read the check) run again, and every other probe's answer, the model's included, is reused.
The hint is offered only when that score is below the review line with no floor, no `enforced` decision and no
independent strong signal (`attended.strong_signals`).
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from ..enums import ProbeStep, ScanStatus, SessionFlag
from ..planir.models import Grant, GrantScope
from ..prepare import Prepared
from ..prepare.credential_home import check, live_credential_grants, parse_credential_pattern
from ..prepare.entities import Entity, EntityKind, Origin, Role
from ..probes.base import Envelope
from ..response.models import GrantHint
from .attended import strong_signals, withheld
from .hints import EXPIRES_IN_DAYS, _from_content, _unhintable, owner_turn, plain_pattern, rank_key
from .merge import collect
from .params import ConvergenceParams
from .retry_cap import unanswered_retry

#: The only floor the grant can clear.
FLOOR = "sensitive_data_sent"
#: Probes that read the credential-home check: run again on the copy.
RESCORED = (ProbeStep.AIRA, ProbeStep.CONTEXT)
_HINT_REF = "hint.credential"
_CODE_ROLES = frozenset({Role.CODE_SOURCE, Role.EXECUTABLE})


def worth_copying(prepared: Prepared, params: ConvergenceParams) -> bool:
    """Before convergence (which adds this scan's judgements to the session state): could this scan get the hint?
    Only then does the scan keep a copy of the preparation to score again."""
    return (
        params.credential_home
        and params.grant_hints_max > 0
        and prepared.credential_home is None
        and prepared.credential_home_check == "unlisted_host"
        and owner_turn(prepared)
        and SessionFlag.TAINTED not in prepared.state.flags
        and not prepared.url_carries
    )


def candidate(prepared: Prepared) -> tuple[str, Entity] | None:
    """The credential name and the host a single `credential` grant would need for the check to hold, or None."""
    if prepared.credential_home is not None or prepared.credential_home_check != "unlisted_host":
        return None
    found: list[tuple[str, Entity]] = []
    for ent in prepared.entities:
        if ent.kind is not EntityKind.HOST:
            continue
        if not (
            ent.has_origin(Origin.PENDING_CALL, Origin.WRITTEN_FILE, Origin.SIBLING)
            or ent.in_resolved_command
        ):
            continue
        home, why = check(prepared, (("", "*", ent.value.lower()),))
        if home is None or why != "ok":
            continue
        if len(home.names) != 1 or not any(h == ent.id for h, _ in home.grants):
            continue
        found.append((home.names[0], ent))
    return found[0] if len(found) == 1 else None


def _imitates_a_granted_host(prepared: Prepared, host: str) -> bool:
    """`host` is not a host the owner's credential or destination grants name, nor under one, but imitates one: it
    spells one inside it (`api.example.com.evil.net`) or is a near miss of it."""
    from ..oracle.near_miss import how_near

    bases = {h.removeprefix("*.") for _, _, h in live_credential_grants(prepared)}
    for g in prepared.planir.grants:
        if g.kind.lower() == "destination" and "@" not in g.pattern and ":" not in g.pattern:
            bases.add(g.pattern.strip().lower().removeprefix("*."))
    for base in bases:
        if not base or host == base or host.endswith("." + base):
            continue
        if base in host or how_near("host", host, base) not in (None, "same"):
            return True
    return False


def eligible(
    prepared: Prepared,
    envelopes: list[Envelope],
    response: Any,
    flags: set[SessionFlag],
    params: ConvergenceParams,
    *,
    exposure_unjudged: bool,
) -> bool:
    """The first scan is one a credential hint may be offered on (everything but the host and the re-score)."""
    if not params.credential_home or params.grant_hints_max <= 0:
        return False
    if response.risk is None or response.risk < params.grant_hints_review_line * 100.0:
        return False
    if response.enforced is not None or any(f.floor != FLOOR for f in response.floors_applied):
        return False
    if not owner_turn(prepared) or SessionFlag.TAINTED in flags or prepared.url_carries:
        return False
    return not withheld(
        envelopes,
        degraded=response.status is ScanStatus.DEGRADED,
        state_lost=prepared.state.fresh,
        exposure_unjudged=exposure_unjudged,
    )


def hint(
    prepared: Prepared,
    envelopes: list[Envelope],
    response: Any,
    params: ConvergenceParams,
    rescore: Callable[[Prepared, list[Envelope]], Any],
    rerun: Callable[[Prepared], dict[ProbeStep, Envelope]],
) -> GrantHint | None:
    """The hint for an eligible scan, or None. `rerun(copy)` runs the probes in `RESCORED` on the copy;
    `rescore(copy, envelopes)` converges them (a `ConvergeResult`)."""
    found = candidate(prepared)
    if found is None:
        return None
    name, host = found
    pattern = f"{name}@{host.value.lower()}"
    if parse_credential_pattern(pattern) is None or not plain_pattern(pattern):
        return None
    if host.id in _unhintable(prepared, collect(envelopes), envelopes) or _from_content(host):
        return None
    if (host.roles | host.future_roles) & _CODE_ROLES:
        return None
    if _imitates_a_granted_host(prepared, host.value.lower()):
        return None

    hyp = copy.deepcopy(prepared)
    hyp.planir.grants.append(
        Grant(grant_ref=_HINT_REF, kind="credential", pattern=pattern, scope=GrantScope.PERSISTENT)
    )
    hyp.credential_home, hyp.credential_home_check = check(hyp)
    if hyp.credential_home is None:
        return None
    again = rerun(hyp)
    envs = [again.get(env.step, env) for env in envelopes]
    result = rescore(hyp, envs)
    r = result.response
    if r.risk is None or r.risk >= params.grant_hints_review_line * 100.0:
        return None
    if r.floors_applied or r.enforced is not None:
        return None
    claims = collect(envs)
    kept = [c for cs in result.merged.claims.values() for c in cs]
    if strong_signals(
        hyp,
        claims,
        kept,
        [(x.subject, x.reason) for x in result.relief],
        [],
        params,
        unanswered_retry=unanswered_retry(envs),
    ):
        return None
    after = {x.code for x in r.reasons}
    return GrantHint(
        kind="credential",
        pattern=pattern,
        expires_in_days=EXPIRES_IN_DAYS,
        subject=host.id,
        relieves=list(dict.fromkeys(x.code for x in response.reasons if x.code not in after)),
        risk=r.risk,
    )


def add(response: Any, new: GrantHint, params: ConvergenceParams, prepared: Prepared) -> None:
    """Put the hint among the response's others, ranked as they are, keeping at most `grant_hints_max`."""

    def entity_kind(h: GrantHint) -> EntityKind | None:
        ent = prepared.entities.by_id(h.subject) if h.subject else None
        return ent.kind if ent is not None else None

    ranked = sorted([*response.grant_hints, new], key=lambda h: rank_key(h, entity_kind(h)))
    response.grant_hints = ranked[: params.grant_hints_max]


__all__ = ["FLOOR", "RESCORED", "add", "candidate", "eligible", "hint", "worth_copying"]
