"""Owner pass: whether the owner may let a held call through, and for how long.

When a plugin holds a call nobody could answer live (a scheduled job, a heartbeat), the owner answers later. Which
answers are safe is the scanner's judgement, so every response carries `owner_pass`:

- `null`: no pass. The response has an `enforced` decision, or the call carries an independent strong signal
  (`attended.strong_signals`, whoever attends): any floor (acting on injected content, sensitive data sent, a
  look-alike code source, …), content the agent read choosing a party or instructing it, a known-bad entity, a
  credential or sensitive file leaving to a destination it does not belong to, a look-alike, a retry of a denied
  action.
- `once`: this call only, never a standing pass. The session read content that tried to instruct the agent
  (`tainted`), the scan is not fully informed (`attended.withheld`), the turn is not the owner's
  (`hints.owner_turn`: someone else chose what the call acts on), a fetch's address carries text the session read
  from a local file, the approval fingerprint names no party or only the tool's provider (a standing pass on it
  would cover any call of that kind), a call that sends off the host (or any message send) names no destination or
  recipient in it (a standing pass would cover sending the same data anywhere), or the call runs code or names a code source or an
  executable (`code.*` reasons, or an entity of the call in a code role now or in a later run the call sets up).
- `always`: anything else; a standing pass for the same action may be offered.

The rules are the ones the grant hints already apply (`hints`). The field is computed after everything else and
changes no score, verdict, hint or mark.
"""

from __future__ import annotations

from typing import Literal

from ..enums import Enforce, SessionFlag
from ..planir.models import ToolKind
from ..prepare import Prepared
from ..prepare.entities import Origin, Role
from ..prepare.fingerprint import ROLE_TAGS, Fingerprint
from ..prepare.grants import sends_off_host
from .attended import strong_signals
from .hints import owner_turn
from .merge import Claim
from .params import ConvergenceParams

OwnerPass = Literal["always", "once"]

#: Entity roles that run code: a grant or pass to send somewhere never sanctions running code from it.
CODE_ROLES = frozenset({Role.CODE_SOURCE, Role.EXECUTABLE})
#: Reasons for a call that runs code (a fetch or decode piped to a shell, an install, running a written file, …).
CODE_REASON_PREFIX = "code."
#: The fingerprint component that names only the tool's own provider.
PROVIDER_TAG = ROLE_TAGS[Role.TOOL_PROVIDER]
#: The fingerprint components that name where a send goes.
DESTINATION_TAGS = frozenset({ROLE_TAGS[Role.DATA_DESTINATION], ROLE_TAGS[Role.RECIPIENT]})


def _components(approval_fingerprint: str | None) -> set[str]:
    """The fingerprint's component tags that name at least one entity."""
    fp = Fingerprint.parse(approval_fingerprint)
    if fp is None:
        return set()
    return {tag for tag, hashes in fp.components.items() if hashes}


def names_a_party(approval_fingerprint: str | None) -> bool:
    """The approval fingerprint names some entity other than the tool's provider."""
    return bool(_components(approval_fingerprint) - {PROVIDER_TAG})


def sends(prepared: Prepared) -> bool:
    """The call sends something off this machine, or is a message send (whose target may not be written)."""
    return prepared.pending.tool_kind is ToolKind.MESSAGE_SEND or sends_off_host(
        prepared.pending, prepared.entities.pending()
    )


def runs_code(prepared: Prepared, claims: list[Claim]) -> bool:
    """The call runs code, or names a code source or an executable, now or in a later run it sets up."""
    if any((c.reason or "").startswith(CODE_REASON_PREFIX) and c.value > 0 for c in claims):
        return True
    return any(
        (ent.roles | ent.future_roles) & CODE_ROLES
        for ent in prepared.entities
        if ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING) and not ent.sibling_only
    )


def owner_pass(
    prepared: Prepared,
    claims: list[Claim],
    kept: list[Claim],
    relief_subjects: list[tuple[str | None, str]],
    floors: list[str],
    params: ConvergenceParams,
    *,
    enforced: Enforce | None,
    held_back: list[str],
    flags: set[SessionFlag],
    unanswered_retry: bool,
) -> OwnerPass | None:
    """`claims`: every claim before relief; `kept`: the claims relief left; `relief_subjects`: (subject, reason) per
    relief applied; `floors`: the floors applied; `held_back`: `attended.withheld` for this scan, whoever attends;
    `flags`: the session's flags with this scan's own."""
    if enforced is not None:
        return None
    if strong_signals(
        prepared, claims, kept, relief_subjects, floors, params, unanswered_retry=unanswered_retry
    ):
        return None
    parties = _components(prepared.approval_fingerprint)
    if (
        held_back
        or SessionFlag.TAINTED in flags
        or not owner_turn(prepared)
        or prepared.url_carries
        or not parties - {PROVIDER_TAG}
        or (sends(prepared) and not parties & DESTINATION_TAGS)
        or runs_code(prepared, claims)
    ):
        return "once"
    return "always"
