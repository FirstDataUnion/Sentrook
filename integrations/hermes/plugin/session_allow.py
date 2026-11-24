"""What a Session answer on a review lets through later in the same chat.

Hermes remembers a Session answer under the rule key the prompt carried (`_rule_key`), and that key holds every entity
of the call: a job whose steps differ only in an incidental file (each writes its own output) would ask at every step.
So, on the owner's own turn, the answer is also kept in the session's state as an allowance: the tool, the parties the
review was about (the entities its reasons name and the ones the card's description of the call names), the risk it
was answered at and the warnings it carried (every reason code but the scanner's scoring and wording notes). A later
review in the same session is let through without asking when it is a call of the same tool about exactly the same
parties, scores no higher, carries no warning the answered review did not (`warnings`), and the scanner neither
enforced it nor applied a floor. Anything else asks: another party (or one more), a higher risk, a new warning,
another tool, another chat, a block. A review whose reasons and description name no party keeps Hermes's exact key only: an allowance about
nothing would cover every call of that tool. An allowance lasts `MAX_AGE`.

Where the Session answer also sets the review's suggested grant, no allowance is kept: the grant goes to the scanner,
which scores later calls with it, and a later review despite the grant is one with something new in it.

The parties are keyed by an HMAC under the install's salt, so the session file reveals nothing about them.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta
from typing import Any

from .store import read_time

#: Allowances kept per session (the oldest go first).
MAX_PER_SESSION = 50
#: How long an allowance lets later reviews through.
MAX_AGE = timedelta(hours=12)
#: Reason codes that are the scanner's scoring and wording notes, not warnings: the judge's own reasons (`jev.*`,
#: `call.*`), relief and caps, coverage and probe agreement, the trigger, a plain send, a party new to the library as
#: a place to send to or a recipient, an origin that names nobody hostile, and the background of what the session has
#: been reading (content that had instructions or claimed authority, or steered earlier: these change at every step
#: of a job that reads documents, and still raise the score, which must stay no higher). Content that tried to change
#: the task, and a call that uses content that tried to steer the agent, are warnings. Every other code is a warning: a later
#: review carrying one the answered review did not always asks, whatever its score, so a code the scanner adds later
#: asks too.
NOTE_PREFIXES = ("jev.", "call.", "relief.", "cap.", "coverage.", "agreement.", "trigger.")
NOTES = frozenset(
    {
        "send.off_host",
        "retry.none",
        "reputation.unknown_host_as_data_destination",
        "reputation.unknown_channel_as_recipient",
        "reputation.unknown_recipient_as_recipient",
        "reputation.unknown_mcp_server_as_data_destination",
        "reputation.unknown_mcp_server_as_tool_provider",
        "reputation.unknown_plugin_as_data_destination",
        "origin.agent_generated",
        "origin.request_named",
        "origin.owner_config",
        "origin.granted",
        "origin.self_recipient",
        "origin.host_configured_provider",
        "origin.recipient_mail_domain",
        "origin.agent_created_visible",
        "origin.sibling_only",
        "exposure.instructions",
        "exposure.authority",
        "exposure.session_tainted",
    }
)
_PLACEHOLDER = re.compile(r"\{(E\d+)\}")


def parties(resp: dict[str, Any]) -> list[tuple[str, str]]:
    """The entities the response's reasons name and those its tool description names, as (kind, display), sorted
    and once each."""
    ents = resp.get("entities") if isinstance(resp.get("entities"), dict) else {}
    ids: set[str] = set()
    for r in resp.get("reasons") or []:
        subject = r.get("subject") if isinstance(r, dict) else None
        if isinstance(subject, str):
            ids.add(subject)
    desc = resp.get("tool_description") if isinstance(resp.get("tool_description"), dict) else {}
    if isinstance(desc.get("template"), str):
        ids.update(_PLACEHOLDER.findall(desc["template"]))
    out: set[tuple[str, str]] = set()
    for i in ids:
        ent = ents.get(i)
        if isinstance(ent, dict) and isinstance(ent.get("display"), str):
            out.add((str(ent.get("kind") or ""), ent["display"]))
    return sorted(out)


def warnings(resp: dict[str, Any]) -> list[str]:
    """The response's reason codes that are warnings (any but `NOTES` and `NOTE_PREFIXES`), sorted and once each."""
    out = set()
    for r in resp.get("reasons") or []:
        code = r.get("code") if isinstance(r, dict) else None
        if isinstance(code, str) and code not in NOTES and not code.startswith(NOTE_PREFIXES):
            out.add(code)
    return sorted(out)


def key(tool: str, named: list[tuple[str, str]], secret: str) -> str | None:
    """The allowance key of a call of `tool` about `named`; None when it names no party or no tool."""
    if not named or not tool:
        return None
    material = "\n".join([tool, *(f"{k}\t{d}" for k, d in named)])
    return hmac.new(
        ("sentrook session allow v1|" + secret).encode(), material.encode(), hashlib.sha256
    ).hexdigest()[:24]


def risk_of(resp: dict[str, Any]) -> float | None:
    r = resp.get("risk")
    return float(r) if isinstance(r, (int, float)) and not isinstance(r, bool) else None


def covering(
    sess: dict[str, Any], k: str | None, resp: dict[str, Any], now: datetime
) -> dict[str, Any] | None:
    """The allowance in `sess` that lets this review through, or None."""
    risk = risk_of(resp)
    if k is None or risk is None or resp.get("enforced") is not None or resp.get("floors_applied"):
        return None
    new = set(warnings(resp))
    for a in sess.get("session_allows") or []:
        if (
            not isinstance(a, dict)
            or a.get("key") != k
            or not isinstance(a.get("risk"), (int, float))
        ):
            continue
        at = read_time(a.get("at"))
        if at is None or now - at > MAX_AGE:
            continue
        if risk <= float(a["risk"]) and not new - set(a.get("warnings") or []):
            return a
    return None


def add(
    sess: dict[str, Any],
    k: str,
    risk: float,
    seen: list[str],
    request_id: str,
    now: datetime,
) -> None:
    """Keep the allowance an answer gave. Each answer is kept on its own: a later review is covered by one answer's
    risk and warnings, never by a mix of several."""
    kept = [
        a
        for a in sess.get("session_allows") or []
        if isinstance(a, dict) and a.get("request_id") != request_id
    ]
    kept.append(
        {
            "key": k,
            "risk": risk,
            "warnings": sorted(set(seen)),
            "request_id": request_id,
            "at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    sess["session_allows"] = kept[-MAX_PER_SESSION:]
