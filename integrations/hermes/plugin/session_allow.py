"""What a Session answer on a review lets through later in the same chat.

Hermes remembers a Session answer under the rule key the prompt carried (`_rule_key`), and that key holds every entity
of the call: a job whose steps differ only in an incidental file (each writes its own output) would ask at every step.
So, on the owner's own turn, the answer is also kept in the session's state as an allowance: the tool, the parties the
review was about (the entities its reasons name and the ones the card's description of the call names), the risk it
was answered at and the attack-type warnings it carried. A later review in the same session is let through without
asking when it is a call of the same tool about exactly the same parties, scores no higher, carries no attack-type
warning the answered review did not (`WARNING_PREFIXES`), and the scanner neither enforced it nor applied a floor.
Anything else asks: another party (or one more), a higher risk, a new warning of that kind, another tool, another chat,
a block. A review whose reasons and description name no party keeps Hermes's exact key only: an allowance about
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
#: Reason codes of an attack kind: a later review carrying one the answered review did not always asks, whatever its
#: score. Content steering the agent, a target only content named or a look-alike, data leaving, a known-bad or
#: look-alike party, a retry after a refusal, a floor, a guardrail, hiding what it does. The judge's wording
#: (`jev.*`, `call.*`) and the plain scoring notes do not count.
WARNING_PREFIXES = (
    "exposure.",
    "exfil.",
    "floor.",
    "guardrail.",
    "conceal.",
    "reputation.known_bad_",
    "reputation.near_miss_",
    "reputation.switched_provider",
    "origin.only_in_untrusted",
    "origin.lookalike_",
    "origin.sibling_value_untrusted",
    "origin.written_content_untrusted",
    "origin.switched_provider",
    "retry.",
)
#: Codes under those prefixes that say nothing happened.
NOT_WARNINGS = frozenset({"retry.none"})
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
    """The response's attack-type reason codes (`WARNING_PREFIXES`), sorted and once each."""
    out = set()
    for r in resp.get("reasons") or []:
        code = r.get("code") if isinstance(r, dict) else None
        if isinstance(code, str) and code.startswith(WARNING_PREFIXES) and code not in NOT_WARNINGS:
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
    """Keep the allowance an answer gave. Answered again for the same parties, the higher risk and every warning
    answered stand, and the allowance runs from the latest answer."""
    kept = [a for a in sess.get("session_allows") or [] if isinstance(a, dict)]
    old = next((a for a in kept if a.get("key") == k), None)
    if old is not None:
        if isinstance(old.get("risk"), (int, float)):
            risk = max(risk, float(old["risk"]))
        seen = sorted(set(seen) | set(old.get("warnings") or []))
    kept = [a for a in kept if a.get("key") != k]
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
