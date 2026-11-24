"""A host the owner's request names by its service: the service-name check.

Owners name services, not hosts: "update our plan on Notion", not "post to api.notion.com". The entity library lists,
on a `known_good` host the vendor controls, the names owners call its service by (`service_names`, from an exact
library answer only; see `probes.oracle`). A host the pending call or its batch uses is a candidate when:

- the library's answer for the host lists service names, and one of them appears in the owner's own words
  (`Prepared.request_words`: the request without host-written wrappers) as a whole word, in any case, with any run of
  whitespace between its words. Never from the host's own labels: a look-alike or an unlisted host with the brand in
  its name has no library answer to give a name;
- the request does not already name the host verbatim (it is request-named already);
- no content the agent read supplied the host, and nothing steered the agent to it. A host that only the agent's own
  installed skills named (`Entity.skill_named`) still counts, as in the credential-home check: the skill is the
  agent's standing instructions for the service, and the library ties the name to the host;
- the call and a later run its written content sets up send to or read from it, never take code from it.

A candidate is not yet a host the owner named: "a notion of whether the plan is right" names no service. The call
judge reads the request and decides (call-v10's `names_service`, sent only when there is a candidate), and convergence
relieves the host as a request-named destination only on its yes (`service_name_relief`). A candidate never adds an
origin here, so every probe scores the host as before.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .entities import Entity, EntityKind, Origin, Role

#: At most this many candidate hosts go to the judge; a call naming more is unusual and the rest keep their score.
MAX_CANDIDATES = 4
_CODE_ROLES = frozenset({Role.CODE_SOURCE, Role.EXECUTABLE})


@dataclass(frozen=True)
class ServiceCandidate:
    entity_id: str
    host: str
    #: The library's names for the host's service that the request contains, as the library writes them.
    names: tuple[str, ...]


def name_in_text(name: str, text: str) -> bool:
    """`name` appears in `text` as a whole word, in any case, with any whitespace between its words: not inside a
    longer word, a hyphenated or dotted name (`notion-clone`, `notion.example`) or an address."""
    words = name.split()
    if not words:
        return False
    body = r"\s+".join(re.escape(w) for w in words)
    return bool(
        re.search(r"(?<![\w@./-])" + body + r"(?![\w-])(?!\.\w)", text, flags=re.IGNORECASE)
    )


def _from_content(ent: Entity) -> bool:
    """Content the agent read supplied the host, or something steered the agent to it; installed-skill reads aside."""
    return ent.steered or (
        (ent.in_session_untrusted or Origin.UNTRUSTED_INPUT in ent.origins) and not ent.skill_named
    )


def candidates(prepared: Any) -> tuple[ServiceCandidate, ...]:
    """The candidate hosts, by host name, at most `MAX_CANDIDATES`. Reads the oracle's answers on `prepared`, so it
    runs after the oracle probe."""
    words = prepared.request_words or ""
    if not words.strip():
        return ()
    out: list[ServiceCandidate] = []
    for ent in prepared.entities:
        if ent.kind is not EntityKind.HOST:
            continue
        if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
            continue
        if Origin.REQUEST in ent.origins or _from_content(ent):
            continue
        if (ent.roles | ent.future_roles) & _CODE_ROLES:
            continue
        info = prepared.oracle_entities.get(ent.id) or {}
        names = tuple(n for n in info.get("service_names") or () if isinstance(n, str))
        matched = tuple(n for n in names if name_in_text(n, words))
        if matched:
            out.append(ServiceCandidate(ent.id, ent.display, matched))
    out.sort(key=lambda c: c.host)
    return tuple(out[:MAX_CANDIDATES])
