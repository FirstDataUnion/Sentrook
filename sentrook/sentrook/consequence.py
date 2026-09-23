"""Consequence classes the 2.0 card names (implementation-plan §3).

A rule may declare ``meta.consequence: C1`` … ``C6`` (engine-first, D25). Until
the library ships that field, the winning review/block rule id is looked up in
the §3 table so the plugin can name a class without waiting on a pin bump.
Observe and allow matches never contribute a class — they do not hold the card.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from sentrook.result import MatchedRule
    from sentrook.rules.models import Rule

ConsequenceCode = Literal["C1", "C2", "C3", "C4", "C5", "C6"]

CONSEQUENCE_LABELS: dict[ConsequenceCode, str] = {
    "C1": "C1 credential",
    "C2": "C2 exfil",
    "C3": "C3 remote code",
    "C4": "C4 persistence",
    "C5": "C5 unknown entity",
    "C6": "C6 injection then action",
}

#: Implementation-plan §3, the rules that name each class today. A rule that
#: declares ``meta.consequence`` wins over this table.
CONSEQUENCE_BY_RULE_ID: dict[str, ConsequenceCode] = {
    "AIRA-083": "C1",
    "AIRA-086": "C1",
    "AIRA-088": "C1",
    "AIRA-089": "C1",
    "AIRA-059": "C1",
    "AIRA-066": "C1",
    "AIRA-052": "C2",
    "AIRA-053": "C2",
    "AIRA-060": "C2",
    "AIRA-067": "C2",
    "AIRA-068": "C2",
    "AIRA-069": "C2",
    "AIRA-071": "C2",
    "AIRA-091": "C2",
    "AIRA-096": "C2",
    "AIRA-001": "C3",
    "AIRA-020": "C3",
    "AIRA-054": "C3",
    "AIRA-055": "C3",
    "AIRA-058": "C3",
    "AIRA-050": "C4",
    "AIRA-070": "C4",
    "AIRA-077": "C4",
    "AIRA-078": "C4",
    "AIRA-084": "C4",
    "AIRA-085": "C4",
    "AIRA-094": "C4",
    "AIRA-092": "C5",
    "AIRA-081": "C5",
    "AIRA-065": "C6",
}


def consequence_label(code: ConsequenceCode | str | None) -> str | None:
    if code is None:
        return None
    if code in CONSEQUENCE_LABELS:
        return CONSEQUENCE_LABELS[code]  # type: ignore[index]
    return None


def consequence_class_for(
    winning: MatchedRule | None,
    rule_by_id: dict[str, Rule] | None = None,
) -> str | None:
    """Class named on the card, or None when no review/block holds the decision."""
    if winning is None or winning.action not in ("review", "block"):
        return None
    rule = (rule_by_id or {}).get(winning.id)
    declared = getattr(getattr(rule, "meta", None), "consequence", None)
    if declared:
        return consequence_label(declared)
    return consequence_label(CONSEQUENCE_BY_RULE_ID.get(winning.id))
