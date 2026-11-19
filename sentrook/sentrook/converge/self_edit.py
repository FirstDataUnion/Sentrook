"""`Response.self_edit`: what a self-edit's saved content adds and whether the save qualifies for lenient handling.

Set only on a declared self-edit (the host's own background process saving to memory or skills). `adds` comes from
`prepare.save_adds`, read by rule from the saved text. `lenient` is true only when all of these hold:

- the save adds nothing, or only commands;
- the self-edit judge answered (its envelope is OK and carries every one of `LENIENT_ANSWERS`), and each of those
  answers is below `LENIENT_ANSWER_LIMIT`;
- no floor applies to the scan (an enforced one, a guardrail, or one that only raises the score).

`lenient` says nothing about the verdict: a plugin that cannot ask anyone about a background save consults it only
when the risk lands in its review band, to let such a save through instead of holding it. It changes no score, and
the scan's overall status is not part of it (a background run often has no session state of its own).
"""

from __future__ import annotations

from collections.abc import Iterable

from ..enums import ProbeStatus, ProbeStep
from ..probes.base import Envelope
from ..response.models import FloorApplied, SelfEditSave

#: The self-edit judge's answers that must each stay below `LENIENT_ANSWER_LIMIT` for a lenient save: a directive
#: taken from read content, loosened oversight, and a claim about the owner no owner message shows.
LENIENT_ANSWERS: tuple[str, ...] = (
    "untrusted_directive",
    "weakens_oversight",
    "unsupported_owner_claim",
)
#: The probability (the judge's raw answer, before the question set's knee) at which one of `LENIENT_ANSWERS` rules
#: out lenient handling.
LENIENT_ANSWER_LIMIT = 0.7
#: What a lenient save may add.
LENIENT_ADDS: frozenset[tuple[str, ...]] = frozenset({(), ("command",)})


def _answers_below_limit(envelopes: Iterable[Envelope]) -> bool:
    for env in envelopes:
        if env.step is not ProbeStep.JEV_CALL:
            continue
        if env.status is not ProbeStatus.OK:
            return False
        answers = env.evidence.get("answers")
        if not isinstance(answers, dict):
            return False
        for q in LENIENT_ANSWERS:
            a = answers.get(q)
            if not isinstance(a, dict) or not isinstance(a.get("noul"), int | float):
                return False
            if float(a["noul"]) >= LENIENT_ANSWER_LIMIT:
                return False
        return True
    return False


def self_edit_save(
    adds: Iterable[str], envelopes: Iterable[Envelope], floors: Iterable[FloorApplied]
) -> SelfEditSave:
    kinds = tuple(sorted(set(adds)))
    lenient = (
        kinds in LENIENT_ADDS and not any(True for _ in floors) and _answers_below_limit(envelopes)
    )
    return SelfEditSave(adds=list(kinds), lenient=lenient)
