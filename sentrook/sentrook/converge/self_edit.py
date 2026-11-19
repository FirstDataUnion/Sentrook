"""`Response.self_edit`: what a self-edit's saved content adds and whether the save qualifies for lenient handling.

Set only on a declared self-edit (the host's own background process saving to memory or skills). `adds` comes from
`prepare.save_adds`, read by rule from the saved text. `lenient` is true only when all of these hold:

- the save adds nothing, or only commands;
- the self-edit judge answered (its envelope is OK and carries every one of `LENIENT_ANSWERS`), and each of those
  answers is below `LENIENT_ANSWER_LIMIT`;
- no floor applies to the scan (an enforced one, a guardrail, or one that only raises the score), and no probe that
  sets floors failed (convergence takes floors only from probes that answered); the rule probe ran.

`lenient` says nothing about the verdict: a plugin that cannot ask anyone about a background save consults it only
when the risk lands in its review band, to let such a save through instead of holding it. It changes no score, and
the scan's overall status is not part of it (a background run often has no session state of its own).
"""

from __future__ import annotations

import math
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
            v = a.get("noul") if isinstance(a, dict) else None
            if not isinstance(v, int | float) or not math.isfinite(v) or v >= LENIENT_ANSWER_LIMIT:
                return False
        return True
    return False


#: Probes whose floors convergence takes only from an OK envelope: one that failed may have hidden a floor. The
#: rule probe also reads the saved commands, so it must have run; the others must not have failed.
FLOOR_PROBES_RUN: frozenset[ProbeStep] = frozenset({ProbeStep.AIRA})
FLOOR_PROBES_NOT_FAILED: frozenset[ProbeStep] = frozenset(
    {ProbeStep.AIRA, ProbeStep.CONTEXT, ProbeStep.ENTITY_ORACLE}
)


def _floor_probes_answered(envelopes: Iterable[Envelope]) -> bool:
    seen: set[ProbeStep] = set()
    for env in envelopes:
        if env.step in FLOOR_PROBES_NOT_FAILED and env.status in (
            ProbeStatus.ERROR,
            ProbeStatus.TIMEOUT,
        ):
            return False
        if env.status is ProbeStatus.OK:
            seen.add(env.step)
    return FLOOR_PROBES_RUN <= seen


def self_edit_save(
    adds: Iterable[str], envelopes: Iterable[Envelope], floors: Iterable[FloorApplied]
) -> SelfEditSave:
    kinds = tuple(sorted(set(adds)))
    envelopes = list(envelopes)
    lenient = (
        kinds in LENIENT_ADDS
        and not any(True for _ in floors)
        and _floor_probes_answered(envelopes)
        and _answers_below_limit(envelopes)
    )
    return SelfEditSave(adds=list(kinds), lenient=lenient)
