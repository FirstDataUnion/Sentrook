"""Versioned Jev question sets and the request bodies built from them.

A set is a JSON file under `jev/questions/`: `name`, `state_view`, an optional `preamble` prepended to
every question's instructions, and `questions` (each `type` noul | score | choice, `instructions`,
`criteria`). `exposure-v1` and `call-v1` are the two halves of the frozen TestNest baseline set
`designed-v1-split`, word for word (build plan D3); their sha is recorded in every envelope so a result
is attributable to exact wording. A wording change is a new file.

`build_body` produces exactly what the runner's Jev targets send (`{model, state, questions, provider}`),
so the TestNest cache key matches and the suite replays.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

QUESTIONS_DIR = Path(__file__).resolve().parent / "questions"


@dataclass(frozen=True)
class QuestionSet:
    name: str
    state_view: str
    preamble: str | None
    questions: dict[str, dict[str, Any]]
    sha: str

    def levels(self, question: str) -> int:
        crit = self.questions[question]["criteria"]
        return len(crit)

    def names_of_type(self, *types: str) -> list[str]:
        return [k for k, q in self.questions.items() if q.get("type") in types]

    def built_questions(self) -> dict[str, dict[str, Any]]:
        """Questions as sent: preamble prepended, `state_view` removed."""
        out: dict[str, dict[str, Any]] = {}
        for name, q in self.questions.items():
            q = copy.deepcopy(q)
            q.pop("state_view", None)
            if self.preamble:
                q["instructions"] = self.preamble + "\n\n" + q["instructions"]
            out[name] = q
        return out


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_question_set(name: str | Path) -> QuestionSet:
    path = Path(name)
    if path.suffix != ".json" or not path.exists():
        path = QUESTIONS_DIR / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    return QuestionSet(
        name=raw["name"],
        state_view=raw.get("state_view", "trimmed"),
        preamble=raw.get("preamble"),
        questions=raw["questions"],
        sha=hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest(),
    )


def build_body(
    qs: QuestionSet, state: dict[str, Any], *, model: str, provider: dict[str, Any]
) -> dict[str, Any]:
    return {
        "model": model,
        "state": copy.deepcopy(state),
        "questions": qs.built_questions(),
        "provider": dict(provider),
    }
