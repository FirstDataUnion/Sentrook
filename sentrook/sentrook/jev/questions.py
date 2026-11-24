"""Versioned Jev question sets and the request bodies built from them.

A set is a JSON file under `jev/questions/`: `name`, `state_view`, an optional `preamble` prepended to
every question's instructions, and `questions` (each `type` noul | score | choice, `instructions`,
`criteria`), and optionally `mapping`, how the answers become signals (kept out of the request body).

Instead of a `preamble`, a set may define named `blocks` (name -> text) that each question lists, in order, under
its own `blocks`, in the set's block order; a question is sent only the blocks it lists, joined by a space, then a
blank line, then its own instructions. `block_when` makes a block conditional: it maps a block name to a dotted path in the state, and the
block is sent only when the state has a non-empty value there (a batch, a reputation block). The questions sent
then depend on the state; with no state, `built_questions` gives the largest form, every listed block, which is
what the view budget is sized for. `question_when` makes a question conditional the same way: it maps a question name to
a dotted state path, and the question is sent (and answered) only when the state has a non-empty value there.
A set uses a `preamble` or `blocks`, never both. `exposure-v1` and
`call-v1` are the two halves of the frozen TestNest baseline set
`designed-v1-split`, word for word; their sha is recorded in every envelope so a result
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
    #: How answers become signals, for sets that define it (the self-edit sets); never sent to Jev.
    mapping: dict[str, Any] | None = None
    #: Named preamble blocks, sent only with the questions that list them (in place of a `preamble`).
    blocks: dict[str, str] | None = None
    #: Block name -> dotted state path: that block is sent only when the state has a non-empty value there.
    block_when: dict[str, str] | None = None
    #: Question name -> dotted state path: that question is sent only when the state has a non-empty value there.
    question_when: dict[str, str] | None = None

    def levels(self, question: str) -> int:
        crit = self.questions[question]["criteria"]
        return len(crit)

    def names_of_type(self, *types: str) -> list[str]:
        return [k for k, q in self.questions.items() if q.get("type") in types]

    def conditional_blocks(self, state: dict[str, Any] | None = None) -> list[str]:
        """The conditional blocks sent with `state`, in block order; with no state, all of them (the largest
        form). Empty for a set without blocks."""
        when = self.block_when or {}
        return [
            b for b in (self.blocks or {}) if b in when and (state is None or _has(state, when[b]))
        ]

    def sent_questions(self, state: dict[str, Any] | None = None) -> list[str]:
        """The questions sent with `state`, in set order; with no state, all of them (the largest form)."""
        when = self.question_when or {}
        return [q for q in self.questions if q not in when or state is None or _has(state, when[q])]

    def built_questions(self, state: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
        """Questions as sent with `state`: the preamble, or the question's blocks that apply, prepended;
        `state_view` and `blocks` removed. With no state, a block set gives its largest form."""
        sent = set(self.conditional_blocks(state))
        when = self.block_when or {}
        asked = set(self.sent_questions(state))
        out: dict[str, dict[str, Any]] = {}
        for name, q in self.questions.items():
            if name not in asked:
                continue
            q = copy.deepcopy(q)
            q.pop("state_view", None)
            listed = q.pop("blocks", None)
            if self.blocks is not None:
                parts = [self.blocks[b] for b in listed or [] if b not in when or b in sent]
                if parts:
                    q["instructions"] = " ".join(parts) + "\n\n" + q["instructions"]
            elif self.preamble:
                q["instructions"] = self.preamble + "\n\n" + q["instructions"]
            out[name] = q
        return out


def _has(state: Any, path: str) -> bool:
    """Whether `state` has a non-empty value (not None, "", [] or {}) at the dotted `path`."""
    cur = state
    for part in path.split("."):
        if not isinstance(cur, dict):
            return False
        cur = cur.get(part)
    return cur not in (None, "", [], {})


def _check_blocks(raw: dict[str, Any], where: str) -> None:
    """A set uses a preamble or blocks, never both; every block a question or `block_when` names exists, and each
    question lists its blocks in the set's block order, so the sentences it is sent keep the order they were written
    in."""
    blocks = raw.get("blocks")
    when = raw.get("block_when")
    questions = raw["questions"]
    if blocks is None:
        if when is not None:
            raise ValueError(f"{where}: block_when without blocks")
        for name, q in questions.items():
            if "blocks" in q:
                raise ValueError(
                    f"{where}: question {name!r} lists blocks but the set defines none"
                )
        return
    if raw.get("preamble") is not None:
        raise ValueError(f"{where}: a set uses either a preamble or blocks, not both")
    if not isinstance(blocks, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and v for k, v in blocks.items()
    ):
        raise ValueError(f"{where}: blocks must map names to non-empty text")
    if when is not None and not isinstance(when, dict):
        raise ValueError(f"{where}: block_when must map block names to dotted state paths")
    for block, path in (when or {}).items():
        if block not in blocks:
            raise ValueError(f"{where}: block_when names {block!r}, which is not a block")
        if not isinstance(path, str) or "" in path.split("."):
            raise ValueError(f"{where}: block_when[{block!r}] must be a dotted state path")
    order = {b: i for i, b in enumerate(blocks)}
    for name, q in questions.items():
        listed = q.get("blocks")
        if not isinstance(listed, list) or not listed:
            raise ValueError(f"{where}: question {name!r} lists no blocks")
        for b in listed:
            if not isinstance(b, str) or b not in blocks:
                raise ValueError(f"{where}: question {name!r} names unknown block {b!r}")
        at = [order[b] for b in listed]
        if at != sorted(set(at)):
            raise ValueError(
                f"{where}: question {name!r} must list its blocks once each, in the set's block order"
            )


def _check_question_when(raw: dict[str, Any], where: str) -> None:
    when = raw.get("question_when")
    if when is None:
        return
    if not isinstance(when, dict):
        raise ValueError(f"{where}: question_when must map question names to dotted state paths")
    for q, path in when.items():
        if q not in raw["questions"]:
            raise ValueError(f"{where}: question_when names {q!r}, which is not a question")
        if not isinstance(path, str) or "" in path.split("."):
            raise ValueError(f"{where}: question_when[{q!r}] must be a dotted state path")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_question_set(name: str | Path) -> QuestionSet:
    path = Path(name)
    if path.suffix != ".json" or not path.exists():
        path = QUESTIONS_DIR / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    _check_blocks(raw, str(raw.get("name") or path.stem))
    _check_question_when(raw, str(raw.get("name") or path.stem))
    return QuestionSet(
        name=raw["name"],
        state_view=raw.get("state_view", "trimmed"),
        preamble=raw.get("preamble"),
        questions=raw["questions"],
        sha=hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest(),
        mapping=raw.get("mapping"),
        blocks=raw.get("blocks"),
        block_when=raw.get("block_when"),
        question_when=raw.get("question_when"),
    )


def build_body(
    qs: QuestionSet, state: dict[str, Any], *, model: str, provider: dict[str, Any]
) -> dict[str, Any]:
    return {
        "model": model,
        "state": copy.deepcopy(state),
        "questions": qs.built_questions(state),
        "provider": dict(provider),
    }
