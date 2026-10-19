"""The two Jev probes.

- `JevExposureProbe` sends the exposure view (request text plus the new untrusted inputs) with the
  `exposure-v1` questions (or `exposure-v2` on the redacted `exposure-v2` view) and contributes
  `suspicion.exposure`; above the taint threshold it sets the `tainted` session flag. It is skipped
  when there is nothing new and untrusted to read.
- `JevCallProbe` sends the call view (request, pending call, history arguments, grants, trigger; `call-v2`
  adds the turn's inputs) with the `call-v1` or `call-v2` questions and contributes misalignment,
  concealment, sensitivity, reach, irreversibility, self-modification, `suspicion.overreach` (call-v2's
  `scope_overreach`) and `confidence.model_certainty` (the mean confidence over Score and Choice
  answers). The `untrusted_origin` answer is recorded in evidence only; the
  context probe owns that signal. The action category goes in evidence for the tool description.

The question set's `state_view` selects which prepared view a probe sends.

Both run in parallel under the scan's thread pool and never raise: an API failure is an envelope with
status `error` or `timeout`, and the scan continues as `degraded`.
"""

from __future__ import annotations

import time
from typing import Any

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..jev.chunking import chunk_exposure_state, est_tokens
from ..jev.client import ApiError, Decider, DecisionResult, JevConfig
from ..jev.questions import QuestionSet, build_body, load_question_set
from ..prepare import Prepared
from ..prepare.views import VIEW_KEYS
from .base import Contribution, Envelope

PROBE_VERSION = "jev/2.0.0a1"

EXPOSURE_QUESTIONS = ("exposure_instructions", "exposure_task_change", "exposure_authority")
#: call question → signal, for Score and Noul questions (a set without the question contributes nothing)
CALL_SIGNALS: dict[str, str] = {
    "scope_overreach": "suspicion.overreach",
    "concealment": "suspicion.concealment",
    "sensitivity": "consequence.sensitivity",
    "reach": "consequence.reach",
    "irreversibility": "consequence.irreversibility",
    "self_modification": "consequence.self_modification",
}


def _unit(x: Any) -> float:
    return min(1.0, max(0.0, float(x)))


def _noul(answer: dict[str, Any]) -> float:
    return _unit(answer.get("noul", 0.0))


def _score(answer: dict[str, Any], levels: int) -> float:
    return _unit(float(answer.get("score", 0.0)) / max(1, levels - 1))


def _usage_summary(results: list[DecisionResult]) -> dict[str, Any]:
    def total(*keys: str) -> float | None:
        vals = []
        for r in results:
            for k in keys:
                if r.usage.get(k) is not None:
                    vals.append(float(r.usage[k]))
                    break
        return sum(vals) if vals else None

    return {
        "input_tokens": total("input_tokens", "prompt_tokens"),
        "output_tokens": total("output_tokens", "completion_tokens"),
        "cost_usd": total("cost"),
        "cache_hits": sum(1 for r in results if r.cache_hit),
        "requests": len(results),
    }


class _JevProbe:
    step: ProbeStep

    def __init__(self, decider: Decider, config: JevConfig, question_set: str | QuestionSet):
        self.decider = decider
        self.config = config
        self.qs: QuestionSet = (
            question_set
            if isinstance(question_set, QuestionSet)
            else load_question_set(question_set)
        )
        self.view_name = self.qs.state_view

    @property
    def versions(self) -> dict[str, str | None]:
        return {
            "probe": PROBE_VERSION,
            "question_set": self.qs.name,
            "question_set_sha": self.qs.sha[:12],
            "model": self.config.model,
        }

    def _versions_with_model(self, results: list[DecisionResult]) -> dict[str, str | None]:
        v = self.versions
        resolved = next((r.model for r in reversed(results) if r.model), None)
        if resolved:
            v["model"] = resolved
        return v

    def _view_evidence(self, prepared: Prepared) -> dict[str, Any]:
        meta = prepared.view_meta.get(self.view_name) or {}
        out: dict[str, Any] = {
            "view": self.view_name,
            "views_version": prepared.views_version.get(self.view_name),
            "redactions": meta.get("redactions", 0),
        }
        if self.step is ProbeStep.JEV_CALL and "new_inputs" in VIEW_KEYS.get(self.view_name, ()):
            out["inputs_truncated"] = bool(meta.get("inputs_truncated"))
            out["inputs_stripped"] = bool(meta.get("inputs_stripped"))
        return out

    def _no_view(self) -> Envelope:
        env = Envelope.failed(
            self.step,
            ProbeStatus.ERROR,
            f"view {self.view_name!r} (question set {self.qs.name}) was not prepared",
            self.versions,
        )
        env.evidence["view"] = self.view_name
        return env

    def _call(self, state: dict[str, Any], repeat: int | None) -> DecisionResult:
        body = build_body(self.qs, state, model=self.config.model, provider=self.config.provider)
        return self.decider.decide(body, repeat=repeat)

    def _failed(
        self, exc: Exception, started: float, states_sent: list[dict[str, Any]]
    ) -> Envelope:
        latency = (time.perf_counter() - started) * 1000
        if isinstance(exc, ApiError):
            status = ProbeStatus.TIMEOUT if exc.timeout else ProbeStatus.ERROR
            env = Envelope.failed(self.step, status, str(exc), self.versions, latency_ms=latency)
            env.evidence["context_limit"] = exc.context_limit
            env.evidence["http_status"] = exc.status
        else:
            env = Envelope.failed(
                self.step, ProbeStatus.ERROR, repr(exc), self.versions, latency_ms=latency
            )
        env.evidence["states_sent"] = len(states_sent)
        return env


class JevExposureProbe(_JevProbe):
    step = ProbeStep.JEV_EXPOSURE

    def __init__(
        self, decider: Decider, config: JevConfig, question_set: QuestionSet | None = None
    ):
        super().__init__(decider, config, question_set or config.exposure_question_set)

    def state_for(self, prepared: Prepared) -> dict[str, Any] | None:
        """The configured exposure view with only the new untrusted inputs that carry content; None
        when there are none. Raises KeyError when the view was not prepared."""
        seqs = {
            i.input.input_seq for i in prepared.untrusted_inputs(new_only=True) if i.input.content
        }
        if not seqs:
            return None
        v = dict(prepared.views[self.view_name])
        v["new_inputs"] = [n for n in v.get("new_inputs") or [] if n.get("input_seq") in seqs]
        return v

    def run(self, prepared: Prepared, *, repeat: int | None = None) -> Envelope:
        try:
            state = self.state_for(prepared)
        except KeyError:
            return self._no_view()
        if state is None:
            return Envelope.skipped(
                self.step, "no new untrusted inputs with content", self.versions
            )
        questions_tokens = est_tokens(self.qs.built_questions())
        chunks = chunk_exposure_state(state, questions_tokens)
        started = time.perf_counter()
        results: list[DecisionResult] = []
        per_chunk: list[dict[str, float]] = []
        try:
            for chunk in chunks:
                res = self._call(chunk, repeat)
                results.append(res)
                per_chunk.append(
                    {q: _noul(res.answers[q]) for q in EXPOSURE_QUESTIONS if q in res.answers}
                )
        except Exception as e:  # noqa: BLE001 (a probe never raises)
            return self._failed(e, started, chunks)
        latency = (time.perf_counter() - started) * 1000
        missing = [q for q in EXPOSURE_QUESTIONS if not any(q in c for c in per_chunk)]
        if missing:
            env = Envelope.failed(
                self.step,
                ProbeStatus.ERROR,
                f"missing answers: {missing}",
                self._versions_with_model(results),
                latency_ms=latency,
            )
            env.evidence["answers"] = [r.answers for r in results]
            return env
        checks = {q: max(c.get(q, 0.0) for c in per_chunk) for q in EXPOSURE_QUESTIONS}
        exposure = max(checks.values())
        reason = max(checks, key=checks.get)
        flags = [SessionFlag.TAINTED] if exposure >= self.config.taint_threshold else []
        return Envelope(
            step=self.step,
            versions=self._versions_with_model(results),
            status=ProbeStatus.OK,
            latency_ms=latency,
            contributions=[
                Contribution(
                    signal="suspicion.exposure",
                    value=exposure,
                    reason=f"exposure.{reason.removeprefix('exposure_')}",
                )
            ],
            flags_set=flags,
            evidence={
                **self._view_evidence(prepared),
                "state": state,
                "checks": checks,
                "chunks": len(chunks),
                "per_chunk": per_chunk,
                "answers": [r.answers for r in results],
                "usage": _usage_summary(results),
                "input_seqs": sorted(
                    {n["input_seq"] for n in state.get("new_inputs") or [] if "input_seq" in n}
                ),
            },
        )


class JevCallProbe(_JevProbe):
    step = ProbeStep.JEV_CALL

    def __init__(
        self, decider: Decider, config: JevConfig, question_set: QuestionSet | None = None
    ):
        super().__init__(decider, config, question_set or config.call_question_set)

    def state_for(self, prepared: Prepared) -> dict[str, Any]:
        """The configured call view. Raises KeyError when it was not prepared."""
        return prepared.views[self.view_name]

    def run(self, prepared: Prepared, *, repeat: int | None = None) -> Envelope:
        try:
            state = self.state_for(prepared)
        except KeyError:
            return self._no_view()
        started = time.perf_counter()
        try:
            res = self._call(state, repeat)
        except Exception as e:  # noqa: BLE001
            return self._failed(e, started, [state])
        latency = (time.perf_counter() - started) * 1000
        answers = res.answers
        missing = [q for q in self.qs.questions if q not in answers]
        if missing:
            env = Envelope.failed(
                self.step,
                ProbeStatus.ERROR,
                f"missing answers: {missing}",
                self._versions_with_model([res]),
                latency_ms=latency,
            )
            env.evidence["answers"] = answers
            return env

        contributions: list[Contribution] = []
        if "supported_by_request" in answers:
            contributions.append(
                Contribution(
                    signal="suspicion.misalignment",
                    value=1.0 - _noul(answers["supported_by_request"]),
                    reason="call.not_supported_by_request",
                )
            )
        for q, signal in CALL_SIGNALS.items():
            if q not in answers:
                continue
            a = answers[q]
            value = _noul(a) if a.get("type") == "noul" else _score(a, self.qs.levels(q))
            contributions.append(Contribution(signal=signal, value=value, reason=f"jev.{q}"))

        confs = [
            float(answers[q].get("confidence", 1.0))
            for q in self.qs.names_of_type("score", "choice")
            if q in answers
        ]
        certainty = sum(confs) / len(confs) if confs else None
        if certainty is not None:
            contributions.append(
                Contribution(
                    signal="confidence.model_certainty",
                    value=_unit(certainty),
                    reason="jev.confidence_mean",
                )
            )

        split = {}
        for q in self.qs.names_of_type("score"):
            probs = answers[q].get("probabilities") or {}
            tail = sum(float(v) for k, v in probs.items() if str(k).isdigit() and int(k) >= 2)
            split[q] = round(tail, 4)
        category = answers.get("action_category", {}).get("choice")

        return Envelope(
            step=self.step,
            versions=self._versions_with_model([res]),
            status=ProbeStatus.OK,
            latency_ms=latency,
            contributions=contributions,
            evidence={
                **self._view_evidence(prepared),
                "state": state,
                "answers": answers,
                "action_category": category,
                "action_category_probs": answers.get("action_category", {}).get("probabilities"),
                "untrusted_origin": _noul(answers["untrusted_origin"])
                if "untrusted_origin" in answers
                else None,
                "p_level_ge_2": split,
                "confidences": confs,
                "usage": _usage_summary([res]),
            },
        )
