"""The two Jev probes.

- `JevExposureProbe` sends the exposure view (request text plus the new untrusted inputs) with the
  `exposure-v1` questions (or `exposure-v2` on the redacted `exposure-v2` view) and contributes
  `suspicion.exposure`; above the taint threshold it sets the `tainted` session flag. It is skipped
  when there is nothing new and untrusted to read. Reads of the agent's own skills and memory
  (`prepare.own_store.own_store_read`) are left out: a skill is instructions by design and a memory note is the
  agent's own standing context. So are reads of the owner's own instruction files (`AGENTS.md`, `SOUL.md`, ...
  where the host keeps them: `prepare.session_sets.owner_config_path`), the owner's orders to the agent; a config
  file read is still judged.
- `JevCallProbe` sends the call view (request, pending call, history arguments, grants, trigger; `call-v2`
  adds the turn's inputs; `call-v3` adds the entity library's verdicts for the call's own entities,
  filled from the oracle probe) with the `call-v1`, `call-v2` or `call-v3` questions and contributes misalignment,
  concealment, sensitivity, reach, irreversibility, self-modification, `suspicion.overreach` (call-v2's
  `scope_overreach`) and `confidence.model_certainty` (the mean confidence over Score and Choice
  answers). The `untrusted_origin` answer is recorded in evidence only; the
  context probe owns that signal. The action category goes in evidence for the tool description. A set that asks
  `names_service` (call-v10) gets a `services` block when the scan found hosts the request names by their service
  (`prepare.service_names`); the answer and the hosts sent go in evidence (`names_service`, `services_sent`) for
  convergence's service-name relief, and contribute no signal.

The question set's `state_view` selects which prepared view a probe sends.

Both run in parallel under the scan's thread pool (after the oracle probe when the call view carries
`reputation`) and never raise: an API failure is an envelope with status `error` or `timeout`, and
the scan continues as `degraded`.
"""

from __future__ import annotations

import time
from typing import Any

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..jev.chunking import chunk_exposure_state, est_tokens
from ..jev.client import ApiError, Decider, DecisionResult, JevConfig
from ..jev.questions import QuestionSet, build_body, load_question_set
from ..prepare import Prepared
from ..prepare.entities import EntityKind, Origin, Role
from ..prepare.views import (
    BATCH_VIEWS,
    OWNER_CONFIG_VIEWS,
    REPUTATION,
    REPUTATION_CAP_CHARS,
    SERVICES,
    VIEW_KEYS,
    _json_chars,
    services_block,
    with_reputation,
    with_resolved,
    with_services,
)
from .base import Contribution, Envelope, SessionMark

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


def mapped_contributions(qs: QuestionSet, answers: dict[str, Any]) -> list[Contribution]:
    """Contributions for a question set that defines its own `mapping` (the self-edit sets). A yes/no answer gives
    the probability that counts against the call (`against_when`), with doubt below `knee` counted as none and the
    rest rescaled to 0-1; a score answer gives its level on 0-1."""
    out: list[Contribution] = []
    mapping = qs.mapping or {}
    for q, m in (mapping.get("noul") or {}).items():
        if q not in answers:
            continue
        v = _noul(answers[q])
        v = v if m.get("against_when", True) else 1.0 - v
        knee = float(m.get("knee", 0.0))
        if knee:
            v = max(0.0, (v - knee) / (1.0 - knee))
        out.append(Contribution(signal=m["signal"], value=v, reason=m["reason"]))
    for q, m in (mapping.get("score") or {}).items():
        if q in answers:
            out.append(
                Contribution(
                    signal=m["signal"], value=_score(answers[q], qs.levels(q)), reason=m["reason"]
                )
            )
    return out


#: Roles in which an owner-configured entity is listed for the judge: where the call sends to, never what it runs.
_OWNER_CONFIG_ROLES = frozenset({Role.DATA_DESTINATION, Role.RECIPIENT})
_OWNER_CONFIG_KINDS = frozenset({EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL})


def owner_config_entries(
    prepared: Prepared, verdicts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """`reputation` entries for the call's destinations and recipients that the owner's own configuration supplied
    on an earlier scan (the token's trusted set), as `verdict: owner_config`. Trust a config read in this request
    establishes is left out: the exposure probe, running alongside, may judge that read injected. An entity content
    the agent read also named, one the library already has a verdict for, and anything the call runs or installs
    from are left out too."""
    listed = {(v.get("kind"), v.get("value")) for v in verdicts}
    out: list[dict[str, Any]] = []
    for ent in prepared.entities.pending():
        if not ent.in_prior_trusted or ent.in_session_untrusted:
            continue
        if Origin.UNTRUSTED_INPUT in ent.origins or ent.kind not in _OWNER_CONFIG_KINDS:
            continue
        if not ent.roles & _OWNER_CONFIG_ROLES or ent.roles & {Role.CODE_SOURCE, Role.EXECUTABLE}:
            continue
        if (ent.kind.value, ent.display) in listed:
            continue
        out.append({"kind": ent.kind.value, "value": ent.display, "verdict": "owner_config"})
    out.sort(key=lambda e: (str(e["kind"]), str(e["value"])))
    return out


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
            out["history_cut"] = int(meta.get("history_cut") or 0)
            out["history_dropped"] = int(meta.get("history_dropped") or 0)
            out["request_cut"] = bool(meta.get("request_cut"))
        if self.step is ProbeStep.JEV_CALL and REPUTATION in VIEW_KEYS.get(self.view_name, ()):
            out["reputation_entries"] = len(prepared.oracle_verdicts)
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
            i.input.input_seq
            for i in prepared.untrusted_inputs(new_only=True)
            if i.input.content and i.input.input_seq not in prepared.exposure_left_out
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
            if prepared.owner_instruction_inputs:
                why = "only reads of the agent's own instruction files, skills or memory"
            elif prepared.own_store_inputs:
                why = "only reads of the agent's own skills or memory"
            else:
                why = "no new untrusted inputs with content"
            env = Envelope.skipped(self.step, why, self.versions)
            env.evidence.update(_left_out_evidence(prepared))
            return env
        # the questions' largest form: chunks are cut before each is built, so a set whose blocks depend on the
        # state is sized as if every block were sent
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
        # The inputs of each chunk judged injected. Only a chunk that holds one input says which input
        # was injected; its call's files and tables join the tainted set.
        judged: dict[int, bool] = {}
        for chunk, answers in zip(chunks, per_chunk, strict=True):
            if not answers or max(answers.values()) < self.config.taint_threshold:
                continue
            seqs = {
                n["input_seq"]
                for n in chunk.get("new_inputs") or []
                if isinstance(n.get("input_seq"), int)
            }
            for seq in seqs:
                judged[seq] = judged.get(seq, False) or len(seqs) == 1
        marks = [
            SessionMark(judgement="tainted", input_seq=seq, attributed=one)
            for seq, one in sorted(judged.items())
        ]
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
            marks=marks,
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
                **_left_out_evidence(prepared),
            },
        )


def _left_out_evidence(prepared: Prepared) -> dict[str, list[int]]:
    """The new inputs the exposure probe left out, by why: reads of the agent's own skills or memory, and of the
    owner's own instruction files."""
    out: dict[str, list[int]] = {}
    if prepared.own_store_inputs:
        out["own_store_skipped"] = sorted(prepared.own_store_inputs)
    if prepared.owner_instruction_inputs:
        out["owner_instructions_skipped"] = sorted(prepared.owner_instruction_inputs)
    return out


class JevCallProbe(_JevProbe):
    step = ProbeStep.JEV_CALL

    def __init__(
        self, decider: Decider, config: JevConfig, question_set: QuestionSet | None = None
    ):
        super().__init__(decider, config, question_set or config.call_question_set)

    def state_for(self, prepared: Prepared) -> dict[str, Any]:
        """The configured call view. Raises KeyError when it was not prepared. A view that carries
        `reputation` (call-v3) gets the oracle verdicts the scan stored on `prepared`; with none
        known the key is absent."""
        state = prepared.views[self.view_name]
        services: list[dict[str, Any]] = []
        if SERVICES in (self.qs.question_when or {}).values() and prepared.service_candidates:
            services = services_block(
                [(c.host, list(c.names)) for c in prepared.service_candidates]
            )
        if REPUTATION in VIEW_KEYS.get(self.view_name, ()):
            verdicts = list(prepared.oracle_verdicts)
            if self.view_name in OWNER_CONFIG_VIEWS:
                verdicts += owner_config_entries(prepared, verdicts)
            # the services block shares the room the view keeps for reputation
            room = REPUTATION_CAP_CHARS - (_json_chars(services) + 16 if services else 0)
            state = with_reputation(state, verdicts, room)
        if services:
            state = with_services(state, services)
        if self.view_name in BATCH_VIEWS:
            # Only a command the join changed in place: a read file's content appended to the command says nothing
            # the sibling's own arguments do not already show.
            pending = prepared.pending.command if isinstance(prepared.pending.command, str) else ""
            commands = [
                c.command
                for c in prepared.resolved
                if isinstance(c.command, str) and not (pending and c.command.startswith(pending))
            ]
            state = with_resolved(state, commands)
        return state

    @staticmethod
    def _services_evidence(
        prepared: Prepared, state: dict[str, Any], answers: dict[str, Any]
    ) -> dict[str, Any]:
        """The service-name hosts the judge was asked about (entity ids) and its answer, when it was asked."""
        sent = {e.get("host") for e in state.get(SERVICES) or [] if isinstance(e, dict)}
        if not sent or "names_service" not in answers:
            return {}
        return {
            "services_sent": [c.entity_id for c in prepared.service_candidates if c.host in sent],
            "names_service": _noul(answers["names_service"]),
        }

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
        missing = [q for q in self.qs.sent_questions(state) if q not in answers]
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
        if self.qs.mapping:
            contributions += mapped_contributions(self.qs, answers)
        if "supported_by_request" in answers:
            contributions.append(
                Contribution(
                    signal="suspicion.misalignment",
                    value=1.0 - _noul(answers["supported_by_request"]),
                    reason="call.not_supported_by_request",
                )
            )
        for q, signal in CALL_SIGNALS.items():
            if q not in answers or self.qs.mapping:
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
                **self._services_evidence(prepared, state, answers),
                "p_level_ge_2": split,
                "confidences": confs,
                "usage": _usage_summary([res]),
                # which conditional preamble blocks the questions carried (sets built from blocks only)
                **(
                    {"question_blocks": self.qs.conditional_blocks(state)} if self.qs.blocks else {}
                ),
            },
        )
