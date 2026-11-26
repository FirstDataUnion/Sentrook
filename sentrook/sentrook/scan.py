"""The in-process scan entry point: `Scanner.scan(raw) -> ScanResult`.

Preparation runs once; the enabled probes run in parallel on a thread pool, each returning an
envelope (a probe that raises is turned into a failed envelope here as a last resort); convergence
turns the envelopes into Response 2.0 and the new state token. Every route and the CLI call this.

Ablation: `probes_enabled` lists the probes to run; the others are recorded as `skipped` so a
TestNest run stays attributable. Ablation is a test-mode feature: the serve configuration refuses
`SENTROOK_PROBES` and the CLI refuses `--probes` unless `SENTROOK_TEST_MODE=1`, and production
`/scan` never passes a probe list. Test mode also passes a `state_seed` and an `oracle_seed` instead
of a token and a live oracle, and `deterministic` fixes the clock and salt.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .converge import ConvergenceParams, ConvergeResult, converge, load_params
from .converge.credential_hint import worth_copying as credential_hint_candidate
from .enums import ProbeStatus, ProbeStep
from .jev.client import Decider, JevConfig
from .jev.questions import QuestionSet, load_question_set
from .oracle.client import NullOracle, OracleClient, SeedOracle
from .planir.validate import InvalidPlanIR
from .prepare import Prepared, PrepareOptions, prepare
from .prepare.context_limits import ContextLimits, apply_context_limits
from .prepare.redact import REDACTION_VERSION
from .prepare.redact_shapes import load_shapes
from .prepare.save_adds import UNREAD_SAVE, save_adds
from .prepare.views import (
    CALL,
    EXPOSURE,
    NEAR_MISS_VIEWS,
    REPUTATION,
    SELFEDIT_VIEWS,
    VIEW_KEYS,
    VIEW_VERSIONS,
    set_state_budget_tokens,
)
from .probes.base import Envelope, Probe
from .probes.context import ContextProbe
from .probes.jev import JevCallProbe, JevExposureProbe
from .probes.oracle import EntityOracleProbe, verdicts_for_view
from .response.models import EntityDisplay, Response

ALL_PROBES: tuple[ProbeStep, ...] = tuple(ProbeStep)
PROBE_TIMEOUT_S = 30.0


@dataclass
class ScanOptions:
    deterministic: bool = False
    clock: datetime | None = None
    salt: str | None = None
    repeat: int | None = None
    probes_enabled: tuple[str, ...] | None = None
    state_seed: dict[str, Any] | None = None
    oracle_seed: dict[str, Any] | None = None
    deployment: str | None = None


@dataclass
class ScanResult:
    response: Response
    envelopes: list[Envelope] = field(default_factory=list)
    prepared: Prepared | None = None
    converge: ConvergeResult | None = None
    #: The view each Jev probe is configured to send (from the question sets' `state_view`).
    jev_views: dict[str, str] = field(default_factory=lambda: {EXPOSURE: EXPOSURE, CALL: CALL})

    @property
    def prepared_views(self) -> dict[str, Any]:
        """What the Jev probes were sent (or, for a probe that did not run, the configured view), the
        view names and versions, the second redaction pass, and the history lineage (paths and
        steps only, never content), for the test-mode `prepared` block and the runner's parity
        checks (which apply only to `trim-v1` views)."""
        out: dict[str, Any] = {}
        for env in self.envelopes:
            if env.step in (ProbeStep.JEV_EXPOSURE, ProbeStep.JEV_CALL) and "state" in env.evidence:
                out[f"{env.step.value}_state"] = env.evidence["state"]
        redactions = 0
        if self.prepared is not None:
            out.setdefault("jev_exposure_state", self.prepared.views.get(self.jev_views[EXPOSURE]))
            out.setdefault("jev_call_state", self.prepared.views.get(self.jev_views[CALL]))
            redactions = sum(
                (self.prepared.view_meta.get(name) or {}).get("redactions", 0)
                for name in set(self.jev_views.values())
            )
        out["views"] = dict(self.jev_views)
        out["views_version"] = {k: VIEW_VERSIONS.get(v) for k, v in self.jev_views.items()}
        out["redaction"] = {
            "version": REDACTION_VERSION,
            "shapes": load_shapes().version,
            "count": redactions,
        }
        if self.prepared is not None:
            out["lineage"] = self.prepared.lineage.names(self.prepared.home)
        return out


@dataclass
class ScannerConfig:
    token_key: str | bytes
    jev: JevConfig = field(default_factory=JevConfig)
    decider: Decider | None = None
    oracle: OracleClient | None = None
    params: ConvergenceParams = field(default_factory=load_params)
    probes_enabled: tuple[str, ...] = tuple(p.value for p in ALL_PROBES)
    default_packs: tuple[str, ...] = ("tier1",)
    scanner_version: str = __version__
    #: Evaluation only (test mode): each request is cut down to these limits on arrival, as if the plugin had sent
    #: less (`prepare.context_limits`). The default limits nothing.
    context_limits: ContextLimits = field(default_factory=ContextLimits)
    #: Extra probe factories keyed by step (AIRA is registered this way so the package can be absent).
    extra_probes: dict[ProbeStep, Callable[[Prepared, ScannerConfig], Probe]] = field(
        default_factory=dict
    )


def _aira_factory(prepared: Prepared, config: ScannerConfig) -> Probe | None:
    try:
        from .probes.aira import AiraProbe  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 (an unfinished or broken AIRA module must not take the scan down)
        return None
    packs = tuple(prepared.planir.options.packs or config.default_packs)
    return AiraProbe(
        enabled_packs=set(packs),
        unvetted_package_sensitivity=config.params.oracle.unvetted_package_sensitivity,
        unvetted_package_as_root=config.params.oracle.unvetted_package_as_root,
        unvetted_package_ecosystems=tuple(config.params.oracle.unvetted_package_ecosystems),
    )


def views_label(jev_views: dict[str, str]) -> str:
    """The `metadata.versions.views` value: one views version, or one per probe when they differ."""
    versions = {k: VIEW_VERSIONS.get(v, v) for k, v in jev_views.items()}
    if len(set(versions.values())) == 1:
        return next(iter(versions.values()))
    return ",".join(f"{k}:{v}" for k, v in versions.items())


def view_budgets(question_sets: Iterable[QuestionSet | None]) -> tuple[int | None, int | None]:
    """The call-view and self-edit-view token budgets for the call question sets a scanner sends: each view is
    built to the room its tightest set leaves in the context, from the set's measured cost where it has one
    (`set_state_budget_tokens`; `None` for a view no set sends: the default reserve). A set that leaves no room at
    all stops startup."""
    call: int | None = None
    selfedit: int | None = None
    for qs in question_sets:
        if qs is None:
            continue
        budget = set_state_budget_tokens(qs)
        if budget <= 0:
            raise ValueError(
                f"question set {qs.name!r} leaves no room for the request in the context"
            )
        if qs.state_view in SELFEDIT_VIEWS:
            selfedit = budget if selfedit is None else min(selfedit, budget)
        else:
            call = budget if call is None else min(call, budget)
    return call, selfedit


def _pending_rule_findings(prepared: Prepared, envelopes: list[Envelope]) -> list[dict[str, Any]]:
    """The rule-based probe's findings on the pending call, for the self-edit reading to reuse (a probe that did not
    answer leaves none, and the save is not lenient for that reason anyway)."""
    from .aira.detectors import call_label

    label = call_label(prepared.pending)
    for env in envelopes:
        if env.step is ProbeStep.AIRA and env.status is ProbeStatus.OK:
            return [
                f
                for f in env.evidence.get("findings", [])
                if isinstance(f, dict) and f.get("call_id") == label
            ]
    return []


class Scanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        #: Loaded once; an unknown set name fails here, at startup.
        self.jev_question_sets: dict[str, QuestionSet] = {
            EXPOSURE: load_question_set(config.jev.exposure_question_set),
            CALL: load_question_set(config.jev.call_question_set),
        }
        self.jev_views: dict[str, str] = {
            k: qs.state_view for k, qs in self.jev_question_sets.items()
        }
        #: The call question set for declared self-edits (the host's own background saves); None sends them to
        #: the call set like any other call.
        self.selfedit_question_set: QuestionSet | None = (
            load_question_set(config.jev.selfedit_question_set)
            if config.jev.selfedit_question_set
            else None
        )
        self.call_budget_tokens, self.selfedit_budget_tokens = view_budgets(
            [self.jev_question_sets[CALL], self.selfedit_question_set]
        )

    @property
    def call_view_wants_reputation(self) -> bool:
        """The configured call view carries the entity library's verdicts (call-v3)."""
        return REPUTATION in VIEW_KEYS.get(self.jev_views.get(CALL, ""), ())

    def call_set_for(self, prepared: Prepared) -> QuestionSet:
        """The call question set for this request: the self-edit set for a declared self-edit, if configured."""
        if self.selfedit_question_set is not None and prepared.planir.is_self_edit:
            return self.selfedit_question_set
        return self.jev_question_sets[CALL]

    def views_for(self, prepared: Prepared) -> dict[str, str]:
        """The view each Jev probe sends for this request."""
        return {EXPOSURE: self.jev_views[EXPOSURE], CALL: self.call_set_for(prepared).state_view}

    def _probes(self, prepared: Prepared, options: ScanOptions) -> dict[ProbeStep, Probe | None]:
        cfg = self.config
        oracle: OracleClient
        if options.oracle_seed is not None:
            oracle = SeedOracle(options.oracle_seed)
        else:
            oracle = cfg.oracle or NullOracle()
        probes: dict[ProbeStep, Probe | None] = {
            ProbeStep.JEV_EXPOSURE: JevExposureProbe(
                cfg.decider, cfg.jev, self.jev_question_sets[EXPOSURE]
            )
            if cfg.decider is not None
            else None,
            ProbeStep.JEV_CALL: JevCallProbe(cfg.decider, cfg.jev, self.call_set_for(prepared))
            if cfg.decider is not None
            else None,
            ProbeStep.AIRA: cfg.extra_probes[ProbeStep.AIRA](prepared, cfg)
            if ProbeStep.AIRA in cfg.extra_probes
            else _aira_factory(prepared, cfg),
            ProbeStep.ENTITY_ORACLE: EntityOracleProbe(oracle, cfg.params.oracle),
            ProbeStep.CONTEXT: ContextProbe(cfg.params.context),
        }
        for step, factory in cfg.extra_probes.items():
            if step not in (ProbeStep.AIRA,):
                probes[step] = factory(prepared, cfg)
        return probes

    def _run_probe(
        self, step: ProbeStep, probe: Probe, prepared: Prepared, options: ScanOptions
    ) -> Envelope:
        t0 = time.perf_counter()
        try:
            if step in (ProbeStep.JEV_EXPOSURE, ProbeStep.JEV_CALL):
                return probe.run(prepared, repeat=options.repeat)  # type: ignore[call-arg]
            return probe.run(prepared)
        except Exception as e:  # noqa: BLE001 (last resort: a probe must not take the scan down)
            return Envelope.failed(
                step,
                ProbeStatus.ERROR,
                f"probe raised: {e!r}",
                getattr(probe, "versions", {}),
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

    def _credential_hint(
        self,
        prepared: Prepared,
        envelopes: list[Envelope],
        result: ConvergeResult,
        probes: dict[ProbeStep, Probe | None],
        enabled: tuple[str, ...],
        options: ScanOptions,
        views: dict[str, str],
    ) -> None:
        """Add the credential grant hint to `result.response` when one is verified (`converge.credential_hint`).
        `prepared` is a copy taken before convergence; nothing here changes the scan's own score or state."""
        from .converge import credential_hint as ch
        from .converge import exposure_unjudged

        params = self.config.params
        try:
            if not ch.eligible(
                prepared,
                envelopes,
                result.response,
                result.flags,
                params,
                exposure_unjudged=exposure_unjudged(prepared, envelopes),
            ):
                return

            def rerun(hyp: Prepared) -> dict[ProbeStep, Envelope]:
                out: dict[ProbeStep, Envelope] = {}
                for step in ch.RESCORED:
                    probe = probes.get(step)
                    if probe is not None and step.value in enabled:
                        out[step] = self._run_probe(step, probe, hyp, options)
                return out

            def rescore(hyp: Prepared, envs: list[Envelope]) -> ConvergeResult:
                return converge(
                    hyp,
                    envs,
                    params=params,
                    scanner_version=self.config.scanner_version,
                    token_key=self.config.token_key,
                    probes_enabled=list(enabled),
                    views=views_label(views),
                )

            found = ch.hint(prepared, envelopes, result.response, params, rescore, rerun)
        except Exception:  # noqa: BLE001 (a hint never fails a scan: without it the review stands as it is)
            return
        if found is not None:
            ch.add(result.response, found, params, prepared)
            if found.subject and found.subject not in result.response.entities:
                ent = prepared.entities.by_id(found.subject)
                if ent is not None:
                    result.response.entities[found.subject] = EntityDisplay(
                        kind=ent.kind.value, display=ent.display
                    )

    def scan(self, raw: dict[str, Any], options: ScanOptions | None = None) -> ScanResult:
        options = options or ScanOptions()
        started = time.perf_counter()
        clock = options.clock if (options.deterministic and options.clock) else datetime.now(tz=UTC)
        salt = options.salt if options.deterministic else None
        raw = apply_context_limits(raw, self.config.context_limits)
        try:
            prepared = prepare(
                raw,
                PrepareOptions(
                    token_key=self.config.token_key,
                    deployment=options.deployment,
                    clock=clock,
                    deterministic_salt=salt,
                    state_seed=options.state_seed,
                    call_budget_tokens=self.call_budget_tokens,
                    selfedit_budget_tokens=self.selfedit_budget_tokens,
                ),
            )
        except InvalidPlanIR as e:
            return ScanResult(
                response=Response.errored(
                    str(raw.get("request_id") or ""), self.config.scanner_version, e.code, e.message
                ),
                jev_views=dict(self.jev_views),
            )
        except Exception as e:  # noqa: BLE001 (a malformed body is an error response, never a 500)
            return ScanResult(
                response=Response.errored(
                    str(raw.get("request_id") or "") if isinstance(raw, dict) else "",
                    self.config.scanner_version,
                    "invalid_planir",
                    repr(e),
                ),
                jev_views=dict(self.jev_views),
            )

        enabled = tuple(options.probes_enabled or self.config.probes_enabled)
        probes = self._probes(prepared, options)
        envelopes: dict[ProbeStep, Envelope] = {}
        # A call view that carries the entity library's verdicts, and AIRA's look-alike and
        # steered-host checks, need the oracle's answer first; the oracle is deterministic and local
        # or one short HTTP round trip, the Jev call is the long one, so it runs alone before the
        # pool. Without the oracle (disabled or not configured) the view simply has no `reputation`
        # block and AIRA judges hosts by its own lists.
        oracle = probes.get(ProbeStep.ENTITY_ORACLE)
        views = self.views_for(prepared)
        wants_reputation = REPUTATION in VIEW_KEYS.get(views[CALL], ())
        aira_on = ProbeStep.AIRA.value in enabled and probes.get(ProbeStep.AIRA) is not None
        if (
            (wants_reputation or aira_on)
            and oracle is not None
            and ProbeStep.ENTITY_ORACLE.value in enabled
        ):
            env = self._run_probe(ProbeStep.ENTITY_ORACLE, oracle, prepared, options)
            envelopes[ProbeStep.ENTITY_ORACLE] = env
            if env.status is ProbeStatus.OK:
                prepared.oracle_entities = dict(env.evidence.get("entities") or {})
            if wants_reputation:
                prepared.oracle_verdicts = verdicts_for_view(
                    env, near_miss=views[CALL] in NEAR_MISS_VIEWS
                )
            if env.status is ProbeStatus.OK and self.config.params.credential_home:
                # A key sent only to its own service: AIRA, the context probe and convergence read the result.
                from .prepare.credential_home import check as credential_home_check

                (
                    prepared.credential_home,
                    prepared.credential_home_check,
                ) = credential_home_check(prepared)
            if env.status is ProbeStatus.OK and self.config.params.service_name_relief:
                # Hosts the owner's request names by their service: the call judge decides whether it means the service.
                from .prepare.service_names import candidates as service_candidates

                prepared.service_candidates = service_candidates(prepared)
        # The probes share one deadline: a probe still running then is recorded as timed out and left
        # behind (a thread cannot be stopped; what it returns later is never read), and the pool is
        # shut down without waiting for it. The deadline bounds the waits, not one long call: a probe
        # inside a single regex search holds the interpreter until the search returns, and the scan
        # answers only then. Keeping each search linear is what keeps the answer near the deadline.
        pool = ThreadPoolExecutor(max_workers=len(ALL_PROBES))
        try:
            futures = {}
            for step in ALL_PROBES:
                if step in envelopes:
                    continue
                probe = probes.get(step)
                if step.value not in enabled:
                    envelopes[step] = Envelope.skipped(
                        step, "disabled", getattr(probe, "versions", {}) if probe else {}
                    )
                elif probe is None:
                    envelopes[step] = Envelope.skipped(step, "not configured")
                else:
                    futures[step] = pool.submit(self._run_probe, step, probe, prepared, options)
            deadline = time.monotonic() + PROBE_TIMEOUT_S
            for step, fut in futures.items():
                try:
                    envelopes[step] = fut.result(timeout=max(0.0, deadline - time.monotonic()))
                except Exception as e:  # noqa: BLE001
                    envelopes[step] = Envelope.failed(
                        step, ProbeStatus.TIMEOUT, f"probe did not finish: {e!r}"
                    )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        ordered = [envelopes[step] for step in ALL_PROBES]

        # What a background save adds, for the plugins' handling of a save nobody can be asked about; no score reads it.
        reading = None
        if prepared.planir.is_self_edit:
            try:
                reading = save_adds(
                    prepared, rule_findings=_pending_rule_findings(prepared, ordered)
                )
            except Exception:  # noqa: BLE001 (the reading never fails a scan: unread, the save is not lenient)
                reading = UNREAD_SAVE
        # A reviewed send of a key to an unlisted service: the credential grant that would let it through, verified
        # by scoring a copy again with it (`converge.credential_hint`). Taken before converge mints the session sets
        # into `prepared`, so the copy starts from the state this scan started from.
        hint_copy: Prepared | None = None
        if credential_hint_candidate(prepared, self.config.params):
            try:
                hint_copy = copy.deepcopy(prepared)
            except Exception:  # noqa: BLE001 (no copy, no hint: the review stands as it is)
                hint_copy = None
        result = converge(
            prepared,
            ordered,
            params=self.config.params,
            scanner_version=self.config.scanner_version,
            token_key=self.config.token_key,
            started=started,
            probes_enabled=list(enabled),
            views=views_label(views),
            self_edit_reading=reading,
        )
        if hint_copy is not None:
            self._credential_hint(hint_copy, ordered, result, probes, enabled, options, views)
        return ScanResult(
            response=result.response,
            envelopes=ordered,
            prepared=prepared,
            converge=result,
            jev_views=views,
        )


def steps_from_csv(value: str | None, default: Iterable[str]) -> tuple[str, ...]:
    """Parse `SENTROOK_PROBES` (comma-separated probe names); unknown names are dropped."""
    if not value:
        return tuple(default)
    known = {p.value for p in ALL_PROBES}
    return tuple(v.strip() for v in value.split(",") if v.strip() in known)
