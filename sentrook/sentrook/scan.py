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

import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .converge import ConvergenceParams, ConvergeResult, converge, load_params
from .enums import ProbeStatus, ProbeStep
from .jev.client import Decider, JevConfig
from .jev.questions import QuestionSet, load_question_set
from .oracle.client import NullOracle, OracleClient, SeedOracle
from .planir.validate import InvalidPlanIR
from .prepare import Prepared, PrepareOptions, prepare
from .prepare.redact import REDACTION_VERSION
from .prepare.redact_shapes import load_shapes
from .prepare.views import CALL, EXPOSURE, REPUTATION, VIEW_KEYS, VIEW_VERSIONS
from .probes.base import Envelope, Probe
from .probes.context import ContextProbe
from .probes.jev import JevCallProbe, JevExposureProbe
from .probes.oracle import EntityOracleProbe, verdicts_for_view
from .response.models import Response

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
    return AiraProbe(enabled_packs=set(packs))


def views_label(jev_views: dict[str, str]) -> str:
    """The `metadata.versions.views` value: one views version, or one per probe when they differ."""
    versions = {k: VIEW_VERSIONS.get(v, v) for k, v in jev_views.items()}
    if len(set(versions.values())) == 1:
        return next(iter(versions.values()))
    return ",".join(f"{k}:{v}" for k, v in versions.items())


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

    @property
    def call_view_wants_reputation(self) -> bool:
        """The configured call view carries the entity library's verdicts (call-v3)."""
        return REPUTATION in VIEW_KEYS.get(self.jev_views.get(CALL, ""), ())

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
            ProbeStep.JEV_CALL: JevCallProbe(cfg.decider, cfg.jev, self.jev_question_sets[CALL])
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

    def scan(self, raw: dict[str, Any], options: ScanOptions | None = None) -> ScanResult:
        options = options or ScanOptions()
        started = time.perf_counter()
        clock = options.clock if (options.deterministic and options.clock) else datetime.now(tz=UTC)
        salt = options.salt if options.deterministic else None
        try:
            prepared = prepare(
                raw,
                PrepareOptions(
                    token_key=self.config.token_key,
                    deployment=options.deployment,
                    clock=clock,
                    deterministic_salt=salt,
                    state_seed=options.state_seed,
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
        # A call view that carries the entity library's verdicts needs the oracle's answer first;
        # the oracle is deterministic and local or one short HTTP round trip, the Jev call is the
        # long one, so it runs alone before the pool. Without the oracle (disabled or not
        # configured) the view simply has no `reputation` block.
        oracle = probes.get(ProbeStep.ENTITY_ORACLE)
        if (
            self.call_view_wants_reputation
            and oracle is not None
            and ProbeStep.ENTITY_ORACLE.value in enabled
        ):
            env = self._run_probe(ProbeStep.ENTITY_ORACLE, oracle, prepared, options)
            envelopes[ProbeStep.ENTITY_ORACLE] = env
            prepared.oracle_verdicts = verdicts_for_view(env)
        with ThreadPoolExecutor(max_workers=len(ALL_PROBES)) as pool:
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
            for step, fut in futures.items():
                try:
                    envelopes[step] = fut.result(timeout=PROBE_TIMEOUT_S)
                except Exception as e:  # noqa: BLE001
                    envelopes[step] = Envelope.failed(
                        step, ProbeStatus.TIMEOUT, f"probe did not finish: {e!r}"
                    )
        ordered = [envelopes[step] for step in ALL_PROBES]

        result = converge(
            prepared,
            ordered,
            params=self.config.params,
            scanner_version=self.config.scanner_version,
            token_key=self.config.token_key,
            started=started,
            probes_enabled=list(enabled),
            views=views_label(self.jev_views),
        )
        return ScanResult(
            response=result.response,
            envelopes=ordered,
            prepared=prepared,
            converge=result,
            jev_views=dict(self.jev_views),
        )


def steps_from_csv(value: str | None, default: Iterable[str]) -> tuple[str, ...]:
    """Parse `SENTROOK_PROBES` (comma-separated probe names); unknown names are dropped."""
    if not value:
        return tuple(default)
    known = {p.value for p in ALL_PROBES}
    return tuple(v.strip() for v in value.split(",") if v.strip() in known)
