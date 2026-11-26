"""Builds the scanner from a `ServeConfig`: the Jev client behind the configured base URL, the oracle
client (Rookery over HTTP when configured, otherwise the null oracle), the convergence parameter set
and, in test mode only, the ablation list. One runtime per process; every request reuses it."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from .. import __version__
from ..converge import load_params
from ..jev.client import OUTCOMES, Decider, DecisionsClient, JevConfig
from ..jev.health import JevHealth, TrackedDecider
from ..jev.routing import (
    FALLS_BACK_ON,
    MODE_PRIMARY,
    MODE_SECONDARY,
    PRIMARY,
    SECONDARY,
    RoutedDecider,
)
from ..jev.secondary import ChatCompletionsClient, SecondaryConfig
from ..oracle.client import HttpOracle, NullOracle, OracleClient
from ..scan import ALL_PROBES, Scanner, ScannerConfig, steps_from_csv
from .config import ServeConfig
from .metrics import init_jev_calls, record_jev_call
from .rate_limit import MemoryTokenBucketLimiter

logger = logging.getLogger("sentrook.serve")


@dataclass
class ServeRuntime:
    config: ServeConfig
    scanner: Scanner
    jev_health: JevHealth
    limiter: MemoryTokenBucketLimiter = field(default_factory=MemoryTokenBucketLimiter)

    @classmethod
    def build(
        cls,
        config: ServeConfig,
        *,
        decider: Decider | None = None,
        secondary: Decider | None = None,
        oracle: OracleClient | None = None,
    ) -> ServeRuntime:
        if config.lists_dir:
            os.environ.setdefault("SENTROOK_LISTS_DIR", config.lists_dir)
        jev = JevConfig(
            base_url=config.jev_base_url,
            api_key=config.jev_api_key,
            model=config.jev_model,
            timeout_s=config.jev_timeout_s,
            exposure_question_set=config.jev_exposure_question_set,
            call_question_set=config.jev_call_question_set,
            selfedit_question_set=config.jev_selfedit_question_set or None,
        )
        if decider is None:
            decider = DecisionsClient(jev)
            if (
                not config.jev_api_key
                and config.jev_route != MODE_SECONDARY
                and config.jev_base_url.rstrip("/") == JevConfig().base_url.rstrip("/")
            ):
                logger.warning(
                    "SENTROOK_JEV_API_KEY is not set; Jev probes will fail and scans will be degraded"
                )
        if config.jev_route != MODE_PRIMARY and secondary is None:
            assert config.jev_secondary_base_url and config.jev_secondary_model
            secondary = ChatCompletionsClient(
                SecondaryConfig(
                    base_url=config.jev_secondary_base_url,
                    model=config.jev_secondary_model,
                    api_key=config.jev_secondary_api_key,
                    timeout_s=config.jev_secondary_timeout_s,
                    structured=config.jev_secondary_structured,
                )
            )
        if config.jev_route != MODE_PRIMARY:
            logger.warning(
                "Jev route mode %s: the secondary route (%s) answers %s",
                config.jev_route,
                config.jev_secondary_model,
                "every call"
                if config.jev_route not in FALLS_BACK_ON
                else f"when the primary fails with {FALLS_BACK_ON[config.jev_route]}",
            )
        init_jev_calls(
            (PRIMARY,) if config.jev_route == MODE_PRIMARY else (PRIMARY, SECONDARY), OUTCOMES
        )
        decider = RoutedDecider(
            decider,
            secondary if config.jev_route != MODE_PRIMARY else None,
            mode=config.jev_route,
            observer=record_jev_call,
        )
        # With the secondary answering every call, the primary's key is not needed.
        jev_health = JevHealth(
            key_configured=bool(config.jev_api_key) or config.jev_route == MODE_SECONDARY
        )
        decider = TrackedDecider(decider, jev_health)
        if oracle is None:
            oracle = (
                HttpOracle(config.oracle_url, config.oracle_api_key)
                if config.oracle_url
                else NullOracle()
            )
        params = load_params(config.convergence)
        scanner = Scanner(
            ScannerConfig(
                token_key=config.state_key,
                jev=jev,
                decider=decider,
                oracle=oracle,
                params=params,
                probes_enabled=steps_from_csv(
                    ",".join(config.probes), (p.value for p in ALL_PROBES)
                )
                if config.probes
                else tuple(p.value for p in ALL_PROBES),
                default_packs=config.packs_default,
                scanner_version=__version__,
                context_limits=config.context_limits,
            )
        )
        return cls(config=config, scanner=scanner, jev_health=jev_health)

    def health_payload(self) -> dict:
        cfg = self.config
        payload = {
            "ok": True,
            "service": "sentrook-scan",
            "version": __version__,
            "environment": cfg.environment,
            "test_mode": cfg.test_mode,
            "jev": {
                "base_url": cfg.jev_base_url,
                "model": cfg.jev_model,
                "key_configured": bool(cfg.jev_api_key),
                **self.jev_health.snapshot(),
                "question_sets": {
                    "exposure": self.scanner.jev_question_sets["exposure"].name,
                    "call": self.scanner.jev_question_sets["call"].name,
                    "self_edit": self.scanner.selfedit_question_set.name
                    if self.scanner.selfedit_question_set
                    else None,
                },
                "views": dict(self.scanner.jev_views),
                **(
                    {
                        "route": cfg.jev_route,
                        # the secondary's address stays out: it may be a private host
                        "secondary": {
                            "model": cfg.jev_secondary_model,
                            "key_configured": bool(cfg.jev_secondary_api_key),
                        },
                    }
                    if cfg.jev_route != MODE_PRIMARY
                    else {}
                ),
            },
            "oracle": self.scanner.config.oracle.name if self.scanner.config.oracle else "null",
            "convergence": self.scanner.config.params.name,
            "probes_enabled": list(self.scanner.config.probes_enabled),
        }
        limits = self.scanner.config.context_limits
        if not limits.unlimited:
            # evaluation runs only (test mode): the limits the run's results were measured under
            payload["context_limits"] = limits.label()
        return payload
