"""Builds the scanner from a `ServeConfig`: the Jev client behind the configured base URL, the oracle
client (Rookery over HTTP when configured, otherwise the null oracle), the convergence parameter set
and, in test mode only, the ablation list. One runtime per process; every request reuses it."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from .. import __version__
from ..converge import load_params
from ..jev.client import Decider, DecisionsClient, JevConfig
from ..oracle.client import HttpOracle, NullOracle, OracleClient
from ..scan import ALL_PROBES, Scanner, ScannerConfig, steps_from_csv
from .config import ServeConfig
from .rate_limit import MemoryTokenBucketLimiter

logger = logging.getLogger("sentrook.serve")


@dataclass
class ServeRuntime:
    config: ServeConfig
    scanner: Scanner
    limiter: MemoryTokenBucketLimiter = field(default_factory=MemoryTokenBucketLimiter)

    @classmethod
    def build(
        cls,
        config: ServeConfig,
        *,
        decider: Decider | None = None,
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
        )
        if decider is None:
            decider = DecisionsClient(jev)
            if not config.jev_api_key and config.jev_base_url.rstrip(
                "/"
            ) == JevConfig().base_url.rstrip("/"):
                logger.warning(
                    "SENTROOK_JEV_API_KEY is not set; Jev probes will fail and scans will be degraded"
                )
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
            )
        )
        return cls(config=config, scanner=scanner)

    def health_payload(self) -> dict:
        cfg = self.config
        return {
            "ok": True,
            "service": "sentrook-scan",
            "version": __version__,
            "environment": cfg.environment,
            "test_mode": cfg.test_mode,
            "jev": {
                "base_url": cfg.jev_base_url,
                "model": cfg.jev_model,
                "key_configured": bool(cfg.jev_api_key),
                "question_sets": {
                    "exposure": self.scanner.jev_question_sets["exposure"].name,
                    "call": self.scanner.jev_question_sets["call"].name,
                },
                "views": dict(self.scanner.jev_views),
            },
            "oracle": self.scanner.config.oracle.name if self.scanner.config.oracle else "null",
            "convergence": self.scanner.config.params.name,
            "probes_enabled": list(self.scanner.config.probes_enabled),
        }
