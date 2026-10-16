"""The wire contracts as JSON Schema, generated from the pydantic models.

`schema/` in the repo root holds the committed output; `make schema-check` (and a unit test) fail when
the committed files drift from the models, so the models stay the single source and the files stay
readable by tools in any language (the TestNest runner, the fixture linter, a plugin).

The schemas list the known enum values. The scanner itself is tolerant (see `enums.TolerantStrEnum`):
a linter may be strict on these files while unknown values still validate at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from . import __version__
from .planir.models import PlanIR
from .probes.base import Envelope
from .response.models import Response

SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
ID_BASE = "https://sentrook.firstdataunion.org/schema/"

CONTRACTS: dict[str, tuple[type[BaseModel], str]] = {
    "planir-2.0.schema.json": (PlanIR, "PlanIR 2.0: the scan request a plugin sends to Sentrook"),
    "response-2.0.schema.json": (
        Response,
        "Response 2.0: the risk tree Sentrook returns to the plugin",
    ),
    "envelope.schema.json": (
        Envelope,
        "Probe result envelope: what each probe returns to convergence",
    ),
}


def render(name: str) -> str:
    model, description = CONTRACTS[name]
    schema = model.model_json_schema(mode="validation")
    schema = {
        "$schema": SCHEMA_DIALECT,
        "$id": ID_BASE + name,
        "title": schema.get("title", model.__name__),
        "description": f"{description}. Generated from sentrook {__version__} models; do not edit by hand.",
        **{k: v for k, v in schema.items() if k not in ("title",)},
    }
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def default_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "schema"


def export(out_dir: Path | None = None) -> list[Path]:
    out = out_dir or default_dir()
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name in CONTRACTS:
        path = out / name
        path.write_text(render(name), encoding="utf-8")
        written.append(path)
    return written


def drift(out_dir: Path | None = None) -> list[str]:
    """Names of committed schema files that differ from (or are missing against) the models."""
    out = out_dir or default_dir()
    stale = []
    for name in CONTRACTS:
        path = out / name
        if not path.exists() or path.read_text(encoding="utf-8") != render(name):
            stale.append(name)
    return stale
