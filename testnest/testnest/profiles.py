from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from sentrook.config import ScannerConfig


class Profile(BaseModel):
    """A TestNest profile: the scanner configuration to run scenarios under."""

    name: str
    description: str = ""
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)


def load_profiles(scenarios_dir: Path) -> dict[str, Profile]:
    """Load ``profiles.yaml`` (profile name → ScannerConfig). Empty when absent."""
    path = scenarios_dir / "profiles.yaml"
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    profiles: dict[str, Profile] = {}
    for name, spec in (raw.get("profiles") or {}).items():
        spec = spec or {}
        profiles[name] = Profile(
            name=name,
            description=spec.get("description", ""),
            scanner=ScannerConfig.model_validate(spec.get("scanner") or {}),
        )
    return profiles


def resolve_scanner_config(scenarios_dir: Path, profile: str) -> ScannerConfig:
    """Scanner config for a profile.

    Falls back to the library default (:class:`ScannerConfig`) when a profile has no
    scanner preset, so all three layers stay enabled unless explicitly configured off.
    """
    found = load_profiles(scenarios_dir).get(profile)
    if found is not None:
        return found.scanner
    return ScannerConfig()
