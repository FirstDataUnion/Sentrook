"""Publish-surface check for the tree promoted to Sentrook-hermes."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..verify import EXPECTED_HOOKS

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REGISTER_HOOK_RE = re.compile(r'ctx\.register_hook\(\s*"([^"]+)"')

# Keep in sync with rsync --exclude in .github/workflows/release-hermes-plugin.yml.
ASSEMBLE_SKIP_DIRS = frozenset({"tests", "__pycache__", ".pytest_cache"})
ASSEMBLE_SKIP_SUFFIXES = frozenset({".pyc", ".pyo"})


def _load_manifest() -> dict:
    import yaml

    doc = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "plugin.yaml must parse to a mapping"
    return doc


def _stage_promote_tree(tmp_path: Path) -> Path:
    stage = tmp_path / "mirror"
    stage.mkdir()
    for src in PLUGIN_ROOT.iterdir():
        if src.name in ASSEMBLE_SKIP_DIRS:
            continue
        if src.suffix in ASSEMBLE_SKIP_SUFFIXES:
            continue
        dest = stage / src.name
        if src.is_dir():
            shutil.copytree(
                src,
                dest,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
        else:
            shutil.copy2(src, dest)
    return stage


def test_plugin_yaml_matches_expected_hooks() -> None:
    doc = _load_manifest()
    assert doc.get("name") == "sentrook"
    version = doc.get("version")
    assert isinstance(version, str) and version.strip(), (
        "plugin.yaml version must be a non-empty string"
    )
    assert version[0].isdigit(), f"plugin.yaml version looks empty/invalid: {version!r}"
    declared = {str(h).strip() for h in doc.get("provides_hooks") or [] if str(h).strip()}
    assert declared == set(EXPECTED_HOOKS), (
        "plugin.yaml provides_hooks must match EXPECTED_HOOKS "
        f"(missing={sorted(EXPECTED_HOOKS - declared)} extra={sorted(declared - EXPECTED_HOOKS)})"
    )


def test_register_covers_expected_hooks() -> None:
    text = (PLUGIN_ROOT / "__init__.py").read_text(encoding="utf-8")
    registered = set(REGISTER_HOOK_RE.findall(text))
    missing = sorted(EXPECTED_HOOKS - registered)
    assert not missing, f"register() is missing hooks declared in EXPECTED_HOOKS: {missing}"


def test_promote_tree_has_runtime_surface(tmp_path: Path) -> None:
    stage = _stage_promote_tree(tmp_path)
    assert (stage / "plugin.yaml").is_file()
    assert (stage / "__init__.py").is_file()
    assert not (stage / "tests").exists(), "promoted tree must not include plugin tests"

    runtime_py = sorted(p.name for p in PLUGIN_ROOT.glob("*.py"))
    assert "__init__.py" in runtime_py
    for name in runtime_py:
        assert (stage / name).is_file(), f"promote tree missing runtime module {name}"
