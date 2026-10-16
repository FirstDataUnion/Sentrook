from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / "planir" / name).read_text(encoding="utf-8"))


@pytest.fixture
def attack_case() -> dict:
    return load_fixture("worked-example-attack.json")


@pytest.fixture
def twin_case() -> dict:
    return load_fixture("worked-example-twin.json")
