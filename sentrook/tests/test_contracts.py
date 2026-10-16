"""The committed JSON Schemas match the models, and the worked examples validate against them."""

from __future__ import annotations

import json

import jsonschema
import pytest

from sentrook import contracts
from sentrook.cli import main


def test_committed_schemas_are_current():
    assert contracts.drift() == [], "schema/*.json differ from the models; run `make schema`"


@pytest.mark.parametrize("name", list(contracts.CONTRACTS))
def test_schema_is_valid_draft_2020_12(name):
    schema = json.loads(contracts.render(name))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith(name)


def test_worked_examples_validate_against_planir_schema(attack_case, twin_case):
    schema = json.loads(contracts.render("planir-2.0.schema.json"))
    validator = jsonschema.Draft202012Validator(schema)
    for case in (attack_case, twin_case):
        errors = sorted(validator.iter_errors(case["fixture"]), key=lambda e: list(e.path))
        assert errors == [], [e.message for e in errors]


def test_cli_schema_check(tmp_path, capsys):
    assert main(["schema", "export", "--out", str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(contracts.CONTRACTS)
    assert main(["schema", "export", "--out", str(tmp_path), "--check"]) == 0
    (tmp_path / "envelope.schema.json").write_text("{}")
    assert main(["schema", "export", "--out", str(tmp_path), "--check"]) == 1
    assert "envelope.schema.json" in capsys.readouterr().err
