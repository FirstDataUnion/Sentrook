# Sentrook 2.0 scanner. Design and work packages: Notion, "Sentrook 2.0 build plan".
# Everything runs through uv; `make install` creates .venv with the dev extras.
.PHONY: help install test lint lint-fix schema schema-check redact-shapes

help:
	@echo "install       uv sync with dev extras"
	@echo "test          unit tests (sentrook/tests)"
	@echo "lint          ruff check + format check"
	@echo "lint-fix      ruff format + check --fix"
	@echo "schema        regenerate schema/*.json from the models"
	@echo "schema-check  fail if schema/*.json differ from the models"
	@echo "redact-shapes regenerate prepare/redact_shapes.yaml from gitleaks $(GITLEAKS_TAG)"

# The gitleaks release the vendor key shapes of the second redaction pass are generated from.
GITLEAKS_TAG ?= v8.30.1

install:
	uv sync --extra dev

test:
	uv run pytest sentrook/tests -q

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff format .
	uv run ruff check . --fix

schema:
	uv run sentrook schema export

schema-check:
	uv run sentrook schema export --check

redact-shapes:
	uv run sentrook redact-shapes import --tag $(GITLEAKS_TAG)
