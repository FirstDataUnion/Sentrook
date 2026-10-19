# Sentrook 2.0 scanner. Design and work packages: Notion, "Sentrook 2.0 build plan".
# Everything runs through uv; `make install` creates .venv with the dev extras.
.PHONY: help install test lint lint-fix schema schema-check

help:
	@echo "install       uv sync with dev extras"
	@echo "test          unit tests (sentrook/tests)"
	@echo "lint          ruff check + format check"
	@echo "lint-fix      ruff format + check --fix"
	@echo "schema        regenerate schema/*.json from the models"
	@echo "schema-check  fail if schema/*.json differ from the models"

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
