# Sentrook 2.0 scanner.
# Everything runs through uv; `make install` creates .venv with the dev extras.
.PHONY: help install test lint lint-fix schema schema-check redact-shapes redact-shapes-check \
	plugin-test hermes-plugin-test plugin-planir-check

help:
	@echo "install       uv sync with dev extras"
	@echo "test          unit tests (sentrook/tests)"
	@echo "lint          ruff check + format check"
	@echo "lint-fix      ruff format + check --fix"
	@echo "schema        regenerate schema/*.json from the models"
	@echo "schema-check  fail if schema/*.json differ from the models"
	@echo "redact-shapes regenerate prepare/redact_shapes.yaml from gitleaks $(GITLEAKS_TAG)"
	@echo "redact-shapes-check  fail if redact_shapes.yaml differs from gitleaks $(GITLEAKS_TAG) (CI;"
	@echo "              a weekly workflow opens a PR moving GITLEAKS_TAG to each new release)"
	@echo "plugin-test   OpenClaw plugin: unit tests, typecheck, build and npm pack check (needs npm ci)"
	@echo "hermes-plugin-test   Hermes plugin unit tests"
	@echo "plugin-planir-check  validate both plugins' PlanIR requests with the scanner's models"

# The gitleaks release the vendor key shapes of the second redaction pass are generated from.
# Also the gitleaks image security.yml scans with. CI checks the file against it;
# .github/workflows/redact-shapes-refresh.yml moves it.
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

redact-shapes-check:
	uv run sentrook redact-shapes import --tag $(GITLEAKS_TAG) --check

OPENCLAW_PLUGIN := integrations/openclaw/plugin

plugin-test:
	cd $(OPENCLAW_PLUGIN) && npm test && npm run typecheck && npm run pack:check

hermes-plugin-test:
	uv run python -m pytest integrations/hermes/plugin/tests -q

# Each plugin's integration test dumps the PlanIR requests it built; the scanner's models and invariant
# checks must accept every one.
plugin-planir-check:
	mkdir -p tmp
	cd $(OPENCLAW_PLUGIN) && SENTROOK_PLANIR_DUMP=$(CURDIR)/tmp/openclaw-planirs.json \
		node --experimental-strip-types --test --test-name-pattern="allow, block" index.test.ts
	SENTROOK_PLANIR_DUMP=$(CURDIR)/tmp/hermes-planirs.json uv run python -m pytest -q \
		integrations/hermes/plugin/tests/test_plugin.py -k episode
	uv run python -c "import json; from sentrook.planir.models import PlanIR; \
	from sentrook.planir.validate import check; \
	raws = [r for h in ('openclaw', 'hermes') for r in json.load(open(f'tmp/{h}-planirs.json'))]; \
	[check(PlanIR.model_validate(r), r.get('scan_kind')) for r in raws]; \
	print(f'{len(raws)} plugin PlanIRs valid')"
