# Sentrook 2.0 scanner.
# Everything runs through uv; `make install` creates .venv with the dev extras.
.PHONY: help install test lint lint-fix schema schema-check redact-shapes redact-shapes-check \
	plugin-test hermes-plugin-test plugin-planir-check compat-test hermes-compat openclaw-compat \
	hermes-release-test openclaw-release-test

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
	@echo "compat-test   unit tests of the host compatibility CI helpers (integrations/compat)"
	@echo "hermes-compat the Hermes plugin on real Hermes images (needs Docker): the pinned floor and"
	@echo "              latest, or HERMES_IMAGE=<image>"
	@echo "openclaw-compat  the OpenClaw plugin on real OpenClaw images (needs Docker and Node): the"
	@echo "              pinned floor and latest, or OPENCLAW_IMAGE=<image>"
	@echo "hermes-release-test  the Hermes plugin release steps (integrations/hermes/release)"
	@echo "openclaw-release-test  the OpenClaw plugin release steps (integrations/openclaw/release; needs npm)"

# The gitleaks release the vendor key shapes of the second redaction pass are generated from.
# Also the gitleaks image security.yml scans with. CI checks the file against it;
# .github/workflows/redact-shapes-refresh.yml moves it.
GITLEAKS_TAG ?= v8.30.1

install:
	uv sync --extra dev

# Four pytest-xdist workers, as many as a CI runner has CPUs. Not `auto`: on a laptop with slower
# efficiency cores a timing test's two runs can land on different kinds of core.
# PYTEST_WORKERS=0 runs in one process.
PYTEST_WORKERS ?= 4
test:
	uv run pytest sentrook/tests -q -n $(PYTEST_WORKERS)

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
	rm -f tmp/openclaw-planirs.json
	cd $(OPENCLAW_PLUGIN) && SENTROOK_PLANIR_DUMP=$(CURDIR)/tmp/openclaw-planirs.json \
		node --experimental-strip-types --test --test-name-pattern="allow, block|tool_call wrapper is not scanned|must declare|Code Mode cell|own shipped skill" index.test.ts
	cd $(OPENCLAW_PLUGIN) && SENTROOK_PLANIR_DUMP=$(CURDIR)/tmp/openclaw-planirs.json \
		node --experimental-strip-types --test --test-name-pattern="goes to the next scan" setupReport.test.ts proposals.test.ts
	rm -rf tmp/hermes-planirs tmp/hermes-planirs.json
	SENTROOK_PLANIR_DUMP_DIR=$(CURDIR)/tmp/hermes-planirs uv run python -m pytest -q \
		integrations/hermes/plugin/tests/test_plugin.py integrations/hermes/plugin/tests/test_setup_report.py \
		integrations/hermes/plugin/tests/test_proposals.py -k episode
	uv run python -c "import glob, json; from sentrook.planir.models import PlanIR; \
	from sentrook.planir.validate import check; \
	hermes = sorted(glob.glob('tmp/hermes-planirs/*.json')); assert hermes, 'no Hermes PlanIR dumps'; \
	raws = [r for f in ['tmp/openclaw-planirs.json', *hermes] for r in json.load(open(f))]; \
	[check(PlanIR.model_validate(r), r.get('scan_kind')) for r in raws]; \
	print(f'{len(raws)} plugin PlanIRs valid ({len(hermes)} Hermes dumps)')"

compat-test:
	uv run python -m pytest integrations/compat/tests -q

# The Hermes plugin release steps (release-hermes-plugin.yml), against a local stand-in for the mirror.
hermes-release-test:
	uv run python -m pytest integrations/hermes/release/tests -q

# The OpenClaw plugin release steps (release-plugin.yml): version, CHANGELOG, channel, the packed artifact.
openclaw-release-test:
	uv run python -m pytest integrations/openclaw/release/tests -q

# The blocking set by default; HERMES_IMAGE=nousresearch/hermes-agent:main for any other image.
HERMES_IMAGE ?= $(shell python3 integrations/compat/compat.py images --host hermes)
hermes-compat:
	for image in $(HERMES_IMAGE); do integrations/hermes/compat/run.sh "$$image" || exit 1; done

# The blocking set by default; OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw:main for any other image.
OPENCLAW_IMAGE ?= $(shell python3 integrations/compat/compat.py images --host openclaw)
openclaw-compat:
	for image in $(OPENCLAW_IMAGE); do integrations/openclaw/compat/run.sh "$$image" || exit 1; done
