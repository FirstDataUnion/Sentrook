.PHONY: install install-dev test test-sentrook test-testnest sanitize-gate lint plugin-test smoke

VENV ?= .venv
PYTHON := $(CURDIR)/$(VENV)/bin/python

install:
	uv pip install -e .

install-dev:
	uv pip install -e ".[dev,ner]"
	uv pip install -e ./testnest
	$(PYTHON) -m spacy download en_core_web_sm || true

test: test-sentrook test-testnest

test-sentrook:
	$(PYTHON) -m pytest sentrook/tests -q

test-testnest:
	cd testnest && $(PYTHON) -m pytest tests -q

smoke:
	$(VENV)/bin/testnest run --suite smoke --profile v0 \
		--rules examples/rules --corpus examples/corpus

sanitize-gate:
	@echo "Sanitize parity against policy suites lives in Rookery; plugin unit tests:"
	cd integrations/openclaw/plugin && npm test

plugin-test:
	cd integrations/openclaw/plugin && npm test && npm run pack:check

lint:
	$(PYTHON) -m compileall sentrook/sentrook testnest/testnest sentrook/tests testnest/tests

scan-demo:
	$(VENV)/bin/sentrook scan --plan fixtures/plans/safe_read_only.json --rules examples/rules
