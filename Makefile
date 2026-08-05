.PHONY: install install-dev test test-sentrook test-testnest sanitize-gate lint plugin-test smoke \
	sync-library testnest-core testnest-all require-library-mirror

VENV ?= .venv
PYTHON := $(CURDIR)/$(VENV)/bin/python
ROOKERY_ROOT ?= $(CURDIR)/../FIDU-Rookery

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

# Local mirror of Rookery SoT (gitignored). See ../FIDU-Rookery/TESTING.md.
sync-library:
	ROOKERY_ROOT="$(ROOKERY_ROOT)" ./scripts/sync-rookery-library.sh

require-library-mirror:
	@test -d rules -a -d corpus -a -d eval/scenarios -a -d eval/plans || { \
		echo "Missing gitignored library mirror (rules/, corpus/, eval/)."; \
		echo "Run: make sync-library"; \
		echo "Or point TestNest at a sibling Rookery without copying:"; \
		echo "  testnest run --suite core --profile v0 \\"; \
		echo "    --scenarios ../FIDU-Rookery/eval/scenarios \\"; \
		echo "    --rules ../FIDU-Rookery/rules \\"; \
		echo "    --corpus ../FIDU-Rookery/corpus"; \
		echo "Cross-repo pin/sync details: ../FIDU-Rookery/TESTING.md"; \
		exit 1; \
	}

testnest-core: require-library-mirror
	$(VENV)/bin/testnest run --suite core --profile v0 \
		--scenarios eval/scenarios --rules rules --corpus corpus

testnest-all: require-library-mirror
	$(VENV)/bin/testnest run --suite all --profile v0 \
		--scenarios eval/scenarios --rules rules --corpus corpus

sanitize-gate:
	@echo "Sanitize parity against policy suites lives in Rookery; plugin unit tests:"
	cd integrations/openclaw/plugin && npm test

plugin-test:
	cd integrations/openclaw/plugin && npm test && npm run pack:check

lint:
	$(PYTHON) -m compileall sentrook/sentrook testnest/testnest sentrook/tests testnest/tests

scan-demo:
	$(VENV)/bin/sentrook scan --plan fixtures/plans/safe_read_only.json --rules examples/rules
