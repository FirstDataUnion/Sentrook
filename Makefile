.PHONY: install install-dev test test-sentrook test-testnest sanitize-gate lint plugin-test smoke \
	sync-library testnest-core testnest-all require-library-mirror require-rookery test-engine

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

# L1/L2/scan_plan policy pytest lives in Rookery (tests/engine) — not duplicated here.
# Delegates to sibling Rookery. For uncommitted engine changes, point Rookery's
# [tool.uv.sources] sentrook at this checkout (editable) first — see TESTING.md.
require-rookery:
	@test -d "$(ROOKERY_ROOT)/tests/engine" || { \
		echo "Rookery checkout not found (need tests/engine) at: $(ROOKERY_ROOT)"; \
		echo "Clone FIDU-Rookery as a sibling, or set ROOKERY_ROOT=/path/to/Rookery."; \
		echo "Cross-repo strategy: $(ROOKERY_ROOT)/TESTING.md."; \
		exit 1; \
	}

test-engine: require-rookery
	$(MAKE) -C "$(ROOKERY_ROOT)" test-engine

# Plugin TS ↔ server Python sanitize + decision/replay parity (Rookery SoT).
# Same files Medivh ran; Rookery helpers resolve the plugin from this sibling checkout.
# Needs Rookery venv + Node. For uncommitted engine/plugin changes, use editable
# Sentrook pin in Rookery first — see TESTING.md.
sanitize-gate: require-rookery
	cd "$(ROOKERY_ROOT)" && $(ROOKERY_ROOT)/$(VENV)/bin/python -m pytest \
		tests/engine/test_scan_sanitize_parity.py \
		tests/engine/test_sanitize_replay_gate.py -q

plugin-test:
	cd integrations/openclaw/plugin && npm test && npm run pack:check

lint:
	$(PYTHON) -m compileall sentrook/sentrook testnest/testnest sentrook/tests testnest/tests

scan-demo:
	$(VENV)/bin/sentrook scan --plan fixtures/plans/safe_read_only.json --rules examples/rules
