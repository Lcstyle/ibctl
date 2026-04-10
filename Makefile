# ibctl development targets

PYTHON := python
TOOLS  := tools
DASHBOARD := dashboard

# --- Config generation ---

.PHONY: generate-configs check-configs preflight test-preflight test-rust test

## Regenerate all config artifacts from Pkl schema.
## Run this after editing any file in config/pkl/.
generate-configs:
	@echo "Generating config artifacts from Pkl schema..."
	$(PYTHON) $(TOOLS)/generate_configs.py --target all
	$(PYTHON) $(TOOLS)/generate_configs.py --profile live --target compose
	$(PYTHON) $(TOOLS)/generate_configs.py --profile both --target compose
	$(PYTHON) $(TOOLS)/generate_configs.py --profile dashboard --target compose
	@echo "All artifacts regenerated."

## Check that generated files are in sync with Pkl source.
## Exits non-zero if drift is detected. Use in CI.
check-configs: generate-configs
	@if git diff --quiet docker/ibctl.toml ibctl.toml.example examples/; then \
		echo "Config files are in sync."; \
	else \
		echo "DRIFT DETECTED: generated files differ from Pkl source."; \
		echo "Run 'make generate-configs' and commit the result."; \
		git diff --stat docker/ibctl.toml ibctl.toml.example examples/; \
		exit 1; \
	fi

# --- Validation ---

## Run pre-flight config validation against docker/ibctl.toml.
preflight:
	cd $(DASHBOARD) && $(PYTHON) -m app.preflight --config ../docker/ibctl.toml --no-env

# --- Tests ---

## Run pre-flight Python tests.
test-preflight:
	cd $(DASHBOARD) && $(PYTHON) -m pytest tests/test_preflight.py -v

## Run Rust tests.
test-rust:
	cargo test

## Run all tests.
test: test-rust test-preflight
