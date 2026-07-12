# ibctl development targets

PYTHON := python
TOOLS  := tools
DASHBOARD := dashboard

# --- Config generation ---

.PHONY: generate-configs regenerate-configs check-configs preflight test-preflight test-rust test

# Pkl runtime version we generate against. Pinned in mise.toml at repo root
# — if you see the "unexpected Pkl version" error below, run `mise install`
# to get the matching runtime. Bumping this value is a deliberate action;
# regenerate all artifacts and diff before committing.
PKL_EXPECTED_VERSION := 0.32

## Verify the Pkl CLI is on PATH and pinned to the expected version.
## Called from generate-configs so schema drift can't sneak in from a
## developer running an older or newer local Pkl.
.PHONY: check-pkl-version
check-pkl-version:
	@command -v pkl >/dev/null 2>&1 || { \
		echo "ERROR: pkl not on PATH. Install via 'mise install' (see mise.toml)." >&2; \
		exit 1; \
	}
	@pkl_v=$$(pkl --version 2>&1 | awk '{print $$2}'); \
	case "$$pkl_v" in \
		$(PKL_EXPECTED_VERSION).*) \
			echo "pkl version $$pkl_v (expected $(PKL_EXPECTED_VERSION).x)" ;; \
		*) \
			echo "ERROR: pkl version $$pkl_v does not match expected $(PKL_EXPECTED_VERSION).x" >&2; \
			echo "  Run 'mise install' at the repo root to sync to the pinned version." >&2; \
			exit 1 ;; \
	esac

## Regenerate all config artifacts from Pkl schema.
## Mutates the working tree — run this after editing any file in config/pkl/.
## Requires the pinned Pkl runtime; call `mise install` first if not present.
regenerate-configs: check-pkl-version
	@echo "Generating config artifacts from Pkl schema..."
	$(PYTHON) $(TOOLS)/generate_configs.py --target all
	$(PYTHON) $(TOOLS)/generate_configs.py --profile live --target compose
	$(PYTHON) $(TOOLS)/generate_configs.py --profile both --target compose
	$(PYTHON) $(TOOLS)/generate_configs.py --profile dashboard --target compose
	@echo "All artifacts regenerated."

## Legacy alias — kept so existing docs / muscle memory still work.
## Prefer `regenerate-configs` in new callers to make mutation explicit.
generate-configs: regenerate-configs

## Pure check: verify tracked generated artifacts are up to date with the
## Pkl source, without mutating the working tree.
## Runs in CI without needing Pkl installed. Two guards:
##   1. Any uncommitted modification to a tracked generated artifact means
##      someone edited the generated file by hand OR forgot to commit after
##      regenerating.
##   2. Any untracked file under config/ suggests a new schema file that was
##      never wired into the generator; flag it so it can't rot silently.
check-configs:
	@dirty=$$(git status --porcelain -- docker/ibctl.toml ibctl.toml.example examples/ dashboard/app/preflight/descriptions.json); \
	if [ -n "$$dirty" ]; then \
		echo "DRIFT DETECTED: generated files have local modifications."; \
		echo "Run 'make regenerate-configs' and commit the result."; \
		echo "$$dirty"; \
		exit 1; \
	fi; \
	untracked=$$(git status --porcelain -- config/ | grep '^??' || true); \
	if [ -n "$$untracked" ]; then \
		echo "WARNING: untracked files under config/ — may indicate stale schema wiring:"; \
		echo "$$untracked"; \
	fi; \
	echo "Generated artifacts match tracked source."

# --- Validation ---

## Run pre-flight config validation against docker/ibctl.toml.
preflight:
	cd $(DASHBOARD) && $(PYTHON) -m app.preflight --config ../docker/ibctl.toml --no-env

# --- Tests ---

## Run pre-flight Python tests.
## Glob covers test_preflight.py + any test_preflight_*.py sibling files
## (e.g. test_preflight_recovery.py). Do NOT tighten to a single filename —
## the audit-fix test suite caught this exact regression.
test-preflight:
	cd $(DASHBOARD) && $(PYTHON) -m pytest tests/test_preflight.py tests/test_preflight_*.py -v

## Run Rust tests.
test-rust:
	cargo test

## Run all tests.
test: test-rust test-preflight
