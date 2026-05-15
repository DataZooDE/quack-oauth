PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=quack_oauth
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# ---------------------------------------------------------------------------
# Catch2 unit tests (pure-logic, no DuckDB linkage). The binary is built as
# part of the main release build; this target just runs it.
# ---------------------------------------------------------------------------
.PHONY: unit_test
unit_test: release
	@if [ ! -x build/release/test/quack_oauth_unit_tests ]; then \
		echo "build/release/test/quack_oauth_unit_tests not found -- check Catch2 in vcpkg.json"; \
		exit 1; \
	fi
	./build/release/test/quack_oauth_unit_tests --reporter console::out=-

# ---------------------------------------------------------------------------
# Static-linkage smoke test. Assert the loadable extension only links against
# the platform's standard libraries. See docs/IMPLEMENTATION.md section 6.
# ---------------------------------------------------------------------------
.PHONY: smoke_static
smoke_static: release
	@./scripts/check_static_linkage.sh \
		build/release/extension/quack_oauth/quack_oauth.duckdb_extension

# ---------------------------------------------------------------------------
# Keycloak integration test (S-7b.3). Brings up a docker-compose Keycloak,
# acquires a real ROPC token, materialises a SQL test from a template, runs
# it through the DuckDB unittest binary, and tears the container down.
# Requires `docker compose` and port 8080 on localhost.
# ---------------------------------------------------------------------------
.PHONY: integration_keycloak
integration_keycloak: release
	@./scripts/run_integration_keycloak.sh

# ---------------------------------------------------------------------------
# Google tokeninfo integration test (S-11b/Google + tokeninfo dispatch).
# Mints a fresh service-account access token from .env.google and validates
# it via Google's tokeninfo endpoint. Requires network access; no container.
# ---------------------------------------------------------------------------
.PHONY: integration_google
integration_google: release
	@./scripts/run_integration_google.sh

# ---------------------------------------------------------------------------
# Quickstart demo. Brings up the same Keycloak compose used by the
# integration tests, configures a server SECRET + a SQL policy table,
# walks through token validation + an allowed query + a denied query
# + the audit log + diagnose(), then tears the container down.
# Intended for human readers: prints commentary as it goes.
# ---------------------------------------------------------------------------
.PHONY: demo
demo: release
	@./scripts/demo.sh

# ---------------------------------------------------------------------------
# End-to-end harness: a real `quack` server with our extension's callbacks
# swapped in, driven by a Python DuckDB client via the quack wire protocol.
# Requires `uv` (https://github.com/astral-sh/uv) + `INSTALL quack` having
# been run once via the duckdb CLI. The harness lives at e2e/ so DuckDB's
# unittest scanner (which globs `test/`) does not stumble over the venv.
# ---------------------------------------------------------------------------
.PHONY: e2e
e2e: release
	@cd e2e && uv sync --frozen && uv run pytest
