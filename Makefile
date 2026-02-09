# =============================================================================
# VBW Makefile — Standard build, test, and quality targets
# =============================================================================
# Usage: make <target>
#
# Targets mirror CI pipeline stages for local development parity.

SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help build test check fmt clippy audit deny clean release verify-example

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build: ## Build debug binary
	cargo build

release: ## Build release binary
	cargo build --release

# ---------------------------------------------------------------------------
# Quality gates (mirrors CI)
# ---------------------------------------------------------------------------
fmt: ## Check formatting
	cargo fmt --all -- --check

clippy: ## Run clippy with strict warnings
	cargo clippy --all-targets --all-features -- -D warnings -D clippy::pedantic \
		-A clippy::module_name_repetitions -A clippy::must_use_candidate

test: ## Run all tests (debug + release)
	cargo test --all-features
	cargo test --release --all-features

audit: ## Run security audit
	cargo audit

deny: ## Run cargo-deny checks (licenses, bans, advisories, sources)
	cargo deny check

check: fmt clippy test audit deny ## Run all quality gates (full CI equivalent)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
clean: ## Remove build artifacts
	cargo clean

verify-example: release ## Run VBW against the example bundle
	./target/release/vbw verify examples/minimal-bundle \
		--no-external --dry-run --slsa-mode schema-only
	@echo "---"
	@cat examples/minimal-bundle/vbw/report.json
