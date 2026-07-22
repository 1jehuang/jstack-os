PYTHON ?= python3
CARGO ?= cargo
RUSTC ?= rustc
REQUIRED_RUSTC_VERSION := 1.85.0
REQUIRED_CARGO_VERSION := 1.85.0
export RUSTC

.PHONY: check toolchain fmt test clippy windows-check plan inventory release examples schemas collector

check: toolchain fmt test clippy windows-check plan inventory release examples schemas collector

toolchain:
	@rustc_actual="$$( $(RUSTC) --version | awk '{print $$2}')"; \
	cargo_actual="$$( $(CARGO) --version | awk '{print $$2}')"; \
	if [ "$$rustc_actual" != "$(REQUIRED_RUSTC_VERSION)" ] || [ "$$cargo_actual" != "$(REQUIRED_CARGO_VERSION)" ]; then \
		echo "error: installer core requires rustc $(REQUIRED_RUSTC_VERSION) and cargo $(REQUIRED_CARGO_VERSION) exactly; found rustc $${rustc_actual:-unknown}, cargo $${cargo_actual:-unknown}" >&2; \
		exit 1; \
	fi

fmt:
	$(CARGO) fmt --all -- --check

test:
	$(CARGO) test --offline

clippy:
	$(CARGO) clippy --offline --all-targets -- -D warnings

windows-check:
	$(CARGO) check --offline --target x86_64-pc-windows-msvc

plan:
	@temporary=$$(mktemp); trap 'rm -f "$$temporary"' EXIT; \
	$(CARGO) run --offline --quiet --bin jstack-plan -- \
		fixtures/windows-11-basic-gpt.json fixtures/signed-release-manifest.json \
		> "$$temporary"; \
	diff -u generated/example-plan.json "$$temporary"; \
	$(CARGO) run --offline --quiet --bin jstack-plan -- --display \
		fixtures/windows-11-basic-gpt.json fixtures/signed-release-manifest.json \
		> "$$temporary"; \
		diff -u generated/example-plan-display.json "$$temporary"

inventory:
	@temporary=$$(mktemp); trap 'rm -f "$$temporary"' EXIT; \
	$(CARGO) run --offline --quiet --bin jstack-inventory -- \
		--from-snapshot fixtures/windows-storage-snapshot.json > "$$temporary"; \
		diff -u generated/example-observed-inventory.json "$$temporary"

release:
	@temporary=$$(mktemp); trap 'rm -f "$$temporary"' EXIT; \
	$(CARGO) run --offline --quiet --bin jstack-release-fixture -- manifest > "$$temporary"; \
	cmp fixtures/signed-release-manifest.json "$$temporary"; \
	$(CARGO) run --offline --quiet --bin jstack-release-fixture -- acceptance > "$$temporary"; \
	cmp fixtures/release-acceptance-state.json "$$temporary"; \
	$(PYTHON) tools/validate_release_vectors.py

examples:
	@temporary=$$(mktemp -d); trap 'rm -rf "$$temporary"' EXIT; \
	$(PYTHON) tools/generate_integrity_examples.py \
		--plan generated/example-plan.json \
		--display generated/example-plan-display.json \
		--state-model ../model/installer-state-graph.json \
		--staging-evidence ../staging/fixtures/staging-evidence.json \
		--release-manifest fixtures/signed-release-manifest.json \
		--output "$$temporary"; \
	for name in example-confirmation.json example-journal-record.json example-journal-chain.json example-failure-evidence.json example-failure-journal-chain.json example-handoff.json example-destination-intent.json example-destination-commit.json; do \
		diff -u "generated/$$name" "$$temporary/$$name" || exit 1; \
	done

schemas:
	$(PYTHON) tools/validate_contracts.py

collector:
	$(PYTHON) tools/validate_windows_collector.py
	$(PYTHON) tools/test_windows_collector_mock.py
