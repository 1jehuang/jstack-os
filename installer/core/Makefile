PYTHON ?= python3
CARGO ?= cargo

.PHONY: check fmt test clippy windows-check plan examples schemas

check: fmt test clippy windows-check plan examples schemas

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
		fixtures/windows-11-basic-gpt.json fixtures/release-requirements.json \
		> "$$temporary"; \
	diff -u generated/example-plan.json "$$temporary"; \
	$(CARGO) run --offline --quiet --bin jstack-plan -- --display \
		fixtures/windows-11-basic-gpt.json fixtures/release-requirements.json \
		> "$$temporary"; \
	diff -u generated/example-plan-display.json "$$temporary"

examples:
	@temporary=$$(mktemp -d); trap 'rm -rf "$$temporary"' EXIT; \
	$(PYTHON) tools/generate_integrity_examples.py \
		--plan generated/example-plan.json \
		--display generated/example-plan-display.json \
		--output "$$temporary"; \
	for name in example-confirmation.json example-journal-record.json example-journal-chain.json example-handoff.json; do \
		diff -u "generated/$$name" "$$temporary/$$name" || exit 1; \
	done

schemas:
	$(PYTHON) tools/validate_contracts.py
