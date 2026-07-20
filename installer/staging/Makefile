PYTHON ?= python3
CARGO ?= cargo

.PHONY: check fmt test clippy windows-check contracts

check: fmt test clippy windows-check contracts

fmt:
	$(CARGO) fmt --all -- --check

test:
	$(CARGO) test --offline --all-targets

clippy:
	$(CARGO) clippy --offline --all-targets -- -D warnings

windows-check:
	$(CARGO) check --offline --target x86_64-pc-windows-msvc

contracts:
	$(PYTHON) tools/validate_contracts.py
