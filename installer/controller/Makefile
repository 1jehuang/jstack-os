CARGO ?= cargo
RUSTC ?= rustc
REQUIRED_RUSTC_VERSION := 1.85.0
REQUIRED_CARGO_VERSION := 1.85.0
export RUSTC

.PHONY: check toolchain fmt test clippy windows-check ubuntu-static

check: toolchain fmt test clippy windows-check

# Install the Linux static executable where the public shell entrypoint looks.
# Build as the normal user, before invoking the installer with sudo.
ubuntu-static: toolchain
	$(CARGO) build --locked --release --target-dir target --target x86_64-unknown-linux-musl --bin jstack-ubuntu-installer
	install -d ../../install/bin
	install -m 755 target/x86_64-unknown-linux-musl/release/jstack-ubuntu-installer ../../install/bin/jstack-ubuntu-installer

toolchain:
	@rustc_actual="$$( $(RUSTC) --version | awk '{print $$2}')"; \
	cargo_actual="$$( $(CARGO) --version | awk '{print $$2}')"; \
	if [ "$$rustc_actual" != "$(REQUIRED_RUSTC_VERSION)" ] || [ "$$cargo_actual" != "$(REQUIRED_CARGO_VERSION)" ]; then \
		echo "error: installer controller requires rustc $(REQUIRED_RUSTC_VERSION) and cargo $(REQUIRED_CARGO_VERSION) exactly; found rustc $${rustc_actual:-unknown}, cargo $${cargo_actual:-unknown}" >&2; \
		exit 1; \
	fi

fmt:
	$(CARGO) fmt --all -- --check

test:
	$(CARGO) test --offline --all-targets

clippy:
	$(CARGO) clippy --offline --all-targets -- -D warnings

windows-check:
	$(CARGO) check --offline --target x86_64-pc-windows-msvc
