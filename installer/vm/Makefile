PYTHON ?= python3
LAB ?= $(JCODE_SCRATCH_DIR)/jstack-windows-vm

.PHONY: check full-check test host-check init readiness host-identities release-identities boot-proof

check: test

full-check: test host-check boot-proof

# Boot the signed artifact on real OVMF and prove Secure Boot refuses a tampered
# and an unsigned image. Skips cleanly without KVM, OVMF, or a kernel.
boot-proof:
	$(PYTHON) -m unittest tests.bootproof_suite -v

# The default gate excludes the boot proof: it launches three real VMs and takes
# ~95s. It is host-dependent, so it belongs in full-check alongside host-check.
# The default gate discovers only `test_*.py`. The boot proof lives in
# `bootproof_suite.py` so it is excluded here by construction rather than by a
# fragile name filter: it launches three real VMs, takes ~95s, and is
# host-dependent, so it belongs in full-check alongside host-check.
test:
	$(PYTHON) -m unittest discover -s tests -v -p 'test_*.py'

host-check:
	$(PYTHON) lab.py check-host --workspace "$(LAB)"

init:
	$(PYTHON) lab.py init --workspace "$(LAB)"

# Silent so stdout is pure JSON and can be piped into jq or a test.
readiness:
	@$(PYTHON) base_image.py --workspace "$(LAB)" readiness

# Resolve the host-scoped profile inputs. Unlike `init`, this needs no VM
# memory envelope, so it works on a busy machine.
host-identities:
	@$(PYTHON) base_image.py --workspace "$(LAB)" host-identities

# Resolve the release-build-scoped profile inputs. Pass the boot-artifact
# manifest digest from a real artifacts build to resolve the fourth.
release-identities:
	@$(PYTHON) base_image.py --workspace "$(LAB)" release-identities
