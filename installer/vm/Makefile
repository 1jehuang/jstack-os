PYTHON ?= python3
LAB ?= $(JCODE_SCRATCH_DIR)/jstack-windows-vm

.PHONY: check full-check test host-check init readiness host-identities

check: test

full-check: test host-check

test:
	$(PYTHON) -m unittest discover -s tests -v

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
