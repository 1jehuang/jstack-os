PYTHON ?= python3
LAB ?= $(JCODE_SCRATCH_DIR)/jstack-windows-vm

.PHONY: check full-check test host-check init readiness

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
