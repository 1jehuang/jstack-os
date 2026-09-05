PYTHON ?= python3
MODEL := model/installer-state-graph.json
UBUNTU_MODEL := model/ubuntu-whole-disk-state-graph.json

.PHONY: check toolchain validate test docs core staging controller vm-test vm-host progress progress-full

check: toolchain validate test docs core staging controller vm-test progress

toolchain:
	$(MAKE) -C core toolchain
	$(MAKE) -C staging toolchain
	$(MAKE) -C controller toolchain

validate:
	$(PYTHON) tools/validate_state_graph.py $(MODEL)
	$(PYTHON) tools/validate_state_graph.py --ubuntu-whole-disk $(UBUNTU_MODEL)

test:
	$(PYTHON) -m unittest discover -s tests -v

docs:
	$(PYTHON) tools/render_state_graph.py $(MODEL) ../docs/installer/generated
	git diff --exit-code -- ../docs/installer/generated

core:
	$(MAKE) -C core check

staging:
	$(MAKE) -C staging check

controller:
	$(MAKE) -C controller check

vm-test:
	$(MAKE) -C vm test

vm-host:
	$(MAKE) -C vm host-check

# Computed pre-hardware progress. The baseline is a ratchet: if a probe that used
# to pass stops passing, this fails the build rather than quietly lowering the
# reported score.
progress:
	$(PYTHON) tools/ledger_status.py --no-commands --require-implemented 19

# The same report including command probes, which actually run the readiness and
# identity-resolution gates. Slower and host-dependent, so it is not in `check`.
progress-full:
	$(PYTHON) tools/ledger_status.py --require-implemented 19
