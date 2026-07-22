PYTHON ?= python3
MODEL := model/installer-state-graph.json

.PHONY: check toolchain validate test docs core staging vm-test vm-host

check: toolchain validate test docs core staging vm-test

toolchain:
	$(MAKE) -C core toolchain
	$(MAKE) -C staging toolchain

validate:
	$(PYTHON) tools/validate_state_graph.py $(MODEL)

test:
	$(PYTHON) -m unittest discover -s tests -v

docs:
	$(PYTHON) tools/render_state_graph.py $(MODEL) ../docs/installer/generated
	git diff --exit-code -- ../docs/installer/generated

core:
	$(MAKE) -C core check

staging:
	$(MAKE) -C staging check

vm-test:
	$(MAKE) -C vm test

vm-host:
	$(MAKE) -C vm host-check
