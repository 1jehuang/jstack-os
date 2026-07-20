PYTHON ?= python3
MODEL := model/installer-state-graph.json

.PHONY: check validate test docs

check: validate test docs

validate:
	$(PYTHON) tools/validate_state_graph.py $(MODEL)

test:
	$(PYTHON) -m unittest discover -s tests -v

docs:
	$(PYTHON) tools/render_state_graph.py $(MODEL) ../docs/installer/generated
	git diff --exit-code -- ../docs/installer/generated
