# Lab maintenance targets. Labs are discovered by globbing workshops/*/chapters/*/lab/,
# so new chapters need no edits here.
#
#   make check               # lab conventions (guard, loopback binds, solutions layout, RoE), Markdown paths, starter drift
#   make check-links         # repo paths named in Markdown exist (also resolves the slides repo next door)
#   make code-diff           # lab/starter .py files that changed in code (REF=<base>)
#   make verify LAB=workshops/01-initiation/chapters/02-*/lab   # that lab's full exit-criteria run
#   make verify-changed      # the above for every lab whose code changed since REF (default HEAD)
#   make audit-deps          # pins vs the AGENTS.md baseline, stale "Pins verified" headers, pip-audit
#   make build-starters      # rebuild the W2-W4 starters from their manifests
#   make clean-venvs         # list lab venvs; CONFIRM=1 deletes them (uv rebuilds fast)

REF  ?= HEAD
LAB  ?=

.DEFAULT_GOAL := help
.PHONY: help check check-links code-diff verify verify-changed audit-deps build-starters clean-venvs

help:
	@echo "Usage:"
	@echo "  make check               Check every lab and starter against the conventions in AGENTS.md"
	@echo "  make check-links         Check that repo paths named in Markdown exist"
	@echo "  make code-diff           List lab/starter .py files that changed in code since REF"
	@echo "  make verify LAB=<lab>    Run a lab's exit criteria: verify.py --all --with-before + --smoke"
	@echo "  make verify-changed      Run those exit criteria for every lab whose code changed since REF"
	@echo "  make audit-deps          Check lab pins against the AGENTS.md baseline (+pip-audit if installed)"
	@echo "  make build-starters      Rebuild the W2-W4 starters from workshops/<NN>/starter.manifest.json"
	@echo "  make clean-venvs         List lab venvs; make clean-venvs CONFIRM=1 deletes them"
	@echo ""
	@echo "Workshops: w1 (Initiation), w2 (Proficient), w3 (Advanced), w4 (AI-Era Bots)"

check:
	python3 scripts/check_labs.py
	python3 scripts/check_links.py
	python3 scripts/starter_check.py --no-boot

check-links:
	python3 scripts/check_links.py

code-diff:
	python3 scripts/code_diff.py --base $(REF)

verify:
	@test -n "$(LAB)" || { echo "usage: make verify LAB=workshops/<NN>/chapters/<NN-slug>/lab"; exit 1; }
	@test -x $(LAB)/.venv/bin/python || { echo "$(LAB) has no .venv - create it first:"; \
		echo "  cd $(LAB) && uv venv -p 3.12 .venv && uv pip install -r requirements.txt"; exit 1; }
	cd $(LAB) && .venv/bin/python tools/verify.py --all --with-before --markdown \
		&& .venv/bin/python tools/verify.py --smoke

verify-changed:
	@labs=$$(python3 scripts/code_diff.py --base $(REF) --labs); \
	if [ -z "$$labs" ]; then echo "no labs changed in code since $(REF)"; exit 0; fi; \
	for lab in $$labs; do \
		if [ -x $$lab/.venv/bin/python ]; then $(MAKE) verify LAB=$$lab || exit 1; \
		else echo "skip $$lab (no .venv - make verify LAB=$$lab after creating one)"; fi; done

audit-deps:
	python3 scripts/audit_deps.py

build-starters:
	python3 scripts/build_starter.py --all

clean-venvs:
	@du -shc workshops/*/chapters/*/lab/.venv workshops/*/starter/.venv 2>/dev/null | tail -20 || true
	@if [ "$(CONFIRM)" = "1" ]; then \
		rm -rf workshops/*/chapters/*/lab/.venv workshops/*/starter/.venv; \
		echo "removed. Rebuild one with: uv venv -p 3.12 .venv && uv pip install -r requirements.txt"; \
	else echo "dry run (nothing deleted) - run 'make clean-venvs CONFIRM=1' to delete the venvs above"; fi
