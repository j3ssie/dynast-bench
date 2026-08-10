# DynAST-Bench — top-level runner for the vulnerable-app suite.
# Each app under vulnerable-apps/<name> is self-contained (own compose + standalone image).
#
#   make build                    # compile `dynast-bench` to dynast-bench/dist/ (no PATH change)
#   make install                  # same build, then symlink it onto your PATH
#   make list                     # show all apps
#   make run APP=nextjs           # start an app (compose: app + datastores)
#   make verify APP=nextjs        # run its ground-truth PoCs (expect all exploitable)
#   make validate APP=nextjs      # full twin loop: vuln all-pass -> safe all-fixed
#   make score APP=nextjs FINDINGS=f.json   # grade a scanner -> precision/recall/F1
#   make check                    # CI gate over every app (schema, anchors, diff scope)
#   make test                     # the scorer test suite
#   make down APP=nextjs          # stop it
#   make solo APP=nextjs          # run as ONE self-contained image (no compose)
#   make solo-down APP=nextjs     # stop the standalone image
#
# Convenience shorthands:  make run-nextjs   make validate-nextjs
# Optional vars: DYNAST_PORT=13311  VARIANT=vuln|safe  TARGET=http://127.0.0.1:13311

APPS := $(filter-out _template,$(notdir $(wildcard vulnerable-apps/*)))
APP  ?=
# host port every app publishes (see dynast-bench/dynast-bench.ts for the plan)
DYNAST_PORT ?= 13311
export DYNAST_PORT
PORT ?= $(DYNAST_PORT)
VARIANT ?= vuln

# `make build` compiles the CLI; `make install` links it onto PATH.
ROOT       := $(abspath .)
CLI        := $(abspath dynast-bench/dynast-bench.ts)
DIST       := $(abspath dynast-bench/dist/dynast-bench)
BIN_DIR    ?= $(HOME)/.bun/bin
BIN        := $(BIN_DIR)/dynast-bench

.PHONY: help build install uninstall test list run down stop stop-all browser-image clean verify validate score check diff solo solo-down guard-app

help:            ## show usage + app list
	@echo "DynAST-Bench — intentionally vulnerable app suite"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | sed 's/^/  make /'
	@echo ""
	@echo "Examples (start an app):"
	@echo "  make run APP=nextjs        # start via compose (app + Postgres/Redis/...)"
	@echo "  make run-nextjs            # same, shorthand"
	@echo "  make solo APP=nextjs       # start as ONE self-contained image (no compose)"
	@echo "  make verify APP=nextjs     # run its PoCs"
	@echo "  make down APP=nextjs       # stop that one app  |  make stop  # stop ALL apps"
	@echo ""
	@echo "  >> apps listen on  http://127.0.0.1:$(DYNAST_PORT)  (health: /api/_verify/health)"
	@echo "     busy port? the CLI relocates it; make targets honour DYNAST_PORT=<n>"
	@echo ""
	@echo "Or use the CLI (health-gated boots, port arbitration, --json):"
	@echo "  make install                 # -> $(BIN)"
	@echo "  dynast-bench start nextjs | verify nextjs | stop --all | clean --all --images"
	@echo ""
	@$(MAKE) --no-print-directory list

build:           ## compile the CLI to a standalone binary (dynast-bench/dist/)
	@command -v bun >/dev/null || { echo "!! bun is required (https://bun.sh)"; exit 2; }
	@mkdir -p "$(dir $(DIST))"
	@bun build --compile --outfile "$(DIST)" \
	  --define DYNAST_REPO_ROOT='"$(ROOT)"' \
	  "$(CLI)"
	@echo ">> built $(DIST) ($$(du -h "$(DIST)" | cut -f1))"

install: build   ## build, then symlink `dynast-bench` into $(BIN_DIR)
	@mkdir -p "$(BIN_DIR)"
	@ln -sf "$(DIST)" "$(BIN)"
	@echo ">> installed $(BIN) -> $(DIST)"
	@case ":$$PATH:" in *":$(BIN_DIR):"*) \
	  echo ">> $(BIN_DIR) is on your PATH — run: dynast-bench list" ;; \
	*) \
	  echo "!! $(BIN_DIR) is NOT on your PATH; add this to your shell rc:"; \
	  echo "     export PATH=\"$(BIN_DIR):\$$PATH\"" ;; \
	esac

uninstall:       ## remove the installed binary + symlink
	@rm -f "$(BIN)" "$(DIST)" && echo ">> removed $(BIN) and $(DIST)"

list:            ## list available apps + the command to start each
	@echo "Apps (vulnerable-apps/<name>):"
	@for a in $(APPS); do \
	  desc=$$(grep -m1 '^# ' vulnerable-apps/$$a/README.md 2>/dev/null | sed 's/^# //'); \
	  solo=$$( [ -f vulnerable-apps/$$a/vuln/Dockerfile.standalone ] && echo '[solo]' || echo '     '); \
	  printf "  %-12s %s  %s\n" "$$a" "$$solo" "$${desc:-(no README)}"; \
	  printf "  %-12s   -> start:  make run APP=%s   (or: make solo APP=%s)\n" "" "$$a" "$$a"; \
	done

guard-app:
	@[ -n "$(APP)" ] || { echo "!! set APP=<name>  (see: make list)"; exit 2; }
	@[ -d "vulnerable-apps/$(APP)" ] || { echo "!! no such app: vulnerable-apps/$(APP)"; exit 2; }

run: guard-app   ## start APP via compose (app + datastores)
	$(MAKE) -C vulnerable-apps/$(APP) up

down: guard-app  ## stop one APP (both variants)
	-$(MAKE) -C vulnerable-apps/$(APP) down
	-$(MAKE) -C vulnerable-apps/$(APP) safe-down

stop:            ## stop ALL apps (every compose variant + standalone image)
	@bun "$(CLI)" stop --all --force

stop-all: stop   ## alias for `make stop`

browser-image:   ## build the headless browser image the browser PoCs drive
	@docker build -t "$${DYNAST_BROWSER_IMAGE:-dynast-bench-browser:1}" dynast-bench/tools/browser

clean:           ## remove EVERY app's containers, volumes and networks (frees disk)
	@bun "$(CLI)" clean --all --yes

verify: guard-app   ## run APP's ground-truth PoCs (expect all exploitable)
	$(MAKE) -C vulnerable-apps/$(APP) verify

validate: guard-app ## full twin loop for APP (vuln all-pass -> safe all-fixed)
	$(MAKE) -C vulnerable-apps/$(APP) validate

score: guard-app    ## grade findings against APP's answer key [FINDINGS= SAFE_FINDINGS=]
	$(MAKE) -C vulnerable-apps/$(APP) score FINDINGS=$(abspath $(FINDINGS)) \
	  $(if $(SAFE_FINDINGS),SAFE_FINDINGS=$(abspath $(SAFE_FINDINGS)),) SCORE_FLAGS="$(SCORE_FLAGS)"

diff: guard-app     ## APP's vuln<->safe delta, cross-checked against the answer key
	@bun "$(CLI)" diff $(APP)

check:              ## CI gate for APP, or every app when APP is unset
	@bun "$(CLI)" check $(if $(APP),$(APP),--all)
	@bun dynast-bench/tools/derive-match.ts $(if $(APP),$(APP),--all) --check >/dev/null

test:               ## run the scorer test suite (schema, matcher, every answer key)
	@command -v bun >/dev/null || { echo "!! bun is required (https://bun.sh)"; exit 2; }
	@cd dynast-bench && bun test

solo: guard-app     ## run APP as ONE self-contained image (no compose) [PORT= VARIANT=]
	$(MAKE) -C vulnerable-apps/$(APP) solo PORT=$(PORT) VARIANT=$(VARIANT)

solo-down: guard-app ## stop APP's standalone image [VARIANT=]
	$(MAKE) -C vulnerable-apps/$(APP) solo-down VARIANT=$(VARIANT)

# Convenience: `make run-nextjs`, `make validate-nextjs`, `make verify-nextjs`.
run-%:
	$(MAKE) -C vulnerable-apps/$* up
verify-%:
	$(MAKE) -C vulnerable-apps/$* verify
validate-%:
	$(MAKE) -C vulnerable-apps/$* validate
