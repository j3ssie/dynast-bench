# Uniform per-app interface. Copied into every vulnerable-apps/<stack>/ (APP auto-detected).
# Run from the app folder, e.g.  cd vulnerable-apps/jsp && make up
APP          := $(notdir $(CURDIR))
COMPOSE_VULN := docker compose -f vuln/docker-compose.yml -p vuln-$(APP)
COMPOSE_SAFE := docker compose -f safe/docker-compose.yml -p safe-$(APP)
# host port published on the machine — override: DYNAST_PORT=13999 make up
DYNAST_PORT  ?= 13311
export DYNAST_PORT
TARGET       ?= http://127.0.0.1:$(DYNAST_PORT)
HOST_PORT    := $(DYNAST_PORT)
ADDR         := http://127.0.0.1:$(HOST_PORT)
VARIANT      ?= vuln
PORT         ?= $(DYNAST_PORT)
# the suite CLI: the installed binary if it is on PATH, else straight from source
DYNAST       ?= $(shell command -v dynast-bench 2>/dev/null || echo "bun ../../dynast-bench/dynast-bench.ts")
SOLO_IMG     := $(VARIANT)-$(APP)-solo
SOLO_HEALTH  ?= /api/_verify/health

.PHONY: up reset down safe safe-down verify verify-safe validate solo solo-down diff score check help

up:        ## build + start the vulnerable variant (127.0.0.1), wait for health
	$(COMPOSE_SAFE) down 2>/dev/null || true
	$(COMPOSE_VULN) up -d --build --wait
	@echo ">> $(APP) (vuln) is listening at $(ADDR)  (health: $(ADDR)/api/_verify/health)"

reset:     ## fresh state: down -v && up
	$(COMPOSE_VULN) down -v
	$(MAKE) up

down:      ## stop the vulnerable variant, drop volumes
	$(COMPOSE_VULN) down -v

safe:      ## build + start the patched twin (stops vuln first — shared port)
	$(COMPOSE_VULN) down 2>/dev/null || true
	$(COMPOSE_SAFE) up -d --build --wait

safe-down: ## stop the patched twin
	$(COMPOSE_SAFE) down -v

verify:    ## run every PoC against $(TARGET); expect ALL exploitable (vuln up)
	@TARGET=$(TARGET) bash ground-truth/run.sh expect-vuln

verify-safe: ## run every PoC against $(TARGET); expect ALL fixed (safe up)
	@TARGET=$(TARGET) bash ground-truth/run.sh expect-safe

validate:  ## full twin loop: reset vuln→all exploitable, then safe→all fixed
	$(MAKE) reset
	@TARGET=$(TARGET) bash ground-truth/run.sh expect-vuln
	$(MAKE) safe
	@TARGET=$(TARGET) bash ground-truth/run.sh expect-safe
	$(COMPOSE_SAFE) down -v

solo:      ## build + run the standalone single-image (no compose) [VARIANT= PORT=]
	docker build -f $(VARIANT)/Dockerfile.standalone -t $(SOLO_IMG) $(VARIANT)
	-docker rm -f $(SOLO_IMG) 2>/dev/null
	@bash ../../dynast-bench/tools/solo-run.sh $(SOLO_IMG) $(VARIANT)/docker-compose.yml -p 127.0.0.1:$(PORT):3000
	@bash ../../dynast-bench/tools/wait-healthy.sh $(SOLO_IMG) "http://127.0.0.1:$(PORT)$(SOLO_HEALTH)"

solo-down: ## stop the standalone single-image container
	-docker rm -f $(SOLO_IMG)

diff:      ## the ground-truth diff (vuln vs safe), cross-checked against the answer key
	@$(DYNAST) diff $(APP) 2>/dev/null || diff -ru vuln safe || true

score:     ## grade a scanner's findings against the answer key  [FINDINGS= SAFE_FINDINGS=]
	@[ -n "$(FINDINGS)" ] || { echo "!! set FINDINGS=path/to/findings.json  (any of: findings/v1, zap, sarif, nuclei, burp, nmap)"; exit 2; }
	@$(DYNAST) score $(APP) $(FINDINGS) $(if $(SAFE_FINDINGS),--safe $(SAFE_FINDINGS),) $(SCORE_FLAGS)

check:     ## CI gate: schema · anchors · diff scope · PoCs · 127.0.0.1 binds
	@$(DYNAST) check $(APP)

help:      ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /	/'
