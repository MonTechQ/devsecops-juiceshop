# ─────────────────────────────────────────────────────────────────────
# DevSecOps Lab Makefile
# Usage: make <target>
# ─────────────────────────────────────────────────────────────────────

.PHONY: help start stop logs scan-all scan-secrets scan-sast \
        scan-deps scan-container scan-dast gate report clean

RESULTS_DIR  := scan-results/$(shell date +%Y%m%d-%H%M%S)
IMAGE_BASE   := juice-shop-devsecops-base
IMAGE_HARD   := juice-shop-devsecops-hardened
JUICE_URL    := http://localhost:3000
FAIL_SEV     := HIGH

# ── Colors ────────────────────────────────────────────────────────────
BOLD := \033[1m
CYAN := \033[0;36m
GRN  := \033[0;32m
RED  := \033[0;31m
RST  := \033[0m

help: ## Show this help
	@echo ""
	@echo "$(BOLD)$(CYAN)🔒 DevSecOps Lab — OWASP Juice Shop$(RST)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-22s$(RST) %s\n", $$1, $$2}'
	@echo ""

# ─── Lab Management ───────────────────────────────────────────────────
start: ## Start Juice Shop (target for scanning/pentesting)
	@echo "$(CYAN)▶ Starting Juice Shop...$(RST)"
	docker compose up -d juice-shop
	@echo "$(GRN)✅ Juice Shop running at $(JUICE_URL)$(RST)"
	@docker compose ps juice-shop

start-hardened: ## Start hardened Juice Shop (post-remediation demo)
	@echo "$(CYAN)▶ Starting hardened Juice Shop...$(RST)"
	docker compose --profile hardened up -d
	@echo "$(GRN)✅ Hardened Juice Shop running at http://localhost:3001$(RST)"

stop: ## Stop all lab services
	@docker compose --profile hardened down
	@echo "$(GRN)✅ All services stopped$(RST)"

logs: ## Tail Juice Shop logs
	docker compose logs -f juice-shop

# ─── Build ────────────────────────────────────────────────────────────
build: ## Build base Docker image (vulnerable — triggers gate fail)
	@echo "$(CYAN)▶ Building base image (vulnerable)...$(RST)"
	docker build -t $(IMAGE_BASE):latest -f Dockerfile .

build-hardened: ## Build hardened Docker image (post-remediation)
	@echo "$(CYAN)▶ Building hardened image...$(RST)"
	docker build -t $(IMAGE_HARD):latest -f Dockerfile.hardened .

# ─── Individual Scans ─────────────────────────────────────────────────
scan-secrets: ## Run secret scanning (TruffleHog + GitLeaks)
	@echo "$(CYAN)▶ Scanning for secrets...$(RST)"
	@mkdir -p $(RESULTS_DIR)
	@if command -v gitleaks >/dev/null; then \
		gitleaks detect --config .gitleaks.toml --source . \
		    --report-format json --report-path $(RESULTS_DIR)/gitleaks.json \
		    && echo "$(GRN)✅ GitLeaks: No secrets$(RST)" \
		    || echo "$(RED)❌ GitLeaks: Secrets found!$(RST)"; \
	else \
		echo "$(RED)GitLeaks not installed. Run: brew install gitleaks$(RST)"; \
	fi
	@if command -v trufflehog >/dev/null; then \
		trufflehog filesystem . --only-verified --json > $(RESULTS_DIR)/trufflehog.json 2>/dev/null; \
		COUNT=$$(wc -l < $(RESULTS_DIR)/trufflehog.json | tr -d ' '); \
		[ "$$COUNT" -eq 0 ] \
		    && echo "$(GRN)✅ TruffleHog: No verified secrets$(RST)" \
		    || echo "$(RED)❌ TruffleHog: $$COUNT verified secret(s)$(RST)"; \
	else \
		echo "$(RED)TruffleHog not installed. Run: pip install trufflehog$(RST)"; \
	fi

scan-sast: ## Run Semgrep SAST scan
	@echo "$(CYAN)▶ Running Semgrep SAST...$(RST)"
	@mkdir -p $(RESULTS_DIR)
	docker run --rm \
		-v "$(PWD):/src" \
		semgrep/semgrep:latest semgrep scan \
		--config "p/owasp-top-ten" \
		--config "p/javascript" \
		--config "/src/scanning/semgrep/custom-rules.yml" \
		--severity ERROR \
		--json \
		--output /src/$(RESULTS_DIR)/semgrep-results.json \
		/src 2>/dev/null
	@python3 -c "\
import json; d=json.load(open('$(RESULTS_DIR)/semgrep-results.json')); \
n=len(d.get('results',[])); \
print(f'\033[0;31m❌ Semgrep: {n} findings\033[0m' if n else '\033[0;32m✅ Semgrep: Clean\033[0m')"

scan-deps: ## Run dependency scan (npm audit)
	@echo "$(CYAN)▶ Scanning dependencies...$(RST)"
	@mkdir -p $(RESULTS_DIR)
	@if [ -f package.json ]; then \
		npm audit --audit-level=high --json > $(RESULTS_DIR)/npm-audit.json 2>/dev/null || true; \
		echo "$(GRN)✅ npm audit complete — see $(RESULTS_DIR)/npm-audit.json$(RST)"; \
	else \
		echo "No package.json found (this is the wrapper repo — point at Juice Shop source)"; \
	fi

scan-container: build ## Scan base Docker image with Trivy (expect failures)
	@echo "$(CYAN)▶ Scanning base container with Trivy...$(RST)"
	@mkdir -p $(RESULTS_DIR)
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(PWD)/$(RESULTS_DIR):/results" \
		aquasec/trivy:latest image \
		--format json \
		--output /results/trivy-results.json \
		--severity CRITICAL,HIGH \
		$(IMAGE_BASE):latest 2>/dev/null || true
	@python3 -c "\
import json; \
d=json.load(open('$(RESULTS_DIR)/trivy-results.json')); \
n=sum(len(r.get('Vulnerabilities',[])) for r in d.get('Results',[])); \
print(f'\033[0;31m❌ Trivy: {n} HIGH/CRITICAL CVEs\033[0m' if n else '\033[0;32m✅ Trivy: Clean\033[0m')"

scan-container-hardened: build-hardened ## Scan hardened image with Trivy (expect pass)
	@echo "$(CYAN)▶ Scanning hardened container...$(RST)"
	@mkdir -p $(RESULTS_DIR)
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy:latest image \
		--severity CRITICAL,HIGH \
		--exit-code 1 \
		$(IMAGE_HARD):latest && echo "$(GRN)✅ Hardened image: PASS$(RST)" || echo "$(RED)❌ Hardened image: FAIL$(RST)"

scan-dast: ## Run OWASP ZAP DAST scan against running Juice Shop
	@echo "$(CYAN)▶ Running OWASP ZAP DAST scan...$(RST)"
	@mkdir -p $(RESULTS_DIR)
	docker run --rm \
		--network host \
		-v "$(PWD)/$(RESULTS_DIR):/zap/wrk" \
		-v "$(PWD)/scanning/zap:/zap/config" \
		ghcr.io/zaproxy/zaproxy:stable \
		zap-baseline.py \
		-t $(JUICE_URL) \
		-c /zap/config/zap-rules.tsv \
		-J /zap/wrk/zap-report.json \
		-r /zap/wrk/zap-report.html \
		-l WARN 2>/dev/null || true
	@echo "$(GRN)✅ ZAP report: $(RESULTS_DIR)/zap-report.html$(RST)"

# ─── Gate + Report ────────────────────────────────────────────────────
gate: ## Run security gate check against latest scan results
	@echo "$(CYAN)▶ Running security gate check...$(RST)"
	@LATEST=$$(ls -1dt scan-results/*/ 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "$(RED)No scan results found. Run: make scan-all first$(RST)"; exit 1; \
	fi; \
	python3 scripts/gate-check.py \
		--severity $(FAIL_SEV) \
		--artifacts-dir "$$LATEST" \
		--output "$$LATEST/gate-report.md"

report: ## Generate consolidated security report
	@LATEST=$$(ls -1dt scan-results/*/ 2>/dev/null | head -1); \
	python3 scripts/parse-results.py \
		--artifacts-dir "$$LATEST" \
		--output "$$LATEST/security-report.md"; \
	echo "$(GRN)✅ Report: $$LATEST/security-report.md$(RST)"

# ─── Full Pipeline ────────────────────────────────────────────────────
scan-all: ## Run the complete security pipeline locally
	@echo ""
	@echo "$(BOLD)$(CYAN)🔒 Running full DevSecOps pipeline$(RST)"
	@echo "$(CYAN)   Fail threshold: $(FAIL_SEV)+$(RST)"
	@echo ""
	@FAIL_SEVERITY=$(FAIL_SEV) bash scripts/run-local-scan.sh

# ─── Demo ─────────────────────────────────────────────────────────────
demo-before: start scan-all ## Demo: Show pipeline FAILING (before remediation)
	@echo ""
	@echo "$(BOLD)$(RED)═══ BEFORE REMEDIATION ═══$(RST)"
	@echo "All gates failed as expected — see remediation/README.md for fixes"

demo-after: start-hardened scan-container-hardened ## Demo: Show container scan PASSING
	@echo ""
	@echo "$(BOLD)$(GRN)═══ AFTER REMEDIATION ═══$(RST)"
	@echo "Hardened container passes Trivy gate ✅"

# ─── Cleanup ──────────────────────────────────────────────────────────
clean: stop ## Remove containers, images, and scan results
	@docker rmi -f $(IMAGE_BASE):latest $(IMAGE_HARD):latest 2>/dev/null || true
	@rm -rf scan-results/
	@echo "$(GRN)✅ Cleaned up$(RST)"
