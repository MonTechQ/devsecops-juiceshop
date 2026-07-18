#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# run-local-scan.sh — Full Local Security Scan
# Replicates the GitHub Actions pipeline locally.
# Prerequisites: docker, node 18+, python3, semgrep
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$ROOT_DIR/scan-results/$(date +%Y%m%d-%H%M%S)"
FAIL_SEVERITY="${FAIL_SEVERITY:-HIGH}"
IMAGE_NAME="juice-shop-devsecops-local"

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[PASS]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fail()    { echo -e "${RED}[FAIL]${RESET}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Setup ─────────────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
cd "$ROOT_DIR"

echo -e "\n${BOLD}🔒 DevSecOps Local Scanner${RESET}"
echo "Results → $RESULTS_DIR"
echo "Fail threshold → $FAIL_SEVERITY+"
echo "────────────────────────────────────────────"

GATE_FAILURES=0

# ─────────────────────────────────────────────────────────────────────
# STAGE 1 — SECRET SCANNING
# ─────────────────────────────────────────────────────────────────────
header "STAGE 1: Secret Scanning"

if command -v gitleaks &>/dev/null; then
    info "Running GitLeaks..."
    if gitleaks detect \
        --config "$ROOT_DIR/.gitleaks.toml" \
        --source "$ROOT_DIR" \
        --report-format json \
        --report-path "$RESULTS_DIR/gitleaks.json" \
        --redact \
        2>/dev/null; then
        success "GitLeaks — No secrets found"
    else
        fail "GitLeaks — Secrets detected!"
        GATE_FAILURES=$((GATE_FAILURES + 1))
    fi
else
    warn "GitLeaks not installed. Install from: https://gitleaks.io"
    warn "Running via Docker instead..."
    docker run --rm \
        -v "$ROOT_DIR:/repo" \
        zricethezav/gitleaks:latest \
        detect \
        --source "/repo" \
        --report-format json \
        --report-path "/repo/scan-results/gitleaks.json" \
        2>/dev/null && success "GitLeaks — Clean" || { fail "GitLeaks — Findings"; GATE_FAILURES=$((GATE_FAILURES + 1)); }
fi

if command -v trufflehog &>/dev/null; then
    info "Running TruffleHog..."
    if trufflehog filesystem "$ROOT_DIR" \
        --only-verified \
        --json > "$RESULTS_DIR/trufflehog.json" 2>/dev/null; then
        SECRETS=$(wc -l < "$RESULTS_DIR/trufflehog.json")
        if [ "$SECRETS" -gt 0 ]; then
            fail "TruffleHog — $SECRETS verified secrets found"
            GATE_FAILURES=$((GATE_FAILURES + 1))
        else
            success "TruffleHog — No verified secrets"
        fi
    fi
else
    warn "TruffleHog not installed. Install: pip install trufflehog"
fi

# ─────────────────────────────────────────────────────────────────────
# STAGE 2 — SAST
# ─────────────────────────────────────────────────────────────────────
header "STAGE 2: SAST (Semgrep)"

if command -v semgrep &>/dev/null || docker image inspect semgrep/semgrep &>/dev/null 2>&1; then
    info "Running Semgrep..."
    if command -v semgrep &>/dev/null; then
        SEMGREP_CMD="semgrep"
    else
        SEMGREP_CMD="docker run --rm -v $ROOT_DIR:/src semgrep/semgrep semgrep"
    fi

    $SEMGREP_CMD scan \
        --config "p/owasp-top-ten" \
        --config "p/javascript" \
        --config "$ROOT_DIR/scanning/semgrep/custom-rules.yml" \
        --severity ERROR \
        --json \
        --output "$RESULTS_DIR/semgrep-results.json" \
        "$ROOT_DIR" 2>/dev/null || true

    if [ -f "$RESULTS_DIR/semgrep-results.json" ]; then
        ERRORS=$(python3 -c "
import json; d=json.load(open('$RESULTS_DIR/semgrep-results.json'))
print(sum(1 for r in d.get('results',[]) if r.get('extra',{}).get('severity')=='ERROR'))
" 2>/dev/null || echo "0")
        if [ "$ERRORS" -gt 0 ]; then
            fail "Semgrep — $ERRORS ERROR-severity findings"
            GATE_FAILURES=$((GATE_FAILURES + 1))
        else
            success "Semgrep — No blocking findings"
        fi
    fi
else
    warn "Semgrep not available. Install: pip install semgrep"
fi

# ─────────────────────────────────────────────────────────────────────
# STAGE 3 — DEPENDENCY SCAN
# ─────────────────────────────────────────────────────────────────────
header "STAGE 3: Dependency Scan (npm audit)"

if command -v npm &>/dev/null && [ -f "$ROOT_DIR/package.json" ]; then
    info "Running npm audit..."
    npm audit \
        --audit-level=high \
        --json > "$RESULTS_DIR/npm-audit.json" 2>/dev/null || true

    if [ -f "$RESULTS_DIR/npm-audit.json" ]; then
        HIGHS=$(python3 -c "
import json
d=json.load(open('$RESULTS_DIR/npm-audit.json'))
vulns=d.get('vulnerabilities',{})
count=sum(1 for v in vulns.values() if v.get('severity') in ['high','critical'])
print(count)
" 2>/dev/null || echo "0")
        if [ "$HIGHS" -gt 0 ]; then
            fail "npm audit — $HIGHS high/critical vulnerabilities"
            GATE_FAILURES=$((GATE_FAILURES + 1))
        else
            success "npm audit — No high/critical vulnerabilities"
        fi
    fi
else
    warn "npm not found or no package.json — skipping"
fi

# ─────────────────────────────────────────────────────────────────────
# STAGE 4 — CONTAINER SCAN
# ─────────────────────────────────────────────────────────────────────
header "STAGE 4: Container Scan (Trivy)"

if command -v docker &>/dev/null; then
    info "Building Docker image..."
    docker build -t "$IMAGE_NAME:latest" -f "$ROOT_DIR/Dockerfile" "$ROOT_DIR" -q

    info "Running Trivy..."
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$RESULTS_DIR:/results" \
        aquasec/trivy:latest \
        image \
        --format json \
        --output /results/trivy-results.json \
        --severity CRITICAL,HIGH \
        --exit-code 0 \
        "$IMAGE_NAME:latest" 2>/dev/null || true

    if [ -f "$RESULTS_DIR/trivy-results.json" ]; then
        HIGHS=$(python3 -c "
import json
d=json.load(open('$RESULTS_DIR/trivy-results.json'))
count=sum(
    1 for r in d.get('Results',[])
    for v in r.get('Vulnerabilities',[])
    if v.get('Severity') in ('HIGH','CRITICAL')
)
print(count)
" 2>/dev/null || echo "0")
        if [ "$HIGHS" -gt 0 ]; then
            fail "Trivy — $HIGHS HIGH/CRITICAL CVEs in container"
            GATE_FAILURES=$((GATE_FAILURES + 1))
        else
            success "Trivy — No HIGH/CRITICAL CVEs"
        fi
    fi
else
    warn "Docker not available — skipping container scan"
fi

# ─────────────────────────────────────────────────────────────────────
# GATE CHECK
# ─────────────────────────────────────────────────────────────────────
header "SECURITY GATE"

python3 "$ROOT_DIR/scripts/gate-check.py" \
    --severity "$FAIL_SEVERITY" \
    --artifacts-dir "$RESULTS_DIR" \
    --output "$RESULTS_DIR/gate-report.md" || GATE_FAILURES=$((GATE_FAILURES + 1))

echo ""
echo "────────────────────────────────────────────"
if [ "$GATE_FAILURES" -eq 0 ]; then
    success "All gates PASSED ✅ — Results in $RESULTS_DIR"
    exit 0
else
    fail "$GATE_FAILURES gate(s) FAILED ❌"
    fail "Review $RESULTS_DIR/gate-report.md and apply remediations"
    echo ""
    echo "  Next steps:"
    echo "  1. cat $RESULTS_DIR/gate-report.md"
    echo "  2. Review remediation/patches/"
    echo "  3. Apply fixes and re-run: make scan-all"
    exit 1
fi
