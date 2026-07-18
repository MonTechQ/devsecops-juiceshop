# ─────────────────────────────────────────────────────────────────────
# Dockerfile — Base (Vulnerable)
# PURPOSE: Starting point for the DevSecOps lab.
# This image intentionally mirrors the upstream Juice Shop image
# and will FAIL the Trivy container scan (HIGH/CRITICAL CVEs).
#
# After running: make scan-container
# → Expected: FAIL — gate-check.py exits 1
#
# Fix: use Dockerfile.hardened and re-run the pipeline.
# ─────────────────────────────────────────────────────────────────────

FROM bkimminich/juice-shop:latest

# Image metadata (portfolio / SBOM)
LABEL org.opencontainers.image.title="juice-shop-devsecops-base" \
      org.opencontainers.image.description="OWASP Juice Shop — base vulnerable image (DevSecOps lab)" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="MontechQ" \
      org.opencontainers.image.source="https://github.com/MontechQ/devsecops-juiceshop-lab" \
      security.scan.status="VULNERABLE" \
      security.scan.gate="FAIL"

# NOTE: The upstream image runs as root, has outdated OS packages,
# and includes development dependencies — all of which Trivy will flag.
# This is intentional for the "before remediation" demo.

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -sf http://localhost:3000 || exit 1
