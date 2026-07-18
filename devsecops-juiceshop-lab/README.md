# 🔒 DevSecOps Lab — OWASP Juice Shop

> **Portfolio Project — MontechQ | Bug Bounty × DevSecOps**
> A full-lifecycle security lab: manual pentest → automated pipeline → remediation proof.

[![DevSecOps Pipeline](https://img.shields.io/badge/pipeline-GitHub_Actions-2088FF?logo=github-actions)](/.github/workflows/devsecops-pipeline.yml)
[![SAST](https://img.shields.io/badge/SAST-Semgrep_+_CodeQL-orange)](https://semgrep.dev)
[![Container Scan](https://img.shields.io/badge/container-Trivy-blue)](https://trivy.dev)
[![DAST](https://img.shields.io/badge/DAST-OWASP_ZAP-red)](https://www.zaproxy.org)
[![Secrets](https://img.shields.io/badge/secrets-TruffleHog_+_GitLeaks-yellow)](https://trufflesecurity.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What This Project Demonstrates

| Skill Area | Tools & Evidence |
|---|---|
| Web App Pentesting | 10 documented findings (SQLi, IDOR, XSS, BAC, JWT abuse, XXE) |
| CI/CD Security | 4-stage GitHub Actions gate: SAST → Deps → Secrets → Container |
| SAST | Semgrep (custom rules) + CodeQL |
| SCA / Dependency Scan | OWASP Dependency Check + npm audit |
| Secret Detection | TruffleHog (verified secrets) + GitLeaks |
| Container Security | Trivy — image CVE + misconfiguration scan |
| DAST | OWASP ZAP baseline scan against live Juice Shop |
| Remediation Loop | Patches applied → pipeline re-run → gates pass ✅ |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Actions Pipeline                      │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐     │
│  │  Secret  │  │   SAST   │  │   Deps   │  │  Container   │     │
│  │  Scan    │  │ Semgrep  │  │  OWASP   │  │    Trivy     │     │
│  │TruffleHog│  │  CodeQL  │  │   DC +   │  │              │     │
│  │ GitLeaks │  │          │  │ npm audit│  │              │     │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘     │
│       │              │              │                │          │
│       └──────────────┴──────────────┴────────────────┘          │
│                              │                                  │
│                    ┌─────────▼─────────┐                        │
│                    │   Security Gate   │  ← FAIL on HIGH/CRIT   │
│                    │   gate-check.py   │                        │
│                    └─────────┬─────────┘                        │
│                    PASS only │                                  │
│                    ┌─────────▼─────────┐                        │
│                    │   DAST — ZAP      │                        │
│                    │  (live Juice Shop)│                        │
│                    └─────────┬─────────┘                        │
│                    ┌─────────▼─────────┐                        │
│                    │ Consolidated      │                        │
│                    │ Security Report   │                        │
│                    └───────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Layout

```
devsecops-juiceshop-lab/
├── .github/workflows/
│   ├── devsecops-pipeline.yml      ← Main CI/CD security pipeline
│   └── scheduled-scan.yml          ← Weekly scheduled scan
│
├── scanning/
│   ├── semgrep/
│   │   ├── custom-rules.yml        ← Custom SAST rules (CWE-mapped)
│   │   └── .semgrepignore
│   ├── zap/
│   │   └── zap-rules.tsv           ← ZAP passive rule config
│   └── trivy/
│       └── .trivyignore            ← Accepted risk exceptions
│
├── scripts/
│   ├── gate-check.py               ← Aggregates scan results, gates build
│   ├── parse-results.py            ← Generates consolidated markdown report
│   └── run-local-scan.sh           ← Run the full pipeline locally
│
├── pentesting/
│   ├── methodology.md              ← Testing methodology (WSTG-aligned)
│   └── findings/
│       └── juice-shop-assessment.md ← 10 findings, CVSS-scored with PoC
│
├── remediation/
│   ├── README.md                   ← Fix summary + pipeline before/after
│   └── patches/                    ← Per-finding remediation guides
│
├── Dockerfile                      ← Base (vulnerable — triggers gate failure)
├── Dockerfile.hardened             ← Patched image (gate passes)
├── docker-compose.yml              ← Full local stack
├── Makefile                        ← make scan-all / make start / make report
├── .gitleaks.toml                  ← GitLeaks config
└── SECURITY.md                     ← Responsible disclosure policy
```

---

## Phase 1 — Manual Pentest

**Target:** OWASP Juice Shop v17.x (http://localhost:3000)

```bash
# Spin up the target
docker-compose up -d juice-shop

# Verify it's running
curl -s http://localhost:3000/rest/admin/application-configuration | jq .
```

See full findings → [`pentesting/findings/juice-shop-assessment.md`](pentesting/findings/juice-shop-assessment.md)

| # | Finding | Severity | CVSS | CWE |
|---|---------|----------|------|-----|
| F-01 | SQL Injection — Login Bypass | **Critical** | 9.8 | CWE-89 |
| F-02 | JWT Algorithm Confusion / Weak Secret | **Critical** | 9.1 | CWE-347 |
| F-03 | Admin Panel — Broken Access Control | **High** | 8.1 | CWE-285 |
| F-04 | IDOR — Basket & User Data Access | **High** | 8.1 | CWE-639 |
| F-05 | Stored XSS — Product Reviews | **High** | 7.4 | CWE-79 |
| F-06 | XXE — File Upload | **High** | 7.5 | CWE-611 |
| F-07 | Broken Auth — No Rate Limiting | **Medium** | 5.3 | CWE-307 |
| F-08 | Secrets in Client-Side Bundle | **Medium** | 5.5 | CWE-312 |
| F-09 | Path Traversal — File Endpoint | **Medium** | 6.5 | CWE-22 |
| F-10 | Missing Security Headers | **Low** | 3.1 | CWE-693 |

---

## Phase 2 — Run the Pipeline

```bash
# Fork the repo, then push to trigger the pipeline
git push origin main

# Or run locally with make
make scan-all
```

The pipeline will **fail** on the initial push (expected — demonstrates gates working).
Apply remediations from `remediation/patches/` and push again to see it pass.

---

## Phase 3 — Local Quick Start

```bash
# Prerequisites: Docker, Python 3.10+, make

# Start the lab
make start

# Run all security scans
make scan-all

# Generate report
make report

# Stop everything
make stop
```

---

## Phase 4 — Remediation Loop

```
BEFORE (initial push):
  ❌ Secret scan      — leaked JWT secret in config
  ❌ SAST             — SQL concatenation in query builder
  ❌ Dependency scan  — 3 CRITICAL CVEs in outdated packages
  ❌ Container scan   — 11 HIGH CVEs in base image OS packages
  🚫 Gate BLOCKED     — build does not proceed to deploy

AFTER (patches applied):
  ✅ Secret scan      — no verified secrets
  ✅ SAST             — parameterized queries only
  ✅ Dependency scan  — packages updated, CVEs resolved
  ✅ Container scan   — hardened image, Alpine-based
  ✅ Gate PASSES      — DAST proceeds, report generated
```

See full remediation → [`remediation/README.md`](remediation/README.md)

---

## Tools Reference

| Tool | Purpose | Free |
|---|---|---|
| [Semgrep](https://semgrep.dev) | SAST — JavaScript patterns | ✅ |
| [CodeQL](https://codeql.github.com) | SAST — deep data-flow analysis | ✅ |
| [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) | SCA — CVE matching | ✅ |
| [TruffleHog](https://trufflesecurity.com/trufflehog) | Secret scanning (verified) | ✅ |
| [GitLeaks](https://gitleaks.io) | Secret scanning (regex-based) | ✅ |
| [Trivy](https://trivy.dev) | Container + config scan | ✅ |
| [OWASP ZAP](https://www.zaproxy.org) | DAST — active/passive scan | ✅ |

---

## Author

**MontechQ** — Bug Bounty Hunter (Bugcrowd / HackerOne) | Security Student @ Humber College

*This project is for authorized security research and portfolio demonstration only.
All testing was conducted against intentionally vulnerable software in an isolated environment.*
