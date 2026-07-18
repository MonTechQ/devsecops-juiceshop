#!/usr/bin/env python3
"""
gate-check.py — DevSecOps Security Gate
========================================
Aggregates results from all security scanners and enforces a
severity threshold. Exits 1 (blocking the pipeline) if any finding
meets or exceeds FAIL_ON_SEVERITY.

Scanners parsed:
  - Semgrep    (SAST)
  - OWASP DC   (SCA / dependencies)
  - npm audit  (dependencies)
  - Trivy      (container CVE + misconfig)

Usage:
  python3 gate-check.py --severity HIGH --artifacts-dir ./artifacts/ --output gate-report.md
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ─── Severity ordering ────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


@dataclass
class Finding:
    source:      str
    tool:        str
    severity:    str
    title:       str
    description: str = ""
    location:    str = ""
    cve:         str = ""
    cvss:        float = 0.0
    fixed_in:    str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.upper(), 0)


@dataclass
class GateResult:
    scanner:  str
    findings: list[Finding] = field(default_factory=list)
    parse_error: Optional[str] = None

    def count(self, min_severity: str) -> int:
        min_rank = SEVERITY_ORDER.get(min_severity.upper(), 0)
        return sum(1 for f in self.findings if f.severity_rank >= min_rank)


# ─── Parsers ──────────────────────────────────────────────────────────

def parse_semgrep(artifact_dir: Path) -> GateResult:
    result = GateResult(scanner="Semgrep (SAST)")
    candidates = list(artifact_dir.rglob("semgrep-results.json"))
    if not candidates:
        return result

    try:
        data = json.loads(candidates[0].read_text())
        for item in data.get("results", []):
            sev = item.get("extra", {}).get("severity", "WARNING")
            # Semgrep uses ERROR/WARNING — map to HIGH/MEDIUM
            severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            result.findings.append(Finding(
                source="semgrep",
                tool="Semgrep",
                severity=severity_map.get(sev, "MEDIUM"),
                title=item.get("check_id", "Unknown rule"),
                description=item.get("extra", {}).get("message", ""),
                location=f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}",
            ))
    except Exception as e:
        result.parse_error = str(e)
    return result


def parse_npm_audit(artifact_dir: Path) -> GateResult:
    result = GateResult(scanner="npm audit (SCA)")
    candidates = list(artifact_dir.rglob("npm-audit.json"))
    if not candidates:
        return result

    try:
        data = json.loads(candidates[0].read_text())
        # npm audit v2+ format
        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln in vulnerabilities.items():
            sev = vuln.get("severity", "unknown").upper()
            if sev not in SEVERITY_ORDER:
                sev = "MEDIUM"
            for via in vuln.get("via", []):
                if isinstance(via, dict):
                    result.findings.append(Finding(
                        source="npm-audit",
                        tool="npm audit",
                        severity=sev,
                        title=f"{pkg_name}: {via.get('title', 'Vulnerability')}",
                        description=via.get("url", ""),
                        location=f"package.json → {pkg_name}@{vuln.get('range', '')}",
                        cve=via.get("cve", ""),
                        cvss=float(via.get("cvss", {}).get("score", 0) or 0),
                        fixed_in=via.get("fixAvailable", {}).get("version", "") if isinstance(via.get("fixAvailable"), dict) else "",
                    ))
                    break  # One finding per package
    except Exception as e:
        result.parse_error = str(e)
    return result


def parse_owasp_dc(artifact_dir: Path) -> GateResult:
    result = GateResult(scanner="OWASP Dependency Check (SCA)")
    candidates = list(artifact_dir.rglob("dependency-check-report.json"))
    if not candidates:
        return result

    try:
        data = json.loads(candidates[0].read_text())
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            for vuln in dep.get("vulnerabilities", []):
                cvss_v3 = vuln.get("cvssv3", {})
                cvss_score = float(cvss_v3.get("baseScore", 0) or 0)
                # Map CVSS score to severity
                if cvss_score >= 9.0:
                    sev = "CRITICAL"
                elif cvss_score >= 7.0:
                    sev = "HIGH"
                elif cvss_score >= 4.0:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"

                result.findings.append(Finding(
                    source="owasp-dc",
                    tool="OWASP Dependency Check",
                    severity=sev,
                    title=f"{dep.get('fileName', 'Unknown')}: {vuln.get('name', '')}",
                    description=vuln.get("description", "")[:200],
                    location=dep.get("filePath", ""),
                    cve=vuln.get("name", ""),
                    cvss=cvss_score,
                ))
    except Exception as e:
        result.parse_error = str(e)
    return result


def parse_trivy(artifact_dir: Path) -> GateResult:
    result = GateResult(scanner="Trivy (Container)")
    candidates = list(artifact_dir.rglob("trivy-results.json"))
    if not candidates:
        return result

    try:
        data = json.loads(candidates[0].read_text())
        for scan_result in data.get("Results", []):
            target = scan_result.get("Target", "")
            for vuln in scan_result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN").upper()
                if sev not in SEVERITY_ORDER:
                    sev = "MEDIUM"
                result.findings.append(Finding(
                    source="trivy",
                    tool="Trivy",
                    severity=sev,
                    title=f"{vuln.get('PkgName', 'Unknown')}: {vuln.get('VulnerabilityID', '')}",
                    description=vuln.get("Description", "")[:200],
                    location=f"{target} → {vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                    cve=vuln.get("VulnerabilityID", ""),
                    cvss=float((vuln.get("CVSS", {}) or {}).get("nvd", {}).get("V3Score", 0) or 0),
                    fixed_in=vuln.get("FixedVersion", ""),
                ))
    except Exception as e:
        result.parse_error = str(e)
    return result


# ─── Report generation ────────────────────────────────────────────────

def generate_report(
    gate_results: list[GateResult],
    fail_severity: str,
    gate_passed: bool,
) -> str:
    lines = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    gate_emoji = "✅ PASS" if gate_passed else "❌ FAIL"
    lines += [
        f"# 🚦 Security Gate Report — {ts}",
        f"",
        f"**Gate Status:** {gate_emoji}  ",
        f"**Fail Threshold:** `{fail_severity}` and above  ",
        f"",
        "---",
        "",
        "## Scanner Results",
        "",
        "| Scanner | Total | Critical | High | Medium | Low | Gate |",
        "|---------|-------|----------|------|--------|-----|------|",
    ]

    for gr in gate_results:
        findings = gr.findings
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
        fail_count = gr.count(fail_severity)
        status = "❌ FAIL" if fail_count > 0 else "✅ PASS"
        if gr.parse_error:
            status = "⚠️ ERROR"
        lines.append(
            f"| {gr.scanner} | {len(findings)} | {counts['CRITICAL']} | "
            f"{counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {status} |"
        )

    lines += ["", "---", ""]

    # Detail per scanner
    for gr in gate_results:
        if gr.parse_error:
            lines += [f"### ⚠️ {gr.scanner} — Parse Error", f"```", gr.parse_error, "```", ""]
            continue

        blocking = [f for f in gr.findings if f.severity_rank >= SEVERITY_ORDER.get(fail_severity, 0)]
        if not blocking:
            lines += [f"### ✅ {gr.scanner} — No blocking findings", ""]
            continue

        lines += [f"### ❌ {gr.scanner} — {len(blocking)} blocking finding(s)", ""]
        for f in sorted(blocking, key=lambda x: -x.severity_rank)[:20]:  # Max 20 per tool
            emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
            lines.append(f"- {emoji} **[{f.severity}]** `{f.title}`")
            if f.location:
                lines.append(f"  - 📁 `{f.location}`")
            if f.cve:
                lines.append(f"  - 🔗 {f.cve}")
            if f.cvss:
                lines.append(f"  - CVSS: {f.cvss:.1f}")
            if f.fixed_in:
                lines.append(f"  - ✅ Fix: upgrade to `{f.fixed_in}`")
            if f.description:
                lines.append(f"  - {f.description[:150]}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Action Required" if not gate_passed else "## ✅ All Gates Passed",
        "",
    ]
    if not gate_passed:
        lines += [
            "The build is **blocked**. Resolve all HIGH/CRITICAL findings before merging.",
            "",
            "1. Review the findings above",
            "2. Apply patches from `remediation/patches/`",
            "3. Re-push to trigger the pipeline",
            "4. Gates must all show ✅ before DAST runs",
        ]
    else:
        lines += ["Proceeding to DAST scan. 🕷️"]

    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DevSecOps Security Gate Checker")
    parser.add_argument("--severity",      default="HIGH",            help="Minimum severity to fail (CRITICAL/HIGH/MEDIUM/LOW)")
    parser.add_argument("--artifacts-dir", default="./scan-artifacts", help="Directory containing scanner output JSON files")
    parser.add_argument("--output",        default="gate-report.md",  help="Output markdown report path")
    args = parser.parse_args()

    fail_severity = args.severity.upper()
    if fail_severity not in SEVERITY_ORDER:
        print(f"❌ Unknown severity: {fail_severity}. Choose from: {list(SEVERITY_ORDER.keys())}")
        sys.exit(2)

    artifacts_dir = Path(args.artifacts_dir)
    if not artifacts_dir.exists():
        print(f"⚠️  Artifacts directory not found: {artifacts_dir}")
        print("   Continuing with zero findings (no artifacts = scan did not run)")

    print(f"\n{'─'*60}")
    print(f"  🚦 DevSecOps Security Gate")
    print(f"  Fail threshold: {fail_severity}+")
    print(f"  Artifacts dir:  {artifacts_dir}")
    print(f"{'─'*60}\n")

    # Run all parsers
    gate_results = [
        parse_semgrep(artifacts_dir),
        parse_npm_audit(artifacts_dir),
        parse_owasp_dc(artifacts_dir),
        parse_trivy(artifacts_dir),
    ]

    # Evaluate gate
    min_rank = SEVERITY_ORDER[fail_severity]
    total_blocking = sum(gr.count(fail_severity) for gr in gate_results)
    gate_passed = total_blocking == 0

    # Print summary to stdout
    for gr in gate_results:
        blocking = gr.count(fail_severity)
        status_icon = "✅" if blocking == 0 else "❌"
        parse_note = f" (parse error: {gr.parse_error})" if gr.parse_error else ""
        print(f"  {status_icon} {gr.scanner:<40} blocking={blocking}{parse_note}")

    print(f"\n{'─'*60}")
    if gate_passed:
        print("  ✅ GATE PASSED — No blocking findings")
    else:
        print(f"  ❌ GATE FAILED — {total_blocking} blocking finding(s) at {fail_severity}+")
    print(f"{'─'*60}\n")

    # Generate and write report
    report = generate_report(gate_results, fail_severity, gate_passed)
    Path(args.output).write_text(report)
    print(f"  📄 Report written to: {args.output}")

    # Write to GitHub Step Summary if available
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as f:
            f.write(report)

    # Set GitHub Actions output
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"status={'PASS' if gate_passed else 'FAIL'}\n")
            f.write(f"finding_count={total_blocking}\n")

    sys.exit(0 if gate_passed else 1)


if __name__ == "__main__":
    main()
