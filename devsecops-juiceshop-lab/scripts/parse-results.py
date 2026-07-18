#!/usr/bin/env python3
"""
parse-results.py — Consolidated Security Report Generator
=========================================================
Reads all scan artifacts, deduplicates findings, and produces
a single markdown report suitable for GitHub Job Summary and
portfolio documentation.

Usage:
  python3 parse-results.py \
    --artifacts-dir ./all-artifacts/ \
    --output security-report.md \
    --commit abc1234 \
    --branch main
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def parse_zap_report(artifacts_dir: Path) -> list[dict]:
    findings = []
    for f in artifacts_dir.rglob("report_json.json"):
        data = load_json(f)
        if not data:
            continue
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "").split(" ")[0].upper()
                findings.append({
                    "tool": "OWASP ZAP (DAST)",
                    "severity": risk,
                    "title": alert.get("name", "Unknown"),
                    "description": alert.get("desc", "")[:300].replace("<p>", "").replace("</p>", " "),
                    "solution": alert.get("solution", "")[:200].replace("<p>", "").replace("</p>", " "),
                    "url": alert.get("instances", [{}])[0].get("uri", ""),
                    "count": alert.get("count", "1"),
                    "cwe": f"CWE-{alert.get('cweid', '?')}",
                    "wasc": f"WASC-{alert.get('wascid', '?')}",
                })
    return findings


def count_severity(findings: list[dict], severity: str) -> int:
    return sum(1 for f in findings if f.get("severity", "").upper() == severity)


def severity_bar(findings: list[dict]) -> str:
    counts = {s: count_severity(findings, s) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    parts = []
    if counts["CRITICAL"]: parts.append(f"🔴 {counts['CRITICAL']} Critical")
    if counts["HIGH"]:     parts.append(f"🟠 {counts['HIGH']} High")
    if counts["MEDIUM"]:   parts.append(f"🟡 {counts['MEDIUM']} Medium")
    if counts["LOW"]:      parts.append(f"🔵 {counts['LOW']} Low")
    return " | ".join(parts) if parts else "✅ No findings"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", default="./all-artifacts/")
    parser.add_argument("--output",        default="security-report.md")
    parser.add_argument("--commit",        default="unknown")
    parser.add_argument("--branch",        default="unknown")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Load ZAP DAST results
    zap_findings = parse_zap_report(artifacts_dir)

    # Count findings from gate report (already parsed)
    gate_report_files = list(artifacts_dir.rglob("gate-report.md"))
    gate_summary = gate_report_files[0].read_text() if gate_report_files else "_Gate report not found._"

    lines = [
        f"# 📊 Consolidated Security Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Timestamp** | {ts} |",
        f"| **Commit** | `{args.commit[:8]}` |",
        f"| **Branch** | `{args.branch}` |",
        f"| **Pipeline** | DevSecOps Lab — MontechQ |",
        f"",
        f"---",
        f"",
        f"## Pipeline Stage Summary",
        f"",
        f"| Stage | Tool | Status |",
        f"|-------|------|--------|",
        f"| Secrets | TruffleHog + GitLeaks | See gate report ↓ |",
        f"| SAST | Semgrep + CodeQL | See gate report ↓ |",
        f"| Dependencies | OWASP DC + npm audit | See gate report ↓ |",
        f"| Container | Trivy | See gate report ↓ |",
        f"| DAST | OWASP ZAP | {len(zap_findings)} alerts |",
        f"",
        f"---",
        f"",
        f"## SAST / SCA / Container Gate",
        f"",
        gate_summary,
        f"",
        f"---",
        f"",
        f"## DAST — OWASP ZAP Findings",
        f"",
    ]

    if not zap_findings:
        lines.append("_ZAP report not available (gate did not pass or scan did not run)._")
    else:
        lines += [
            f"**Summary:** {severity_bar(zap_findings)}",
            f"",
            f"| Severity | Title | URL | CWE |",
            f"|----------|-------|-----|-----|",
        ]
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        for f in sorted(zap_findings, key=lambda x: severity_order.get(x["severity"], 5)):
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
            url = f["url"][:60] + "..." if len(f["url"]) > 60 else f["url"]
            lines.append(f"| {sev_emoji} {f['severity']} | {f['title']} | `{url}` | {f['cwe']} |")

        lines += [""]

        # Detail cards for HIGH+
        blocking_zap = [f for f in zap_findings if f["severity"] in ("CRITICAL", "HIGH")]
        if blocking_zap:
            lines += [f"### 🟠 High+ Finding Details", ""]
            for f in blocking_zap:
                lines += [
                    f"#### {f['title']}",
                    f"- **Severity:** {f['severity']} | **CWE:** {f['cwe']} | **WASC:** {f['wasc']}",
                    f"- **Instances:** {f['count']}",
                    f"- **Example URL:** `{f['url']}`",
                    f"- **Description:** {f['description']}",
                    f"- **Remediation:** {f['solution']}",
                    f"",
                ]

    lines += [
        "---",
        "",
        "## Next Steps",
        "",
        "1. Review all HIGH/CRITICAL findings above",
        "2. Cross-reference with manual findings in `pentesting/findings/juice-shop-assessment.md`",
        "3. Apply remediations from `remediation/patches/`",
        "4. Re-push and verify all gates pass",
        "",
        "---",
        f"_Report generated by `parse-results.py` at {ts}_",
    ]

    output = Path(args.output)
    output.write_text("\n".join(lines))
    print(f"✅ Report written to: {output}")


if __name__ == "__main__":
    main()
