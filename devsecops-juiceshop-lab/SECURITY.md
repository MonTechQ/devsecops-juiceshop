# Security Policy

## Project Scope

This project contains **intentionally vulnerable software** (OWASP Juice Shop)
used for authorized security research, DevSecOps skill demonstration, and
portfolio documentation.

**All testing documented here was conducted:**
- In an isolated Docker environment on localhost
- Against OWASP Juice Shop — an intentionally vulnerable training application
- With no real users, real data, or production systems involved

---

## Authorized Testing Only

The penetration testing techniques, payloads, and tools documented in this
repository are for **educational and authorized security research purposes only**.

**Do NOT use these techniques against:**
- Systems you do not own or have explicit written authorization to test
- Production applications or live services
- Any system without a signed Rules of Engagement / Authorization document

Unauthorized testing is illegal and unethical. The author (MontechQ) is not
responsible for misuse of this material.

---

## Reporting Security Issues in This Repository

If you discover a security issue in the **DevSecOps pipeline scripts or
configuration** in this repository (not in Juice Shop itself):

1. **Do not open a public GitHub issue**
2. Use the **GitHub Security Advisory** feature to report privately
3. Include: description, reproduction steps, and suggested remediation

For vulnerabilities in OWASP Juice Shop itself, report to the
[Juice Shop project](https://github.com/juice-shop/juice-shop/security).

---

## Responsible Disclosure (Bug Bounty Context)

For bug bounty hunting on Bugcrowd / HackerOne:
- Always operate within program scope
- Obtain authorization before testing
- Follow the platform's disclosure policy
- Do not access, modify, or exfiltrate real user data
- Report findings through the official program channel

---

## Legal Notice

OWASP Juice Shop is an open-source project by OWASP Foundation.
This repository wraps it for DevSecOps demonstration and does not
claim ownership of the Juice Shop application itself.

All CVE references, vulnerability descriptions, and CVSS scores are
used for educational documentation purposes.
