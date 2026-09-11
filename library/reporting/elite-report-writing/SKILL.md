---
name: elite-report-writing
description: "The difference between a $500 and $50,000 report is the quality of the writeup." — Vickie Li, Bug Bounty Bootcamp
category: reporting
---

# 📝 Elite Report Writing (Top 1% Standard)

> **"The difference between a $500 and $50,000 report is the quality of the writeup."**
> — Vickie Li, Bug Bounty Bootcamp

## Title Format

`[VulnType] in [Component] Allows [BusinessImpact]`

- ❌ "XSS Found" → This tells the triager nothing
- ✅ "Stored XSS in /admin/comments Allows Session Hijacking of All Moderators"

## Report Structure (HackerOne-Optimized)

1. **Summary** (2-4 sentences — triager reads only this first): What broke, how, worst-case.
2. **CVSS 4.0 Vector** — Must be defensible; wrong CVSS destroys credibility.
3. **Attack Scenario** — 3-5 sentence narrative from attacker's perspective.
4. **Impact** — MUST include at least one real number: "Affects 4.2M users" not "affects many users".
5. **Steps to Reproduce** — Deterministic. A junior dev who has never seen this bug reproduces it exactly.
6. **PoC** — Copy-paste runnable. No placeholders. Match the exact HTTP method.
7. **Remediation** — Don't say "sanitize input." Give the exact code fix, before/after.
8. **CWE + References** — SSRF→CWE-918, IDOR→CWE-639, SQLi→CWE-89, XSS→CWE-79.

## Pre-Report Verification (5 Checks)

1. 🔍 **Hallucination Detector** — Verify endpoints, CVEs, and code paths are real
2. 🤖 **AI Writing Pattern Check** — Remove "Certainly!", "It's worth noting", generic phrasing
3. 🧪 **PoC Reproducibility** — Payload syntax valid for context? Prerequisites stated?
4. 📋 **Duplicate Detection** — Is this a scanner-generic finding? Known public disclosure?
5. 📈 **Impact Plausibility** — Severity matches technical capability? No inflation?

## CWE Quick Reference

| Vulnerability | CWE | OWASP Category |
|---|---|---|
| SQL Injection | CWE-89 | A03:2021 Injection |
| XSS (all types) | CWE-79 | A03:2021 Injection |
| SSRF | CWE-918 | A10:2021 SSRF |
| IDOR | CWE-639 | A01:2021 Broken Access Control |
| CSRF | CWE-352 | A01:2021 Broken Access Control |
| Path Traversal | CWE-22 | A01:2021 Broken Access Control |
| Command Injection | CWE-78 | A03:2021 Injection |
| Deserialization | CWE-502 | A08:2021 Software Integrity |
| XXE | CWE-611 | A05:2021 Security Misconfiguration |
| Open Redirect | CWE-601 | A01:2021 Broken Access Control |
