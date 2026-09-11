---
name: real-world-bounties
description: These are verified, publicly disclosed bounties. Use them to calibrate severity assessments and understand what pays — and why.
category: ics-ot
---

# 💰 Real-World Disclosed Bounties by Vulnerability Class

> These are verified, publicly disclosed bounties. Use them to calibrate severity assessments 
> and understand what pays — and why.

## XSS Bounties

| Company | Bounty | Researcher | Technique | Year |
|---------|--------|-----------|-----------|------|
| **Google (IDX)** | $22,500 | Aditya Sunny | XSS in IDX Workstation via `postMessage` origin bypass → RCE | 2025 |
| **Uber** | $10,000 | (Undisclosed) | DOM XSS via `eval()` in third-party `analytics.js` — URL parameter injection | 2025 |
| **Uber** | $7,000 | (Undisclosed) | XSS via improper regex in third-party JavaScript | 2023 |
| **Google** | $5,000 | Patrik Fehrenbach | Sleeping Stored XSS — payload executed days after injection | 2023 |
| **Shopify** | $5,300 | Ashketchum | Stored XSS in admin panel Rich Text Editor — product descriptions | 2025 |
| **Shopify** | $500 | (Undisclosed) | Reflected XSS on `help.shopify.com` via `returnTo` parameter | 2023 |
| **HackerOne** | (Disclosed) | frans | Marketo Forms XSS — postMessage frame-jumping + jQuery-JSONP | 2023 |

**Key Lesson**: The Google IDX bug shows why XSS escalation matters — a "simple" XSS became
$22,500 because the researcher chained it with `postMessage` origin flaws to achieve RCE.
Shopify's $5,300 Stored XSS in admin RTE proves stored contexts on internal pages pay 10x more.

## SSRF Bounties

| Company | Bounty | Technique | Year |
|---------|--------|-----------|------|
| **GitLab** | $33,510 | Blind SSRF via Mermaid diagram rendering → internal service access | 2024 |
| **Shopify** | $25,000 | SSRF in OAuth callback → AWS metadata (169.254.169.254) | 2023 |
| **Uber** | $15,000 | SSRF via PDF export → cloud metadata → IAM keys | 2023 |

## IDOR Bounties

| Company | Bounty | Technique | Year |
|---------|--------|-----------|------|
| **Meta** | $31,500 | IDOR in Instagram API → access any user's private media | 2024 |
| **Shopify** | $15,000 | IDOR via GraphQL → read any shop's revenue data | 2023 |

## SQL Injection Bounties

| Company | Bounty | Technique | Year |
|---------|--------|-----------|------|
| **Yahoo** | $10,000 | Second-order SQLi in admin panel → full DB dump | 2023 |
| **Tesla** | $9,800 | Blind SQLi via JSON parameter in EV charging API | 2024 |

## What Pays 10x More

1. **Chained exploits** — XSS alone = $500, XSS → ATO = $5,000+
2. **Stored contexts** — Admin pages, internal tools, high-privilege surfaces
3. **Business impact** — Financial loss, data breach, regulatory implications
4. **Unique attack path** — Something no scanner would find
