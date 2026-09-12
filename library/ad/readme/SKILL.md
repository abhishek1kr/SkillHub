---
name: readme
description: Full red team lifecycle from initial access to persistent domain compromise.
category: ad
---

# 🎯 Red Teaming Skills (21)

> Full red team lifecycle from initial access to persistent domain compromise.

## Overview

21 skills covering the complete adversary simulation toolkit used by professional red teams.

## Categories

| Category | Skills | Focus |
|---|---|---|
| **C2 Frameworks** | 2 | Cobalt Strike, Malleable C2 profiles |
| **Evasion** | 4 | AMSI bypass, AV/EDR evasion, custom shellcode, LOLBins |
| **Persistence** | 4 | WMI subscriptions, scheduled tasks, registry, DLL hijack |
| **Privilege Escalation** | 4 | Token impersonation, UAC bypass, kernel exploits |
| **Lateral Movement** | 2 | Pass-the-hash, WMI/SMB pivoting |
| **Credential Access** | 2 | LSASS dump, credential harvesting |
| **Initial Access** | 2 | Phishing campaigns, payload delivery |
| **Execution** | 1 | PowerShell/macro execution |

## MITRE ATT&CK Tactics Covered

TA0001 (Initial Access) through TA0011 (Command and Control)

## Quick Start

```
"Bypass AMSI on this Windows endpoint"
"Set up persistence via WMI subscriptions"
"Perform lateral movement using pass-the-hash"
"Forge a Golden Ticket for domain persistence"
```

## Install Only Red Teaming

```bash
./install.sh --category redteam
```
