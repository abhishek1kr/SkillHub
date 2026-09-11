# SkillHub: Security & Bug Bounty Agent Skills Engine

Harvester, parser, and package manager for AI agent security methodology skills.

SkillHub addresses two common challenges when integrating public security checklists and prompt collections with coding agents:
1. **Directory format requirements**: Modern agent frameworks (including Anthropic Agent Skills and Antigravity) look for individual directories matching `skills/<category>/<skill-name>/SKILL.md` with structured frontmatter, rather than unstructured flat markdown files.
2. **Context window limits**: Storing hundreds of security checklists in a global configuration consumes tens of thousands of tokens per prompt and pushes other system instructions out of context. SkillHub enables selective installation of specific skills into active project workspaces (`.agents/skills/`).

---

## Features

- **Starter Packs**: One-command installation of curated bundles for beginners, web audits, API testing, Active Directory, and recon.
- **Agent Prompt Generator**: Automatically generates structured system/user prompts tailored for Claude, Antigravity, or ChatGPT.
- **Standardized packaging**: Converts flat or nested upstream markdown files into valid directory bundles with sanitized YAML frontmatter.
- **Domain categorization**: Automatically maps methodology files to domains: Web, API, Cloud, Recon, Mobile, Logic Flaws, Active Directory, Industrial Control Systems (ICS/OT), and AI Agent Defense.
- **Zero dependencies**: Built entirely on Python 3.10+ standard libraries with no external package requirements.

---

## Installation

### Linux / Kali (One-Liner)
```bash
curl -sSL https://raw.githubusercontent.com/abhishek1kr/SkillHub/main/install.sh | bash
```

### Windows
```powershell
git clone https://github.com/abhishek1kr/SkillHub.git
cd SkillHub
python skillhub.py check
```

---

## Usage

### 1. Interactive Mode
Running with no arguments launches the guided interactive assistant:
```bash
python skillhub.py
```

### 2. Starter Packs
Install pre-configured bundles directly into your project's `./.agents/skills/` directory:
```bash
# View available starter packs
python skillhub.py pack

# Install specific packs
python skillhub.py pack beginner
python skillhub.py pack web
python skillhub.py pack api
python skillhub.py pack recon
python skillhub.py pack ad
python skillhub.py pack ai-sec
```

### 3. Generate Agent Prompts
Generate ready-to-use prompt instructions for your AI coding assistant:
```bash
# For a starter pack:
python skillhub.py prompt web
python skillhub.py prompt beginner

# For an individual skill:
python skillhub.py prompt offensive-api-abuse
```

### 4. Search & Inspect Skills
```bash
# Search across keywords
python skillhub.py search "graphql"
python skillhub.py search "kerberos"
python skillhub.py search "scada"

# View skill details and preview
python skillhub.py info offensive-api-abuse
```

### 5. List by Domain
```bash
python skillhub.py list
python skillhub.py list -c web
python skillhub.py list -c api
python skillhub.py list -c ad
python skillhub.py list -c recon
```

### 6. Install Specific Skills or Categories
```bash
# Install single skill into current workspace
python skillhub.py install hunt-sqli

# Install an entire category into a custom target folder
python skillhub.py install-category web -t ./my-pentest/.agents/skills
```

### 7. Self-Check Diagnostic
Verify catalog validity, search indexing, and packaging integrity:
```bash
python skillhub.py check
```

---

## Automated Synchronization

A scheduled GitHub Actions workflow (`.github/workflows/harvest.yml`) runs daily at 04:00 UTC:
1. Reads repository targets listed in `sources.txt`.
2. Downloads new or modified skills.
3. Parses, cleans, and standardizes frontmatter.
4. Categorizes skills and avoids duplicates via SHA-256 and slug normalization.
5. Updates `catalog.json` and commits newly discovered skills.

To run a manual sync locally:
```bash
# Optional: Set GITHUB_TOKEN to bypass GitHub unauthenticated rate limits
export GITHUB_TOKEN="ghp_your_personal_token"   # Linux / macOS
$env:GITHUB_TOKEN="ghp_your_personal_token"      # Windows PowerShell

python skillhub.py sync
```

---

## Repository Structure

```text
.
├── .github/
│   └── workflows/
│       └── harvest.yml        # Daily GitHub Actions harvest pipeline
├── library/                   # Categorized agent skills (<category>/<name>/SKILL.md)
│   ├── ad/                    # Active Directory & enterprise identity
│   ├── ai-security/           # Agent security & prompt injection defense
│   ├── api/                   # REST, GraphQL, and authorization testing
│   ├── cloud/                 # AWS, Azure, GCP, and Kubernetes
│   ├── ics-ot/                # Industrial control systems & SCADA
│   ├── mobile/                # Android APK & iOS application testing
│   ├── network/               # Network protocols & infrastructure
│   ├── recon/                 # OSINT, asset discovery, and enumeration
│   ├── reporting/             # Triage templates and proof-of-concept guides
│   └── web/                   # Web vulnerabilities & input auditing
├── catalog.json               # Indexed metadata catalog for CLI search
├── install.sh                 # Single-line installer for Linux / Kali
├── skillhub.py                # Harvester, parser, packager & CLI manager
├── sources.txt                # Upstream repository tracking list
└── README.md
```

---

## Credits & Upstream Sources

SkillHub structures and indexes material produced by security researchers and the open-source security community. Credit belongs to the authors and maintainers of each upstream repository:

| Repository | Focus & Contribution | Author / Maintainer |
|---|---|---|
| [S1N6H/Bug-Bounty-Skills](https://github.com/S1N6H/Bug-Bounty-Skills) | Harvester pipeline reference and aggregated skill library | [@S1N6H](https://github.com/S1N6H) |
| [0x002132/skills-bugbounty](https://github.com/0x002132/skills-bugbounty) | Vulnerability checklists (SQLi, SSRF, OAuth, Cloud IAM, SAML) | [@0x002132](https://github.com/0x002132) |
| [Gabson0x/bountyforge](https://github.com/Gabson0x/bountyforge) | Bug bounty checklists and smart contract security reviews | [@Gabson0x](https://github.com/Gabson0x) |
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | Specialized bug hunting workflows and attack chains | [@elementalsouls](https://github.com/elementalsouls) |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | Offensive security workflows and red-teaming methodologies | [@SnailSploit](https://github.com/SnailSploit) |
| [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) | Open Source Intelligence (OSINT) and asset enumeration skills | [@elementalsouls](https://github.com/elementalsouls) |
| [Aetherdz/huntpack](https://github.com/Aetherdz/huntpack) | Vulnerability hunt packs and detection signals | [@Aetherdz](https://github.com/Aetherdz) |
| [murraywu/Bug-Bounty-Skills](https://github.com/murraywu/Bug-Bounty-Skills) | Security tool operational guides (Burp Suite, code auditing) | [@murraywu](https://github.com/murraywu) |
| [vigilantshield/Claude-HunterKit](https://github.com/vigilantshield/Claude-HunterKit) | Offensive testing checklists and workflow orchestration | [@vigilantshield](https://github.com/vigilantshield) |
| [ADScanPro/Claude-AD](https://github.com/ADScanPro/Claude-AD) | Active Directory attack surface, privilege escalation, and Kerberos | [@ADScanPro](https://github.com/ADScanPro) |
| [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill) | Industrial control systems (ICS/OT) and operational security skills | [@Masriyan](https://github.com/Masriyan) |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Enterprise cybersecurity and application defense skills | [@mukul975](https://github.com/mukul975) |
| [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) | AI agent skill security scanner and prompt injection auditing | [NVIDIA](https://github.com/NVIDIA) |
| [akashrpatil/awesome-offensive-security-skills](https://github.com/akashrpatil/awesome-offensive-security-skills) | Curated index of offensive security skill files | [@akashrpatil](https://github.com/akashrpatil) |
| [anthropics/skills](https://github.com/anthropics/skills) | Agent Skills folder specification and formatting reference | [Anthropic](https://github.com/anthropics) |
| [alirezarezvani/claude-skills](https://github.com/alirezarezvani/claude-skills) | Open-source agent skills reference collection | [@alirezarezvani](https://github.com/alirezarezvani) |

---

## Scope & Authorized Testing

The methodology files indexed by this utility are intended strictly for authorized security assessments, penetration tests conducted under formal engagement rules, and bug bounty programs with explicit safe harbor provisions. Never perform security testing against applications or infrastructure without documented owner authorization.
