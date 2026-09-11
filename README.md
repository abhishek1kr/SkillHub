# SkillHub: Security & Bug Bounty Agent Skills Engine

Harvester, parser, and package manager for AI agent security methodology skills.

SkillHub addresses two common challenges when integrating public security checklists and prompt collections with coding agents:
1. **Directory format requirements**: Modern agent frameworks (including Anthropic Agent Skills and Antigravity) look for individual directories matching `skills/<category>/<skill-name>/SKILL.md` with structured frontmatter, rather than unstructured flat markdown files.
2. **Context window limits**: Storing hundreds of security checklists in a global configuration consumes tens of thousands of tokens per prompt and pushes other system instructions out of context. SkillHub enables selective installation of specific skills into active project workspaces (`.agents/skills/`).

---

## Features

- **Standardized packaging**: Converts flat or nested upstream markdown files into valid directory bundles with sanitized YAML frontmatter.
- **Selective installation**: Install individual skills or entire categories into an active workspace or global path on demand.
- **Domain categorization**: Automatically maps methodology files to domains: Web, API, Cloud, Recon, Mobile, Logic Flaws, Network, and Reporting.
- **Standard library only**: Built entirely on Python 3.10+ standard libraries with no external package requirements.

---

## Usage

### 1. Library Status
View sync time, total skills, and category distributions:
```bash
python skillhub.py status
```

### 2. Search Skills
Search by keyword, vulnerability type, or technology:
```bash
python skillhub.py search "graphql"
python skillhub.py search "ssrf"
python skillhub.py search "cloud"
```

### 3. List by Category
List all recognized domains:
```bash
python skillhub.py list
```

List skills inside a specific domain:
```bash
python skillhub.py list -c web
python skillhub.py list -c api
python skillhub.py list -c recon
```

### 4. Inspect a Skill
View metadata, source repository, and a file preview:
```bash
python skillhub.py info offensive-api-abuse
```

### 5. Install into Workspace
To add a skill to your current project (writes to `./.agents/skills/<skill-name>/SKILL.md`):
```bash
python /path/to/skillhub.py install hunt-sqli
```

Or target a specific directory:
```bash
python skillhub.py install offensive-api-abuse -t ./my-pentest/.agents/skills
```

### 6. Install an Entire Category
To equip a workspace with all skills in a domain:
```bash
python skillhub.py install-category api -t ./my-api-audit/.agents/skills
```

---

## Automated Synchronization

A scheduled GitHub Actions workflow (`.github/workflows/harvest.yml`) is configured to run daily at 04:00 UTC:
1. Reads repository targets listed in `sources.txt`.
2. Downloads new or modified skills.
3. Parses, cleans, and standardizes frontmatter.
4. Categorizes skills and avoids duplicates via SHA-256 and slug normalization.
5. Updates `catalog.json` and commits newly discovered skills.

### Adding Upstream Repositories
Append `owner/repo` entries to `sources.txt`:
```text
0x002132/skills-bugbounty
Gabson0x/bountyforge
SnailSploit/Claude-Red
```

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
│   ├── api/
│   ├── cloud/
│   ├── mobile/
│   ├── network/
│   ├── recon/
│   ├── reporting/
│   └── web/
├── catalog.json               # Indexed metadata catalog for CLI search
├── skillhub.py                # Harvester and package manager CLI
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
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | Offensive security workflows and red-teaming methodologies | [@SnailSploit](https://github.com/SnailSploit) |
| [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) | Open Source Intelligence (OSINT) and asset enumeration skills | [@elementalsouls](https://github.com/elementalsouls) |
| [Aetherdz/huntpack](https://github.com/Aetherdz/huntpack) | Vulnerability hunt packs and detection signals | [@Aetherdz](https://github.com/Aetherdz) |
| [murraywu/Bug-Bounty-Skills](https://github.com/murraywu/Bug-Bounty-Skills) | Security tool operational guides (Burp Suite, code auditing) | [@murraywu](https://github.com/murraywu) |
| [vigilantshield/Claude-HunterKit](https://github.com/vigilantshield/Claude-HunterKit) | Offensive testing checklists and workflow orchestration | [@vigilantshield](https://github.com/vigilantshield) |
| [akashrpatil/awesome-offensive-security-skills](https://github.com/akashrpatil/awesome-offensive-security-skills) | Curated index of offensive security skill files | [@akashrpatil](https://github.com/akashrpatil) |
| [anthropics/skills](https://github.com/anthropics/skills) | Agent Skills folder specification and formatting reference | [Anthropic](https://github.com/anthropics) |
| [alirezarezvani/claude-skills](https://github.com/alirezarezvani/claude-skills) | Open-source agent skills reference collection | [@alirezarezvani](https://github.com/alirezarezvani) |

---

## Scope & Authorized Testing

The methodology files indexed by this utility are intended strictly for authorized security assessments, penetration tests conducted under formal engagement rules, and bug bounty programs with explicit safe harbor provisions. Never perform security testing against applications or infrastructure without documented owner authorization.
