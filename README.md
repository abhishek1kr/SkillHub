# 🛡️ SkillHub: Security & Bug Bounty Agent Skills Engine

> **Automated harvester, parser, and package manager for AI Agent Security Skills.**  
> Solves the flat-file incompatibility and context-window saturation problems by providing clean, categorized, and on-demand installation of security skills into your active workspaces.

---

## 🚀 Why SkillHub?

Existing aggregators dump thousands of unindexed flat `.md` files into a single folder. This causes two critical problems:
1. **Format Incompatibility**: Modern agent frameworks (Anthropic Agent Skills, Antigravity, Claude Code) require directory-scoped skills formatted as `<skill-name>/SKILL.md` with valid YAML frontmatter.
2. **Context Window Exhaustion**: Loading 1,000+ security skills into your global agent configuration burns 30,000+ tokens on every turn and causes the AI to drop relevant skills due to context limits.

**SkillHub solves both**:
- 📦 **Standardizes & Packages**: Converts any upstream repo (flat or nested) into compliant `<category>/<skill-name>/SKILL.md` bundles.
- 🎯 **Targeted Workspace Installation**: Install only the 2–5 skills you need for an active engagement into your project's `.agents/skills` folder.
- 🏷️ **Domain Categorization**: Automatically organizes skills across **Web, API, Cloud, Recon, Mobile, Logic Flaws, Network, and Reporting**.
- ⚡ **Pure Standard Library**: Zero external Python dependencies (`pyyaml` or `requests` not required). Runs immediately on Python 3.10+.

---

## 📦 Quick Start

### 1. Check Library Status
```bash
python skillhub.py status
```

### 2. Search for Skills
Search across vulnerability names, tags, and methodologies:
```bash
python skillhub.py search "graphql"
python skillhub.py search "ssrf"
python skillhub.py search "cloud"
```

### 3. List by Category
View available domains:
```bash
python skillhub.py list
```
View all skills in a specific domain:
```bash
python skillhub.py list -c api
python skillhub.py list -c web
python skillhub.py list -c mobile
```

### 4. Inspect a Skill
View full metadata, upstream source credit, and a preview:
```bash
python skillhub.py info offensive-api-abuse
```

### 5. Install into Your Workspace (Recommended)
Install a specific skill into your active engagement workspace (creates `./.agents/skills/<name>/SKILL.md`):
```bash
# In your target engagement directory:
python /path/to/skillhub.py install hunt-sqli

# Or specify custom path:
python skillhub.py install offensive-api-abuse -t ./my-pentest/.agents/skills
```

### 6. Install an Entire Category
```bash
python skillhub.py install-category api -t ./my-api-audit/.agents/skills
```

---

## 🔄 Daily Automated Harvesting

SkillHub includes a fully configured GitHub Actions workflow (`.github/workflows/harvest.yml`) that runs daily at **04:00 UTC**:

1. Reads every upstream repository configured in `sources.txt`.
2. Downloads newly added or updated skills.
3. Parses and cleans YAML frontmatter.
4. Categorizes and deduplicates using SHA-256 and canonical slug normalization.
5. Updates `catalog.json` and commits fresh skills back to your repository.

### Adding New Sources
Simply edit `sources.txt` and add the `owner/repo`:
```text
# sources.txt
0x002132/skills-bugbounty
Gabson0x/bountyforge
SnailSploit/Claude-Red
your-handle/your-custom-skills
```

To run a manual sync locally:
```bash
# Optional: Set GITHUB_TOKEN to bypass GitHub API rate limits
export GITHUB_TOKEN="ghp_your_personal_token"   # Linux / macOS
$env:GITHUB_TOKEN="ghp_your_personal_token"      # Windows PowerShell

python skillhub.py sync
```

---

## 📁 Repository Layout

```text
.
├── .github/
│   └── workflows/
│       └── harvest.yml        # Daily automated GitHub Actions harvester
├── library/                   # Categorized agent-compliant skill bundles
│   ├── api/
│   │   └── offensive-api-abuse/
│   │       └── SKILL.md
│   ├── cloud/
│   ├── mobile/
│   ├── recon/
│   ├── reporting/
│   └── web/
├── catalog.json               # Indexed metadata catalog for fast querying
├── skillhub.py                # Harvester, parser, packager & CLI manager
├── sources.txt                # Upstream repository tracking list
└── README.md
```

---

## ⚖️ Ethical & Authorized Use Only

The skills collected and managed by this tool provide methodology checklists and workflows intended exclusively for **authorized security evaluations, bug bounty programs operating under safe harbor, and defensive security hardening**. 

Always ensure you have explicit, documented authorization prior to executing any security assessment against a target system.
