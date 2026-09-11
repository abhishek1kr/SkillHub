#!/usr/bin/env python3
"""
SkillHub - Automated Harvester & Package Manager for Security Agent Skills.

Features:
- Harvests from GitHub repos (flat or structured SKILL.md layout).
- YAML frontmatter parser & metadata extractor (pure stdlib).
- Automatic categorization (Web, API, Cloud, Recon, Mobile, Logic, Reporting).
- Semantic & SHA256 deduplication.
- Standard packaging (<category>/<skill_name>/SKILL.md).
- Search, list, inspect, and selective installation into project workspaces.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Base paths
ROOT_DIR = Path(__file__).resolve().parent
LIBRARY_DIR = ROOT_DIR / "library"
CATALOG_FILE = ROOT_DIR / "catalog.json"
SOURCES_FILE = ROOT_DIR / "sources.txt"

# Default global destination for Antigravity / Gemini config
DEFAULT_GLOBAL_SKILLS = Path.home() / ".gemini" / "config" / "skills"

# GitHub Endpoints
API_BASE = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"

# Network & safety limits
MAX_FILES_PER_REPO = 1000
MAX_BYTES_PER_FILE = 2_000_000  # 2MB cap per markdown file
REQUEST_TIMEOUT = 30

# Domain categorization rules (order: specific domains first)
CATEGORY_RULES: List[Tuple[str, List[str]]] = [
    ("ad", [
        "active-directory", "kerberos", "adcs", "bloodhound", "mimikatz",
        "pass-the-hash", "gpo", "dcsync", "ntds", "ldap-injection", "golden-ticket"
    ]),
    ("ics-ot", [
        "scada", "ics", "modbus", "plc", "dnp3", "industrial", "ot-security",
        "opc-ua", "bacnet"
    ]),
    ("ai-security", [
        "prompt-injection", "jailbreak", "skill-inspector", "guardrail",
        "model-security", "ai-security", "adversarial"
    ]),
    ("mobile", [
        "apk", "ipa", "android", "ios", "frida", "deeplink", "reverse-apk",
        "mobile", "mobile-audit"
    ]),
    ("recon", [
        "subdomain", "osint", "whois", "shodan", "censys", "crawler",
        "spider", "tech-detect", "fingerprint", "port-scan", "asset-discovery", "recon"
    ]),
    ("cloud", [
        "aws", "azure", "gcp", "iam", "entra", "s3", "bucket", "kubernetes",
        "k8s", "lambda", "cognito", "cloud-misconfig", "serverless", "storage-account"
    ]),
    ("reporting", [
        "report", "template", "bugcrowd", "hackerone", "cvss", "triage",
        "evidence", "writeup", "poc-template", "reporting"
    ]),
    ("network", [
        "smb", "vpn", "ntlm", "ssh", "snmp", "pivoting", "tunneling", "network"
    ]),
    ("logic", [
        "business-logic", "race-condition", "payment", "coupon", "workflow",
        "privilege-escalation", "parameter-pollution", "logic-flaw"
    ]),
    ("api", [
        "graphql", "oauth", "jwt", "saml", "sso", "rest-api", "api-misconfig",
        "mfa-bypass", "auth-bypass", "idor", "rate-limit", "webhook", "grpc", "api-abuse"
    ]),
    ("web", [
        "sqli", "sql-injection", "xss", "cross-site", "csrf", "ssrf", "ssti",
        "xxe", "rce", "remote-code", "lfi", "rfi", "file-upload", "cache-poison",
        "http-smuggling", "crlf", "open-redirect", "clickjacking", "prototype-pollution",
        "aspnet", "sharepoint", "wordpress", "burp"
    ]),
]


# ==============================================================================
# Helper Utilities
# ==============================================================================

def get_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SkillHub-Harvester/2.0"
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_request(endpoint: str, retries: int = 3) -> Optional[Any]:
    """Execute GitHub REST API call with exponential backoff on rate limits."""
    url = f"{API_BASE}{endpoint}" if endpoint.startswith("/") else endpoint
    headers = get_headers()

    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                wait = (attempt + 1) * 30
                print(f"[!] GitHub API rate-limited (HTTP {e.code}). Backing off {wait}s...", flush=True)
                time.sleep(wait)
                continue
            if e.code == 404:
                return None
            print(f"[!] HTTP error {e.code} for {url}: {e.reason}", flush=True)
            return None
        except urllib.error.URLError as e:
            print(f"[!] Network error on attempt {attempt+1}: {e.reason}", flush=True)
            time.sleep(5)
        except Exception as e:
            print(f"[!] Unexpected error: {e}", flush=True)
            return None
    return None


def fetch_raw_content(url: str) -> Optional[bytes]:
    """Fetch raw markdown from raw.githubusercontent.com."""
    req = urllib.request.Request(url, headers={"User-Agent": "SkillHub-Harvester/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read()
    except Exception as e:
        return None


# ==============================================================================
# Frontmatter Parser & Normalizer
# ==============================================================================

def parse_frontmatter(content_str: str) -> Tuple[Dict[str, Any], str]:
    """
    Extract YAML frontmatter between `---` delimiters using pure stdlib.
    Returns (metadata_dict, clean_markdown_body).
    """
    metadata: Dict[str, Any] = {}
    body = content_str

    pattern = r"^---\s*\r?\n(.*?)\r?\n---\s*\r?\n(.*)$"
    match = re.search(pattern, content_str, re.DOTALL)
    if match:
        raw_yaml = match.group(1)
        body = match.group(2)

        # Parse simple key-value YAML pairs line-by-line
        for line in raw_yaml.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower()
                v = v.strip().strip("'\"")
                metadata[k] = v

    return metadata, body


def sanitize_skill_name(name: str) -> str:
    """Normalize a skill slug to lower-kebab-case."""
    name = name.lower()
    # Strip common redundant prefixes
    name = re.sub(r"^(0x[0-9a-f]+-)?(skills?-)?(bugbounty-)?", "", name)
    name = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    return name or "unnamed-skill"


def classify_category(name: str, desc: str, body: str) -> str:
    """Classify a skill into a security domain based on name and content signals."""
    name_lower = name.lower()
    desc_lower = desc.lower()
    body_snippet = body[:1500].lower()

    def has_kw(kw: str, target: str, is_slug: bool = False) -> bool:
        if is_slug:
            return bool(re.search(r"(?:^|[-_])" + re.escape(kw) + r"(?:$|[-_])", target))
        return bool(re.search(r"\b" + re.escape(kw) + r"\b", target))

    # Pass 1: Strict name slug match (highest confidence)
    for category, keywords in CATEGORY_RULES:
        for kw in keywords:
            if has_kw(kw, name_lower, is_slug=True):
                return category

    # Pass 2: Frontmatter description match
    for category, keywords in CATEGORY_RULES:
        for kw in keywords:
            if has_kw(kw, desc_lower):
                return category

    # Pass 3: Body snippet match
    for category, keywords in CATEGORY_RULES:
        for kw in keywords:
            if has_kw(kw, body_snippet):
                return category

    return "general"


def synthesize_frontmatter(name: str, desc: str, category: str, body: str) -> str:
    """Create a clean, standardized SKILL.md string with validated frontmatter."""
    # Strip markdown bolding and blockquote symbols from description
    clean_desc = re.sub(r"[*_>#`]", "", desc).replace("\n", " ").strip()
    clean_desc = re.sub(r"\s+", " ", clean_desc)
    if len(clean_desc) > 240:
        clean_desc = clean_desc[:237] + "..."

    header = (
        "---\n"
        f"name: {name}\n"
        f"description: {clean_desc or 'Security testing methodology checklist and instructions.'}\n"
        f"category: {category}\n"
        "---\n\n"
    )
    return header + body.lstrip()


# ==============================================================================
# Harvester & Sync Core (Option A)
# ==============================================================================

class SkillHarvester:
    def __init__(self, sources_path: Path = SOURCES_FILE, lib_dir: Path = LIBRARY_DIR):
        self.sources_path = sources_path
        self.lib_dir = lib_dir
        self.catalog_path = CATALOG_FILE
        self.catalog = self._load_catalog()

    def _load_catalog(self) -> Dict[str, Any]:
        if self.catalog_path.exists():
            try:
                with open(self.catalog_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "last_synced": None,
            "total_skills": 0,
            "categories": {},
            "skills": {}
        }

    def _save_catalog(self):
        # Update summary counts
        cat_counts: Dict[str, int] = {}
        for item in self.catalog["skills"].values():
            cat = item.get("category", "general")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        self.catalog["last_synced"] = datetime.now(timezone.utc).isoformat()
        self.catalog["total_skills"] = len(self.catalog["skills"])
        self.catalog["categories"] = cat_counts

        with open(self.catalog_path, "w", encoding="utf-8") as f:
            json.dump(self.catalog, f, indent=2)

    def harvest_all(self, limit_per_repo: int = MAX_FILES_PER_REPO, force: bool = False):
        if not self.sources_path.exists():
            print(f"[!] Sources file missing at {self.sources_path}")
            return

        with open(self.sources_path, "r", encoding="utf-8") as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        print(f"[*] Starting harvest across {len(sources)} source repositories...")
        self.lib_dir.mkdir(parents=True, exist_ok=True)

        added_count = 0
        updated_count = 0
        skipped_count = 0

        for repo in sources:
            print(f"\n---> Scanning [{repo}]")
            repo_meta = api_request(f"/repos/{repo}")
            if not repo_meta:
                print(f"     [!] Repo not found, empty, or inaccessible.")
                continue

            default_branch = repo_meta.get("default_branch", "main")
            tree_data = api_request(f"/repos/{repo}/git/trees/{default_branch}?recursive=1")
            if not tree_data or "tree" not in tree_data:
                print(f"     [!] Failed to read git tree.")
                continue

            # Identify target files (either flat skills/*.md or nested **/SKILL.md)
            candidates = []
            for item in tree_data.get("tree", []):
                if item.get("type") != "blob":
                    continue
                p = item.get("path", "")
                lower = p.lower()
                if lower.endswith("skill.md") or (lower.startswith("skills/") and lower.endswith(".md")):
                    candidates.append(p)

            candidates = candidates[:limit_per_repo]
            print(f"     Found {len(candidates)} skill candidate files.")

            for path in candidates:
                raw_url = f"{RAW_BASE}/{repo}/{default_branch}/{path}"
                content_bytes = fetch_raw_content(raw_url)
                if not content_bytes or len(content_bytes) > MAX_BYTES_PER_FILE:
                    continue

                sha = hashlib.sha256(content_bytes).hexdigest()

                try:
                    text_content = content_bytes.decode("utf-8", errors="replace")
                except Exception:
                    continue

                meta, body = parse_frontmatter(text_content)

                # Derive clean skill name
                candidate_name = meta.get("name")
                if not candidate_name:
                    # Derive from filename
                    fname = Path(path).stem
                    if fname.lower() == "skill":
                        candidate_name = Path(path).parent.name
                    else:
                        candidate_name = fname

                skill_slug = sanitize_skill_name(candidate_name)
                desc = meta.get("description", "")
                if not desc:
                    # Find first non-empty markdown paragraph
                    for p in body.split("\n\n"):
                        p_stripped = p.strip()
                        if p_stripped and not p_stripped.startswith("#"):
                            desc = p_stripped
                            break

                category = meta.get("category") or classify_category(skill_slug, desc, body)

                # Check if identical version is already in catalog
                existing = self.catalog["skills"].get(skill_slug)
                if existing and existing.get("sha256") == sha and not force:
                    skipped_count += 1
                    continue

                # Prepare destination folder: library/<category>/<skill_slug>/SKILL.md
                dest_dir = self.lib_dir / category / skill_slug
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_file = dest_dir / "SKILL.md"

                # Generate clean markdown with standard frontmatter
                clean_desc = re.sub(r"[*_>#`]", "", desc).replace("\n", " ").strip()
                clean_desc = re.sub(r"\s+", " ", clean_desc)

                standardized_content = synthesize_frontmatter(skill_slug, clean_desc, category, body)
                with open(dest_file, "w", encoding="utf-8") as out_f:
                    out_f.write(standardized_content)

                is_update = bool(existing)
                self.catalog["skills"][skill_slug] = {
                    "name": skill_slug,
                    "category": category,
                    "description": clean_desc[:300],
                    "relative_path": str(dest_file.relative_to(ROOT_DIR)).replace("\\", "/"),
                    "source": f"{repo}/{path}",
                    "sha256": sha,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }

                if is_update:
                    updated_count += 1
                else:
                    added_count += 1

                # Polite delay to prevent rate issues
                time.sleep(0.05)

        self._save_catalog()
        print("\n" + "=" * 60)
        print(f"[+] Harvest Complete!")
        print(f"    Added:   {added_count}")
        print(f"    Updated: {updated_count}")
        print(f"    Skipped: {skipped_count} (identical)")
        print(f"    Total in Library: {self.catalog['total_skills']}")
        print("=" * 60)


# ==============================================================================
# CLI Search & Installer (Option B)
# ==============================================================================

class SkillManager:
    def __init__(self):
        self.catalog_path = CATALOG_FILE
        self.catalog = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.catalog_path.exists():
            return {"skills": {}, "categories": {}}
        try:
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error reading catalog.json: {e}")
            return {"skills": {}, "categories": {}}

    def list_categories(self, selected_category: Optional[str] = None):
        skills = self.catalog.get("skills", {})
        if not skills:
            print("[!] Library is empty. Run 'python skillhub.py sync' first.")
            return

        if selected_category:
            cat = selected_category.lower()
            matching = [s for s in skills.values() if s.get("category") == cat]
            if not matching:
                print(f"[!] No skills found under category '{cat}'.")
                return
            print(f"\n--- Category: {cat.upper()} ({len(matching)} skills) ---")
            for item in sorted(matching, key=lambda x: x["name"]):
                desc = item.get("description", "No description").replace("\n", " ")
                if len(desc) > 80:
                    desc = desc[:77] + "..."
                print(f"  - {item['name']:<28} - {desc}")
            return

        print(f"\nAvailable Categories (Total Skills: {len(skills)}):")
        categories = self.catalog.get("categories", {})
        for cat, count in sorted(categories.items()):
            print(f"  [{cat:<10}] : {count:>4} skills")
        print("\nTip: Use 'python skillhub.py list -c <category>' to view skills in a category.")

    def search(self, query: str):
        skills = self.catalog.get("skills", {})
        if not skills:
            print("[!] Library is empty. Run 'python skillhub.py sync' first.")
            return

        q = query.lower()
        results = []
        for s in skills.values():
            if q in s["name"].lower() or q in s.get("description", "").lower() or q in s.get("category", "").lower():
                results.append(s)

        if not results:
            print(f"[!] No skills matching query: '{query}'")
            return

        print(f"\nSearch results for '{query}' ({len(results)} found):")
        print("-" * 75)
        for item in results[:30]:
            cat = f"[{item.get('category', 'misc')}]"
            desc = item.get("description", "").replace("\n", " ")
            if len(desc) > 60:
                desc = desc[:57] + "..."
            print(f"{item['name']:<30} {cat:<12} {desc}")
        if len(results) > 30:
            print(f"... and {len(results) - 30} more. Refine your search keyword.")

    def info(self, skill_name: str):
        skill = self.catalog.get("skills", {}).get(sanitize_skill_name(skill_name))
        if not skill:
            print(f"[!] Skill '{skill_name}' not found in catalog.")
            return

        skill_file = ROOT_DIR / skill["relative_path"]
        print("\n" + "=" * 60)
        print(f"Skill:       {skill['name']}")
        print(f"Category:    {skill.get('category')}")
        print(f"Source:      {skill.get('source')}")
        print(f"File Path:   {skill_file}")
        print("-" * 60)
        print(f"Description:\n{skill.get('description')}")
        print("=" * 60)

        if skill_file.exists():
            print("\nPreview (First 20 lines):")
            with open(skill_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                print("".join(lines[:20]))

    def install(self, skill_name: str, target_dir: Optional[Path] = None, is_global: bool = False):
        skill = self.catalog.get("skills", {}).get(sanitize_skill_name(skill_name))
        if not skill:
            print(f"[!] Skill '{skill_name}' not found.")
            return

        source_path = ROOT_DIR / skill["relative_path"]
        if not source_path.exists():
            print(f"[!] Source file missing: {source_path}")
            return

        if is_global:
            dest_root = DEFAULT_GLOBAL_SKILLS
        elif target_dir:
            dest_root = Path(target_dir).resolve()
        else:
            # Default to active project workspace .agents/skills
            dest_root = Path.cwd() / ".agents" / "skills"

        dest_skill_dir = dest_root / skill["name"]
        dest_skill_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_skill_dir / "SKILL.md"

        shutil.copyfile(source_path, dest_file)
        print(f"[+] Installed '{skill['name']}' to: {dest_file}")

    def install_category(self, category: str, target_dir: Optional[Path] = None, is_global: bool = False):
        cat = category.lower()
        matching = [s for s in self.catalog.get("skills", {}).values() if s.get("category") == cat]
        if not matching:
            print(f"[!] No skills found in category '{cat}'.")
            return

        print(f"[*] Installing {len(matching)} skills from category '{cat}'...")
        for s in matching:
            self.install(s["name"], target_dir=target_dir, is_global=is_global)
        print(f"[+] Completed installing category '{cat}'.")

    def list_packs(self):
        print("\nAvailable Starter Packs:")
        print("-" * 75)
        for key, pack in STARTER_PACKS.items():
            print(f"  {key:<12} : {pack['title']}")
            print(f"               {pack['description']}")
            print(f"               Skills: {', '.join(pack['skills'])}\n")
        print("Usage: python skillhub.py pack <name> [-t <target_directory>]")

    def install_pack(self, pack_name: str, target_dir: Optional[Path] = None, is_global: bool = False):
        pack_key = pack_name.lower()
        if pack_key not in STARTER_PACKS:
            print(f"[!] Unknown pack '{pack_name}'. Available packs: {', '.join(STARTER_PACKS.keys())}")
            return

        pack = STARTER_PACKS[pack_key]
        print(f"[*] Installing Starter Pack: {pack['title']} ({len(pack['skills'])} skills)...")
        installed_count = 0
        for s_name in pack["skills"]:
            if s_name in self.catalog.get("skills", {}):
                self.install(s_name, target_dir=target_dir, is_global=is_global)
                installed_count += 1
            else:
                matches = [s for s in self.catalog.get("skills", {}).keys() if s_name in s or s in s_name]
                if matches:
                    self.install(matches[0], target_dir=target_dir, is_global=is_global)
                    installed_count += 1
                else:
                    print(f"  [-] Note: Skill '{s_name}' not yet synced in local catalog. Run 'skillhub sync'.")

        print(f"[+] Pack '{pack_key}' installed ({installed_count} skills ready).")

    def generate_prompt(self, target_name: str):
        target = target_name.lower()
        if target in STARTER_PACKS:
            pack = STARTER_PACKS[target]
            skills_included = pack["skills"]
            print("\n" + "=" * 70)
            print(f"Agent Prompt for Starter Pack: {pack['title']}")
            print("=" * 70)
            print("Copy and paste this into your AI Agent:\n")
            prompt_text = (
                f"You are an authorized application security auditor performing a security assessment.\n"
                f"You have been equipped with the following methodology skill checklists:\n"
                + "\n".join([f"- {s}" for s in skills_included]) + "\n\n"
                f"Target Scope / Endpoints:\n"
                f"[Paste URLs, API documentation, or code files here]\n\n"
                f"Instructions:\n"
                f"1. Systematically review the scope against each checklist.\n"
                f"2. Detail potential attack paths, state transitions, and authorization checks.\n"
                f"3. Provide realistic reproduction steps and CVSS severity ratings for any findings.\n"
                f"4. Focus on critical logic flaws and input validation boundaries."
            )
            print(prompt_text)
            print("=" * 70 + "\n")
            return

        clean_name = sanitize_skill_name(target)
        skill = self.catalog.get("skills", {}).get(clean_name)
        if not skill:
            print(f"[!] Skill or pack '{target_name}' not found.")
            return

        print("\n" + "=" * 70)
        print(f"Agent Prompt for Skill: {skill['name']} ({skill.get('category', 'general')})")
        print("=" * 70)
        print("Copy and paste this into your AI Agent:\n")
        desc = skill.get("description", "Security checklist methodology.")
        prompt_text = (
            f"You are an authorized security specialist evaluating application security.\n"
            f"Apply the methodology defined in the '{skill['name']}' skill:\n\n"
            f"Overview: {desc}\n\n"
            f"Target Details:\n"
            f"[Paste target endpoint, source code, or request/response here]\n\n"
            f"Execution Steps:\n"
            f"1. Analyze all inputs and parameters according to the {skill['name']} checklist.\n"
            f"2. Identify potential filter bypasses, misconfigurations, or edge cases.\n"
            f"3. Report findings with clear impact analysis and remediation advice."
        )
        print(prompt_text)
        print("=" * 70 + "\n")

    def interactive_menu(self):
        while True:
            total = len(self.catalog.get("skills", {}))
            print("\n" + "=" * 60)
            print(f"SkillHub - Security Agent Skills Manager ({total} skills indexed)")
            print("=" * 60)
            print("1. Install a Starter Pack (beginner, web, api, recon, ad, ai-sec)")
            print("2. Search skills by keyword")
            print("3. Browse categories & skills")
            print("4. Generate Agent Prompt for a skill or pack")
            print("5. Run self-check diagnostic")
            print("6. Synchronize library from sources.txt")
            print("0. Exit")
            print("-" * 60)

            try:
                choice = input("Select an option [0-6]: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nExiting.")
                break

            if choice == "1":
                self.list_packs()
                p_name = input("Enter pack name to install [e.g. beginner, web, api]: ").strip()
                if p_name:
                    target = input("Target directory [Press Enter for ./.agents/skills]: ").strip()
                    target_path = Path(target) if target else None
                    self.install_pack(p_name, target_dir=target_path)
            elif choice == "2":
                q = input("Search keyword (e.g. sqli, burp, oauth): ").strip()
                if q:
                    self.search(q)
            elif choice == "3":
                self.list_categories()
                cat = input("\nEnter category to inspect (or press Enter to return): ").strip()
                if cat:
                    self.list_categories(selected_category=cat)
            elif choice == "4":
                tgt = input("Enter skill or pack name (e.g. web, offensive-api-abuse): ").strip()
                if tgt:
                    self.generate_prompt(tgt)
            elif choice == "5":
                run_self_check()
            elif choice == "6":
                harvester = SkillHarvester()
                harvester.harvest_all()
                self.catalog = self._load()
            elif choice in ("0", "exit", "quit", "q"):
                print("Goodbye.")
                break
            else:
                print("[!] Invalid selection. Please choose 0 to 6.")


# Pre-defined Starter Packs
STARTER_PACKS: Dict[str, Dict[str, Any]] = {
    "beginner": {
        "title": "Beginner Essentials",
        "description": "Fundamental methodologies for newcomers in bug bounty and security assessments.",
        "skills": ["bug-bounty-burp-guide", "offensive-api-abuse", "elite-report-writing", "bb-local-toolkit"]
    },
    "web": {
        "title": "Web Application Security",
        "description": "OWASP Top 10 vulnerabilities, code review, Burp Suite workflows, and input abuse.",
        "skills": ["bug-bounty-burp-guide", "bug-bounty-code-review", "offensive-api-abuse"]
    },
    "api": {
        "title": "API & Microservices Security",
        "description": "REST, GraphQL, authentication bypass, and logic abuse workflows.",
        "skills": ["offensive-api-abuse", "apk-redteam-pipeline"]
    },
    "recon": {
        "title": "Recon & Asset Discovery",
        "description": "OSINT, subdomain discovery, and attack surface enumeration.",
        "skills": ["bb-local-toolkit", "run-claude-osint", "cloud-saas-exposure"]
    },
    "ad": {
        "title": "Active Directory & Enterprise Infrastructure",
        "description": "Kerberos, BloodHound, privilege escalation, and domain security.",
        "skills": ["offensive-active-directory"]
    },
    "ai-sec": {
        "title": "AI Agent & Prompt Security",
        "description": "Prompt injection analysis, skill vetting, and agent defense.",
        "skills": ["ai-01-prompt-injection", "skill-inspector"]
    }
}


def run_self_check():
    print("[*] Running SkillHub self-check...")
    assert CATALOG_FILE.exists(), f"catalog.json not found at {CATALOG_FILE}"
    with open(CATALOG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    skills = data.get("skills", {})
    assert len(skills) > 0, "Catalog contains 0 skills"
    print("  [+] Catalog check: OK")

    first_skill = next(iter(skills.values()))
    q = first_skill["name"][:4]
    matches = [s for s in skills.values() if q.lower() in s["name"].lower()]
    assert len(matches) > 0, f"Search failed for keyword '{q}'"
    print("  [+] Search index check: OK")

    mgr = SkillManager()
    test_sandbox = ROOT_DIR / "_test_sandbox"
    try:
        mgr.install(first_skill["name"], target_dir=test_sandbox)
        installed_file = test_sandbox / first_skill["name"] / "SKILL.md"
        assert installed_file.exists(), f"Installed file missing at {installed_file}"

        with open(installed_file, "r", encoding="utf-8") as f:
            content = f.read()
        assert content.startswith("---"), "Installed SKILL.md missing YAML frontmatter"
        print("  [+] Workspace install & packaging check: OK")
    finally:
        if test_sandbox.exists():
            shutil.rmtree(test_sandbox)

    print("\n[+] All self-checks passed successfully.")


# ==============================================================================
# CLI Entrypoint
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SkillHub - Pro Harvester & Package Manager for Security Agent Skills"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: sync
    sync_p = subparsers.add_parser("sync", help="Harvest and synchronize skills from sources.txt")
    sync_p.add_argument("--sources", type=Path, default=SOURCES_FILE, help="Path to sources.txt")
    sync_p.add_argument("--limit", type=int, default=MAX_FILES_PER_REPO, help="Max skills per repository")
    sync_p.add_argument("--force", action="store_true", help="Force overwrite existing library skills")

    # Command: list
    list_p = subparsers.add_parser("list", help="List available categories or skills")
    list_p.add_argument("-c", "--category", type=str, help="Filter by specific category")

    # Command: pack
    pack_p = subparsers.add_parser("pack", help="Install a pre-configured Starter Pack (beginner, web, api, recon, ad, ai-sec)")
    pack_p.add_argument("name", type=str, nargs="?", help="Pack name (leave empty to list all packs)")
    pack_p.add_argument("-t", "--target", type=Path, help="Target directory (default: ./.agents/skills)")
    pack_p.add_argument("-g", "--global", dest="is_global", action="store_true", help="Install into global ~/.gemini config")

    # Command: prompt
    prompt_p = subparsers.add_parser("prompt", help="Generate ready-to-use Agent prompt for a skill or pack")
    prompt_p.add_argument("target", type=str, help="Skill name or pack name (e.g. offensive-api-abuse, web)")

    # Command: search
    search_p = subparsers.add_parser("search", help="Search skills by keyword")
    search_p.add_argument("query", type=str, help="Keyword or vulnerability name")

    # Command: info
    info_p = subparsers.add_parser("info", help="View skill details and preview")
    info_p.add_argument("name", type=str, help="Skill name")

    # Command: install
    inst_p = subparsers.add_parser("install", help="Install a skill into workspace or global config")
    inst_p.add_argument("name", type=str, help="Skill name")
    inst_p.add_argument("-t", "--target", type=Path, help="Target directory (default: ./.agents/skills)")
    inst_p.add_argument("-g", "--global", dest="is_global", action="store_true", help="Install into global ~/.gemini config")

    # Command: install-category
    cat_p = subparsers.add_parser("install-category", help="Install all skills in a category")
    cat_p.add_argument("category", type=str, help="Category name (web, api, cloud, recon, etc.)")
    cat_p.add_argument("-t", "--target", type=Path, help="Target directory (default: ./.agents/skills)")
    cat_p.add_argument("-g", "--global", dest="is_global", action="store_true", help="Install into global ~/.gemini config")

    # Command: status
    subparsers.add_parser("status", help="Show library health and metrics")

    # Command: check
    subparsers.add_parser("check", help="Run self-check test on catalog, search, and packaging")

    args = parser.parse_args()
    mgr = SkillManager()

    if not args.command:
        # Fall back to interactive guided menu for ease of use
        mgr.interactive_menu()
        sys.exit(0)

    if args.command == "sync":
        harvester = SkillHarvester(sources_path=args.sources)
        harvester.harvest_all(limit_per_repo=args.limit, force=args.force)

    elif args.command == "list":
        mgr.list_categories(selected_category=args.category)

    elif args.command == "pack":
        if not args.name:
            mgr.list_packs()
        else:
            mgr.install_pack(args.name, target_dir=args.target, is_global=args.is_global)

    elif args.command == "prompt":
        mgr.generate_prompt(args.target)

    elif args.command == "search":
        mgr.search(args.query)

    elif args.command == "info":
        mgr.info(args.name)

    elif args.command == "install":
        mgr.install(args.name, target_dir=args.target, is_global=args.is_global)

    elif args.command == "install-category":
        mgr.install_category(args.category, target_dir=args.target, is_global=args.is_global)

    elif args.command == "status":
        cat_file = CATALOG_FILE
        if not cat_file.exists():
            print("[!] Library not initialized. Run 'python skillhub.py sync'.")
        else:
            with open(cat_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("\nSkillHub Status:")
            print(f"  Last Synced:  {data.get('last_synced', 'Never')}")
            print(f"  Total Skills: {data.get('total_skills', 0)}")
            print("  Categories:")
            for c, cnt in data.get("categories", {}).items():
                print(f"    - {c:<12}: {cnt}")

    elif args.command == "check":
        run_self_check()


if __name__ == "__main__":
    main()
