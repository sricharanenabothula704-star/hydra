"""RAG Knowledge Base — Contextual CVE/Method Lookup

Stolen from: PentestGPT's contextual knowledge + PentestAgent's RAG tool optimizer
What it does: Vector store for playbooks, CVEs, WAF signatures, tool usage

How it works:
1. Index all SKILL.md playbooks
2. Index CVE database (local JSON dump)
3. Index WAF signatures
4. Query: "How to bypass Cloudflare WAF for SQLi"
   → Returns: relevant playbook + WAF bypass technique + example payloads
5. Context-aware: knows what target you're testing, suggests next steps

This is what makes HYDRA better:
- PentestGPT: Static knowledge (no contextual lookup)
- PentestAgent: RAG for tool selection only
- HYDRA: Full knowledge base with contextual recommendations
"""
import json
import os
import re
from pathlib import Path
from typing import Optional
from difflib import SequenceMatcher


class KnowledgeEntry:
    """A single knowledge entry (playbook, CVE, technique, etc.)."""

    def __init__(self, id: str, title: str, content: str, category: str, tags: list[str] = None):
        self.id = id
        self.title = title
        self.content = content
        self.category = category
        self.tags = tags or []
        self.relevance_score = 0.0

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content[:500],
            "category": self.category,
            "tags": self.tags,
            "relevance_score": self.relevance_score,
        }


class RAGKnowledge:
    """Simple keyword-based knowledge base (no ChromaDB dependency)."""

    def __init__(self, knowledge_dir: Optional[Path] = None):
        self.knowledge_dir = knowledge_dir or Path.home() / ".hydra_data" / "knowledge"
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)
        self.entries: dict[str, KnowledgeEntry] = {}
        self.index_file = self.knowledge_dir / "index.json"
        self._load_index()
        self._auto_index()

    def _load_index(self):
        """Load existing index."""
        if self.index_file.exists():
            try:
                data = json.loads(self.index_file.read_text(encoding="utf-8"))
                for e_data in data.get("entries", []):
                    entry = KnowledgeEntry(
                        id=e_data["id"],
                        title=e_data["title"],
                        content=e_data.get("content", ""),
                        category=e_data.get("category", "unknown"),
                        tags=e_data.get("tags", []),
                    )
                    self.entries[entry.id] = entry
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_index(self):
        """Save index to disk."""
        data = {
            "entries": [e.to_dict() for e in self.entries.values()],
            "total": len(self.entries),
        }
        self.index_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _auto_index(self):
        """Auto-index available knowledge sources (lazy — skip if already indexed)."""
        # Only index built-in techniques + WAF signatures (fast)
        # Skills are indexed on-demand via index_skills() to avoid slow init
        if not self.entries:
            self._index_builtin_techniques()
            self._index_waf_signatures()
            self._save_index()

    def index_skills(self, max_skills: int = 50):
        """Index HYDRA skills on-demand (call manually, not on init)."""
        skills_dir = Path(__file__).parent.parent / "skills"
        if not skills_dir.exists():
            return 0
        count = 0
        for skill_dir in skills_dir.iterdir():
            if count >= max_skills:
                break
            if skill_dir.is_dir():
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists():
                    self._index_skill(skill_file, skill_dir.name)
                    count += 1
        if count > 0:
            self._save_index()
        return count

    def _index_skill(self, skill_file: Path, skill_name: str):
        """Index a SKILL.md file."""
        content = skill_file.read_text(encoding="utf-8", errors="ignore")
        tags = self._extract_tags(content)

        entry_id = f"skill_{skill_name}"
        if entry_id not in self.entries:
            self.entries[entry_id] = KnowledgeEntry(
                id=entry_id,
                title=skill_name.replace("-", " ").title(),
                content=content[:2000],
                category="playbook",
                tags=tags,
            )

    def _index_builtin_techniques(self):
        """Index built-in attack techniques."""
        techniques = [
            {
                "id": "technique_sqli_error",
                "title": "SQL Injection — Error-Based",
                "content": """Error-based SQL injection extracts data via database error messages.
Payloads: ' OR 1=1--, ' UNION SELECT NULL--  , 1' AND 1=CONVERT(int,@@version)--
Detection: Response contains SQL error messages (mysql, sqlite, postgresql errors)
Bypass WAF: Use inline comments /**/, URL encoding, case variation (SeLeCt)
Tool: sqlmap -u "target/?id=1" --dbs""",
                "tags": ["sqli", "error", "injection", "database", "owasp"],
            },
            {
                "id": "technique_sqli_time",
                "title": "SQL Injection — Time-Based Blind",
                "content": """Time-based blind SQLi extracts data by measuring response delays.
Payloads: ' OR SLEEP(5)--, ' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))a)--
Detection: Response time > expected time
Bypass: Use conditional delays: ' AND IF(1=1,SLEEP(5),0)--
Tool: sqlmap -u "target/?id=1" --time-sec=5""",
                "tags": ["sqli", "blind", "time", "injection", "database"],
            },
            {
                "id": "technique_xss_reflected",
                "title": "XSS — Reflected",
                "content": """Reflected XSS injects scripts via URL parameters.
Payloads: <script>alert(1)</script>, <img onerror=alert(1) src=x>, {{7*7}}
Detection: Payload reflects in response without encoding
Context-dependent: HTML context, attribute context, JavaScript context
Tool: dalfox url "target/?q=test" --skip-mining-all""",
                "tags": ["xss", "reflected", "script", "injection", "owasp"],
            },
            {
                "id": "technique_idor",
                "title": "IDOR — Insecure Direct Object Reference",
                "content": """IDOR accesses unauthorized resources by changing object IDs.
Method: Change ID in URL/body (1→2, admin→user, etc.)
Detection: Different response for different IDs, same authorization level
Common patterns: /api/users/{id}, /files/{id}, /orders/{id}
Bypass: Try UUID, base64 encoded IDs, sequential vs random""",
                "tags": ["idor", "access-control", "authorization", "owasp"],
            },
            {
                "id": "technique_ssrf",
                "title": "SSRF — Server-Side Request Forgery",
                "content": """SSRF makes the server request internal/external resources.
Payloads: http://127.0.0.1, http://169.254.169.254/latest/meta-data/
Detection: Response contains internal data, or out-of-band callback
Bypass: Use DNS rebinding, URL parsing tricks, IPv6 notation
Tool: ffuf -u "target/?url=FUZZ" -w urls.txt""",
                "tags": ["ssrf", "server-side", "request", "forgery", "owasp"],
            },
            {
                "id": "technique_command_injection",
                "title": "Command Injection — RCE",
                "content": """Command injection executes OS commands via vulnerable parameters.
Payloads: ;id, |whoami, `id`, $(id)
Detection: Command output appears in response
Bypass: Use backticks, $(), ||, &&, newlines
Tool: commix -u "target/?cmd=test".""",
                "tags": ["rce", "command", "injection", "os", "critical"],
            },
            {
                "id": "technique_auth_bypass",
                "title": "Authentication Bypass",
                "content": """Auth bypass accesses protected resources without credentials.
Methods: Remove auth headers, use default creds, JWT manipulation
JWT: Change alg to none, strip signature, use weak secret
Detection: Protected resource accessible without auth
Tool: jwt_tool, burp suite""",
                "tags": ["auth", "bypass", "authentication", "jwt", "owasp"],
            },
            {
                "id": "technique_waf_bypass",
                "title": "WAF Bypass Techniques",
                "content": """WAF bypass techniques to evade Web Application Firewalls.
Cloudflare: Inline comments /**/, unicode, chunked encoding
AWS WAF: Double encoding, case variation, null bytes
ModSecurity: Non-standard encoding, multipart bodies
Generic: URL encoding, double encoding, unicode, case mix
Tool: wafw00f to detect, custom payloads for bypass""",
                "tags": ["waf", "bypass", "firewall", "evasion", "cloudflare", "aws"],
            },
        ]

        for tech in techniques:
            if tech["id"] not in self.entries:
                self.entries[tech["id"]] = KnowledgeEntry(
                    id=tech["id"],
                    title=tech["title"],
                    content=tech["content"],
                    category="technique",
                    tags=tech["tags"],
                )

    def _index_waf_signatures(self):
        """Index WAF detection signatures."""
        wafs = [
            {"name": "Cloudflare", "headers": ["cf-ray", "cf-cache-status"], "bypass": "Inline comments, chunked encoding, unicode"},
            {"name": "AWS WAF", "headers": ["x-amzn-requestid"], "bypass": "Double encoding, case variation"},
            {"name": "Akamai", "headers": ["x-akamai-transformed"], "bypass": "HTTP/2 smuggling, chunked encoding"},
            {"name": "Sucuri", "headers": ["x-sucuri-id"], "bypass": "Unicode encoding, null bytes"},
            {"name": "ModSecurity", "headers": ["mod_security"], "bypass": "Non-standard encoding, multipart bodies"},
        ]

        for waf in wafs:
            entry_id = f"waf_{waf['name'].lower().replace(' ', '_')}"
            if entry_id not in self.entries:
                self.entries[entry_id] = KnowledgeEntry(
                    id=entry_id,
                    title=f"WAF: {waf['name']}",
                    content=f"Headers: {', '.join(waf['headers'])}\nBypass: {waf['bypass']}",
                    category="waf",
                    tags=["waf", waf["name"].lower(), "bypass"],
                )

    def _extract_tags(self, content: str) -> list[str]:
        """Extract tags from content."""
        tags = set()
        keywords = [
            "sqli", "xss", "ssrf", "idor", "rce", "csrf", "xxe", "ssti",
            "auth", "jwt", "oauth", "session", "cookie", "header",
            "injection", "traversal", "overflow", "bypass",
            "owasp", "critical", "high", "medium", "low",
        ]
        content_lower = content.lower()
        for kw in keywords:
            if kw in content_lower:
                tags.add(kw)
        return list(tags)

    def search(self, query: str, category: str = None, limit: int = 5) -> list[KnowledgeEntry]:
        """Search knowledge base with keyword matching + fuzzy similarity."""
        query_lower = query.lower()
        query_words = set(re.findall(r'\w+', query_lower))

        results = []
        for entry in self.entries.values():
            if category and entry.category != category:
                continue

            # Calculate relevance score
            score = 0.0
            title_lower = entry.title.lower()
            content_lower = entry.content.lower()
            tags_lower = [t.lower() for t in entry.tags]

            # Exact title match
            if query_lower in title_lower:
                score += 10.0

            # Word matches in title
            for word in query_words:
                if word in title_lower:
                    score += 3.0

            # Word matches in content
            for word in query_words:
                if word in content_lower:
                    score += 1.0

            # Tag matches
            for tag in tags_lower:
                for word in query_words:
                    if word in tag or tag in word:
                        score += 2.0

            # Fuzzy title similarity
            seq_score = SequenceMatcher(None, query_lower, title_lower).ratio()
            score += seq_score * 5.0

            if score > 0:
                entry.relevance_score = score
                results.append(entry)

        # Sort by relevance
        results.sort(key=lambda e: e.relevance_score, reverse=True)
        return results[:limit]

    def get_context_for_target(self, target_info: dict) -> str:
        """Get contextual knowledge for a target."""
        context_parts = []

        # Check target type
        target_type = target_info.get("type", "web")
        if target_type == "web":
            web_entries = self.search("web application owasp injection", limit=3)
            context_parts.append("## Web Application Testing\n" + "\n".join(
                f"- {e.title}: {e.content[:200]}" for e in web_entries
            ))

        # Check for WAF
        waf = target_info.get("waf")
        if waf:
            waf_entries = self.search(waf, category="waf", limit=2)
            if waf_entries:
                context_parts.append(f"\n## WAF Detected: {waf}\n{waf_entries[0].content}")

        # Check scope
        if target_info.get("scope"):
            context_parts.append(f"\n## Scope: {target_info['scope']}")

        return "\n".join(context_parts)

    def get_next_steps(self, current_findings: list[dict]) -> list[str]:
        """Suggest next steps based on current findings."""
        suggestions = []
        vuln_classes = [f.get("vuln_class", "").lower() for f in current_findings]

        # If no findings yet, start with recon
        if not current_findings:
            suggestions.append("Run port scan (nmap -sV target)")
            suggestions.append("Run subdomain enumeration")
            suggestions.append("Check for common web vulnerabilities")
            return suggestions

        # If found SQLi, suggest deeper testing
        if "sql injection" in vuln_classes:
            suggestions.append("Test for blind SQLi (time-based)")
            suggestions.append("Enumerate databases (sqlmap --dbs)")
            suggestions.append("Check for second-order SQLi")

        # If found XSS, suggest stored XSS
        if "cross-site scripting" in vuln_classes:
            suggestions.append("Test for stored XSS")
            suggestions.append("Check DOM-based XSS")
            suggestions.append("Test CSP bypass")

        # If found IDOR, suggest privilege escalation
        if "idor" in vuln_classes:
            suggestions.append("Test horizontal privilege escalation")
            suggestions.append("Test vertical privilege escalation")
            suggestions.append("Check for mass assignment")

        # Always suggest verification
        if len(current_findings) > 0:
            suggestions.append("Verify all findings with oracles")
            suggestions.append("Generate proof capsules")

        return suggestions

    def stats(self) -> dict:
        """Get knowledge base statistics."""
        categories = {}
        for entry in self.entries.values():
            categories[entry.category] = categories.get(entry.category, 0) + 1
        return {"total": len(self.entries), "categories": categories}


# Global instance
rag_knowledge = RAGKnowledge()
