"""Strategy Mutation — Polymorphic Tactics Engine

Stolen from: DRAKBEN's polymorphic mutation engine
What it does: Adapt attack strategies based on what works per target/WAF

How it works:
1. Track per-target-type success rates:
   - Web app → SQLi first, then XSS, then IDOR
   - API → IDOR first, then auth bypass, then injection
   - Network → port scan, then service exploit
2. Track per-WAF success rates:
   - Cloudflare → inline comments bypass
   - AWS WAF → unicode encoding
   - ModSecurity → case variation
3. Adapt strategy based on historical data
4. Mutate payloads when blocked (encoding, case, chunks)

This is what makes HYDRA better:
- PentestGPT: Static attack order
- PentestAgent: Manual strategy selection
- HYDRA: Auto-mutate based on what works
"""
import json
import random
import time
from pathlib import Path
from typing import Optional


class MutationStrategy:
    """Tracks and mutates attack strategies."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".hydra_data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.strategies_file = self.data_dir / "strategies.json"
        self.target_strategies: dict[str, dict] = {}  # target_type → {vuln_class: success_rate}
        self.waf_strategies: dict[str, dict] = {}  # waf_type → {technique: success_rate}
        self.mutation_log: list[dict] = []
        self._load()

    def _load(self):
        """Load strategies from disk."""
        if self.strategies_file.exists():
            try:
                data = json.loads(self.strategies_file.read_text(encoding="utf-8"))
                self.target_strategies = data.get("target_strategies", {})
                self.waf_strategies = data.get("waf_strategies", {})
                self.mutation_log = data.get("mutation_log", [])[-100:]  # Keep last 100
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        """Save strategies to disk."""
        data = {
            "target_strategies": self.target_strategies,
            "waf_strategies": self.waf_strategies,
            "mutation_log": self.mutation_log[-100:],
        }
        self.strategies_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_attack_order(self, target_type: str, scope: dict = None) -> list[str]:
        """Get optimized attack order for target type."""
        # Default orders
        default_orders = {
            "web": ["recon", "sqli", "xss", "idor", "ssrf", "auth_bypass", "rce"],
            "api": ["recon", "idor", "auth_bypass", "sqli", "rce", "ssrf"],
            "network": ["port_scan", "service_enum", "exploit", "privesc"],
            "mobile": ["recon", "api_analysis", "auth_bypass", "sqli", "insecure_storage"],
        }

        base_order = default_orders.get(target_type, default_orders["web"])

        # Adjust based on historical success
        if target_type in self.target_strategies:
            success_rates = self.target_strategies[target_type]
            # Sort by success rate (highest first)
            sorted_vulns = sorted(success_rates.items(), key=lambda x: x[1], reverse=True)

            # Put high-success vulns first (but keep recon at start)
            if sorted_vulns and base_order[0] == "recon":
                high_success = [v[0] for v in sorted_vulns if v[1] > 0.3]
                # Insert high-success vulns after recon
                order = ["recon"]
                for v in high_success:
                    if v not in order:
                        order.append(v)
                # Add remaining from default
                for v in base_order:
                    if v not in order:
                        order.append(v)
                return order

        return base_order

    def record_success(self, target_type: str, vuln_class: str, technique: str = None):
        """Record a successful finding."""
        if target_type not in self.target_strategies:
            self.target_strategies[target_type] = {}

        # Update success rate (exponential moving average)
        current = self.target_strategies[target_type].get(vuln_class, 0.5)
        self.target_strategies[target_type][vuln_class] = min(1.0, current + 0.1)

        # Record technique success
        if technique:
            if target_type not in self.waf_strategies:
                self.waf_strategies[target_type] = {}
            current = self.waf_strategies[target_type].get(technique, 0.5)
            self.waf_strategies[target_type][technique] = min(1.0, current + 0.15)

        self.mutation_log.append({
            "timestamp": time.time(),
            "event": "success",
            "target_type": target_type,
            "vuln_class": vuln_class,
            "technique": technique,
        })
        self._save()

    def record_failure(self, target_type: str, vuln_class: str, technique: str = None, reason: str = None):
        """Record a failed attempt."""
        if target_type not in self.target_strategies:
            self.target_strategies[target_type] = {}

        # Update success rate (exponential moving average)
        current = self.target_strategies[target_type].get(vuln_class, 0.5)
        self.target_strategies[target_type][vuln_class] = max(0.0, current - 0.15)

        # Record technique failure
        if technique:
            if target_type not in self.waf_strategies:
                self.waf_strategies[target_type] = {}
            current = self.waf_strategies[target_type].get(technique, 0.5)
            self.waf_strategies[target_type][technique] = max(0.0, current - 0.2)

        self.mutation_log.append({
            "timestamp": time.time(),
            "event": "failure",
            "target_type": target_type,
            "vuln_class": vuln_class,
            "technique": technique,
            "reason": reason,
        })
        self._save()

    def get_waf_bypass(self, waf_type: str) -> list[str]:
        """Get best bypass techniques for WAF type."""
        default_bypasses = {
            "cloudflare": [
                "inline_comments", "chunked_encoding", "unicode",
                "double_encoding", "case_variation",
            ],
            "aws_waf": [
                "double_encoding", "case_variation", "null_bytes",
                "unicode", "multipart",
            ],
            "akamai": [
                "http2_smuggling", "chunked_encoding", "unicode",
                "case_variation",
            ],
            "modsecurity": [
                "non_standard_encoding", "multipart", "unicode",
                "case_variation", "null_bytes",
            ],
            "sucuri": [
                "unicode", "null_bytes", "double_encoding",
                "case_variation",
            ],
        }

        bypasses = default_bypasses.get(waf_type.lower(), [
            "url_encoding", "double_encoding", "unicode",
            "case_variation", "null_bytes",
        ])

        # Sort by historical success
        if waf_type.lower() in self.waf_strategies:
            success_rates = self.waf_strategies[waf_type.lower()]
            scored = [(b, success_rates.get(b, 0.5)) for b in bypasses]
            scored.sort(key=lambda x: x[1], reverse=True)
            return [b[0] for b in scored]

        return bypasses

    def mutate_payload(self, payload: str, mutation_type: str = "auto") -> list[str]:
        """Generate mutated versions of a payload."""
        mutations = []

        # URL encoding
        url_encoded = "".join(f"%{ord(c):02x}" if c.isalnum() else c for c in payload)
        mutations.append(("url_encoded", url_encoded))

        # Double encoding
        double_encoded = "".join(f"%25{ord(c):02x}" if c.isalnum() else c for c in payload)
        mutations.append(("double_encoded", double_encoded))

        # Case variation
        case_varied = "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        mutations.append(("case_variation", case_varied))

        # Inline comments (for SQL)
        if any(kw in payload.lower() for kw in ["select", "union", "from", "where"]):
            commented = payload.replace(" ", "/**/").replace("'", "'/**/'")
            mutations.append(("inline_comments", commented))

        # Null bytes
        null_byte = payload.replace("'", "%00'").replace('"', '%00"')
        mutations.append(("null_bytes", null_byte))

        # Unicode
        unicode_payload = payload.replace("'", "%EF%BC%87").replace('"', '%EF%BC%82')
        mutations.append(("unicode", unicode_payload))

        # Case variation (SQL keywords)
        sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
        sql_varied = payload
        for kw in sql_keywords:
            if kw.lower() in payload.lower():
                mixed = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in kw
                )
                sql_varied = sql_varied.replace(kw, mixed).replace(kw.lower(), mixed)
        mutations.append(("sql_case_mixed", sql_varied))

        if mutation_type == "auto":
            # Return all mutations
            return mutations
        else:
            # Return specific mutation
            return [(t, m) for t, m in mutations if t == mutation_type]

    def get_next_strategy(self, target_type: str, failed_techniques: list[str] = None) -> dict:
        """Get next best strategy based on history."""
        failed = failed_techniques or []

        # Get attack order
        order = self.get_attack_order(target_type)

        # Filter out failed techniques
        available = [v for v in order if v not in failed]

        if not available:
            # All techniques failed, try mutations
            return {
                "action": "mutate",
                "message": "All standard techniques failed. Trying payload mutations.",
                "mutations": ["url_encoding", "double_encoding", "unicode", "case_variation"],
            }

        # Get next best technique
        next_tech = available[0]

        # Check if we have WAF info
        waf_bypasses = []
        if target_type in self.waf_strategies:
            best_bypasses = sorted(
                self.waf_strategies[target_type].items(),
                key=lambda x: x[1],
                reverse=True,
            )
            waf_bypasses = [b[0] for b in best_bypasses[:3]]

        return {
            "action": "attack",
            "technique": next_tech,
            "waf_bypasses": waf_bypasses,
            "message": f"Trying {next_tech} (success rate: {self.target_strategies.get(target_type, {}).get(next_tech, 0.5):.0%})",
        }

    def stats(self) -> dict:
        """Get strategy statistics."""
        return {
            "target_strategies": self.target_strategies,
            "waf_strategies": self.waf_strategies,
            "mutations_logged": len(self.mutation_log),
        }


# Global instance
strategy_mutation = MutationStrategy()
