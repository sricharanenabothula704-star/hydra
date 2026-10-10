"""Multi-Stage Attack Chain — Recon → Exploit → Pivot → Persist

Inspired by: CVE-2026-32882 attack chain (libheif → OpenAI forum → SSO → internal repos)
What it does: Chain multiple attack stages into a complete kill chain

How it works:
1. Recon stage: map attack surface (subdomains, ports, services)
2. Vulnerability stage: identify exploitable vulns
3. Exploitation stage: gain initial access
4. Pivoting stage: move laterally from compromised host
5. Persistence stage: maintain access
6. Exfiltration stage: extract data (proof only in bug bounty)

Each stage produces outputs that feed the next stage.
The chain is stored as a DAG (directed acyclic graph).
"""

import json
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class StageType(Enum):
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    PIVOTING = "pivoting"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    REPORTING = "reporting"


class StageStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ChainStage:
    """A single stage in an attack chain."""

    def __init__(
        self,
        name: str,
        stage_type: StageType,
        command: str = "",
        depends_on: list[str] = None,
    ):
        self.name = name
        self.stage_type = stage_type
        self.command = command
        self.depends_on = depends_on or []
        self.status = StageStatus.PENDING
        self.output = {}
        self.error = ""
        self.started_at = None
        self.completed_at = None
        self.artifacts = []  # Files produced by this stage
        self.findings = []  # Vulnerabilities found

    def to_dict(self):
        return {
            "name": self.name,
            "stage_type": self.stage_type.value,
            "command": self.command,
            "depends_on": self.depends_on,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "artifacts": self.artifacts,
            "findings": self.findings,
        }


class AttackChain:
    """A multi-stage attack chain."""

    def __init__(self, name: str, target: str, description: str = ""):
        self.name = name
        self.target = target
        self.description = description
        self.stages: dict[str, ChainStage] = {}
        self.created_at = time.time()
        self.completed_at = None

    def add_stage(
        self,
        name: str,
        stage_type: StageType,
        command: str = "",
        depends_on: list[str] = None,
    ):
        """Add a stage to the chain."""
        self.stages[name] = ChainStage(name, stage_type, command, depends_on)

    def get_ready_stages(self) -> list[ChainStage]:
        """Get stages whose dependencies are completed."""
        ready = []
        for stage in self.stages.values():
            if stage.status != StageStatus.PENDING:
                continue
            deps_met = all(
                self.stages[dep].status == StageStatus.COMPLETED
                for dep in stage.depends_on
                if dep in self.stages
            )
            if deps_met:
                ready.append(stage)
        return ready

    def is_complete(self) -> bool:
        return all(
            s.status in (StageStatus.COMPLETED, StageStatus.SKIPPED)
            for s in self.stages.values()
        )

    def render(self) -> str:
        lines = [f"ATTACK CHAIN: {self.name}", f"Target: {self.target}", "=" * 60]

        type_icons = {
            StageType.RECON: "[SCAN]",
            StageType.VULNERABILITY: "[VULN]",
            StageType.EXPLOITATION: "[EXEC]",
            StageType.PIVOTING: "[PIVT]",
            StageType.PERSISTENCE: "[PERS]",
            StageType.EXFILTRATION: "[EXFL]",
            StageType.REPORTING: "[RPT]",
        }

        status_icons = {
            StageStatus.PENDING: "..",
            StageStatus.RUNNING: ">>",
            StageStatus.COMPLETED: "OK",
            StageStatus.FAILED: "!!",
            StageStatus.SKIPPED: "--",
        }

        for stage in self.stages.values():
            icon = type_icons.get(stage.stage_type, "[???]")
            status = status_icons[stage.status]
            deps = (
                f" (after: {', '.join(stage.depends_on)})" if stage.depends_on else ""
            )
            lines.append(f"  [{status}] {icon} {stage.name}{deps}")

        lines.append("=" * 60)
        completed = sum(
            1 for s in self.stages.values() if s.status == StageStatus.COMPLETED
        )
        lines.append(f"  Progress: {completed}/{len(self.stages)} stages")
        return "\n".join(lines)

    def to_dict(self):
        return {
            "name": self.name,
            "target": self.target,
            "description": self.description,
            "stages": {n: s.to_dict() for n, s in self.stages.items()},
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class AttackChainEngine:
    """Manages and executes attack chains."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".hydra_data" / "chains"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.chains: dict[str, AttackChain] = {}
        self._load_templates()

    def _load_templates(self):
        """Load built-in attack chain templates."""

        # Web App Chain
        web_chain = AttackChain(
            "web_app_pentest", "{target}", "Full web application penetration test"
        )
        web_chain.add_stage(
            "subdomain_enum", StageType.RECON, "subfinder -d {target} -silent"
        )
        web_chain.add_stage(
            "port_scan",
            StageType.RECON,
            "naabu -list subdomains.txt -silent",
            ["subdomain_enum"],
        )
        web_chain.add_stage(
            "web_probe", StageType.RECON, "httpx -list ports.txt -silent", ["port_scan"]
        )
        web_chain.add_stage(
            "dir_scan",
            StageType.RECON,
            "ffuf -u {target}/FUZZ -w wordlist.txt",
            ["web_probe"],
        )
        web_chain.add_stage(
            "vuln_scan",
            StageType.VULNERABILITY,
            "nuclei -list web_probe.txt",
            ["web_probe"],
        )
        web_chain.add_stage(
            "sqli_test",
            StageType.VULNERABILITY,
            "sqlmap -u {target} --batch",
            ["dir_scan"],
        )
        web_chain.add_stage(
            "xss_test", StageType.VULNERABILITY, "dalfox url {target}", ["dir_scan"]
        )
        web_chain.add_stage(
            "exploit",
            StageType.EXPLOITATION,
            "auto",
            ["vuln_scan", "sqli_test", "xss_test"],
        )
        web_chain.add_stage("report", StageType.REPORTING, "auto", ["exploit"])
        self.chains["web_app"] = web_chain

        # Cloud Chain
        cloud_chain = AttackChain(
            "cloud_recon", "{target}", "Cloud infrastructure reconnaissance"
        )
        cloud_chain.add_stage("s3_enum", StageType.RECON, "aws s3 ls")
        cloud_chain.add_stage(
            "gcp_enum", StageType.RECON, "gcloud compute instances list"
        )
        cloud_chain.add_stage("azure_enum", StageType.RECON, "az vm list")
        cloud_chain.add_stage(
            "k8s_scan", StageType.VULNERABILITY, "kube-hunter --remote {target}"
        )
        cloud_chain.add_stage(
            "exploit", StageType.EXPLOITATION, "auto", ["s3_enum", "k8s_scan"]
        )
        cloud_chain.add_stage("report", StageType.REPORTING, "auto", ["exploit"])
        self.chains["cloud"] = cloud_chain

        # API Chain
        api_chain = AttackChain("api_pentest", "{target}", "API security testing")
        api_chain.add_stage("api_discover", StageType.RECON, "katana -u {target} -jc")
        api_chain.add_stage("param_find", StageType.RECON, "arjun -u {target}")
        api_chain.add_stage(
            "auth_test", StageType.VULNERABILITY, "auto", ["api_discover"]
        )
        api_chain.add_stage(
            "idor_test", StageType.VULNERABILITY, "auto", ["param_find", "auth_test"]
        )
        api_chain.add_stage(
            "injection_test", StageType.VULNERABILITY, "auto", ["param_find"]
        )
        api_chain.add_stage(
            "exploit", StageType.EXPLOITATION, "auto", ["idor_test", "injection_test"]
        )
        api_chain.add_stage("report", StageType.REPORTING, "auto", ["exploit"])
        self.chains["api"] = api_chain

        # CVE Exploitation Chain (like the OpenAI attack)
        cve_chain = AttackChain(
            "cve_exploit", "{target}", "CVE-based exploitation chain"
        )
        cve_chain.add_stage("cve_recon", StageType.RECON, "nmap -sV {target}")
        cve_chain.add_stage(
            "cve_identify",
            StageType.VULNERABILITY,
            "nuclei -target {target} -tags cve",
            ["cve_recon"],
        )
        cve_chain.add_stage(
            "cve_research",
            StageType.VULNERABILITY,
            "search exploitdb",
            ["cve_identify"],
        )
        cve_chain.add_stage(
            "exploit_gen", StageType.EXPLOITATION, "auto", ["cve_research"]
        )
        cve_chain.add_stage(
            "exploit_port", StageType.EXPLOITATION, "auto", ["exploit_gen"]
        )
        cve_chain.add_stage(
            "exploit_exec", StageType.EXPLOITATION, "auto", ["exploit_port"]
        )
        cve_chain.add_stage("pivot", StageType.PIVOTING, "auto", ["exploit_exec"])
        cve_chain.add_stage("persist", StageType.PERSISTENCE, "auto", ["pivot"])
        cve_chain.add_stage("report", StageType.REPORTING, "auto", ["persist"])
        self.chains["cve_exploit"] = cve_chain

    def get_chain(self, name: str) -> Optional[AttackChain]:
        return self.chains.get(name)

    def list_chains(self) -> list[dict]:
        return [
            {
                "name": c.name,
                "target": c.target,
                "description": c.description,
                "stages": len(c.stages),
            }
            for c in self.chains.values()
        ]

    def create_chain(
        self, name: str, target: str, stages: list[dict], description: str = ""
    ) -> AttackChain:
        """Create a custom attack chain."""
        chain = AttackChain(name, target, description)
        for stage_def in stages:
            chain.add_stage(
                name=stage_def["name"],
                stage_type=StageType(stage_def["type"]),
                command=stage_def.get("command", "auto"),
                depends_on=stage_def.get("depends_on", []),
            )
        self.chains[name] = chain
        return chain

    def render_chain(self, name: str) -> str:
        chain = self.get_chain(name)
        if not chain:
            return f"Chain '{name}' not found"
        return chain.render()


# Global instance
attack_chain_engine = AttackChainEngine()
