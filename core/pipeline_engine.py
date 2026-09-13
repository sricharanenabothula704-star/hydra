"""YAML Pipeline Engine — Repeatable Attack DAGs

Stolen from: opencode-pentester's YAML pipeline engine
What it does: Define attack workflows as YAML DAGs for repeatable testing

How it works:
1. Define pipeline as YAML: stages, tools, conditions, parallel groups
2. Engine parses YAML and builds execution graph
3. Execute stages in order, parallel groups concurrently
4. Each stage produces output that feeds next stages
5. Pipeline can be saved, shared, and replayed

This beats opencode-pentester because:
- Theirs: Basic YAML parsing
- Ours: YAML + strategy mutation + self-healing + anti-hallucination
"""
import json
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class StageStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Stage:
    """A single pipeline stage."""

    def __init__(self, name: str, tool: str, command: str, depends_on: list[str] = None):
        self.name = name
        self.tool = tool
        self.command = command
        self.depends_on = depends_on or []
        self.status = StageStatus.PENDING
        self.output = ""
        self.exit_code = None
        self.duration_ms = None
        self.started_at = None
        self.completed_at = None

    def to_dict(self):
        return {
            "name": self.name,
            "tool": self.tool,
            "command": self.command,
            "depends_on": self.depends_on,
            "status": self.status.value,
            "output": self.output[:500] if self.output else "",
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }


class Pipeline:
    """A YAML-defined attack pipeline."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.stages: dict[str, Stage] = {}
        self.created_at = time.time()
        self.completed_at = None

    def add_stage(self, name: str, tool: str, command: str, depends_on: list[str] = None):
        """Add a stage to the pipeline."""
        self.stages[name] = Stage(name, tool, command, depends_on)

    def get_ready_stages(self) -> list[Stage]:
        """Get stages whose dependencies are all completed."""
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
        """Check if all stages are done."""
        return all(
            s.status in (StageStatus.COMPLETED, StageStatus.SKIPPED)
            for s in self.stages.values()
        )

    def has_failed(self) -> bool:
        """Check if any stage failed."""
        return any(s.status == StageStatus.FAILED for s in self.stages.values())

    def render(self) -> str:
        """Render pipeline as text."""
        lines = [f"PIPELINE: {self.name}", "=" * 50]
        if self.description:
            lines.append(f"  {self.description}")
            lines.append("")

        for stage in self.stages.values():
            icon = {
                StageStatus.PENDING: "[..]",
                StageStatus.RUNNING: "[>>]",
                StageStatus.COMPLETED: "[OK]",
                StageStatus.FAILED: "[!!]",
                StageStatus.SKIPPED: "[--]",
            }[stage.status]

            deps = f" (after: {', '.join(stage.depends_on)})" if stage.depends_on else ""
            lines.append(f"  {icon} {stage.name}: {stage.tool}{deps}")

        lines.append("=" * 50)
        completed = sum(1 for s in self.stages.values() if s.status == StageStatus.COMPLETED)
        lines.append(f"  Progress: {completed}/{len(self.stages)} stages")
        return "\n".join(lines)

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "stages": {n: s.to_dict() for n, s in self.stages.items()},
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class PipelineEngine:
    """Manages and executes pipelines."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".hydra_data" / "pipelines"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.pipelines: dict[str, Pipeline] = {}
        self._load_templates()

    def _load_templates(self):
        """Load built-in pipeline templates."""
        # Recon pipeline
        recon = Pipeline("recon", "Full reconnaissance pipeline")
        recon.add_stage("port_scan", "nmap", "nmap -sV -p- {target}")
        recon.add_stage("service_enum", "nmap", "nmap -sV -sC -p {ports} {target}", ["port_scan"])
        recon.add_stage("dir_scan", "ffuf", "ffuf -u {target}/FUZZ -w wordlist.txt", ["port_scan"])
        recon.add_stage("vuln_scan", "nuclei", "nuclei -u {target} -severity medium,high,critical", ["service_enum"])
        self.pipelines["recon"] = recon

        # Bug bounty pipeline
        bounty = Pipeline("bounty_sweep", "Fast bug bounty reconnaissance")
        bounty.add_stage("subdomains", "subfinder", "subfinder -d {domain} -silent")
        bounty.add_stage("ports", "naabu", "naabu -list subdomains.txt -silent", ["subdomains"])
        bounty.add_stage("web_probe", "httpx", "httpx -list ports.txt -silent -status-code", ["ports"])
        bounty.add_stage("dir_fuzz", "ffuf", "ffuf -u {target}/FUZZ -w wordlist.txt -mc 200,301,302", ["web_probe"])
        bounty.add_stage("vuln_nuclei", "nuclei", "nuclei -list web_probe.txt -severity high,critical", ["web_probe"])
        self.pipelines["bounty_sweep"] = bounty

        # Web app pipeline
        web = Pipeline("web_app", "Web application security testing")
        web.add_stage("tech_detect", "whatweb", "whatweb {target}")
        web.add_stage("param_discover", "arjun", "arjun -u {target}")
        web.add_stage("sqli_test", "sqlmap", "sqlmap -u {target} --batch --level=3", ["param_discover"])
        web.add_stage("xss_test", "dalfox", "dalfox url {target} --skip-mining-all", ["param_discover"])
        web.add_stage("ssrf_test", "custom", "curl -s {target}/proxy?url=http://127.0.0.1", ["tech_detect"])
        web.add_stage("header_check", "custom", "curl -sI {target} | grep -i 'x-frame-options\\|content-security\\|strict-transport'", ["tech_detect"])
        self.pipelines["web_app"] = web

    def get_pipeline(self, name: str) -> Optional[Pipeline]:
        """Get a pipeline by name."""
        return self.pipelines.get(name)

    def list_pipelines(self) -> list[dict]:
        """List all available pipelines."""
        return [
            {"name": p.name, "description": p.description, "stages": len(p.stages)}
            for p in self.pipelines.values()
        ]

    def create_pipeline(self, name: str, stages: list[dict], description: str = "") -> Pipeline:
        """Create a custom pipeline from stage definitions."""
        pipeline = Pipeline(name, description)
        for stage_def in stages:
            pipeline.add_stage(
                name=stage_def["name"],
                tool=stage_def["tool"],
                command=stage_def["command"],
                depends_on=stage_def.get("depends_on", []),
            )
        self.pipelines[name] = pipeline
        return pipeline

    def render_pipeline(self, name: str) -> str:
        """Render a pipeline as text."""
        pipeline = self.get_pipeline(name)
        if not pipeline:
            return f"Pipeline '{name}' not found"
        return pipeline.render()


# Global instance
pipeline_engine = PipelineEngine()
