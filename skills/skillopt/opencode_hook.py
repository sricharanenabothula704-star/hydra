#!/usr/bin/env python3
"""
OpenCode Trajectory Hook for SkillOpt

This module integrates with OpenCode to automatically log agent trajectories
for SkillOpt training. Add to your OpenCode config or use as a wrapper.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

# Add skillopt to path
sys.path.insert(0, str(Path(__file__).parent))
from skillopt_optimizer import TrajectoryLogger, Trajectory


@dataclass
class OpenCodeEvent:
    """Event from OpenCode agent."""
    event_type: str  # "tool_call", "tool_result", "agent_message", "task_complete"
    timestamp: str
    data: Dict[str, Any]


class OpenCodeTrajectoryHook:
    """Hooks into OpenCode to capture trajectories for SkillOpt."""
    
    def __init__(self, skill_dir: str, skill_name: str = "bug-bounty"):
        self.skill_dir = Path(skill_dir)
        self.skill_name = skill_name
        self.logger = TrajectoryLogger(self.skill_dir / "trajectories")
        self.current_task: Optional[str] = None
        self.current_version: Optional[str] = None
        self.step_buffer: List[Dict] = []
        self.active = False
    
    def on_task_start(self, task: str, skill_version: str = "latest"):
        """Called when a new task begins."""
        self.current_task = task
        self.current_version = skill_version
        self.step_buffer = []
        self.active = True
        
        # Load current skill version for reference
        print(f"[SkillOpt] Starting trajectory for: {task}")
    
    def on_tool_call(self, tool: str, params: Dict[str, Any]):
        """Called when agent makes a tool call."""
        if not self.active:
            return
        
        self.step_buffer.append({
            "type": "tool_call",
            "tool": tool,
            "params": params,
            "timestamp": datetime.now().isoformat()
        })
    
    def on_tool_result(self, tool: str, result: Any, error: str = None):
        """Called when tool returns result."""
        if not self.active:
            return
        
        self.step_buffer.append({
            "type": "tool_result",
            "tool": tool,
            "result": str(result)[:5000],  # Truncate large outputs
            "error": error,
            "timestamp": datetime.now().isoformat()
        })
    
    def on_agent_message(self, message: str):
        """Called when agent outputs a message."""
        if not self.active:
            return
        
        self.step_buffer.append({
            "type": "agent_message",
            "content": message,
            "timestamp": datetime.now().isoformat()
        })
    
    def on_task_complete(self, score: float = None, metadata: Dict = None):
        """Called when task completes. Saves trajectory."""
        if not self.active or not self.current_task:
            return
        
        # Convert buffer to trajectory format
        steps = []
        for item in self.step_buffer:
            if item["type"] == "tool_call":
                steps.append({
                    "action": f"tool:{item['tool']}",
                    "params": item["params"],
                    "observation": "",
                    "tool": item["tool"]
                })
            elif item["type"] == "tool_result":
                if steps and steps[-1]["tool"] == item["tool"]:
                    steps[-1]["observation"] = item["result"]
                    if item["error"]:
                        steps[-1]["observation"] = f"ERROR: {item['error']}\n{steps[-1]['observation']}"
            elif item["type"] == "agent_message":
                steps.append({
                    "action": "agent_reasoning",
                    "observation": item["content"],
                    "tool": "reasoning"
                })
        
        # Use provided score or estimate from metadata
        final_score = score
        if final_score is None and metadata:
            final_score = metadata.get("estimated_score", 5.0)
        elif final_score is None:
            final_score = 5.0  # Default neutral
        
        # Save trajectory
        self.logger.start_trajectory(self.current_task, self.current_version)
        for step in steps:
            self.logger.log_step(
                action=step["action"],
                observation=step["observation"],
                tool=step["tool"]
            )
        traj = self.logger.end_trajectory(final_score, metadata or {})
        
        print(f"[SkillOpt] Saved trajectory v{traj.skill_version} score={final_score}")
        
        self.active = False
        self.current_task = None
        self.step_buffer = []
        
        return traj
    
    def get_stats(self) -> Dict:
        """Get logging statistics."""
        trajectories = self.logger.load_trajectories()
        return {
            "total_trajectories": len(trajectories),
            "skill_versions": list(set(t.skill_version for t in trajectories)),
            "avg_score": sum(t.score for t in trajectories) / len(trajectories) if trajectories else 0
        }


# Example usage as standalone script
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SkillOpt OpenCode Hook")
    parser.add_argument("skill_dir", help="Skill directory")
    parser.add_argument("--task", help="Task description")
    parser.add_argument("--version", default="latest", help="Skill version")
    parser.add_argument("--score", type=float, help="Task score (0-10)")
    
    args = parser.parse_args()
    
    hook = OpenCodeTrajectoryHook(args.skill_dir)
    
    if args.task:
        hook.on_task_start(args.task, args.version)
        # Simulate some steps
        hook.on_tool_call("bash", {"command": "subfinder -d example.com"})
        hook.on_tool_result("bash", "sub1.example.com\nsub2.example.com")
        hook.on_agent_message("Found 2 subdomains, now scanning ports")
        hook.on_tool_call("bash", {"command": "nmap -sS -T4 sub1.example.com"})
        hook.on_tool_result("bash", "80/tcp open  http\n443/tcp open  https")
        hook.on_task_complete(score=args.score or 7.5, metadata={"subdomain_count": 2, "ports_found": 2})
        
        print(f"Stats: {hook.get_stats()}")