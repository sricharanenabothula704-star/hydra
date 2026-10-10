"""HYDRA command-line interface. Targeted commands fail closed on scope.

After setup, use `hydra <command>`. From a source checkout without installing,
use `python hydra_cli.py <command>`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.scope_policy import DEFAULT_ALLOWLIST, scope_decision
from core.version import __version__


def _target_from(args):
    for i, arg in enumerate(args):
        if arg in ("--target", "--url") and i + 1 < len(args):
            return args[i + 1]
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return None


def _scope_gate(target):
    if not target:
        print("[-] A target is required.")
        return False
    allowed, reason = scope_decision(target)
    if not allowed:
        print(f"[SCOPE-DENY] {reason}")
        print(f"Add only an authorized domain to {DEFAULT_ALLOWLIST}.")
        return False
    print(f"[SCOPE-ALLOW] {reason}")
    return True


def _run_opencode(prompt):
    executable = shutil.which("opencode")
    if not executable:
        print("[-] OpenCode was not found on PATH. Run the setup first.")
        return 127
    try:
        timeout = max(30, int(os.environ.get("HYDRA_RUN_TIMEOUT_SECONDS", "1800")))
    except ValueError:
        timeout = 1800
    print(f"[*] Starting OpenCode; timeout={timeout}s. You can interrupt with Ctrl+C.")
    try:
        result = subprocess.run(
            [executable, "run", prompt], cwd=str(ROOT), timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        print("[-] Timed out. The run is not reported as complete.")
        return 124
    except OSError as exc:
        print(f"[-] Could not start OpenCode: {exc}")
        return 127
    print(f"[*] OpenCode exit status: {result.returncode}")
    return result.returncode


def cmd_status(_args=None):
    print(f"HYDRA v{__version__} — AI Bug Bounty System")
    print(f"Scope allowlist: {DEFAULT_ALLOWLIST}")
    print(
        f"Scope allowlist exists: {'yes' if DEFAULT_ALLOWLIST.is_file() else 'no — targeted commands will be denied'}"
    )
    try:
        from core.pipeline_engine import PipelineEngine
        from core.attack_chain import AttackChainEngine

        print(f"Pipelines available: {len(PipelineEngine().list_pipelines())}")
        print(f"Attack chains available: {len(AttackChainEngine().list_chains())}")
    except Exception as exc:
        print(f"Core status unavailable: {exc}")


def cmd_hunt(args=None):
    args = args or []
    target = _target_from(args)
    if target is None or not _scope_gate(target):
        return 2
    prompt = (
        f"/hunt {target} — Only test the explicitly authorized target. "
        "Run scope_check before every new host, use real tool output as evidence, "
        "and never report a phase or finding as complete unless it actually ran. "
        "Stop if scope is uncertain."
    )
    return _run_opencode(prompt)


def cmd_scan(args=None):
    args = args or []
    target = _target_from(args)
    if target is None or not _scope_gate(target):
        return 2
    from core.security_misconfiguration import SecurityMisconfigurationScanner

    try:
        result = SecurityMisconfigurationScanner().scan(target)
    except Exception as exc:
        print(f"[-] Header audit failed: {exc}")
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if "error" not in result else 1


def cmd_validate(args=None):
    args = args or []
    if not args:
        print("Usage: hydra validate <finding.json | JSON-string>")
        return 2
    arg = args[0]
    try:
        path = Path(arg)
        finding = json.loads(
            path.read_text(encoding="utf-8") if path.is_file() else arg
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[-] Could not read finding JSON: {exc}")
        return 2
    if not isinstance(finding, dict):
        print("[-] A finding must be a JSON object.")
        return 2
    from core.validation_gate import ValidationGate

    result = ValidationGate().validate(finding)
    print("\n7-QUESTION VALIDATION GATE")
    print("=" * 50)
    icons = {"pass": "PASS", "fail": "FAIL", "needs_work": "TODO"}
    for q in result["questions"]:
        print(f"  Q{q['number']}: [{icons[q['result']]}] {q['question']}")
        if q["answer"]:
            print(f"       {q['answer']}")
    print("=" * 50)
    print(f"  Score: {result['score']}% | Result: {result['overall'].upper()}")
    return 0 if result["overall"] == "pass" else 1


def _execute_with_agent(label, target, plan):
    if target is None or not _scope_gate(target):
        return 2
    prompt = (
        f"Execute the HYDRA {label} for this authorized target: {target}.\n\n"
        f"Workflow definition:\n{plan}\n\n"
        "Before every tool invocation, verify the exact host against the scope "
        "allowlist. Do not use high-volume or intrusive checks unless the scope "
        "and user authorization explicitly permit them. Report actual tool "
        "outputs; do not fabricate completed stages or findings."
    )
    return _run_opencode(prompt)


def cmd_chains(args=None):
    args = args or []
    from core.attack_chain import AttackChainEngine

    engine = AttackChainEngine()
    if not args or args[0] == "list":
        print("Available attack chains:")
        for chain in engine.list_chains():
            print(
                f"  {chain['name']}: {chain['description']} ({chain['stages']} stages)"
            )
        return 0
    if args[0] not in ("show", "run") or len(args) < 2:
        print(
            "Usage: hydra chains list | show <name> | run <name> --target <url> --execute"
        )
        return 2
    name = args[1]
    chain = engine.get_chain(name)
    if chain is None:
        print(f"[-] Chain not found: {name}")
        return 2
    if args[0] == "show" or "--execute" not in args:
        print(chain.render())
        if args[0] == "run":
            print(
                "\nDry run only. Add --execute and an authorized --target to invoke OpenCode."
            )
        return 0
    target = _target_from(args)
    return _execute_with_agent(f"attack chain {name}", target, chain.render())


def cmd_pipeline(args=None):
    args = args or []
    from core.pipeline_engine import PipelineEngine

    engine = PipelineEngine()
    if not args or args[0] == "list":
        print("Available pipelines:")
        for pipeline in engine.list_pipelines():
            print(
                f"  {pipeline['name']}: {pipeline['description']} ({pipeline['stages']} stages)"
            )
        return 0
    if args[0] not in ("show", "run") or len(args) < 2:
        print(
            "Usage: hydra pipeline list | show <name> | run <name> --target <url> --execute"
        )
        return 2
    name = args[1]
    pipeline = engine.get_pipeline(name)
    if pipeline is None:
        print(f"[-] Pipeline not found: {name}")
        return 2
    plan = pipeline.render()
    if args[0] == "show" or "--execute" not in args:
        print(plan)
        if args[0] == "run":
            print(
                "\nDry run only. Add --execute and an authorized --target to invoke OpenCode."
            )
        return 0
    target = _target_from(args)
    return _execute_with_agent(f"pipeline {name}", target, plan)


def cmd_history(_args=None):
    from core.session_logger import SessionLogger

    entries = SessionLogger().get_entries(limit=10)
    if not entries:
        print("No recorded tool runs yet.")
        return 0
    for entry in entries:
        print(
            f"{entry.id} | {entry.agent}/{entry.tool} | {entry.target} | exit={entry.exit_code}"
        )
    return 0


def cmd_stats(_args=None):
    from core.autopilot import AutopilotEngine
    from core.validation_gate import ValidationGate
    from core.cve_exploit_generator import CVEExploitGenerator

    print(
        json.dumps(
            {
                "autopilot": AutopilotEngine().stats(),
                "validation": ValidationGate().stats(),
                "exploits": CVEExploitGenerator().stats(),
            },
            indent=2,
        )
    )
    return 0


def cmd_help(_args=None):
    print(__doc__)
    return 0


COMMANDS = {
    "status": cmd_status,
    "hunt": cmd_hunt,
    "scan": cmd_scan,
    "validate": cmd_validate,
    "chains": cmd_chains,
    "pipeline": cmd_pipeline,
    "history": cmd_history,
    "stats": cmd_stats,
    "help": cmd_help,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return cmd_help()
    command, *args = argv
    handler = COMMANDS.get(command)
    if handler is None:
        print(f"Unknown command: {command}")
        return cmd_help()
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
