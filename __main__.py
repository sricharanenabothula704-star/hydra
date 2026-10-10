"""HYDRA CLI - Standalone command-line interface

Usage:
    python -m hydra status
    python -m hydra hunt <target> [--scope domain1,domain2]
    python -m hydra hunt --program <program_name>
    python -m hydra scan <url>
    python -m hydra validate <finding_json>
    python -m hydra chains list
    python -m hydra chains run <chain_name> --target <url>
    python -m hydra pipeline list
    python -m hydra pipeline run <pipeline_name> --target <url>
    python -m hydra history
    python -m hydra stats
"""

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def cmd_status(args=None):
    print("=" * 60)
    print("HYDRA v0.2.0 - AI Bug Bounty System")
    print("=" * 60)
    try:
        from hydra.core.status_bar import StatusBar

        sb = StatusBar()
        print("  Status bar: OK")
    except Exception as e:
        print(f"  Status bar: {e}")
    try:
        from hydra.core.pipeline_engine import PipelineEngine

        pe = PipelineEngine()
        pipelines = pe.list_pipelines()
        print(f"  Pipelines: {len(pipelines)} available")
    except Exception as e:
        print(f"  Pipelines: {e}")
    try:
        from hydra.core.attack_chain import AttackChainEngine

        ae = AttackChainEngine()
        chains = ae.list_chains()
        print(f"  Attack chains: {len(chains)} available")
    except Exception as e:
        print(f"  Attack chains: {e}")
    try:
        from hydra.core.autopilot import AutopilotEngine

        ap = AutopilotEngine()
        stats = ap.stats()
        print(
            f"  Autopilot: {stats['active_hunts']} active, {stats['completed_hunts']} completed"
        )
    except Exception as e:
        print(f"  Autopilot: {e}")
    try:
        from hydra.core.validation_gate import ValidationGate

        vg = ValidationGate()
        vstats = vg.stats()
        print(
            f"  Validation gate: {vstats['passed']} passed, {vstats['failed']} failed"
        )
    except Exception as e:
        print(f"  Validation gate: {e}")
    try:
        from hydra.core.cve_exploit_generator import CVEExploitGenerator

        gen = CVEExploitGenerator()
        estats = gen.stats()
        print(f"  CVE exploits: {estats['total']} generated")
    except Exception as e:
        print(f"  CVE exploits: {e}")
    print("=" * 60)


def cmd_hunt(args=None):
    if not args:
        print("Usage: hydra hunt <target_domain> [--scope domain1,domain2]")
        return
    target = args[0]
    scope = None
    if "--scope" in args:
        idx = args.index("--scope")
        if idx + 1 < len(args):
            scope = args[idx + 1].split(",")
    from hydra.core.autopilot import AutopilotEngine

    ap = AutopilotEngine()
    hunt_id, result = ap.start_hunt(target, target, scope)
    print(f"[*] Hunt started: {hunt_id}")
    print(f"    Target: {target}")
    if scope:
        print(f"    Scope: {scope}")
    print(f"    Running phases...")
    max_phases = 8
    for i in range(max_phases):
        r = ap.execute_phase(hunt_id)
        if r and r.get("status") == "complete":
            print(f"[+] Hunt complete!")
            print(f"    Duration: {r['result']['duration']:.0f}s")
            break
        elif r and r.get("error"):
            print(f"[-] Error: {r['error']}")
            break
    print(f"\n    Final phase: {result.phase.value}")
    print(f"    Actions logged: {len(result.actions_log)}")
    for action in result.actions_log:
        print(f"      [{action['phase']}] {action['action']}: {action['details']}")


def cmd_scan(args=None):
    if not args:
        print("Usage: hydra scan <url>")
        return
    url = args[0]
    print(f"[*] Scanning {url}...")
    try:
        from hydra.core.security_misconfiguration import SecurityMisconfigurationScanner

        scanner = SecurityMisconfigurationScanner()
        results = scanner.scan(url)
        print(f"[+] Scan complete: {json.dumps(results, indent=2)}")
    except Exception as e:
        print(f"[-] Scanner error: {e}")
        print("[*] Falling back to basic scan...")
        print(f"    Target: {url}")
        print("    (Full scan requires MCP servers)")


def cmd_validate(args=None):
    if not args:
        print("Usage: hydra validate <finding_json_string>")
        print("  or:  hydra validate <finding_file.json>")
        return
    arg = args[0]
    try:
        if Path(arg).exists():
            finding = json.loads(Path(arg).read_text(encoding="utf-8"))
        else:
            finding = json.loads(arg)
    except json.JSONDecodeError:
        print(f"[-] Invalid JSON: {arg}")
        return
    from hydra.core.validation_gate import ValidationGate

    vg = ValidationGate()
    result = vg.validate(finding)
    print(f"\n7-QUESTION VALIDATION GATE")
    print(f"=" * 50)
    for q in result["questions"]:
        icon = {"pass": "PASS", "fail": "FAIL", "needs_work": "????"}[q["result"]]
        print(f"  Q{q['number']}: [{icon}] {q['question']}")
        if q["answer"]:
            print(f"       {q['answer']}")
    print(f"=" * 50)
    print(f"  Score: {result['score']}% | Result: {result['overall'].upper()}")


def cmd_chains(args=None):
    if not args or args[0] == "list":
        from hydra.core.attack_chain import AttackChainEngine

        ae = AttackChainEngine()
        chains = ae.list_chains()
        print("Available attack chains:")
        for c in chains:
            print(f"  {c['name']}: {c['description']} ({c['stages']} stages)")
    elif args[0] == "run" and len(args) > 1:
        chain_name = args[1]
        target = None
        if "--target" in args:
            idx = args.index("--target")
            if idx + 1 < len(args):
                target = args[idx + 1]
        from hydra.core.attack_chain import AttackChainEngine

        ae = AttackChainEngine()
        chain = ae.get_chain(chain_name)
        if chain:
            print(f"[*] Running chain: {chain_name}")
            print(chain.render())
        else:
            print(f"[-] Chain not found: {chain_name}")
    else:
        print("Usage: hydra chains [list|run <name> --target <url>]")


def cmd_pipeline(args=None):
    if not args or args[0] == "list":
        from hydra.core.pipeline_engine import PipelineEngine

        pe = PipelineEngine()
        pipelines = pe.list_pipelines()
        print("Available pipelines:")
        for p in pipelines:
            print(f"  {p['name']}: {p.get('description', 'N/A')}")
    elif args[0] == "run" and len(args) > 1:
        pipe_name = args[1]
        target = None
        if "--target" in args:
            idx = args.index("--target")
            if idx + 1 < len(args):
                target = args[idx + 1]
        from hydra.core.pipeline_engine import PipelineEngine

        pe = PipelineEngine()
        print(f"[*] Running pipeline: {pipe_name}")
        result = pe.run_pipeline(pipe_name, target=target)
        print(f"[+] Pipeline result: {json.dumps(result, indent=2)}")
    else:
        print("Usage: hydra pipeline [list|run <name> --target <url>]")


def cmd_history(args=None):
    from hydra.core.session_logger import SessionLogger

    sl = SessionLogger()
    sessions = sl.list_sessions() if hasattr(sl, "list_sessions") else []
    print(f"Session history: {len(sessions)} sessions")
    for s in sessions[-5:]:
        print(f"  {s}")


def cmd_stats(args=None):
    stats = {}
    try:
        from hydra.core.autopilot import AutopilotEngine

        ap = AutopilotEngine()
        stats["autopilot"] = ap.stats()
    except Exception:
        pass
    try:
        from hydra.core.validation_gate import ValidationGate

        vg = ValidationGate()
        stats["validation"] = vg.stats()
    except Exception:
        pass
    try:
        from hydra.core.cve_exploit_generator import CVEExploitGenerator

        gen = CVEExploitGenerator()
        stats["exploits"] = gen.stats()
    except Exception:
        pass
    print(json.dumps(stats, indent=2))


def cmd_help():
    print(__doc__)


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


def main():
    if len(sys.argv) < 2:
        cmd_help()
        return
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in COMMANDS:
        COMMANDS[cmd](args)
    else:
        print(f"Unknown command: {cmd}")
        cmd_help()


if __name__ == "__main__":
    main()
