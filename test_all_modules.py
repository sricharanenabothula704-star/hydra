"""Test all HYDRA modules"""

import sys

sys.path.insert(0, ".")

modules = []
errors = []

# 1. cve_exploit_generator
try:
    from hydra.core.cve_exploit_generator import (
        CVEExploitGenerator,
        VulnClass,
        Architecture,
    )

    gen = CVEExploitGenerator()
    e = gen.generate_exploit(
        "CVE-2026-32882",
        "buffer overflow in libheif",
        "libheif",
        Architecture.X86_64,
        cvss=9.8,
    )
    print(
        f"  cve_exploit_generator: {e.cve_id} ({e.vuln_class.value}) sev={e.severity}"
    )
    modules.append("cve_exploit_generator")
except Exception as ex:
    errors.append(f"cve_exploit_generator: {ex}")
    print(f"  FAIL cve_exploit_generator: {ex}")

# 2. validation_gate
try:
    from hydra.core.validation_gate import ValidationGate

    gate = ValidationGate()
    r = gate.validate(
        {
            "id": "test-1",
            "evidence": "SQL error",
            "status": "verified",
            "cvss_score": 8.5,
            "severity": "high",
            "in_scope": True,
            "exploitable": True,
        }
    )
    print(f"  validation_gate: {r['overall']} score={r['score']}%")
    modules.append("validation_gate")
except Exception as ex:
    errors.append(f"validation_gate: {ex}")
    print(f"  FAIL validation_gate: {ex}")

# 3. attack_chain
try:
    from hydra.core.attack_chain import AttackChainEngine

    engine = AttackChainEngine()
    chains = engine.list_chains()
    print(f"  attack_chain: {len(chains)} chains")
    modules.append("attack_chain")
except Exception as ex:
    errors.append(f"attack_chain: {ex}")
    print(f"  FAIL attack_chain: {ex}")

# 4. completion_gates
try:
    from hydra.core.completion_gates import CompletionGates

    cg = CompletionGates()
    print(f"  completion_gates: OK")
    modules.append("completion_gates")
except Exception as ex:
    errors.append(f"completion_gates: {ex}")
    print(f"  FAIL completion_gates: {ex}")

# 5. leads_ledger
try:
    from hydra.core.leads_ledger import LeadsLedger

    ll = LeadsLedger()
    print(f"  leads_ledger: OK")
    modules.append("leads_ledger")
except Exception as ex:
    errors.append(f"leads_ledger: {ex}")
    print(f"  FAIL leads_ledger: {ex}")

# 6. session_logger
try:
    from hydra.core.session_logger import SessionLogger

    sl = SessionLogger()
    print(f"  session_logger: OK")
    modules.append("session_logger")
except Exception as ex:
    errors.append(f"session_logger: {ex}")
    print(f"  FAIL session_logger: {ex}")

# 7. pipeline_engine
try:
    from hydra.core.pipeline_engine import PipelineEngine

    pe = PipelineEngine()
    print(f"  pipeline_engine: OK")
    modules.append("pipeline_engine")
except Exception as ex:
    errors.append(f"pipeline_engine: {ex}")
    print(f"  FAIL pipeline_engine: {ex}")

# 8. status_bar (actual class: StatusBar)
try:
    from hydra.core.status_bar import StatusBar

    sb = StatusBar()
    print(f"  status_bar: OK")
    modules.append("status_bar")
except Exception as ex:
    errors.append(f"status_bar: {ex}")
    print(f"  FAIL status_bar: {ex}")

# 9. session_store (actual class: SessionStore)
try:
    from hydra.core.session_store import SessionStore

    ss = SessionStore()
    print(f"  session_store: OK")
    modules.append("session_store")
except Exception as ex:
    errors.append(f"session_store: {ex}")
    print(f"  FAIL session_store: {ex}")

# 10. task_tree
try:
    from hydra.core.task_tree import TaskTree

    tt = TaskTree()
    print(f"  task_tree: OK")
    modules.append("task_tree")
except Exception as ex:
    errors.append(f"task_tree: {ex}")
    print(f"  FAIL task_tree: {ex}")

# 11. oracles (uses verify_finding + individual oracles)
try:
    from hydra.core.oracles import verify_finding

    print(f"  oracles: OK")
    modules.append("oracles")
except Exception as ex:
    errors.append(f"oracles: {ex}")
    print(f"  FAIL oracles: {ex}")

# 12. proof_capsule
try:
    from hydra.core.proof_capsule import ProofCapsule

    print(f"  proof_capsule: OK (needs vuln_class + endpoint)")
    modules.append("proof_capsule")
except Exception as ex:
    errors.append(f"proof_capsule: {ex}")
    print(f"  FAIL proof_capsule: {ex}")

# 13. anti_hallucination
try:
    from hydra.core.anti_hallucination import AntiHallucination

    ah = AntiHallucination()
    print(f"  anti_hallucination: OK")
    modules.append("anti_hallucination")
except Exception as ex:
    errors.append(f"anti_hallucination: {ex}")
    print(f"  FAIL anti_hallucination: {ex}")

# 14. conversation
try:
    from hydra.core.conversation import ConversationManager

    cm = ConversationManager()
    print(f"  conversation: OK")
    modules.append("conversation")
except Exception as ex:
    errors.append(f"conversation: {ex}")
    print(f"  FAIL conversation: {ex}")

# 15. rag_knowledge
try:
    from hydra.core.rag_knowledge import RAGKnowledge

    rk = RAGKnowledge()
    print(f"  rag_knowledge: OK (lazy-loaded)")
    modules.append("rag_knowledge")
except Exception as ex:
    errors.append(f"rag_knowledge: {ex}")
    print(f"  FAIL rag_knowledge: {ex}")

# 16. self_healing (actual class: SelfHealer)
try:
    from hydra.core.self_healing import SelfHealer

    sh = SelfHealer()
    print(f"  self_healing: OK")
    modules.append("self_healing")
except Exception as ex:
    errors.append(f"self_healing: {ex}")
    print(f"  FAIL self_healing: {ex}")

# 17. strategy_mutation (actual: MutationStrategy or module-level strategy_mutation)
try:
    from hydra.core.strategy_mutation import MutationStrategy

    print(f"  strategy_mutation: OK")
    modules.append("strategy_mutation")
except Exception as ex:
    errors.append(f"strategy_mutation: {ex}")
    print(f"  FAIL strategy_mutation: {ex}")

# 18. autopilot
try:
    from hydra.core.autopilot import AutopilotEngine

    ap = AutopilotEngine()
    print(f"  autopilot: OK")
    modules.append("autopilot")
except Exception as ex:
    errors.append(f"autopilot: {ex}")
    print(f"  FAIL autopilot: {ex}")

# 19. __main__ (CLI)
try:
    from hydra.__main__ import main, COMMANDS

    print(f"  cli (__main__): OK ({len(COMMANDS)} commands)")
    modules.append("cli")
except Exception as ex:
    errors.append(f"cli: {ex}")
    print(f"  FAIL cli: {ex}")

print(f"\n{'=' * 60}")
print(f"RESULT: {len(modules)}/19 modules loaded OK")
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print(f"  - {e}")
else:
    print("ALL MODULES WORKING!")
