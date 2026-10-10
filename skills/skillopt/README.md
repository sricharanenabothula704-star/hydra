# SkillOpt Integration for OpenCode

Self-evolving agent skills using Microsoft's SkillOpt methodology.

## Quick Start

### 1. Initialize a new skill
```bash
cd ~/.config/opencode/skills/skillopt
python skillopt_cli.py init bug-bounty --seed-file seed_bug_bounty.md
```

### 2. Run tasks with trajectory logging
The hook automatically logs trajectories when you run OpenCode tasks. 

### 3. Train the skill
```bash
python skillopt_cli.py train .opencode/skills/bug-bounty --epochs 10 --validator bug_bounty
```

### 4. Deploy best skill
```bash
python skillopt_cli.py deploy .opencode/skills/bug-bounty
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      OpenCode Agent                          │
└──────────────────────────┬──────────────────────────────────┘
                           │ Trajectory Hook
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Trajectory Logger                         │
│  (stores: task, steps, score, skill_version, metadata)      │
└──────────────────────────┬──────────────────────────────────┘
                           │ Training Data
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    SkillOptimizer                            │
│  Rollout → Reflect → Aggregate → Select → Update → Evaluate │
└──────────────────────────┬──────────────────────────────────┘
                           │ Validation Gate
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Skill Store                             │
│  Versions + Validation Scores + Edit History + best_skill.md │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts (from SkillOpt paper)

### Skill Document
Markdown file (300-2000 tokens) containing natural-language instructions for the agent.

### Trajectory-Driven Edits
Optimizer model analyzes failed/successful trajectories and proposes specific `add`/`delete`/`replace` edits.

### Validation Gate
Each candidate edit is tested against held-out validation trajectories. Only edits that **strictly improve** validation score are accepted.

### Textual Learning Rate
Budget mechanism limiting edits per epoch for stable training.

### Zero Inference Cost
Deployed `best_skill.md` runs with the **unchanged** target model - no extra LLM calls at inference.

## Configuration

Edit `skillopt_config.yaml`:
```yaml
optimizer:
  learning_rate: 0.1          # Edit budget per epoch
  validation_split: 0.2       # Held-out trajectories
  max_edits_per_epoch: 5      # Max edits per training step
  validator: bug_bounty       # Task-specific validator
```

## Validators

- `bug_bounty` - Weights: subdomain_coverage(25%), vuln_discovery(35%), poc_quality(25%), report_quality(15%)
- `code_review` - Weights: issues_found(40%), fix_quality(30%), coverage(30%)
- `analysis` - General task scoring
- `default` - Simple average score

## Integration with OpenCode

Add to your agent config or use the hook directly:

```python
from skillopt.opencode_hook import OpenCodeTrajectoryHook

hook = OpenCodeTrajectoryHook(".opencode/skills/bug-bounty")

# In your task loop:
hook.on_task_start("Find XSS on example.com", "v3")
hook.on_tool_call("bash", {"command": "dalfox url http://example.com"})
hook.on_tool_result("bash", "Found XSS at /search?q=...")
hook.on_task_complete(score=8.5, metadata={"vuln_type": "XSS", "poc_quality": 0.9})
```

## Training Loop Details

For each epoch:
1. **Split** trajectories into train/validation
2. **Reflect**: Optimizer model analyzes each train trajectory → proposes edits
3. **Aggregate**: Merge duplicate/conflicting edits
4. **Select**: Test each edit on validation set → keep only improving edits
5. **Update**: Apply selected edits to create new skill version
6. **Evaluate**: Score new version on train + validation
7. **Deploy**: If validation improves → becomes new `best_skill.md`

## Files

```
.opencode/skills/skillopt/
├── SKILL.md              # This documentation
├── skillopt_optimizer.py # Core optimizer implementation
├── skillopt_cli.py       # Command-line interface
├── opencode_hook.py      # OpenCode trajectory hook
├── skillopt_config.yaml  # Configuration
├── seed_bug_bounty.md    # Seed skill for bug bounty
└── bug-bounty/           # Created skill directory
    ├── skillopt_config.yaml
    ├── versions/         # Versioned skills + metadata
    ├── trajectories/     # Logged trajectories
    ├── best_skill.md     # Deployed best skill
    └── index.json        # Version index
```

## Research Background

Based on: **SkillOpt: Executive Strategy for Self-Evolving Agent Skills** (Microsoft, 2026)
- arXiv:2605.23904
- Project: https://microsoft.github.io/SkillOpt/
- Best or tied-best on 52/52 (model, benchmark, harness) cells
- +23.5 avg accuracy on GPT-5.5 (direct chat)
- +24.8 inside Codex agentic loop
- +19.1 inside opencode

## License

MIT - Same as SkillOpt upstream