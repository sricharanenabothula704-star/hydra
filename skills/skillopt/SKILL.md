# SkillOpt: Self-Evolving Agent Skills for OpenCode

## Overview

This skill implements Microsoft's SkillOpt methodology for training reusable natural-language skills for frozen LLM agents through trajectory-driven edits, validation-gated updates, and deployable `best_skill.md` artifacts.

## Core Concepts

- **Skill Document**: Markdown file containing natural-language instructions (300-2000 tokens)
- **Trajectory-Driven Edits**: Optimizer model turns scored rollouts into bounded add/delete/replace edits
- **Validation Gates**: Candidate edits accepted only when they strictly improve held-out validation score
- **Textual Learning Rate**: Budget mechanism for stable skill training
- **Zero Inference Cost**: Deployed `best_skill.md` runs against unchanged target model

## Components

### 1. Skill Optimizer (`skillopt_optimizer.py`)

Implements the core optimization loop:
- Rollout → Reflect → Aggregate → Select → Update → Evaluate

### 2. Skill Store (`skill_store.py`)

Manages skill versions, validation scores, and edit history.

### 3. Validators (`validators.py`)

Validation gates for different task types (coding, analysis, bug-bounty, etc.)

### 4. Trajectory Logger (`trajectory_logger.py`)

Records agent trajectories for training data.

## Usage

```python
from skillopt import SkillOptimizer

optimizer = SkillOptimizer(
    skill_path=".opencode/skills/bug-bounty/best_skill.md",
    validator="bug_bounty_validator"
)

# Train from trajectories
optimizer.train(trajectories, epochs=10)

# Deploy best skill
optimizer.deploy()
```

## Configuration

Edit `skillopt_config.yaml` to customize:
- Learning rate budget
- Validation split
- Epoch count
- Backend model (OpenAI, the AI agent, local)
- Benchmark tasks