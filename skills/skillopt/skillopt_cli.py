#!/usr/bin/env python3
"""SkillOpt CLI for OpenCode integration."""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from skillopt_optimizer import (
    SkillOptimizer, 
    TrajectoryLogger, 
    Trajectory,
    create_skillopt_skill
)


def cmd_init(args):
    """Initialize a new SkillOpt skill."""
    seed = None
    if args.seed_file:
        seed = Path(args.seed_file).read_text()
    
    skill_dir = create_skillopt_skill(args.name, seed)
    print(f"Created SkillOpt skill at: {skill_dir}")
    print(f"Config: {skill_dir / 'skillopt_config.yaml'}")
    if seed:
        print(f"Seed skill: {skill_dir / 'seed_skill.md'}")


def cmd_train(args):
    """Train skill from collected trajectories."""
    optimizer = SkillOptimizer(
        args.skill_dir,
        validator=args.validator,
        learning_rate=args.lr,
        validation_split=args.val_split,
        max_edits_per_epoch=args.max_edits
    )
    
    logger = TrajectoryLogger(Path(args.skill_dir) / "trajectories")
    trajectories = logger.load_trajectories()
    
    if not trajectories:
        print("No trajectories found. Run tasks first to collect data.")
        return
    
    print(f"Loaded {len(trajectories)} trajectories")
    optimizer.add_trajectories(trajectories)
    
    history = optimizer.train(epochs=args.epochs)
    best_path = optimizer.deploy()
    print(f"\nTraining complete!")
    print(f"Best skill deployed to: {best_path}")
    print(f"Versions created: {len(history)}")


def cmd_evaluate(args):
    """Evaluate current best skill against trajectories."""
    optimizer = SkillOptimizer(args.skill_dir, validator=args.validator)
    best_skill = optimizer.store.load_best()
    
    if not best_skill:
        print("No trained skill found")
        return
    
    logger = TrajectoryLogger(Path(args.skill_dir) / "trajectories")
    trajectories = logger.load_trajectories()
    
    if not trajectories:
        print("No trajectories to evaluate against")
        return
    
    score = optimizer.validator.evaluate(best_skill, trajectories)
    print(f"Validation score: {score:.3f}")


def cmd_log(args):
    """Log a trajectory manually (for testing)."""
    logger = TrajectoryLogger(Path(args.skill_dir) / "trajectories")
    
    logger.start_trajectory(args.task, args.version)
    
    print("Logging steps (empty line to finish):")
    while True:
        action = input("Action: ").strip()
        if not action:
            break
        observation = input("Observation: ").strip()
        tool = input("Tool (optional): ").strip()
        logger.log_step(action, observation, tool)
    
    score = float(input("Score (0-10): ").strip() or "0")
    traj = logger.end_trajectory(score)
    print(f"Saved trajectory: {args.task} (score: {score})")


def cmd_show(args):
    """Show skill versions and scores."""
    optimizer = SkillOptimizer(args.skill_dir)
    versions = optimizer.store.list_versions()
    
    if not versions:
        print("No skill versions found")
        return
    
    print(f"{'Version':<10} {'Val Score':<12} {'Train Score':<12} {'Timestamp'}")
    print("-" * 60)
    for v in versions:
        print(f"{v['version']:<10} {v['validation_score']:<12.3f} {v['train_score']:<12.3f} {v['timestamp'][:19]}")
    
    best = optimizer.store.index.get("best_version")
    if best:
        print(f"\nBest version: {best}")


def cmd_deploy(args):
    """Deploy best skill for use."""
    optimizer = SkillOptimizer(args.skill_dir)
    path = optimizer.deploy()
    print(f"Deployed best skill to: {path}")


def main():
    parser = argparse.ArgumentParser(prog="skillopt", description="SkillOpt CLI for OpenCode")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # init
    p_init = subparsers.add_parser("init", help="Initialize new SkillOpt skill")
    p_init.add_argument("name", help="Skill name")
    p_init.add_argument("--seed-file", help="Path to seed skill markdown")
    p_init.set_defaults(func=cmd_init)
    
    # train
    p_train = subparsers.add_parser("train", help="Train skill from trajectories")
    p_train.add_argument("skill_dir", help="Skill directory")
    p_train.add_argument("--epochs", type=int, default=10)
    p_train.add_argument("--validator", default="bug_bounty")
    p_train.add_argument("--lr", type=float, default=0.1)
    p_train.add_argument("--val-split", type=float, default=0.2)
    p_train.add_argument("--max-edits", type=int, default=5)
    p_train.set_defaults(func=cmd_train)
    
    # evaluate
    p_eval = subparsers.add_parser("evaluate", help="Evaluate best skill")
    p_eval.add_argument("skill_dir")
    p_eval.add_argument("--validator", default="bug_bounty")
    p_eval.set_defaults(func=cmd_evaluate)
    
    # log
    p_log = subparsers.add_parser("log", help="Manually log a trajectory")
    p_log.add_argument("skill_dir")
    p_log.add_argument("task")
    p_log.add_argument("version")
    p_log.set_defaults(func=cmd_log)
    
    # show
    p_show = subparsers.add_parser("show", help="Show skill versions")
    p_show.add_argument("skill_dir")
    p_show.set_defaults(func=cmd_show)
    
    # deploy
    p_deploy = subparsers.add_parser("deploy", help="Deploy best skill")
    p_deploy.add_argument("skill_dir")
    p_deploy.set_defaults(func=cmd_deploy)
    
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()