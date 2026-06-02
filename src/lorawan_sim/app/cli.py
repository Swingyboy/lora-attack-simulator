from __future__ import annotations

import argparse
import logging

from lorawan_sim.core.runner.scenario_runner import ScenarioRunner
from lorawan_sim.domain.attack_scenario.loader import load_attack_scenario
from lorawan_sim.domain.scenario.loader import load_scenario
from lorawan_sim.observability.logging.json_logger import configure_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lorawan-sim")
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="Run a scenario")
    run_cmd.add_argument("scenario_path")

    validate_cmd = sub.add_parser("validate", help="Validate a scenario")
    validate_cmd.add_argument("scenario_path")
    
    # Attack scenario commands
    run_attack_cmd = sub.add_parser("run-attack", help="Run an attack scenario")
    run_attack_cmd.add_argument("scenario_path", help="Path to attack scenario JSON")
    
    validate_attack_cmd = sub.add_parser("validate-attack", help="Validate an attack scenario")
    validate_attack_cmd.add_argument("scenario_path", help="Path to attack scenario JSON")
    
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle attack scenario commands
    if args.command in ["run-attack", "validate-attack"]:
        try:
            attack_scenario = load_attack_scenario(args.scenario_path)
        except ValueError as exc:
            print(f"attack validation failed: {exc}")
            return 2

        if args.command == "validate-attack":
            print("attack scenario is valid")
            return 0

        # For now, print message that attack runner is not yet implemented
        print(f"Attack scenario loaded: {attack_scenario.attack.name}")
        print(f"Attack type: {attack_scenario.attack.attack_type}")
        print("Note: Attack runner will be implemented in Phase 2-4")
        return 0

    # Handle regular scenario commands
    try:
        scenario = load_scenario(args.scenario_path)
    except ValueError as exc:
        print(f"validation failed: {exc}")
        return 2

    if args.command == "validate":
        print("scenario is valid")
        return 0

    configure_logging(level=scenario.logging.level)
    logger = logging.getLogger("lorawan_sim")
    runner = ScenarioRunner(logger=logger)
    try:
        runner.run(scenario)
    except Exception as exc:
        logger.exception("runtime error: %s", exc)
        return 1
    return 0
