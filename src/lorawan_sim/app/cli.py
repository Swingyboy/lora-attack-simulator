from __future__ import annotations

import argparse
import json
import logging

from lorawan_sim.attacks.runner import AttackRunner
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

        # Run attack scenario
        configure_logging(level=attack_scenario.logging.level)
        logger = logging.getLogger("lorawan_sim.attacks")
        runner = AttackRunner(logger=logger)
        
        print(f"\n=== Running Attack: {attack_scenario.attack.name} ===")
        print(f"Type: {attack_scenario.attack.attack_type}")
        print(f"Target: {attack_scenario.gateway.semtech_udp.host}:{attack_scenario.gateway.semtech_udp.port}")
        print(f"Device: {attack_scenario.device.activation.dev_eui}")
        print()
        
        try:
            results = runner.run(attack_scenario)
            
            print(f"\n=== Attack Results ===")
            print(f"Success: {results.get('success', False)}")
            print(f"Message: {results.get('message', 'No message')}")
            print(f"\nMetrics:")
            for key, value in results.get('metrics', {}).items():
                print(f"  {key}: {value}")
            
            # Save results
            import pathlib
            results_file = pathlib.Path(args.scenario_path).with_suffix(".results.json")
            with open(results_file, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {results_file}")
            
            return 0 if results.get('success') else 1
            
        except Exception as exc:
            logger.exception("Attack execution failed")
            print(f"\nAttack failed: {exc}")
            return 1

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
