"""Attack scenario runner implementation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from lorawan_sim.attacks.join_abuse import JoinAbuseAttack
from lorawan_sim.attacks.mac_abuse import MACCommandAbuse
from lorawan_sim.attacks.replay import ReplayAttack
from lorawan_sim.domain.attack_scenario.schema import AttackScenarioConfig
from lorawan_sim.domain.device.factory import create_device
from lorawan_sim.domain.gateway.factory import create_gateway
from lorawan_sim.domain.scenario.schema import RadioMetadata


class AttackRunner:
    """Runner for executing attack scenarios."""
    
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("lorawan_sim.attacks")
    
    def run(self, scenario: AttackScenarioConfig) -> dict[str, Any]:
        """
        Run an attack scenario.
        
        Args:
            scenario: The attack scenario to execute
            
        Returns:
            Attack results including analysis and metrics
        """
        self.logger.info(f"Starting attack scenario: {scenario.attack.name}")
        self.logger.info(f"Attack type: {scenario.attack.attack_type}")
        self.logger.info(f"Description: {scenario.attack.description}")
        
        # Build device and gateway from config
        device = create_device(scenario.device)
        gateway = create_gateway(scenario.gateway, self.logger)
        
        # Extract radio metadata
        radio = RadioMetadata(
            frequency=scenario.gateway.radio_metadata.frequency,
            data_rate=scenario.gateway.radio_metadata.data_rate,
            rssi=scenario.gateway.radio_metadata.rssi,
            snr=scenario.gateway.radio_metadata.snr,
        )
        
        # Create attack instance based on type
        attack = self._create_attack(scenario, device, gateway, radio)
        
        # Run attack lifecycle using built-in run() method
        try:
            self.logger.info("Executing attack...")
            result = attack.run()
            
            # Convert AttackResult to dict
            results = {
                "success": result.success,
                "message": result.message,
                "metrics": result.metrics,
                "captured_packets": result.captured_packets,
            }
            
            self.logger.info(f"Attack completed: {results['message']}")
            return results
            
        except Exception as e:
            self.logger.exception(f"Attack failed: {e}")
            return {
                "success": False,
                "message": f"Attack execution failed: {str(e)}",
                "metrics": {},
                "error": str(e),
            }
    
    def _create_attack(
        self,
        scenario: AttackScenarioConfig,
        device: Any,
        gateway: Any,
        radio: RadioMetadata,
    ) -> Any:
        """Create attack instance based on scenario configuration."""
        attack_type = scenario.attack.attack_type
        config_dict = {
            "name": scenario.attack.name,
            "description": scenario.attack.description,
            "timeout_sec": scenario.attack.timeout_sec,
        }
        
        if attack_type == "replay":
            from lorawan_sim.attacks.base import AttackConfig
            config = AttackConfig(**config_dict)
            return ReplayAttack(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                replay_mode=scenario.replay.mode if scenario.replay else "immediate",
                delay_sec=scenario.replay.delay_sec if scenario.replay else 0.0,
                burst_count=scenario.replay.burst_count if scenario.replay else 1,
                burst_interval_sec=scenario.replay.burst_interval_sec if scenario.replay else 0.1,
            )
        
        elif attack_type in ("join_abuse", "join_replay", "join_flood"):
            # Handle join abuse attacks (unified under JoinAbuseAttack class)
            from lorawan_sim.attacks.base import AttackConfig
            config = AttackConfig(**config_dict)
            
            # Determine mode from attack_type or config
            if attack_type == "join_flood":
                mode = "flood"
            elif attack_type == "join_replay":
                mode = "replay"
            elif scenario.join_abuse:
                mode = scenario.join_abuse.mode
            else:
                mode = "replay"  # default
            
            # Get parameters
            if scenario.join_abuse:
                flood_count = scenario.join_abuse.flood_count
                flood_interval = scenario.join_abuse.flood_interval_sec
                virtual_devices = scenario.join_abuse.virtual_devices
            else:
                flood_count = 10
                flood_interval = 0.1
                virtual_devices = 1
            
            return JoinAbuseAttack(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                mode=mode,
                flood_count=flood_count,
                flood_interval_sec=flood_interval,
                virtual_devices=virtual_devices,
            )
        
        elif attack_type == "mac_abuse":
            from lorawan_sim.attacks.base import AttackConfig
            config = AttackConfig(**config_dict)
            
            # Use mac_command field (not mac_abuse) to align with schema
            if not scenario.mac_command:
                raise ValueError("MAC abuse attack requires mac_command configuration")
            
            # Extract malformation_type from parameters if present
            params = scenario.mac_command.parameters or {}
            malformation_type = params.get("malformation_type", "truncated")
            
            return MACCommandAbuse(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                command_type=scenario.mac_command.command_type,
                malformed=scenario.mac_command.malformed,
                malformation_type=malformation_type,
                parameters=params,
            )
        
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")
    
    def run_from_file(self, scenario_path: str) -> dict[str, Any]:
        """
        Load and run attack scenario from file.
        
        Args:
            scenario_path: Path to attack scenario JSON file
            
        Returns:
            Attack results
        """
        from lorawan_sim.domain.attack_scenario.loader import load_attack_scenario
        
        scenario = load_attack_scenario(scenario_path)
        results = self.run(scenario)
        
        # Save results to file
        results_path = Path(scenario_path).with_suffix(".results.json")
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to: {results_path}")
        return results
