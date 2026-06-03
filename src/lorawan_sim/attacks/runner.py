"""Attack scenario runner implementation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from lorawan_sim.attacks.join_abuse import JoinAbuseAttack
from lorawan_sim.attacks.mac_abuse import MACCommandAbuse
from lorawan_sim.attacks.replay import ReplayAttack
from lorawan_sim.lorawan.scenario.schema_v1 import (
    AttackScenarioV1,
    parse_join_flood_config,
    parse_join_replay_config,
    parse_mac_command_config,
    parse_replay_config,
)
from lorawan_sim.lorawan.device.factory import create_device
from lorawan_sim.lorawan.gateway.factory import create_gateway
from lorawan_sim.lorawan.scenario.schema import RadioMetadata


class AttackRunner:
    """Runner for executing attack scenarios."""
    
    def __init__(self, logger: logging.Logger | None = None, session_id: str | None = None) -> None:
        """
        Initialize attack runner.
        
        Args:
            logger: Logger instance (created if None)
            session_id: Session ID for result file organization (generated if None)
        """
        self.logger = logger or logging.getLogger("lorawan_sim.attacks")
        self.session_id = session_id or self._generate_session_id()
    
    @staticmethod
    def _generate_session_id() -> str:
        """Generate a session ID for result organization."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def run(self, scenario: AttackScenarioV1) -> dict[str, Any]:
        """
        Run an attack scenario (v1.0 format only).
        
        Args:
            scenario: The attack scenario to execute (v1.0)
            
        Returns:
            Attack results including analysis and metrics
        
        Note:
            Legacy v0.9 format support removed
        """
        return self._run_v1(scenario)
    
    def _run_v1(self, scenario: AttackScenarioV1) -> dict[str, Any]:
        """Run v1.0 format scenario."""
        self.logger.info(f"Starting attack scenario (v1.0): {scenario.scenario.title}")
        self.logger.info(f"Attack type: {scenario.attack.type}")
        self.logger.info(f"Description: {scenario.scenario.description}")
        self.logger.info(f"Target: {scenario.target.name} @ {scenario.target.host}:{scenario.target.port}")
        
        # Build device and gateway from config
        device = create_device(scenario.device)
        
        # Create gateway with v1.0 config (factory handles the conversion)
        gateway = create_gateway((scenario.gateway, scenario.target), self.logger)
        
        # Extract radio metadata for attack
        from lorawan_sim.lorawan.scenario.schema import RadioMetadata
        radio = RadioMetadata(
            frequency=scenario.gateway.radio.frequency_hz,
            data_rate=scenario.gateway.radio.data_rate,
            rssi=scenario.gateway.radio.rssi,
            snr=scenario.gateway.radio.snr,
        )
        
        # Create attack instance based on type
        attack = self._create_attack_v1(scenario, device, gateway, radio)
        
        # Run attack lifecycle
        try:
            self.logger.info("Executing attack...")
            result = attack.run()
            
            # Convert AttackResult to dict
            results = {
                "success": result.success,
                "message": result.message,
                "metrics": result.metrics,
                "captured_packets": result.captured_packets,
                "expected_behavior": scenario.expected.secure_behavior,
                "success_criteria": scenario.expected.success_criteria,
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
    
    def _create_attack_v1(
        self,
        scenario: AttackScenarioV1,
        device: Any,
        gateway: Any,
        radio: RadioMetadata,
    ) -> Any:
        """Create attack instance from v1.0 scenario configuration."""
        from lorawan_sim.attacks.base import AttackConfig
        
        attack_type = scenario.attack.type
        
        # Build base attack config
        config_dict = {
            "name": scenario.scenario.id,
            "description": scenario.scenario.description,
            "timeout_sec": scenario.scenario.timeout_sec,
        }
        config = AttackConfig(**config_dict)
        
        # Parse attack-specific config and create attack
        if attack_type == "uplink_replay":
            replay_config = parse_replay_config(scenario.attack.config)
            return ReplayAttack(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                replay_mode=replay_config.replay_phase.mode,
                delay_sec=replay_config.replay_phase.delay_sec,
                burst_count=replay_config.replay_phase.count,
                burst_interval_sec=0.1,  # Not in config, use default
                expected=scenario.expected,
            )
        
        elif attack_type == "join_replay":
            join_config = parse_join_replay_config(scenario.attack.config)
            return JoinAbuseAttack(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                mode="replay",
                flood_count=join_config.replay_count,
                flood_interval_sec=join_config.delay_sec,
                replay_delay_sec=join_config.delay_sec,  # Pass delay for replay timing
                virtual_devices=1,
                expected=scenario.expected,
                timing=join_config.timing,  # Pass timing configuration
                inter_message_delay_sec=scenario.scenario.timeout_sec,  # Delay between uplinks
            )
        
        elif attack_type == "join_flood":
            flood_config = parse_join_flood_config(scenario.attack.config)
            return JoinAbuseAttack(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                mode="flood",
                flood_count=flood_config.flood_count,
                flood_interval_sec=flood_config.flood_interval_sec,
                virtual_devices=flood_config.virtual_devices,
                expected=scenario.expected,
            )
        
        elif attack_type in ("mac_command_injection", "mac_malformed"):
            mac_config = parse_mac_command_config(scenario.attack.config)
            malformation_type = mac_config.malformation_type or "truncated"
            return MACCommandAbuse(
                config=config,
                device=device,
                gateway=gateway,
                logger=self.logger,
                radio=radio,
                command_type=mac_config.command_type,
                malformed=mac_config.malformed,
                malformation_type=malformation_type,
                parameters=mac_config.parameters or {},
                expected=scenario.expected,
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
        from lorawan_sim.lorawan.scenario.loader import load_attack_scenario
        
        scenario = load_attack_scenario(scenario_path)
        results = self.run(scenario)
        
        # Save results with session-based organization
        # Format: results/<session-id>/<scenario-name>.results.json
        scenario_name = Path(scenario_path).stem
        results_dir = Path("results") / self.session_id
        results_dir.mkdir(parents=True, exist_ok=True)
        
        results_path = results_dir / f"{scenario_name}.results.json"
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to: {results_path}")
        return results
