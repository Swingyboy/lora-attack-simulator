"""Attack scenario runner implementation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from lora_attack_toolkit.attacks.registry import AttackRegistry
from lora_attack_toolkit.core.schema_v1 import AttackScenarioV1
from lora_attack_toolkit.runtime.device import create_device
from lora_attack_toolkit.runtime.gateway import create_gateway
from lora_attack_toolkit.core.schema import RadioMetadata


class AttackRunner:
    """Runner for executing attack scenarios."""
    
    def __init__(self, logger: logging.Logger | None = None, session_id: str | None = None) -> None:
        """
        Initialize attack runner.
        
        Args:
            logger: Logger instance (created if None)
            session_id: Session ID for result file organization (generated if None)
        """
        self.logger = logger or logging.getLogger("lora_attack_toolkit.attacks")
        self.session_id = session_id or self._generate_session_id()
    
    @staticmethod
    def _generate_session_id() -> str:
        """Generate a session ID for result organization."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def run(self, scenario: AttackScenarioV1, cancel_event=None) -> dict[str, Any]:
        """
        Run an attack scenario (v1.0 format only).
        
        Args:
            scenario: The attack scenario to execute (v1.0)
            cancel_event: Optional threading.Event; set it to request cooperative cancellation.
            
        Returns:
            Attack results including analysis and metrics
        """
        return self._run_v1(scenario, cancel_event=cancel_event)
    
    def _run_v1(self, scenario: AttackScenarioV1, cancel_event=None) -> dict[str, Any]:
        """Run v1.0 format scenario with new attack API."""
        # Resolve attack metadata from registry
        try:
            spec = AttackRegistry.get_spec(scenario.attack.type)
        except ValueError as exc:
            return {
                "success": False,
                "message": str(exc),
                "metrics": {},
                "error": str(exc),
            }

        title = spec.title or spec.name
        category = spec.category or spec.name
        self.logger.info(f"Starting attack scenario: {title}")
        self.logger.info(f"Attack type: {scenario.attack.type}  Category: {category}")
        self.logger.info(f"Description: {scenario.scenario.description}")
        self.logger.info(f"Target: {scenario.target.name} @ {scenario.target.host}:{scenario.target.port}")
        
        # Build device and gateway from config
        device = create_device(scenario.device, logger=self.logger)
        
        # Create gateway with v1.0 config
        gateway = create_gateway((scenario.gateway, scenario.target), self.logger)
        
        radio = RadioMetadata(
            frequency=scenario.gateway.radio.frequency_hz,
            data_rate=scenario.gateway.radio.data_rate,
            rssi=scenario.gateway.radio.rssi,
            snr=scenario.gateway.radio.snr,
        )
        
        # Create attack context with services and typed config
        try:
            self.logger.info("Executing attack...")
            typed_config = spec.config_parser(scenario.attack.config)
            ctx = self._create_attack_context(
                scenario,
                device,
                gateway,
                radio,
                typed_config,
                cancel_event=cancel_event,
            )
            attack = spec.attack_class()
            
            result = attack.run(ctx)
            
            # Use AttackResult.to_dict() for consistent output
            results = result.to_dict()
            
            # Add expected behavior for compatibility
            results["expected_behavior"] = scenario.expected.secure_behavior
            results["success_criteria"] = scenario.expected.success_criteria
            
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
    
    def _create_attack_context(
        self,
        scenario: AttackScenarioV1,
        device: Any,
        gateway: Any,
        radio: RadioMetadata,
        typed_config: Any,
        cancel_event=None,
    ) -> Any:
        """
        Create AttackContext with services and typed configuration.
        
        Args:
            scenario: Attack scenario with configuration
            device: Simulated device
            gateway: Gateway simulator
            radio: Radio metadata
        
        Returns:
            AttackContext ready for attack execution
        """
        from lora_attack_toolkit.attacks.context import AttackContext, AttackServices, AttackInput
        from lora_attack_toolkit.attacks.packet_capture import PacketCapture
        attack_config_dict = scenario.attack.config
        
        # Create services
        capture = PacketCapture(logger=self.logger)
        services = AttackServices(
            device=device,
            gateway=gateway,
            logger=self.logger,
            capture=capture,
            metrics=None,  # TODO: Add metrics collector when implemented
        )
        
        # Create input
        attack_input = AttackInput(
            typed_config=typed_config,
            expected_behavior=scenario.expected,
            radio=radio,
            timeout_sec=scenario.scenario.timeout_sec,
            attack_config=attack_config_dict if typed_config is None else None,
        )
        
        # Create and return context
        import threading
        return AttackContext(
            services=services,
            input=attack_input,
            cancel_event=cancel_event if cancel_event is not None else threading.Event(),
        )
    
    def run_from_file(self, scenario_path: str) -> dict[str, Any]:
        """
        Load and run attack scenario from file.
        
        Args:
            scenario_path: Path to attack scenario JSON file
            
        Returns:
            Attack results
        """
        from lora_attack_toolkit.core.loader import load_attack_scenario
        
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
