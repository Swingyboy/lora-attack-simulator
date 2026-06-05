"""Example: How to Add a Custom Attack Plugin

This file demonstrates how to extend the attack simulator with a custom attack type.
The plugin system makes it easy to add new attacks without modifying framework code.

Steps to add a custom attack:
1. Create an attack class inheriting from BaseAttack
2. Implement setup(), execute(), teardown() methods
3. Create a config parser function
4. Create a factory function
5. Register the attack with an AttackSpec
6. Create a JSON scenario that uses your attack type
"""

from __future__ import annotations

import time
from typing import Any
from logging import Logger

from lora_attack_toolkit.attacks.base import AttackConfig, BaseAttack, AttackResult
from lora_attack_toolkit.attacks.analyzer import AttackAnalyzer
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.registry import AttackRegistry, AttackSpec
from lora_attack_toolkit.device.model import SimulatedDevice
from lora_attack_toolkit.gateway.model import GatewaySimulator
from lora_attack_toolkit.core.schema import RadioMetadata
from lora_attack_toolkit.core.schema_v1 import ExpectedBehavior


# Step 1: Create your attack class
class CustomAttack(BaseAttack):
    """Example custom attack that sends multiple uplinks rapidly."""
    
    def __init__(
        self,
        config: AttackConfig,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        logger: Logger,
        radio: RadioMetadata,
        burst_size: int,
        interval_sec: float,
        expected: ExpectedBehavior | None = None,
    ) -> None:
        """Initialize custom attack.
        
        Args:
            config: Base attack configuration
            device: Simulated device
            gateway: Gateway simulator
            logger: Logger instance
            radio: Radio metadata
            burst_size: Number of uplinks to send
            interval_sec: Interval between uplinks
            expected: Expected behavior (optional)
        """
        super().__init__(config, device, gateway, logger, expected)
        self.radio = radio
        self.burst_size = burst_size
        self.interval_sec = interval_sec
    
    def _create_analyzer(self) -> AttackAnalyzer:
        """Create analyzer for this attack."""
        # You can create a custom analyzer or use a generic one
        return AttackAnalyzer()  # Base analyzer
    
    def setup(self) -> None:
        """Setup phase - perform OTAA join."""
        self.logger.info("Custom attack setup: performing OTAA join")
        
        # Use framework utilities to perform join
        from lora_attack_toolkit.lorawan.lifecycle.join import perform_otaa_join
        
        join_result = perform_otaa_join(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            logger=self.logger,
        )
        
        if not join_result.success:
            raise RuntimeError(f"OTAA join failed: {join_result.message}")
        
        self.logger.info("OTAA join successful")
    
    def execute(self) -> None:
        """Execute attack - send rapid uplinks."""
        self.logger.info(
            f"Custom attack execute: sending {self.burst_size} uplinks "
            f"with {self.interval_sec}s interval"
        )
        
        for i in range(self.burst_size):
            # Build and send uplink
            payload = f"uplink-{i}".encode()
            
            uplink_frame = self.device.build_uplink(
                payload=payload,
                fport=1,
                confirmed=False,
            )
            
            # Capture the uplink
            self.capture.add_uplink(
                frame=uplink_frame,
                gateway_eui=self.gateway.gateway_eui,
                radio=self.radio,
            )
            
            # Send via gateway
            self.gateway.send_uplink(uplink_frame, self.radio)
            
            # Wait between uplinks
            if i < self.burst_size - 1:
                time.sleep(self.interval_sec)
        
        self.logger.info(f"Sent {self.burst_size} uplinks")
    
    def teardown(self) -> None:
        """Cleanup phase."""
        self.logger.info("Custom attack teardown")
        # Cleanup if needed


# Step 2: Create config parser
def parse_custom_attack_config(config: dict[str, Any]) -> dict[str, Any]:
    """Parse custom attack configuration from JSON.
    
    Args:
        config: Raw config dict from scenario JSON
        
    Returns:
        Parsed config dict
        
    Raises:
        ValueError: If config is invalid
    """
    burst_size = config.get("burst_size", 10)
    interval_sec = config.get("interval_sec", 0.5)
    
    if burst_size < 1:
        raise ValueError("burst_size must be >= 1")
    
    if interval_sec < 0:
        raise ValueError("interval_sec must be >= 0")
    
    return {
        "burst_size": burst_size,
        "interval_sec": interval_sec,
    }


# Step 3: Create factory function
def create_custom_attack(
    config: AttackConfig,
    device: SimulatedDevice,
    gateway: GatewaySimulator,
    logger: Logger,
    radio: RadioMetadata,
    attack_config: dict[str, Any],
    expected: ExpectedBehavior | None,
) -> CustomAttack:
    """Factory to create CustomAttack instance.
    
    Args:
        config: Base attack config
        device: Device simulator
        gateway: Gateway simulator
        logger: Logger
        radio: Radio metadata
        attack_config: Attack-specific config from scenario
        expected: Expected behavior
        
    Returns:
        CustomAttack instance
    """
    # Parse attack-specific config
    parsed = parse_custom_attack_config(attack_config)
    
    return CustomAttack(
        config=config,
        device=device,
        gateway=gateway,
        logger=logger,
        radio=radio,
        burst_size=parsed["burst_size"],
        interval_sec=parsed["interval_sec"],
        expected=expected,
    )


# Step 4: Register the attack
def register_custom_attack() -> None:
    """Register custom attack with the attack registry."""
    spec = AttackSpec(
        name="custom_uplink_burst",
        attack_class=CustomAttack,
        config_parser=parse_custom_attack_config,
        factory=create_custom_attack,
        aliases=["uplink_burst"],  # Optional aliases
        description="Send burst of uplinks to test rate limiting",
    )
    
    AttackRegistry.register(spec)


# Step 5: Use it!
if __name__ == "__main__":
    """
    To use this custom attack:
    
    1. Import and register it in your bootstrap:
       from custom_attack_example import register_custom_attack
       register_custom_attack()
    
    2. Create a JSON scenario:
       {
         "schema_version": "1.0",
         "scenario": {
           "id": "custom-burst-attack",
           "type": "custom_uplink_burst",
           ...
         },
         "attack": {
           "type": "custom_uplink_burst",
           "config": {
             "burst_size": 20,
             "interval_sec": 0.1
           }
         },
         ...
       }
    
    3. Run it:
       lorat use custom-burst-attack run
    """
    print(__doc__)
