"""Base attack class for all attack implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Any

from lorawan_sim.attacks.analyzer import AttackAnalyzer
from lorawan_sim.attacks.packet_capture import PacketCapture
from lorawan_sim.domain.device.model import SimulatedDevice
from lorawan_sim.domain.gateway.model import GatewaySimulator


@dataclass
class AttackConfig:
    """Configuration for attack execution."""
    
    name: str
    description: str
    timeout_sec: float = 60.0
    capture_enabled: bool = True


@dataclass
class AttackResult:
    """Result of attack execution."""
    
    attack_name: str
    success: bool
    message: str
    metrics: dict[str, Any]
    captured_packets: int = 0


class BaseAttack(ABC):
    """
    Abstract base class for all attack implementations.
    
    Provides common infrastructure for:
    - Packet capture and replay
    - Response analysis
    - Attack lifecycle management
    """
    
    def __init__(
        self,
        config: AttackConfig,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        logger: Logger,
    ) -> None:
        self.config = config
        self.device = device
        self.gateway = gateway
        self.logger = logger
        self.capture = PacketCapture(logger=logger)
        self.analyzer = self._create_analyzer()
    
    @abstractmethod
    def _create_analyzer(self) -> AttackAnalyzer:
        """Create attack-specific analyzer."""
        raise NotImplementedError
    
    @abstractmethod
    def setup(self) -> None:
        """
        Setup phase - prepare for attack execution.
        
        This may include:
        - Device provisioning
        - Initial join procedure
        - Session establishment
        """
        raise NotImplementedError
    
    @abstractmethod
    def execute(self) -> None:
        """
        Execute the main attack logic.
        
        This is where the actual attack happens:
        - Packet injection
        - Replay attacks
        - Flooding
        - Malformed traffic generation
        """
        raise NotImplementedError
    
    @abstractmethod
    def teardown(self) -> None:
        """
        Teardown phase - cleanup after attack.
        
        Clean up resources and prepare for analysis.
        """
        raise NotImplementedError
    
    def run(self) -> AttackResult:
        """
        Execute complete attack lifecycle.
        
        Returns:
            AttackResult with success status and metrics
        """
        self.logger.info(f"Starting attack: {self.config.name}")
        
        try:
            # Setup phase
            self.logger.info("Attack phase: setup")
            self.setup()
            
            # Execute attack
            self.logger.info("Attack phase: execute")
            self.execute()
            
            # Teardown
            self.logger.info("Attack phase: teardown")
            self.teardown()
            
            # Analyze results
            self.logger.info("Attack phase: analysis")
            analysis = self.analyzer.analyze(self.capture)
            
            result = AttackResult(
                attack_name=self.config.name,
                success=analysis["success"],
                message=analysis["message"],
                metrics=analysis["metrics"],
                captured_packets=len(self.capture.uplinks) + len(self.capture.downlinks),
            )
            
            self.logger.info(
                f"Attack completed: {self.config.name}",
                extra={
                    "success": result.success,
                    "attack_message": result.message,
                    "metrics": result.metrics,
                },
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Attack failed: {self.config.name}", exc_info=True)
            return AttackResult(
                attack_name=self.config.name,
                success=False,
                message=f"Attack execution failed: {str(e)}",
                metrics={},
            )
