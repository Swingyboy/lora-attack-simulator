"""Base attack class for all attack implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING, Any

from lorawan_sim.attacks.analyzer import AttackAnalyzer
from lorawan_sim.attacks.packet_capture import PacketCapture
from lorawan_sim.domain.device.model import SimulatedDevice
from lorawan_sim.domain.gateway.model import GatewaySimulator

if TYPE_CHECKING:
    from lorawan_sim.domain.attack_scenario.schema_v1 import ExpectedBehavior


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
    validation_summary: str | None = None
    criteria_met: dict[str, bool] | None = None


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
        expected: ExpectedBehavior | None = None,
    ) -> None:
        self.config = config
        self.device = device
        self.gateway = gateway
        self.logger = logger
        self.expected = expected
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
            analysis = self.analyzer.analyze(self.capture, self.expected)
            
            result = AttackResult(
                attack_name=self.config.name,
                success=analysis["success"],
                message=analysis["message"],
                metrics=analysis["metrics"],
                captured_packets=len(self.capture.uplinks) + len(self.capture.downlinks),
            )
            
            # Include validation results if present
            if "validation_summary" in analysis:
                result.validation_summary = analysis["validation_summary"]
                result.criteria_met = analysis.get("criteria_met", {})
            
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
